"""Guide-derived hints kept in private evaluator metadata until released."""
import re


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif value is not None:
        import json
        yield json.dumps(value)


def guide_hints(flow, graph):
    """Render the guide against the frozen graph's resolved hosts and outputs."""
    if not flow:
        return []
    from scenarioforge.utils.guide_export import participant_hint_plan
    nodes = {str(node['id']): node for node in graph['nodes']}
    order = graph.get('chain_order') or list(nodes)
    chain = [dict(nodes[str(ref)], name=nodes[str(ref)].get('label') or str(ref))
             for ref in order if str(ref) in nodes]
    raw_assignments = flow.get('flag_assignments', [])
    raw_assignments = raw_assignments if isinstance(raw_assignments, list) else []
    saved = {str(item.get('node_id')): item for item in raw_assignments
             if isinstance(item, dict)}
    assignments = []
    for node in chain:
        assignment = dict(saved.get(str(node['id']), {}), node_id=str(node['id']))
        generator = node.get('generator') or {}
        for key in ('resolved_inputs', 'resolved_outputs', 'flag_value'):
            if generator.get(key) is not None:
                assignment[key] = generator[key]
        assignments.append(assignment)
    return participant_hint_plan(graph['scenario'], {
        'chain': chain, 'flag_assignments': assignments,
        'starting_facts': graph.get('starting_facts', []),
        'discovery': bool(flow.get('discovery')),
        'vuln_readme_entries': flow.get('vuln_readme_entries', []),
    })


def hints_for_nodes(flow, source_nodes, verifier, private_facts=(), *, rendered=(), graph=None):
    assignments = flow.get('flag_assignments', [])
    assignments = [item for item in assignments if isinstance(item, dict)] if isinstance(assignments, list) else []
    assignments += [node['generator'] for node in (graph or {}).get('nodes', [])
                    if isinstance(node.get('generator'), dict)]
    secrets = list(strings(verifier.get('expected')))
    secrets += [str(item.get('value') or '') for item in private_facts if isinstance(item, dict)]
    for assignment in assignments:
        secrets.append(str(assignment.get('flag_value') or ''))
        outputs = assignment.get('resolved_outputs')
        for key, value in (outputs.items() if isinstance(outputs, dict) else ()):
            if any(word in str(key).lower() for word in ('flag', 'token', 'secret', 'password', 'credential')):
                secrets.extend(strings(value))
    result = []
    # The renderer preserves chain order and low -> medium -> high order per step.
    for hint in rendered:
        if source_nodes is not None and str(hint.get('node_id')) not in source_nodes:
            continue
        value = str(hint.get('text') or '').strip()
        # Guide rendering annotates node names with addresses, even when a node
        # name occurs inside an answer. Do not let that disguise a verifier value.
        unannotated = re.sub(r' @ (?:\d{1,3}\.){3}\d{1,3}', '', value)
        if not value or len(value) > 1500 or '{{' in value or '}}' in value or any(
                secret and (secret in value or secret in unannotated) for secret in secrets):
            continue
        if value not in result:
            result.append(value)
        if len(result) == 16:
            break
    return result
