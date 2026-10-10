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


def _guide_preview(flow, graph):
    """Render the guide against the frozen graph's resolved hosts and outputs."""
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
    return {
        'chain': chain, 'flag_assignments': assignments,
        'starting_facts': graph.get('starting_facts', []),
        'discovery': bool(flow.get('discovery')),
        'vuln_readme_entries': flow.get('vuln_readme_entries', []),
    }


def guide_hints(flow, graph):
    if not flow:
        return []
    from scenarioforge.utils.guide_export import participant_hint_plan
    return participant_hint_plan(graph['scenario'], _guide_preview(flow, graph))


def guide_solutions(flow, graph):
    if not flow:
        return []
    from scenarioforge.utils.guide_export import facilitator_solution_plan
    return facilitator_solution_plan(graph['scenario'], _guide_preview(flow, graph))


def solutions_for_task(rendered, graph, refs, verifier, prompt, labels=None):
    import json
    nodes = {str(node['id']): node for node in graph['nodes']}
    if refs is None:
        matches = [ref for ref, node in nodes.items() if node.get('ipv4') and node['ipv4'] in prompt]
        ref = matches[0] if len(matches) == 1 else next(iter(nodes)) if len(nodes) == 1 else None
        selected = [dict(node_id=ref or 'task', text=next((item['text'] for item in rendered if item['node_id']==ref), ''))]
    else:
        selected = [item for item in rendered if item['node_id'] in refs]
    all_flags = [node['generator']['flag_value'] for node in nodes.values()
                 if isinstance(node.get('generator'),dict) and node['generator'].get('flag_value')]
    result = []
    for item in selected:
        ref = item['node_id']
        answer = verifier['expected']
        if refs is not None:
            flag = nodes[ref]['generator']['flag_value']
            answer = {'flags':[flag]} if verifier['type']=='flags_found' else {'flags':{(labels or {}).get(ref,ref):flag}}
            completion = [flag]
        else:
            completion = []
            if verifier['type'] == 'rubric' and ref in nodes:
                flag = (nodes[ref].get('generator') or {}).get('flag_value')
                if flag:
                    completion = [flag]
        walkthrough = re.sub(r' @ (?:\d{1,3}\.){3}\d{1,3}', '', item['text'])
        for flag in all_flags:
            if flag not in completion:
                walkthrough = walkthrough.replace(flag, '[another challenge answer withheld]')
        text = 'Solution walkthrough for challenge ' + ref + ':\nReviewed task: ' + prompt + '\n' + walkthrough[:14000]
        if verifier['type'] == 'rubric':
            references = [c.get('private_reference', '') for c in answer['criteria'] if c.get('private_reference')]
            if not walkthrough.strip() and not references and not completion:
                continue
            text += '\nFacilitator reference:\n' + '\n'.join(references)
            if completion:
                text += '\nCurrent challenge answer / flag:\n' + '\n'.join(completion)
        else:
            text += '\nExact answer / flag to submit:\n' + json.dumps(answer, ensure_ascii=False)
        result.append(dict(node_id=ref,text=text,completion_values=completion))
    return result


def hints_for_nodes(flow, source_nodes, verifier, private_facts=(), *, rendered=(), graph=None):
    assignments = flow.get('flag_assignments', [])
    assignments = [item for item in assignments if isinstance(item, dict)] if isinstance(assignments, list) else []
    assignments += [node['generator'] for node in (graph or {}).get('nodes', [])
                    if isinstance(node.get('generator'), dict)]
    secrets = ([c.get('private_reference', '') for c in verifier['expected']['criteria']]
               if verifier.get('type') == 'rubric' else list(strings(verifier.get('expected'))))
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


def solutions_for_plan(rendered, graph, plan, rubric):
    """Release only the selected challenge's private walkthrough and references."""
    nodes = {str(n['id']): n for n in graph['nodes']}
    guides = {str(s['node_id']): s['text'] for s in rendered}
    criteria = {c['id']: c for c in rubric['criteria']}
    flags = {ref: (n.get('generator') or {}).get('flag_value') for ref, n in nodes.items()}
    result = []
    for step in plan['steps']:
        ref = step['node_id']
        text = guides.get(ref) or step.get('solution', '')
        text += '\nFacilitator reference for this challenge:\n' + '\n'.join(
            criteria[c].get('private_reference', '') for c in step['criterion_ids'])
        if flags.get(ref):
            text += '\nCurrent challenge answer / flag:\n' + flags[ref]
        text = withhold_other_answers(text, graph, ref)
        if text.strip():
            result.append(dict(node_id=ref, step_id=step['id'], text=text[:32000],
                               completion_values=[flags[ref]] if flags.get(ref) else []))
    return result


def withhold_other_answers(text, graph, current_node):
    """Keep other challenges' known answers out of a released walkthrough."""
    nodes = {str(n['id']): n for n in graph['nodes']}
    def answers(node):
        generator = node.get('generator') or {}
        values = list(strings(generator.get('flag_value')))
        for key, value in (generator.get('resolved_outputs') or {}).items():
            if any(word in str(key).lower() for word in ('flag','token','secret','password','credential','proof')):
                values.extend(strings(value))
        return {value for value in values if value}
    current = answers(nodes.get(str(current_node), {}))
    for ref, node in nodes.items():
        if ref == str(current_node):
            continue
        for value in sorted(answers(node) - current, key=len, reverse=True):
            text = text.replace(value, '[another challenge answer withheld]')
    return text
