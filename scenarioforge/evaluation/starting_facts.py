"""Public starting knowledge shared by guides, graphs and evaluation packages."""
import json


def collect_starting_facts(*, flow=None, assignments=(), definitions=None):
    flow = flow if isinstance(flow, dict) else {}
    result, seen = [], set()

    def add(fact, **context):
        if not isinstance(fact, dict):
            raise ValueError('Starting facts must be objects')
        if any(not isinstance(fact.get(k), str) or not fact[k].strip() for k in ('id', 'artifact', 'value')):
            raise ValueError('Starting facts require nonempty id, artifact and value')
        # Deliberately copy only public fields, never generator outputs/evidence.
        row = {k: fact[k] for k in ('id', 'artifact', 'value')}
        row.update(context)
        key = (row.get('task_id'), row['artifact'], row['value'])
        if key not in seen:
            seen.add(key)
            result.append(row)

    for fact in flow.get('starting_facts', []):
        add(fact, **{k: fact[k] for k in ('task_id', 'source_node') if k in fact})
    for index, assignment in enumerate(assignments or []):
        if not isinstance(assignment, dict):
            continue
        supplied = assignment.get('chain_supplied_input_values', {})
        if not isinstance(supplied, dict):
            continue
        for key, value in supplied.items():
            if value is None or value == '':
                continue
            add({'id': f'supplied-{index + 1}-{len(result) + 1}', 'artifact': str(key),
                 'value': value if isinstance(value, str) else json.dumps(value, sort_keys=True)},
                source_node=str(assignment.get('node_id') or ''))
    tasks = definitions if definitions is not None else flow.get('evaluation_tasks', [])
    for task in tasks or []:
        for fact in task.get('starting_facts', []):
            add(fact, task_id=task['id'])
    return result


def starting_facts_markdown(facts):
    """Plain text suitable for a public briefing; values are escaped as Markdown."""
    def escape(value):
        text = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        for char in ('\\', '`', '*', '_', '[', ']', '#', '|'):
            text = text.replace(char, '\\' + char)
        return text.replace('\n', ' ')
    lines = ['## Starting facts', '', 'Information supplied before the exercise:', '']
    for fact in facts:
        scope = f" (task: {fact['task_id']})" if fact.get('task_id') else ''
        lines.append(f"- {escape(fact['artifact'])}{escape(scope)}: {escape(fact['value'])}")
    if not facts:
        lines.append('No explicit starting facts recorded.')
    return '\n'.join(lines) + '\n'
