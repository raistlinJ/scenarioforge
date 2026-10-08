"""Participant-safe authored hints carried from saved Flow into task metadata."""
from pathlib import PurePosixPath


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


def hints_for_nodes(flow, source_nodes, verifier, private_facts=()):
    assignments = flow.get('flag_assignments', [])
    assignments = [item for item in assignments if isinstance(item, dict)] if isinstance(assignments, list) else []
    secrets = list(strings(verifier.get('expected')))
    secrets += [str(item.get('value') or '') for item in private_facts if isinstance(item, dict)]
    for assignment in assignments:
        secrets.append(str(assignment.get('flag_value') or ''))
        outputs = assignment.get('resolved_outputs')
        for key, value in (outputs.items() if isinstance(outputs, dict) else ()):
            if any(word in str(key).lower() for word in ('flag', 'token', 'secret', 'password', 'credential')):
                secrets.extend(strings(value))
    result = []
    for assignment in assignments:
        if str(assignment.get('node_id') or '') not in source_nodes:
            continue
        values = []
        for key in ('promoted_first_step_hint_lines', 'chain_supplied_input_hints', 'hints', 'description_hints', 'hint'):
            raw = assignment.get(key)
            if isinstance(raw, str):
                values.append(raw)
            elif isinstance(raw, list):
                values.extend(raw)
        levels = assignment.get('hint_levels')
        if isinstance(levels, dict):
            for level in ('low', 'medium', 'high'):
                raw = levels.get(level)
                if isinstance(raw, str):
                    values.append(raw)
                elif isinstance(raw, list):
                    values.extend(raw)
        outputs = assignment.get('resolved_outputs')
        outputs = outputs if isinstance(outputs, dict) else {}
        for value in values:
            if not isinstance(value, str):
                continue
            for field in ('File(path)', 'FlagFile(path)'):
                path = outputs.get(field)
                if isinstance(path, str) and path:
                    value = value.replace('{{OUTPUT.' + field + ':basename}}', PurePosixPath(path).name)
            value = value.strip()
            if not value or len(value) > 1500 or '{{' in value or '}}' in value or any(secret and secret in value for secret in secrets):
                continue
            if value not in result:
                result.append(value)
            if len(result) == 16:
                return result
    return result
