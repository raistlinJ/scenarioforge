"""Explicit participant knowledge; does not infer knowledge from tool permissions."""
import ipaddress
import json
import re


def reject_discovery_leaks(text, facts):
    """Catch literal facts and IPv4 addresses within a hidden subnet."""
    for fact in facts:
        value = fact['value']
        if value in text:
            raise ValueError('Discoverable fact appears in participant content')
        if fact['artifact'] == 'InternalNetwork(subnet)':
            network = ipaddress.ip_network(value, strict=False)
            for token in re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])', text):
                try:
                    address = ipaddress.ip_address(token)
                except ValueError:
                    continue
                if address in network:
                    raise ValueError('Hidden subnet address appears in participant content')


def prepare_facts(item, nodes):
    """Resolve an authored knowledge contract, with private evidence provenance."""
    starting, hidden = item.get('starting_facts', []), item.get('discoverable_facts', [])
    if not isinstance(starting, list) or not isinstance(hidden, list):
        raise ValueError('starting_facts and discoverable_facts must be lists')
    seen = {}
    for facts, private in ((starting, False), (hidden, True)):
        for fact in facts:
            fields = {'id', 'artifact', 'value'} | ({'source_node', 'evidence', 'requires'} if private else set())
            required = fields - {'requires'}
            if not isinstance(fact, dict) or set(fact) - fields or required - set(fact):
                raise ValueError('Invalid starting/discoverable fact fields')
            if any(not isinstance(fact[k], str) or not fact[k].strip() for k in required):
                raise ValueError('Fact fields must be nonempty strings')
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', fact['id']) or fact['id'] in seen:
                raise ValueError('Fact IDs must be valid and unique')
            if fact['artifact'] == 'InternalNetwork(subnet)':
                ipaddress.ip_network(fact['value'], strict=False)
            if private and fact['source_node'] not in nodes:
                raise ValueError('Discoverable fact source_node is not in the graph')
            seen[fact['id']] = fact
    requirements = item.get('objective_requires', {})
    if not isinstance(requirements, dict) or any(ref not in nodes for ref in requirements):
        raise ValueError('objective_requires must map graph node IDs to fact IDs')
    def refs(values):
        if not isinstance(values, list) or any(not isinstance(v, str) or v not in seen for v in values):
            raise ValueError('Fact requirements must reference declared facts')
        return values
    for values in requirements.values():
        refs(values)
    dependencies = {}
    for fact in hidden:
        dependencies[fact['id']] = set(refs(fact.get('requires', []))) | set(
            requirements.get(fact['source_node'], []))
    def visit(key, visiting, complete):
        if key in visiting:
            raise ValueError('Circular discovery prerequisite; supply an initial fact or fix the evidence path')
        if key in complete:
            return
        for dep in dependencies.get(key, []):
            visit(dep, visiting | {key}, complete)
        complete.add(key)
    complete = set()
    for key in seen:
        visit(key, set(), complete)
    if not starting:
        raise ValueError('Discovery tasks require explicit starting_facts; missing inputs are never auto-revealed')
    briefing = '\nStarting facts:\n' + '\n'.join(f"- {f['artifact']}: {f['value']}" for f in starting)
    reject_discovery_leaks(briefing, hidden)
    return briefing, {'starting_facts': starting, 'discoverable_facts': hidden,
                      'objective_requires': requirements}
