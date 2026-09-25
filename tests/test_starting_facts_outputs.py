import json
import subprocess

import pytest
from jsonschema import Draft202012Validator

from scenarioforge.evaluation.starting_facts import collect_starting_facts
from test_guide_exports import guide_source, ROOT
from webapp.app_backend import _attack_graph_for_chain, _attack_graph_dot
from webapp.solutions_script import build_solutions_script


START = {'id': 'entry', 'artifact': 'InternalNetwork(subnet)', 'value': '10.77.0.0/24'}
TASK = {'id': 'discover', 'discovery': True, 'starting_facts': [START],
        'discoverable_facts': [{'value': '10.78.0.0/24', 'evidence': '/private/clue'}]}


def test_collector_and_graph_keep_starting_knowledge_distinct():
    assignments = [{'node_id': 'entry', 'chain_supplied_input_values': {'Credential(user, password)': 'analyst:example'},
                    'resolved_inputs': {'hidden': 'DO_NOT_SUPPLY'},
                    'resolved_outputs': {'InternalNetwork(subnet)': '10.78.0.0/24'}}]
    facts = collect_starting_facts(flow={'starting_facts': [START]}, assignments=assignments, definitions=[TASK])
    assert '10.78.' not in json.dumps(facts) and 'DO_NOT_SUPPLY' not in json.dumps(facts)
    assert [f['task_id'] for f in facts if 'task_id' in f] == ['discover']
    graph = _attack_graph_for_chain(chain_nodes=[{'id': 'entry', 'name': 'Entry'}], scenario_label='Lab',
                                   flag_assignments=assignments, starting_facts=facts)
    schema = json.loads((ROOT / 'schemas/attack_graph/attack_graph_v2.schema.json').read_text())
    assert not list(Draft202012Validator(schema).iter_errors(graph))
    dot = _attack_graph_dot(graph)
    assert 'Starting facts (given)' in dot and '10.77.0.0/24' in dot
    assert 'task: discover' in dot
    script = build_solutions_script('Lab', [], [], starting_facts=facts)
    assert '# - InternalNetwork(subnet)' in script and '10.77.0.0/24' in script


@pytest.mark.parametrize('renderer', ['flow', 'reports'])
def test_guides_include_starting_facts_without_disclosing_discovery(renderer):
    facts = collect_starting_facts(definitions=[TASK])
    code = guide_source(renderer) + """
const options = JSON.parse(process.argv[1]);
const nodes = [{id:'hidden', name:'10.78.0.20', ipv4:'10.78.0.20'}];
const assignments = [{node_id:'hidden', chain_supplied_input_values:{secret:'PRIVATE_UNUSED'}}];
const markdown = buildGuide('Lab', nodes, assignments, options);
process.stdout.write(JSON.stringify({markdown, html:markdownToHtmlDocument('Lab',markdown)}));
"""
    options = {'startingFacts': facts, 'discovery': True}
    result = subprocess.run(['node', '-e', code, json.dumps(options)], capture_output=True, text=True, check=True)
    output = json.loads(result.stdout)
    assert 'Starting facts' in output['markdown'] and '10.77.0.0/24' in output['html']
    assert 'task: discover' in output['markdown']
    for private in ['10.78.', 'PRIVATE_UNUSED', '/private/clue']:
        assert private not in result.stdout


def test_state_save_preserves_facts_for_older_clients_and_allows_explicit_clear(monkeypatch, tmp_path):
    from webapp import app_backend as backend
    saved = {'starting_facts': [START], 'evaluation_tasks': [TASK]}
    captured = []
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *a: saved)
    monkeypatch.setattr(backend, '_xml_trace_snapshot', lambda *a: {})
    monkeypatch.setattr(backend, '_enrich_flow_state_with_artifacts', lambda state: state)
    def update(path, scenario, state):
        captured.append(state)
        return True, 'saved'
    monkeypatch.setattr(backend, '_update_flow_state_in_xml', update)
    for extra in ({}, {'starting_facts': [], 'evaluation_tasks': []}):
        with backend.app.test_request_context('/api/flag-sequencing/save_flow_state_to_xml', method='POST', json={
                'xml_path': str(tmp_path / 'scenario.xml'), 'scenario': 'Lab',
                'flow_state': {'chain_ids': ['entry'], **extra}}):
            response = backend.app.view_functions['api_flow_save_flow_state_to_xml']()
            assert response.get_json()['ok']
    assert captured[0]['starting_facts'] == [START] and captured[0]['evaluation_tasks'] == [TASK]
    assert captured[1]['starting_facts'] == [] and captured[1]['evaluation_tasks'] == []
