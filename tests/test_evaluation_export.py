import json
import stat
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from scenarioforge.evaluation.export import encoded, export_package, read_readiness, sha256


@pytest.fixture
def inputs(tmp_path):
    xml = tmp_path / 'scenario.xml'
    xml.write_text('<Scenarios><Scenario name="Lab"/></Scenarios>')
    graph = {'schema_version': 2, 'scenario': 'Lab', 'nodes': [
        {'id': 'entry', 'ipv4': '10.77.0.10', 'generator': {'flag_value': 'FLAG{private-entry}'}},
        {'id': 'target', 'ipv4': '10.77.0.20', 'generator': {'flag_value': 'FLAG{private-target}'}}
    ], 'edges': [{'source': 'entry', 'target': 'target'}],
        'fact_dependencies': [{'secret': 'PRIVATE_CREDENTIAL'}]}
    readiness = {'status': 'complete', 'ok': True, 'overall': 'pass', 'scenario': 'Lab',
                 'session_id': 9, 'core_host': 'core.example', 'session_confirmed': True,
                 'xml_sha256': sha256(xml.read_bytes()), 'checked_at': datetime.now(timezone.utc).isoformat(),
                 'checks': [{'key': key, 'status': 'pass', 'items': []}
                            for key in ['containers', 'services', 'ports', 'injects']]}
    return {'xml_path': xml, 'graph': graph, 'output': tmp_path / 'package',
            'suite_id': 'lab-study', 'readiness': readiness, 'session_id': 9}


def test_export_separates_answers_and_keeps_hashes(inputs):
    manifest = export_package(**inputs)
    root = inputs['output']
    public = (root / 'participant/tasks.json').read_text()
    assert 'FLAG{' not in public and 'PRIVATE_CREDENTIAL' not in public
    assert '10.77.0.10' in public
    assert len(json.loads(public)) == 1
    assert manifest['version'] == 3
    assert not (root / 'participant/network-policy.json').exists()
    assert 'Allowed targets:' not in public
    private = json.loads((root / 'evaluator/verifiers.json').read_text())
    assert private['collect-flags']['expected']['entry'] == 'FLAG{private-entry}'
    assert stat.S_IMODE((root / 'evaluator').stat().st_mode) == 0o700
    for name, expected in manifest['files'].items():
        assert sha256((root / name).read_bytes()) == expected
    original = dict(manifest)
    digest = original.pop('package_hash')
    assert sha256(encoded(original)) == digest
    with pytest.raises(ValueError, match='already exists'):
        export_package(**inputs)


@pytest.mark.parametrize('change', ['xml', 'scenario', 'session', 'duplicate', 'leak', 'unresolved'])
def test_invalid_export_leaves_no_package(inputs, change):
    if change == 'xml':
        inputs['readiness']['xml_sha256'] = 'wrong'
    elif change == 'scenario':
        inputs['readiness']['scenario'] = 'Wrong'
    elif change == 'session':
        inputs['session_id'] = 77
    elif change == 'duplicate':
        inputs['graph']['nodes'].append(inputs['graph']['nodes'][0])
    elif change == 'unresolved':
        inputs['graph']['nodes'][0]['generator']['flag_value'] = None
        inputs['definitions'] = [{'id': 'task', 'family': 'flags', 'flag_nodes': ['entry'], 'required_checks': ['injects']}]
    else:
        inputs['definitions'] = [{'id': 'task', 'family': 'flags', 'flag_nodes': ['entry'],
                                 'prompt': 'Answer FLAG{private-target}', 'required_checks': ['injects']}]
    with pytest.raises(ValueError):
        export_package(**inputs)
    assert not inputs['output'].exists()


def test_explicit_inventory_task_and_draft(inputs):
    inputs['readiness'] = None
    inputs['definitions'] = [{'id': 'inventory', 'family': 'inventory', 'split': 'validation',
                             'prompt': 'Report the live service inventory as JSON.', 'required_checks': ['ports'],
                             'verifier': {'type': 'json_equals', 'expected': {'open_ports': [80]}}}]
    export_package(**inputs)
    task = json.loads((inputs['output'] / 'participant/tasks.json').read_text())[0]
    assert task['split'] == 'validation'
    assert json.loads((inputs['output'] / 'evaluator/readiness.json').read_text())['status'] == 'unverified'


def test_readiness_marker(inputs, tmp_path):
    path = tmp_path / 'checks.log'
    path.write_text('Human progress\nCHECK_ARTIFACTS_SUMMARY_JSON: ' + json.dumps(inputs['readiness']) + '\n')
    assert read_readiness(path) == inputs['readiness']
    path.write_text('{}')
    assert read_readiness(path) == {}


def test_cli_export_dispatch_from_saved_flow(inputs, monkeypatch, capsys):
    from scenarioforge import cli
    backend = SimpleNamespace(_attack_graph_for_chain=lambda **kwargs: inputs['graph'])
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(cli, '_cli_phase_scenario', lambda *args, **kwargs: 'Lab')
    monkeypatch.setattr(cli, '_flow_state_from_xml', lambda *args: {'chain': inputs['graph']['nodes']})
    report = inputs['xml_path'].parent / 'readiness.json'
    report.write_text(json.dumps(inputs['readiness']))
    args = cli._build_cli_parser().parse_args([
        'evaluation-export', '--xml', str(inputs['xml_path']), '--suite-id', 'lab-study',
        '--output-dir', str(inputs['output']),
        '--readiness-report', str(report), '--session-id', '9'])
    assert cli._run_evaluation_export_phase(args) == 0
    assert json.loads(capsys.readouterr().out)['package_hash']
    assert '--readiness-report' in cli._build_cli_help_parser('evaluation-export').format_help()


@pytest.mark.parametrize('mutate_xml,live', [(False, True), (True, True), (False, False)])
def test_live_check_marker_binds_xml_and_session(inputs, mutate_xml, live):
    import io
    from scenarioforge import cli
    initial_hash = sha256(inputs['xml_path'].read_bytes())
    def schedule(*args, **kwargs):
        if mutate_xml:
            inputs['xml_path'].write_text('<changed/>')
    backend = SimpleNamespace(
        _list_active_core_sessions=lambda *args: [{'id': 9}] if live else [],
        _init_artifact_check_progress=lambda *args, **kwargs: None,
        _schedule_artifact_checks=schedule,
        _get_artifact_check_progress=lambda *args: {'status': 'complete', 'overall': 'pass',
            'checks': [{'key': 'containers', 'status': 'pass', 'items': []}]})
    out = io.StringIO()
    args = SimpleNamespace(scenario='Lab', xml=str(inputs['xml_path']))
    assert cli._run_cli_artifact_checks(backend=backend, args=args, core_cfg={'host': 'core.example'},
                                       session_id=9, strict=True, stream=out)
    line = next(line for line in out.getvalue().splitlines() if line.startswith(cli.CHECK_ARTIFACTS_MARKER))
    report = json.loads(line[len(cli.CHECK_ARTIFACTS_MARKER):])
    assert report['xml_sha256'] == (None if mutate_xml else initial_hash)
    assert report['session_confirmed'] is live
    assert report['core_host'] == 'core.example' and report['session_id'] == 9
    assert datetime.fromisoformat(report['checked_at']).tzinfo is not None


def test_export_main_uses_saved_xml_without_remote_execution(tmp_path, monkeypatch, capsys):
    import sys
    from pathlib import Path
    from scenarioforge import cli
    from webapp.app_backend import _attack_graph_for_chain
    source = Path(__file__).parent / 'fixtures/scenarioforge_suite_sources/scenario.xml'
    before = source.read_bytes()
    backend = SimpleNamespace(_attack_graph_for_chain=_attack_graph_for_chain)
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(cli, '_cli_phase_scenario', lambda *a, **k: 'Evaluation fixture')
    monkeypatch.setattr(cli, '_configure_cli_logging', lambda *a: None)
    monkeypatch.setattr(cli, '_maybe_delegate_cli_to_remote', lambda *a, **k: pytest.fail('Export delegated execution'))
    monkeypatch.setattr(sys, 'argv', ['cli.py', 'evaluation-export', '--xml', str(source),
        '--suite-id', 'fixture-suite', '--output-dir', str(tmp_path / 'suite')])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)['readiness_attached'] is False
    assert source.read_bytes() == before
    verifiers = json.loads((tmp_path / 'suite/evaluator/verifiers.json').read_text())
    assert verifiers['collect-flags']['expected']['entry'] == 'FLAG{fixture-entry}'


def discovery_definition():
    return {
        'id': 'discovery', 'family': 'discovery', 'discovery': True,
        'flag_nodes': ['entry', 'target'], 'required_checks': ['injects'],
        'starting_facts': [{'id': 'entry-net', 'artifact': 'InternalNetwork(subnet)', 'value': '10.77.0.0/24'}],
        'discoverable_facts': [{'id': 'internal', 'artifact': 'InternalNetwork(subnet)', 'value': '10.78.0.0/24',
                               'source_node': 'entry', 'evidence': '/opt/scenario/network.conf', 'requires': ['entry-net']}],
        'objective_requires': {'entry': ['entry-net'], 'target': ['internal']}}


def test_discovery_exports_only_starting_knowledge(inputs):
    inputs['graph']['nodes'][1]['ipv4'] = '10.78.0.20'
    inputs['definitions'] = [discovery_definition()]
    export_package(**inputs)
    public = (inputs['output'] / 'participant/tasks.json').read_text()
    assert '10.77.0.0/24' in public
    for secret in ('10.78.', 'network.conf', 'private-target', '10.77.0.10'):
        assert secret not in public
    private = json.loads((inputs['output'] / 'evaluator/task-metadata.json').read_text())['discovery']
    assert private['discoverable_facts'][0]['value'] == '10.78.0.0/24'
    assert private['objective_nodes'] == {'objective-1': 'entry', 'objective-2': 'target'}


@pytest.mark.parametrize('change', ['cycle', 'missing', 'leak', 'duplicate', 'source'])
def test_discovery_rejects_invalid_contract(inputs, change):
    task = discovery_definition()
    if change == 'cycle':
        task['objective_requires']['entry'] = ['internal']
    elif change == 'missing':
        task['starting_facts'] = []
    elif change == 'leak':
        task['prompt'] = 'Scan 10.78.0.20'
    elif change == 'duplicate':
        task['discoverable_facts'][0]['id'] = 'entry-net'
    else:
        task['discoverable_facts'][0]['source_node'] = 'absent'
    inputs['definitions'] = [task]
    with pytest.raises(ValueError):
        export_package(**inputs)
    assert not inputs['output'].exists()


def test_network_clue_generator_and_explicit_starting_subnet(tmp_path):
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / 'generator_templates/network-discovery-clue/generator.py'
    spec = importlib.util.spec_from_file_location('network_clue_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = {'seed': 'test', 'secret': 'fixture', 'internal_subnet': '10.78.0.0/24'}
    first = module.generate(config, tmp_path)
    assert module.generate(config, tmp_path) == first
    assert '10.78.0.0/24' in (tmp_path / 'artifacts/network.conf').read_text()
    from webapp.app_backend import _flow_chain_supplied_value_for_input
    with pytest.raises(ValueError, match='explicit deployed CIDR'):
        _flow_chain_supplied_value_for_input('internal_subnet', scenario_label='test', node_id='1',
                                            gen_id='test', username='user', password='pass')


def test_starting_subnet_is_explicit_and_only_supplied_at_start():
    import copy
    from webapp.app_backend import _flow_apply_first_step_chain_supplied_inputs
    definition = {'inputs': [{'name': 'InternalNetwork(subnet)', 'type': 'string',
                              'required': True, 'flow_supply_when_first': True}]}
    assignment = {'node_id': 'entry', 'id': 'test',
                  'config_overrides': {'InternalNetwork(subnet)': '10.77.0.10/24'}}
    result = _flow_apply_first_step_chain_supplied_inputs(copy.deepcopy(assignment), definition,
                                                         scenario_label='test', supply_on_start=True)
    assert result['chain_supplied_input_values']['InternalNetwork(subnet)'] == '10.77.0.0/24'
    later = _flow_apply_first_step_chain_supplied_inputs(result, definition,
                                                        scenario_label='test', supply_on_start=False)
    assert 'chain_supplied_input_values' not in later
    with pytest.raises(ValueError):
        _flow_apply_first_step_chain_supplied_inputs(
            {'node_id': 'entry', 'id': 'test', 'config_overrides': {'InternalNetwork(subnet)': 'not-a-cidr'}},
            definition, scenario_label='test', supply_on_start=True)


def test_network_clue_template_matches_manifest_and_output_schema(tmp_path):
    import importlib.util
    import jsonschema
    import yaml
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    template = root / 'generator_templates/network-discovery-clue'
    manifest = yaml.safe_load((template / 'manifest.yaml').read_text())
    jsonschema.validate(manifest, json.loads((root / 'schemas/generators/generator_manifest_v1.schema.json').read_text()))
    spec = importlib.util.spec_from_file_location('clue_schema_test', template / 'generator.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    outputs = module.generate({'seed': 'test', 'secret': 'test', 'internal_subnet': '10.78.0.0/24'}, tmp_path)
    jsonschema.validate(outputs, json.loads((root / 'schemas/generators/flag_generator_outputs.schema.json').read_text()))
    assert set(outputs['outputs']) == set(manifest['artifacts']['produces'])


def test_progressive_hints_export_only_to_private_metadata(inputs):
    hint = 'Facilitator excerpt: inspect the next page link.'
    inputs['definitions'] = [dict(id='guided', family='http', prompt='Explore the public entry page.',
        verifier=dict(type='contains_all', expected=['FLAG{private-entry}']),
        required_checks=['ports'], progressive_hints=[hint])]
    export_package(**inputs)
    root = inputs['output']
    assert hint not in (root / 'participant/tasks.json').read_text()
    assert json.loads((root / 'evaluator/task-metadata.json').read_text())['guided']['progressive_hints'] == [hint]


@pytest.mark.parametrize('hints', ['text', [''], ['x' * 1501], [False]])
def test_invalid_progressive_hints_are_rejected(inputs, hints):
    inputs['definitions'] = [dict(id='guided', family='http', prompt='Explore the entry page.',
        verifier=dict(type='contains_all', expected=['FLAG{private-entry}']),
        required_checks=['ports'], progressive_hints=hints)]
    with pytest.raises(ValueError, match='progressive_hints'):
        export_package(**inputs)


def test_default_flag_task_inherits_safe_flow_hints_privately(inputs):
    import xml.etree.ElementTree as ET
    xml = inputs['xml_path']
    tree = ET.parse(xml)
    flow = {'flag_assignments': [
        {'node_id': 'entry', 'flag_value': 'FLAG{private-entry}',
         'hints': ['Inspect the service with curl.', 'Return FLAG{private-entry}', 'Password is secret-password', '{{unresolved}}'],
         'resolved_outputs': {'Password(password)': 'secret-password'}},
        {'node_id': 'target', 'hint_levels': {'low': ['Look for the target page.']}},
    ]}
    ET.SubElement(tree.find('./Scenario'), 'FlowState').text = json.dumps(flow)
    tree.write(xml)
    inputs['readiness']['xml_sha256'] = sha256(xml.read_bytes())
    export_package(**inputs)
    metadata = json.loads((inputs['output']/'evaluator/task-metadata.json').read_text())
    plan = metadata['collect-flags']['progressive_hints']
    assert plan == ['Inspect the service with curl.', 'Look for the target @ 10.77.0.20 page.',
                    'Review the target @ 10.77.0.20 details and access instructions for this step.']
    assert 'FLAG{' not in json.dumps(plan) and 'secret-password' not in json.dumps(plan)
    assert 'Inspect the service with curl.' not in (inputs['output']/'participant/tasks.json').read_text()


def test_explicit_empty_hint_plan_does_not_inherit_flow_hints(inputs):
    from scenarioforge.evaluation.export import _tasks
    definitions = [dict(id='one',family='flags',flag_nodes=['entry'],required_checks=['ports'],progressive_hints=[])]
    flow = {'flag_assignments': [{'node_id':'entry','hints':['Inspect the entry service.']}]}
    _,_,metadata = _tasks(inputs['graph'],'scenario-id',definitions,'development',flow)
    assert 'progressive_hints' not in metadata['one']


def test_guide_templates_defaults_and_custom_verifier_tasks_supply_hint_plan(inputs):
    import xml.etree.ElementTree as ET
    from scenarioforge.evaluation.hints import guide_hints
    tree = ET.parse(inputs['xml_path'])
    flow = {'flag_assignments': [
        {'node_id': 'entry', 'hint_level_templates': {
            'low': ['Inspect {{OUTPUT.File(path):basename}}.'],
            'high': ['Answer: {{OUTPUT.Flag(flag_id)}}']},
         'resolved_outputs': {'File(path)': '/challenge/public-note.txt',
                              'Flag(flag_id)': 'FLAG{private-entry}'}},
        {'node_id': 'target'},
    ]}
    ET.SubElement(tree.find('./Scenario'), 'FlowState').text = json.dumps(flow)
    tree.write(inputs['xml_path'])
    inputs['readiness']['xml_sha256'] = sha256(inputs['xml_path'].read_bytes())
    inputs['definitions'] = [dict(id='custom', family='http', prompt='Inspect the live services.',
        verifier={'type':'json_equals','expected':{'answer':'PRIVATE_ANSWER'}}, required_checks=['ports'])]
    export_package(**inputs)
    metadata = json.loads((inputs['output']/'evaluator/task-metadata.json').read_text())
    plan = metadata['custom']['progressive_hints']
    assert 'Inspect public-note.txt.' in plan
    assert 'Target: target @ 10.77.0.20' in plan
    assert 'FLAG{' not in json.dumps(plan)
    # Every released hint comes from the participant renderer, including defaults.
    assert set(plan) <= {hint['text'] for hint in guide_hints(flow, inputs['graph'])}
    assert 'Inspect public-note.txt.' not in (inputs['output']/'participant/tasks.json').read_text()


def test_discovery_does_not_inherit_hidden_step_hints(inputs):
    from scenarioforge.evaluation.export import _tasks
    flow = {'flag_assignments':[{'node_id':'entry','hint':'Hidden node is 10.77.0.10.'}]}
    definitions = [dict(id='discovery',family='flags',flag_nodes=['entry'],required_checks=['ports'],
                        discovery=True, starting_facts=[{'id':'start','artifact':'Knowledge(ip)',
                            'value':'10.77.0.10'}], discoverable_facts=[])]
    _, _, metadata = _tasks(inputs['graph'], 'scenario-id', definitions, 'development', flow)
    assert 'progressive_hints' not in metadata['discovery']


def test_solutions_are_current_challenge_guide_sections_in_private_metadata(inputs):
    import xml.etree.ElementTree as ET
    tree = ET.parse(inputs['xml_path'])
    flow = {'flag_assignments':[
        {'node_id':'entry','access_instructions':{'title':'Find the token', 'steps':[
            {'instructions':'Use curl to inspect the headers.'}]},
            'resolved_outputs':{'Flag(flag_id)':'FLAG{private-entry}'}},
        {'node_id':'target','access_instructions':{'title':'Open the protected page','steps':[
            {'instructions':'Submit the key to the protected endpoint.'}]},
            'resolved_outputs':{'Flag(flag_id)':'FLAG{private-target}'}}]}
    ET.SubElement(tree.find('./Scenario'),'FlowState').text=json.dumps(flow)
    tree.write(inputs['xml_path'])
    inputs['readiness']['xml_sha256']=sha256(inputs['xml_path'].read_bytes())
    export_package(**inputs)
    meta=json.loads((inputs['output']/'evaluator/task-metadata.json').read_text())['collect-flags']
    solutions=meta['challenge_solutions']
    assert [solution['node_id'] for solution in solutions]==['entry','target']
    assert 'Use curl' in solutions[0]['text'] and 'FLAG{private-entry}' in solutions[0]['text']
    assert 'FLAG{private-target}' not in solutions[0]['text']
    assert 'Submit the key' in solutions[1]['text'] and 'FLAG{private-target}' in solutions[1]['text']
    assert 'FLAG{private-entry}' not in solutions[1]['text']
    assert solutions[0]['completion_values']==['FLAG{private-entry}']
    assert 'FLAG{' not in (inputs['output']/'participant/tasks.json').read_text()
    assert 'FLAG{' not in json.dumps(meta['progressive_hints'])


def test_judge_only_rubric_exports_without_flags_and_keeps_references_private(inputs):
    for node in inputs['graph']['nodes']:node.pop('generator',None)
    rubric={'version':1,'criteria':[dict(id='read',requirement='Read the service configuration.',evidence='Successful tool output containing the configuration.',private_reference='PRIVATE_REFERENCE_VALUE')]}
    inputs['definitions']=[dict(id='investigate',family='config-investigation',prompt='Inspect the service configuration.',required_checks=['containers','ports'],verification_mode='judge',rubric=rubric)]
    manifest=export_package(**inputs)
    assert manifest['version']==4
    public=(inputs['output']/'participant/tasks.json').read_text()
    assert 'PRIVATE_REFERENCE_VALUE' not in public and 'Challenge requirements:' in public
    metadata=json.loads((inputs['output']/'evaluator/task-metadata.json').read_text())
    assert metadata['investigate']['rubric']['criteria'][0]['private_reference']=='PRIVATE_REFERENCE_VALUE'
    private=json.loads((inputs['output']/'evaluator/verifiers.json').read_text())
    assert private['investigate']['type']=='rubric'


def test_both_mode_requires_exact_criteria_and_rubric(inputs):
    inputs['definitions']=[dict(id='inspect',family='inspection',prompt='Inspect it.',required_checks=['ports'],verification_mode='both',verifier={'type':'contains_all','expected':['observed']})]
    with pytest.raises(ValueError,match='rubric'):export_package(**inputs)


def test_rubric_hints_can_repeat_public_requirements_but_not_private_reference():
    from scenarioforge.evaluation.hints import hints_for_nodes
    rubric={'version':1,'criteria':[dict(id='inspect',requirement='Read the configuration.',evidence='Successful tool output.',private_reference='PRIVATE_ANSWER')]}
    hints=hints_for_nodes({},None,{'type':'rubric','expected':rubric},rendered=[dict(node_id='service',text='Read the configuration.'),dict(node_id='service',text='The answer is PRIVATE_ANSWER')])
    assert hints==['Read the configuration.']


def test_rubric_solution_keeps_current_challenge_answer_and_withholds_other_flags():
    from scenarioforge.evaluation.hints import solutions_for_task
    graph={'nodes':[dict(id='current',ipv4='10.0.1.2',generator={'flag_value':'FLAG{current}'}),dict(id='later',ipv4='10.0.1.3',generator={'flag_value':'FLAG{later}'})]}
    rubric={'version':1,'criteria':[dict(id='recover',requirement='Recover the current challenge.',evidence='Observed tool output.') ]}
    plans=solutions_for_task([dict(node_id='current',text='Inspect the response. Current answer FLAG{current}; later answer FLAG{later}.')],graph,None,dict(type='rubric',expected=rubric),'Inspect 10.0.1.2 and recover its challenge.')
    assert len(plans)==1 and 'FLAG{current}' in plans[0]['text']
    assert 'FLAG{later}' not in plans[0]['text']
    assert plans[0]['completion_values']==['FLAG{current}']
