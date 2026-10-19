import json
import xml.etree.ElementTree as ET

from scenarioforge.evaluation.access import access_check
from scenarioforge.evaluation.execution import build_execution_package
from scenarioforge.evaluation.scaffold import draft_tasks, graph_from_flow
from test_evaluation_execution import build  # noqa: F401


def check(solution, prompt=''):
    return access_check(dict(steps=[dict(id='step-1', node_id='n1', title='Target', solution=solution)]),
                        dict(nodes=[dict(id='n1', ipv4='192.0.2.10')]), prompt)


def test_access_rejects_answer_only_and_internal_host_get():
    assert check('Expected flag: PRIVATE')['status']=='fail'
    bad='### Access Instructions\nnc 192.0.2.10 11521\nGET /tmp/vulns/run/service/wallet.txt\n### Check Your Progress\n'
    assert check(bad)['status']=='fail'
    assert 'service-relative' in check(bad)['items'][0]['detail']
    assert check(bad.replace('/tmp/vulns/run/service/wallet.txt', 'database/wallet.txt'))['status']=='pass'


def test_access_requires_connection_not_just_container_cat():
    assert check('cat /flow_injects/proof.txt')['status']=='fail'
    assert check('Use curl to retrieve the artifact')['status']=='fail'
    assert check('ssh user@192.0.2.10; cat /flow_injects/proof.txt')['status']=='pass'
    assert check('No specific access instructions were provided.', 'Fetch with curl http://192.0.2.10/proof')['status']=='pass'
    assert check('curl http://{{HOST}}/proof')['status']=='fail'
    assert check('No specific access instructions were provided.', 'curl http://192.0.2.11/proof')['status']=='fail'
    assert check('curl http://192.0.2.100/proof')['status']=='fail'


def test_access_accepts_documented_browser_or_poc_vulnerability_result():
    solution = '''### Access Instructions
Use http://192.0.2.10:8080/reset to locate the target, then execute:
python poc.py -t http://192.0.2.10:8080 --token VALUE
Submit the predicted code to demonstrate account takeover.
### Check Your Progress
'''
    assert check(solution)['status'] == 'pass'


def missing_access_tasks(build):
    root=ET.parse(build['xml_path'])
    state=root.find('.//FlowState')
    flow=json.loads(state.text)
    graph=graph_from_flow(flow, build['scenario'])
    flow['evaluation_tasks']=draft_tasks(flow, graph, rendered_hints=[], rendered_solutions=[])
    state.text=json.dumps(flow)
    root.write(build['xml_path'])
    return flow['evaluation_tasks']


def test_missing_guides_are_advisory_when_core_checks_pass(build):
    missing_access_tasks(build)
    result=build_execution_package(**build)
    assert result['readiness_passed'] is True
    readiness=json.loads((build['output']/'evaluator/readiness.json').read_text())
    access=next(c for c in readiness['advisories'] if c['key']=='challenge_access')
    assert access['status']=='fail' and access['items']
    assert readiness['ok'] is True and readiness['overall']=='pass'
    assert not any(c['key']=='challenge_access' for c in readiness['checks'])
    metadata=json.loads((build['output']/'evaluator/task-metadata.json').read_text())['solve-scenario']
    assert 'challenge_access' not in metadata['required_checks']
    assert metadata['access_validation']['status']=='fail'


def test_explicitly_required_access_still_blocks_missing_guides(build):
    tasks=missing_access_tasks(build)
    tasks[0]['required_checks'].append('challenge_access')
    result=build_execution_package(**build, definitions=tasks)
    assert result['readiness_passed'] is False
    readiness=json.loads((build['output']/'evaluator/readiness.json').read_text())
    access=next(c for c in readiness['checks'] if c['key']=='challenge_access')
    assert access['status']=='fail' and access['items']
    assert readiness['ok'] is False


def test_required_documented_task_is_not_blocked_by_optional_missing_guides(build):
    from copy import deepcopy
    tasks=missing_access_tasks(build)
    reviewed=deepcopy(tasks[0])
    reviewed['id']='reviewed-task'
    reviewed['required_checks'].append('challenge_access')
    root=ET.parse(build['xml_path'])
    graph=graph_from_flow(json.loads(root.find('.//FlowState').text), build['scenario'])
    addresses={str(n['id']): n['ipv4'] for n in graph['nodes']}
    for step in reviewed['challenge_plan']['steps']:
        step['solution']='curl http://' + addresses[str(step['node_id'])] + '/proof'
    result=build_execution_package(**build, definitions=[*tasks, reviewed])
    assert result['readiness_passed'] is True
    readiness=json.loads((build['output']/'evaluator/readiness.json').read_text())
    assert readiness['advisories'][0]['status']=='fail'
    required=next(c for c in readiness['checks'] if c['key']=='challenge_access')
    assert required['status']=='pass'
    assert {item['task_id'] for item in required['items']}=={'reviewed-task'}


def test_guide_advisory_does_not_override_runtime_failure(build, monkeypatch):
    from scenarioforge import cli
    missing_access_tasks(build)
    def fail(**kwargs):
        raise RuntimeError('environment unavailable')
    monkeypatch.setattr(cli, '_run_cli_artifact_checks', fail)
    result=build_execution_package(**build)
    assert result['readiness_passed'] is False
    readiness=json.loads((build['output']/'evaluator/readiness.json').read_text())
    assert readiness['ok'] is False
    assert readiness['advisories'][0]['status']=='fail'
