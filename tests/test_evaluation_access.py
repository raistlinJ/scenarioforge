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


def test_execution_blocks_missing_access_even_when_core_checks_pass(build):
    root=ET.parse(build['xml_path'])
    state=root.find('.//FlowState')
    flow=json.loads(state.text)
    graph=graph_from_flow(flow, build['scenario'])
    flow['evaluation_tasks']=draft_tasks(flow, graph, rendered_hints=[], rendered_solutions=[])
    state.text=json.dumps(flow)
    root.write(build['xml_path'])
    result=build_execution_package(**build)
    assert result['readiness_passed'] is False
    readiness=json.loads((build['output']/'evaluator/readiness.json').read_text())
    access=next(c for c in readiness['checks'] if c['key']=='challenge_access')
    assert access['status']=='fail' and access['items']
    metadata=json.loads((build['output']/'evaluator/task-metadata.json').read_text())['solve-scenario']
    assert 'challenge_access' in metadata['required_checks']
    assert metadata['access_validation']['status']=='fail'
