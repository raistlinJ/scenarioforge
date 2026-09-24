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
            'suite_id': 'lab-study', 'allow': ['10.77.0.0/24'], 'readiness': readiness, 'session_id': 9}


def test_export_separates_answers_and_keeps_hashes(inputs):
    manifest = export_package(**inputs)
    root = inputs['output']
    public = (root / 'participant/tasks.json').read_text()
    assert 'FLAG{' not in public and 'PRIVATE_CREDENTIAL' not in public
    assert '10.77.0.10' in public
    assert len(json.loads(public)) == 1
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


@pytest.mark.parametrize('change', ['xml', 'scenario', 'session', 'scope', 'duplicate', 'leak', 'unresolved'])
def test_invalid_export_leaves_no_package(inputs, change):
    if change == 'xml':
        inputs['readiness']['xml_sha256'] = 'wrong'
    elif change == 'scenario':
        inputs['readiness']['scenario'] = 'Wrong'
    elif change == 'session':
        inputs['session_id'] = 77
    elif change == 'scope':
        inputs['allow'] = ['192.0.2.0/24']
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
        '--output-dir', str(inputs['output']), '--eval-allow', '10.77.0.0/24',
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
        '--suite-id', 'fixture-suite', '--eval-allow', '10.77.0.0/24', '--output-dir', str(tmp_path / 'suite')])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)['readiness_attached'] is False
    assert source.read_bytes() == before
    verifiers = json.loads((tmp_path / 'suite/evaluator/verifiers.json').read_text())
    assert verifiers['collect-flags']['expected']['entry'] == 'FLAG{fixture-entry}'
