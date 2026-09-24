import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask

from scenarioforge.evaluation.execution import build_execution_package
from scenarioforge.evaluation.export import sha256
from webapp.app_backend import _attack_graph_for_chain
from scenarioforge import cli
from webapp.evaluation_artifacts import EvaluationArtifacts
from webapp.routes.evaluation_artifacts import register


@pytest.fixture
def build(tmp_path, monkeypatch):
    source = Path(__file__).parent / 'fixtures/scenarioforge_suite_sources/scenario.xml'
    xml = tmp_path / 'scenario.xml'
    shutil.copy(source, xml)
    def checks(*, args, session_id, core_cfg, stream, **kwargs):
        payload = {'status': 'complete', 'ok': True, 'overall': 'pass', 'scenario': args.scenario,
                   'session_id': session_id, 'core_host': core_cfg['host'], 'session_confirmed': True,
                   'checked_at': datetime.now(timezone.utc).isoformat(),
                   'xml_sha256': sha256(Path(args.xml).read_bytes()),
                   'checks': [{'key': key, 'status': 'pass'} for key in ['containers', 'services', 'ports', 'injects']]}
        print(cli.CHECK_ARTIFACTS_MARKER + ' ' + json.dumps(payload), file=stream)
        return True
    monkeypatch.setattr(cli, '_run_cli_artifact_checks', checks)
    return dict(backend=SimpleNamespace(_attack_graph_for_chain=_attack_graph_for_chain), xml_path=xml,
                scenario='Evaluation fixture', session_id=9, core_cfg={'host': 'fixture-only.invalid'},
                output=tmp_path / 'package', suite_id='execute-fixture')


def test_execution_build_defaults_to_host_scope_and_private_zip(build):
    result = build_execution_package(**build)
    assert result['readiness_passed'] is True
    assert result['allow'] == ['10.77.0.10/32', '10.77.0.20/32']
    with zipfile.ZipFile(result['archive']) as bundle:
        assert len(bundle.namelist()) == 8
        assert 'FLAG{' not in bundle.read('participant/tasks.json').decode()
        assert 'FLAG{' in bundle.read('evaluator/verifiers.json').decode()
    with pytest.raises(ValueError, match='already exists'):
        build_execution_package(**build)


def test_failed_readiness_creates_blocked_package(build, monkeypatch):
    def fail(**kwargs):
        raise RuntimeError('private connection secret')
    monkeypatch.setattr(cli, '_run_cli_artifact_checks', fail)
    result = build_execution_package(**build)
    assert result['readiness_passed'] is False
    assert 'private connection secret' not in (build['output'] / 'evaluator/readiness.json').read_text()


def test_changed_xml_refused_before_checks(build):
    with pytest.raises(ValueError, match='changed after execution'):
        build_execution_package(**build, expected_xml_sha256='old-hash')
    assert not build['output'].exists()


def test_cli_post_execute_uses_explicit_scope_and_split(build, capsys):
    args = SimpleNamespace(xml=str(build['xml_path']), scenario=build['scenario'], suite_id='cli-eval',
        evaluation_output_dir=str(build['output']), eval_allow=['10.77.0.0/24'], eval_disallow=[],
        eval_split='validation', evaluation_tasks=None, readiness_report=None)
    assert cli._post_execution_evaluation(args, backend=build['backend'], core_cfg=build['core_cfg'], session_id=9)
    assert 'EVALUATION_PACKAGE_JSON:' in capsys.readouterr().out
    task = json.loads((build['output'] / 'participant/tasks.json').read_text())[0]
    assert task['split'] == 'validation'
    assert json.loads((build['output'] / 'participant/network-policy.json').read_text())['allow'] == ['10.77.0.0/24']


def test_background_artifact_is_idempotent_and_download_authorized(build, tmp_path, monkeypatch):
    class InlineThread:
        def __init__(self, target, **kwargs): self.target = target
        def start(self): self.target()
    monkeypatch.setattr('webapp.evaluation_artifacts.threading.Thread', InlineThread)
    backend = build['backend']
    backend._outputs_dir = lambda: str(tmp_path / 'outputs')
    backend.app = Flask(__name__)
    backend._current_user = lambda: {'role': 'builder'}
    backend._load_run_history = lambda: [{'run_id': 'run-1', 'scenario_names': ['Evaluation fixture']}]
    backend._builder_filter_report_scenarios = lambda names, selection, user: (names, '', None)
    artifacts = EvaluationArtifacts(backend)
    options = {k: build[k] for k in ['xml_path', 'scenario', 'session_id', 'core_cfg']}
    artifacts.schedule(run_id='run-1', **options)
    before = artifacts.status('run-1')
    artifacts.schedule(run_id='run-1', **options)
    assert artifacts.status('run-1') == before
    assert before['state'] == 'complete'
    register(backend.app, backend=backend, artifacts=artifacts)
    client = backend.app.test_client()
    status = client.get('/api/reports/run-1/evaluation')
    assert status.status_code == 200 and 'archive' not in status.json
    download = client.get('/api/reports/run-1/evaluation/download')
    assert download.status_code == 200 and 'no-store' in download.headers['Cache-Control']
    backend._builder_filter_report_scenarios = lambda names, selection, user: ([], '', set())
    assert client.get('/api/reports/run-1/evaluation/download').status_code == 403
    backend._current_user = lambda: {'role': 'participant'}
    assert client.get('/api/reports/run-1/evaluation').status_code == 403
    assert client.get('/api/reports/missing/evaluation/download').status_code == 403


def test_generic_report_download_cannot_bypass_eval_authorization(tmp_path, monkeypatch):
    from webapp import app_backend as backend
    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(tmp_path))
    private = tmp_path / 'evaluation-packages' / 'run' / 'package.zip'
    private.parent.mkdir(parents=True)
    private.write_bytes(b'private answers')
    client = backend.app.test_client()
    with client.session_transaction() as session:
        session['user'] = {'username': 'example', 'role': 'participant'}
    assert client.get('/download_report', query_string={'path': str(private)}).status_code == 403
    alias = tmp_path / 'alias.zip'
    alias.symlink_to(private)
    assert client.get('/download_report', query_string={'path': str(alias)}).status_code == 403


def test_report_browser_action_polls_then_downloads(tmp_path):
    import subprocess
    source = (Path(__file__).parents[1] / 'webapp/templates/reports.html').read_text()
    assert source.count('data-kind="evaluation-package"') == 2
    start = source.index('async function handleReportDownloadAction(link)')
    end = source.index("document.addEventListener('click'", start)
    function = source[start:end]
    script = '''
const assert = require('assert');
const messages = [], downloads = [];
const setReportGenerationStatus = s => messages.push(s);
const setTimeout = fn => fn();
const window = {alert: s => {throw Error(s);}};
const startReportArtifactDownload = async (blob, filename) => downloads.push(filename);
let calls = 0;
const fetch = async path => {
  calls++;
  if (path.endsWith('/download')) return {ok:true,blob: async () => new Blob(['zip'])};
  return {ok:true,json: async () => calls === 1 ? {state:'preparing'} :
    {state:'complete',suite_id:'test-suite',readiness_passed:true}};
};
''' + function + '''
(async () => {
  await handleReportDownloadAction({dataset:{kind:'evaluation-package',scenario:'Lab',runId:'run-1'}});
  assert.deepStrictEqual(downloads, ['test-suite.zip']);
  assert.strictEqual(calls, 3);
  assert(messages.some(s => s.includes('Checking deployment')));
})().catch(e => {console.error(e);process.exitCode=1;});
'''
    result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
