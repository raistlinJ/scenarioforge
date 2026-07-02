import json
from pathlib import Path
from types import SimpleNamespace

from webapp import app_backend
from webapp.routes import flag_catalog_batch


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_build_batch_input_config_autogenerates_scalar_inputs_and_marks_file_inputs_manual():
    result = flag_catalog_batch._build_batch_input_config(
        {
            'id': 'demo_gen',
            'inputs': [
                {'name': 'username', 'required': True},
                {'name': 'input_file', 'required': True, 'type': 'file'},
                {'name': 'seed', 'required': True, 'default': '42'},
                {'name': 'Credential(user, password)', 'required': True, 'type': 'string'},
            ]
        }
    )

    assert result['ok'] is False
    assert result['manual_inputs'] == ['input_file']
    assert set(result['generated_inputs']) == {'username', 'Credential(user, password)'}
    assert result['cfg']['seed'] == '42'
    assert result['cfg']['username'].startswith('user_')
    assert ':' in result['cfg']['Credential(user, password)']


def test_build_batch_input_config_autogenerates_required_values_by_format():
    result = flag_catalog_batch._build_batch_input_config(
        {
            'id': 'node-demo',
            'inputs': [
                {'name': 'seed', 'required': True, 'type': 'string'},
                {'name': 'node_name', 'required': True, 'type': 'string'},
                {'name': 'ssh_port', 'required': True, 'type': 'number', 'min': 2000, 'max': 2999},
                {'name': 'contact_email', 'required': True, 'type': 'string', 'format': 'email'},
                {'name': 'callback_url', 'required': True, 'type': 'string', 'format': 'url'},
            ],
        }
    )

    assert result['ok'] is True
    assert result['manual_inputs'] == []
    assert set(result['generated_inputs']) == {'seed', 'node_name', 'ssh_port', 'contact_email', 'callback_url'}
    assert str(result['cfg']['seed']).startswith('batch_node-demo_')
    assert str(result['cfg']['node_name']).startswith('node_node-demo_')
    assert 2000 <= int(result['cfg']['ssh_port']) <= 2999
    assert str(result['cfg']['contact_email']).endswith('@example.test')
    assert str(result['cfg']['callback_url']).startswith('http://example.test/')


def test_flag_catalog_batch_query_matches_compose_dependency_metadata():
    item = {
        'id': 'alpha',
        'name': 'Alpha',
        'missing_required_files': ['.venv'],
        'required_files': [
            {'path': '.venv', 'kind': 'volume', 'service': 'generator', 'required': True, 'exists': False},
            {'path': 'optional.env', 'kind': 'env_file', 'required': False, 'exists': False},
        ],
    }

    assert flag_catalog_batch._item_matches_query(item, 'has:missing') is True
    assert flag_catalog_batch._item_matches_query(item, '.venv') is True
    assert flag_catalog_batch._item_matches_query(item, 'optional.env') is True
    assert flag_catalog_batch._item_matches_query(item, 'no-such-file') is False


def test_flag_catalog_batch_start_selects_matching_items(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        app_backend,
        '_flag_generators_from_manifests',
        lambda *, kind: (
            [
                {'id': 'alpha', 'name': 'Alpha', 'inputs': [], 'source': {'path': 'outputs/installed_generators/a'}},
                {'id': 'beta', 'name': 'Beta', 'inputs': [{'name': 'token', 'required': True}], 'source': {'path': 'outputs/installed_generators/b'}},
                {'id': 'gamma', 'name': 'Gamma', 'inputs': [], 'source': {'path': 'outputs/installed_generators/c'}, '_disabled': True},
            ],
            {},
            [],
        ),
    )
    monkeypatch.setattr(app_backend, '_is_installed_generator_view', lambda _generator: True)
    monkeypatch.setattr(app_backend, '_annotate_disabled_state', lambda generators, *, kind: generators)
    monkeypatch.setattr(
        app_backend,
        '_merge_core_configs',
        lambda *_args, **_kwargs: {
            'ssh_host': '127.0.0.1',
            'ssh_port': 22,
            'ssh_username': 'u',
            'ssh_password': 'p',
            'host': '127.0.0.1',
            'port': 50051,
        },
    )
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(app_backend, '_ensure_core_vm_idle_for_test', lambda _cfg: None)

    class _DummyThread:
        def __init__(self, target=None, args=(), kwargs=None, name=None, daemon=None):
            self.target = target
            self.args = args

        def start(self):
            return None

    monkeypatch.setattr(app_backend.threading, 'Thread', _DummyThread)

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    resp = client.post('/flag_catalog_items/batch/start', json={'kind': 'flag-generator', 'query': 'a', 'core': {}})

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload['ok'] is True
    assert payload['selected_count'] == 2
    assert payload['eligible_count'] == 2
    assert payload['manual_input_count'] == 0
    assert payload['generated_input_count'] == 1

    run_id = str(payload.get('run_id') or '')
    meta = app_backend.RUNS.get(run_id) or {}
    assert meta.get('kind') == 'flag_test_batch'
    assert meta.get('kind_name') == 'flag-generator'
    assert [item['id'] for item in meta.get('selected_items') or []] == ['alpha', 'beta']

    app_backend.RUNS.pop(run_id, None)


def test_flag_catalog_batch_start_filters_by_scope(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(app_backend, 'RUNS', {})
    monkeypatch.setattr(
        app_backend,
        '_flag_generators_from_manifests',
        lambda *, kind: (
            [
                {'id': 'passed', 'name': 'Passed', 'inputs': [], 'validated_ok': True, 'source': {'path': 'outputs/installed_generators/p'}},
                {'id': 'failed', 'name': 'Failed', 'inputs': [], 'validated_ok': False, 'source': {'path': 'outputs/installed_generators/f'}},
                {'id': 'fresh', 'name': 'Fresh', 'inputs': [], 'validated_ok': None, 'source': {'path': 'outputs/installed_generators/u'}},
                {'id': 'incomplete', 'name': 'Incomplete', 'inputs': [], 'validated_ok': True, 'validated_incomplete': True, 'source': {'path': 'outputs/installed_generators/i'}},
                {'id': 'disabled', 'name': 'Disabled', 'inputs': [], 'validated_ok': False, '_disabled': True, 'source': {'path': 'outputs/installed_generators/d'}},
            ],
            {},
            [],
        ),
    )
    monkeypatch.setattr(app_backend, '_is_installed_generator_view', lambda _generator: True)
    monkeypatch.setattr(app_backend, '_annotate_disabled_state', lambda generators, *, kind: generators)
    monkeypatch.setattr(
        app_backend,
        '_merge_core_configs',
        lambda *_args, **_kwargs: {
            'ssh_host': '127.0.0.1',
            'ssh_port': 22,
            'ssh_username': 'u',
            'ssh_password': 'p',
            'host': '127.0.0.1',
            'port': 50051,
        },
    )
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(app_backend, '_ensure_core_vm_idle_for_test', lambda _cfg: None)

    class _DummyThread:
        def __init__(self, target=None, args=(), kwargs=None, name=None, daemon=None):
            self.target = target
            self.args = args

        def start(self):
            return None

    monkeypatch.setattr(app_backend.threading, 'Thread', _DummyThread)

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    failed_resp = client.post('/flag_catalog_items/batch/start', json={'kind': 'flag-generator', 'scope': 'failed', 'core': {}})
    assert failed_resp.status_code == 200
    failed_run_id = str((failed_resp.get_json() or {}).get('run_id') or '')
    failed_meta = app_backend.RUNS.get(failed_run_id) or {}
    assert [item['id'] for item in failed_meta.get('selected_items') or []] == ['failed']
    assert (failed_resp.get_json() or {})['scope'] == 'failed'
    app_backend.RUNS.pop(failed_run_id, None)

    all_resp = client.post('/flag_catalog_items/batch/start', json={'kind': 'flag-generator', 'scope': 'all_enabled', 'core': {}})
    assert all_resp.status_code == 200
    all_run_id = str((all_resp.get_json() or {}).get('run_id') or '')
    all_meta = app_backend.RUNS.get(all_run_id) or {}
    assert [item['id'] for item in all_meta.get('selected_items') or []] == ['passed', 'failed', 'fresh', 'incomplete']
    assert (all_resp.get_json() or {})['scope_label'] == 'All Enabled'
    app_backend.RUNS.pop(all_run_id, None)


def test_flag_catalog_batch_start_filters_by_scope_from_annotated_state(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(app_backend, 'RUNS', {})
    monkeypatch.setattr(
        app_backend,
        '_flag_generators_from_manifests',
        lambda *, kind: (
            [
                {'id': 'passed', 'name': 'Passed', 'inputs': [], 'source': {'path': 'outputs/installed_generators/p'}},
                {'id': 'failed', 'name': 'Failed', 'inputs': [], 'source': {'path': 'outputs/installed_generators/f'}},
                {'id': 'fresh', 'name': 'Fresh', 'inputs': [], 'source': {'path': 'outputs/installed_generators/u'}},
                {'id': 'incomplete', 'name': 'Incomplete', 'inputs': [], 'source': {'path': 'outputs/installed_generators/i'}},
            ],
            {},
            [],
        ),
    )
    monkeypatch.setattr(app_backend, '_is_installed_generator_view', lambda _generator: True)

    def _annotate(generators, *, kind):
        state = {
            'passed': (True, False),
            'failed': (False, False),
            'fresh': (None, False),
            'incomplete': (True, True),
        }
        for generator in generators:
            ok, incomplete = state[str(generator.get('id'))]
            generator['_validated_ok'] = ok
            generator['_validated_incomplete'] = incomplete
            generator['_validated_at'] = 'now'
        return generators

    monkeypatch.setattr(app_backend, '_annotate_disabled_state', _annotate)
    monkeypatch.setattr(
        app_backend,
        '_merge_core_configs',
        lambda *_args, **_kwargs: {
            'ssh_host': '127.0.0.1',
            'ssh_port': 22,
            'ssh_username': 'u',
            'ssh_password': 'p',
            'host': '127.0.0.1',
            'port': 50051,
        },
    )
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(app_backend, '_ensure_core_vm_idle_for_test', lambda _cfg: None)

    class _DummyThread:
        def __init__(self, target=None, args=(), kwargs=None, name=None, daemon=None):
            self.target = target
            self.args = args

        def start(self):
            return None

    monkeypatch.setattr(app_backend.threading, 'Thread', _DummyThread)

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    failed_resp = client.post('/flag_catalog_items/batch/start', json={'kind': 'flag-generator', 'scope': 'failed', 'core': {}})
    assert failed_resp.status_code == 200
    failed_run_id = str((failed_resp.get_json() or {}).get('run_id') or '')
    failed_meta = app_backend.RUNS.get(failed_run_id) or {}
    assert [item['id'] for item in failed_meta.get('selected_items') or []] == ['failed']
    assert failed_meta['selected_items'][0]['validated_ok'] is False
    app_backend.RUNS.pop(failed_run_id, None)

    unvalidated_resp = client.post('/flag_catalog_items/batch/start', json={'kind': 'flag-generator', 'scope': 'unvalidated', 'core': {}})
    assert unvalidated_resp.status_code == 200
    unvalidated_run_id = str((unvalidated_resp.get_json() or {}).get('run_id') or '')
    unvalidated_meta = app_backend.RUNS.get(unvalidated_run_id) or {}
    assert [item['id'] for item in unvalidated_meta.get('selected_items') or []] == ['fresh', 'incomplete']
    app_backend.RUNS.pop(unvalidated_run_id, None)


def test_flag_catalog_batch_start_native_mode_prefers_ssh_host_when_not_explicit(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        app_backend,
        '_flag_generators_from_manifests',
        lambda *, kind: (
            [
                {'id': 'alpha', 'name': 'Alpha', 'inputs': [], 'source': {'path': 'outputs/installed_generators/a'}},
            ],
            {},
            [],
        ),
    )
    monkeypatch.setattr(app_backend, '_is_installed_generator_view', lambda _generator: True)
    monkeypatch.setattr(app_backend, '_annotate_disabled_state', lambda generators, *, kind: generators)
    monkeypatch.setattr(
        app_backend,
        '_merge_core_configs',
        lambda *_args, **_kwargs: {
            'ssh_host': 'vm-node-host',
            'ssh_port': 22,
            'ssh_username': 'u',
            'ssh_password': 'p',
            'host': 'configured-core-host',
            'grpc_host': 'configured-core-host',
            'port': 50051,
        },
    )
    monkeypatch.setattr(app_backend, '_webui_runtime_mode', lambda: 'native')
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)

    seen = {}

    def _capture_core_cfg(core_cfg):
        seen['host'] = core_cfg.get('host')
        seen['grpc_host'] = core_cfg.get('grpc_host')
        seen['ssh_host'] = core_cfg.get('ssh_host')
        return None

    monkeypatch.setattr(app_backend, '_ensure_core_vm_idle_for_test', _capture_core_cfg)

    class _DummyThread:
        def __init__(self, target=None, args=(), kwargs=None, name=None, daemon=None):
            self.target = target
            self.args = args

        def start(self):
            return None

    monkeypatch.setattr(app_backend.threading, 'Thread', _DummyThread)

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    resp = client.post('/flag_catalog_items/batch/start', json={'kind': 'flag-generator', 'core': {'ssh_host': 'vm-node-host'}})

    assert resp.status_code == 200
    assert seen['host'] == 'vm-node-host'
    assert seen['grpc_host'] == 'vm-node-host'
    assert seen['ssh_host'] == 'vm-node-host'

    run_id = str((resp.get_json() or {}).get('run_id') or '')
    if run_id:
        app_backend.RUNS.pop(run_id, None)


def test_flag_catalog_batch_start_vm_mode_accepts_missing_core_payload(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(app_backend, 'RUNS', {})
    monkeypatch.setattr(
        app_backend,
        '_flag_generators_from_manifests',
        lambda *, kind: (
            [
                {'id': 'alpha', 'name': 'Alpha', 'inputs': [], 'source': {'path': 'outputs/installed_generators/a'}},
            ],
            {},
            [],
        ),
    )
    monkeypatch.setattr(app_backend, '_is_installed_generator_view', lambda _generator: True)
    monkeypatch.setattr(app_backend, '_annotate_disabled_state', lambda generators, *, kind: generators)
    monkeypatch.setattr(app_backend, '_webui_runtime_mode', lambda: 'vm')

    seen = {}

    def _merge_defaults(*args, **_kwargs):
        seen['raw_core'] = args[0] if args else None
        return {
            'ssh_host': 'vm-core',
            'ssh_port': 22,
            'ssh_username': 'sampleuser',
            'ssh_password': 'samplepassword',
            'host': 'vm-core',
            'grpc_host': 'vm-core',
            'port': 50051,
            'grpc_port': 50051,
        }

    monkeypatch.setattr(app_backend, '_merge_core_configs', _merge_defaults)
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(app_backend, '_ensure_core_vm_idle_for_test', lambda _cfg: None)

    class _DummyThread:
        def __init__(self, target=None, args=(), kwargs=None, name=None, daemon=None):
            self.target = target
            self.args = args

        def start(self):
            return None

    monkeypatch.setattr(app_backend.threading, 'Thread', _DummyThread)

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    resp = client.post('/flag_catalog_items/batch/start', json={'kind': 'flag-generator'})

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload['ok'] is True
    assert seen['raw_core'] is None

    run_id = str(payload.get('run_id') or '')
    if run_id:
        app_backend.RUNS.pop(run_id, None)


def test_flag_catalog_batch_status_and_stop(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)

    batch_id = 'flag-batch-123'
    app_backend.RUNS[batch_id] = {
        'kind': 'flag_test_batch',
        'kind_name': 'flag-generator',
        'run_id': batch_id,
        'done': False,
        'status': 'running',
        'scope': 'failed',
        'query': '',
        'include_disabled': False,
        'limit': None,
        'selected_items': [{'id': 'alpha', 'name': 'Alpha'}, {'id': 'beta', 'name': 'Beta'}],
        'results': [{'item_id': 'alpha', 'item_name': 'Alpha', 'status': 'passed', 'reason': 'generated 1 output file'}],
        'log_lines': ['[batch] starting'],
        'active_item_id': 'beta',
        'active_item_name': 'Beta',
        'active_child_run_id': '',
        'active_child_stop_requested': False,
        'stop_requested': False,
        'started_at': 'now',
        'finished_at': None,
    }

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    status_resp = client.get('/flag_catalog_items/batch/status', query_string={'run_id': batch_id})
    assert status_resp.status_code == 200
    status_payload = status_resp.get_json() or {}
    assert status_payload['ok'] is True
    assert status_payload['selection']['kind'] == 'flag-generator'
    assert status_payload['selection']['scope'] == 'failed'
    assert status_payload['selection']['scope_label'] == 'Previously Failed'
    assert status_payload['progress'] == {
        'total': 2,
        'completed': 1,
        'passed': 1,
        'failed': 0,
        'incomplete': 0,
        'skipped': 0,
        'pending': 1,
    }
    assert status_payload['active_item']['id'] == 'beta'

    stop_resp = client.post('/flag_catalog_items/batch/stop', json={'run_id': batch_id})
    assert stop_resp.status_code == 200
    assert stop_resp.get_json() == {'ok': True, 'run_id': batch_id, 'stop_requested': True}
    assert app_backend.RUNS[batch_id]['stop_requested'] is True
    assert app_backend.RUNS[batch_id]['status'] == 'stopping'

    app_backend.RUNS.pop(batch_id, None)


def test_flag_catalog_batch_classify_requires_contract_and_scenario_validation(tmp_path, monkeypatch):
    run_dir = tmp_path / 'run'
    run_dir.mkdir()
    artifact = run_dir / 'artifacts' / 'secret.txt'
    artifact.parent.mkdir()
    artifact.write_text('FLAG{demo}\n', encoding='utf-8')
    (run_dir / 'outputs.json').write_text(
        json.dumps({'outputs': {'File(path)': 'artifacts/secret.txt', 'Flag(flag_id)': 'FLAG{demo}'}}),
        encoding='utf-8',
    )

    child_meta = {
        'run_id': 'child-assurance-pass',
        'kind': 'flag_generator_test',
        'run_dir': str(run_dir),
        'returncode': 0,
        'done': True,
        'generator_item': {
            'id': 'text_demo',
            'outputs': [{'name': 'File(path)'}, {'name': 'Flag(flag_id)'}],
            'inject_files': ['File(path)'],
        },
        'validation_summary': {
            'ok': True,
            'missing_nodes': [],
            'docker_not_running': [],
            'injects_missing': [],
            'generator_outputs_missing': [],
            'generator_injects_missing': [],
        },
    }

    monkeypatch.setattr(app_backend, '_extract_async_error_from_text', lambda _text: None)

    result = flag_catalog_batch._classify_single_run(app_backend, child_meta)

    assert result['status'] == 'passed'
    assert result['reason'] == 'contract and scenario validation passed'
    assert 'generator_contract_passed' in result['categories']
    assert 'scenario_validation_passed' in result['categories']
    assert result['assurance_summary']['ok'] is True
    assert result['validation_summary']['ok'] is True


def test_flag_catalog_batch_classify_fails_missing_declared_inject(tmp_path, monkeypatch):
    run_dir = tmp_path / 'run'
    run_dir.mkdir()
    (run_dir / 'outputs.json').write_text(
        json.dumps({'outputs': {'File(path)': 'artifacts/missing.txt'}}),
        encoding='utf-8',
    )

    child_meta = {
        'run_id': 'child-assurance-fail',
        'kind': 'flag_generator_test',
        'run_dir': str(run_dir),
        'returncode': 0,
        'done': True,
        'generator_item': {
            'id': 'text_demo',
            'outputs': [{'name': 'File(path)'}],
            'inject_files': ['File(path)'],
        },
        'validation_summary': {'ok': True},
    }

    monkeypatch.setattr(app_backend, '_extract_async_error_from_text', lambda _text: None)

    result = flag_catalog_batch._classify_single_run(app_backend, child_meta)

    assert result['status'] == 'failed'
    assert 'missing inject source' in result['reason']
    assert 'generator_contract' in result['categories']
    assert 'generator_injects' in result['categories']
    assert result['assurance_summary']['ok'] is False


def test_flag_catalog_batch_worker_finishes_when_stopped_child_is_missing(monkeypatch):
    class NoSleep:
        def sleep(self, _seconds):
            raise AssertionError('batch worker should not keep polling a missing stopped child')

    batch_meta = {
        'kind': 'flag_test_batch',
        'kind_name': 'flag-generator',
        'run_id': 'batch-stop-race',
        'done': False,
        'status': 'queued',
        'query': '',
        'include_disabled': False,
        'limit': None,
        'selected_items': [{'id': 'alpha', 'name': 'Alpha', 'inputs': []}],
        'results': [],
        'log_lines': [],
        'active_item_id': None,
        'active_item_name': None,
        'active_child_run_id': None,
        'active_child_stop_requested': False,
        'stop_requested': False,
        'started_at': 'now',
        'finished_at': None,
    }
    backend = SimpleNamespace(
        RUNS={},
        time=NoSleep(),
        _local_timestamp_display=lambda: 'done',
    )

    def fake_start_child(_backend, *, kind, item, core_cfg):
        batch_meta['stop_requested'] = True
        return {'ok': True, 'run_id': 'missing-child'}, 200

    monkeypatch.setattr(flag_catalog_batch, '_start_child_run', fake_start_child)

    flag_catalog_batch._run_batch(backend, batch_meta, {})

    assert batch_meta['done'] is True
    assert batch_meta['status'] == 'stopped'
    assert batch_meta['active_child_run_id'] is None
    assert batch_meta['active_child_stop_requested'] is False
    assert len(batch_meta['results']) == 1
    result = batch_meta['results'][0]
    assert result['status'] == 'incomplete'
    assert result['reason'] == 'batch stop requested; child metadata missing'
    assert 'batch_stopped' in result['categories']
    assert 'metadata_missing' in result['categories']


def test_flag_catalog_batch_start_conflict_reports_active_run(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)

    active_id = 'active-flag-run'
    app_backend.RUNS[active_id] = {
        'kind': 'flag_generator_test',
        'done': False,
        'status': 'generator_running',
        'generator_id': 'alpha',
        'generator_name': 'Alpha',
    }

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    try:
        resp = client.post('/flag_catalog_items/batch/start', json={'kind': 'flag-generator', 'core': {}})
    finally:
        app_backend.RUNS.pop(active_id, None)

    assert resp.status_code == 409
    payload = resp.get_json() or {}
    assert payload['ok'] is False
    assert payload['can_stop_active'] is True
    assert payload['active_run']['run_id'] == active_id
    assert payload['active_run']['kind'] == 'flag_generator_test'
    assert payload['active_run']['generator_id'] == 'alpha'


def test_flag_catalog_batch_active_and_stop_active_routes(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)
    captured = {}

    def fake_cleanup(backend_module, meta):
        captured['run_id'] = meta.get('run_id')
        captured['kind'] = meta.get('kind')
        meta['done'] = True
        backend_module.RUNS.pop(str(meta.get('run_id') or ''), None)

    monkeypatch.setattr(flag_catalog_batch, '_cleanup_child_run', fake_cleanup)

    active_id = 'active-node-run'
    app_backend.RUNS[active_id] = {
        'kind': 'flag_node_generator_test',
        'done': False,
        'status': 'generator_running',
        'generator_id': 'node-alpha',
        'generator_name': 'Node Alpha',
    }

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    active_resp = client.get('/flag_catalog_items/batch/active')
    assert active_resp.status_code == 200
    active_payload = active_resp.get_json() or {}
    assert active_payload['active_run']['run_id'] == active_id

    stop_resp = client.post('/flag_catalog_items/batch/stop_active', json={})
    assert stop_resp.status_code == 200
    stop_payload = stop_resp.get_json() or {}
    assert stop_payload['ok'] is True
    assert stop_payload['run_id'] == active_id
    assert stop_payload['active_run']['generator_name'] == 'Node Alpha'
    assert captured == {'run_id': active_id, 'kind': 'flag_node_generator_test'}
    assert active_id not in app_backend.RUNS


def test_flag_catalog_batch_status_exports_and_item_log(monkeypatch):
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)

    batch_log_path = Path(app_backend._outputs_dir()) / 'test-flag-batch-item.log'
    batch_log_path.write_text('full flag batch child log\nline two\n', encoding='utf-8')

    batch_id = 'flag-batch-export'
    app_backend.RUNS[batch_id] = {
        'kind': 'flag_test_batch',
        'kind_name': 'flag-node-generator',
        'run_id': batch_id,
        'done': True,
        'status': 'completed',
        'query': 'alpha',
        'include_disabled': False,
        'limit': 25,
        'selected_items': [{'id': 'alpha', 'name': 'Alpha'}, {'id': 'beta', 'name': 'Beta'}],
        'results': [
            {
                'item_id': 'alpha',
                'item_name': 'Alpha',
                'status': 'failed',
                'reason': 'execute returncode=1',
                'categories': ['execute_returncode', 'outputs_missing'],
                'log_path': str(batch_log_path),
                'log_filename': 'alpha.log',
            },
            {'item_id': 'beta', 'item_name': 'Beta', 'status': 'passed', 'reason': 'generated 1 output file', 'categories': ['outputs_present']},
        ],
        'log_lines': ['[batch] completed'],
        'active_item_id': None,
        'active_item_name': None,
        'active_child_run_id': '',
        'active_child_stop_requested': False,
        'stop_requested': False,
        'started_at': 'now',
        'finished_at': 'later',
    }

    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()
    _login(client)

    status_resp = client.get('/flag_catalog_items/batch/status', query_string={'run_id': batch_id})
    assert status_resp.status_code == 200
    status_payload = status_resp.get_json() or {}
    assert status_payload['category_counts'] == {
        'execute_returncode': 1,
        'outputs_missing': 1,
        'outputs_present': 1,
    }
    assert status_payload['results'][0]['log_available'] is True
    assert status_payload['results'][0]['log_download_url'] == f'/flag_catalog_items/batch/item_log?run_id={batch_id}&item_id=alpha'

    json_resp = client.get('/flag_catalog_items/batch/export.json', query_string={'run_id': batch_id})
    assert json_resp.status_code == 200
    json_payload = json_resp.get_json() or {}
    assert json_payload['ok'] is True
    assert json_payload['run_id'] == batch_id
    assert json_payload['category_counts']['execute_returncode'] == 1

    md_resp = client.get('/flag_catalog_items/batch/export.md', query_string={'run_id': batch_id})
    assert md_resp.status_code == 200
    assert 'attachment; filename=flag-batch-flag-batch-export.md' in md_resp.headers.get('Content-Disposition', '')
    markdown = md_resp.get_data(as_text=True)
    assert '# Flag Catalog Batch Test Report' in markdown
    assert 'execute_returncode: 1' in markdown
    assert '| alpha | Alpha | failed | execute_returncode, outputs_missing | execute returncode=1 |' in markdown

    log_resp = client.get('/flag_catalog_items/batch/item_log', query_string={'run_id': batch_id, 'item_id': 'alpha'})
    assert log_resp.status_code == 200
    assert 'attachment; filename=alpha.log' in log_resp.headers.get('Content-Disposition', '')
    assert log_resp.get_data(as_text=True) == 'full flag batch child log\nline two\n'

    app_backend.RUNS.pop(batch_id, None)
    batch_log_path.unlink(missing_ok=True)
