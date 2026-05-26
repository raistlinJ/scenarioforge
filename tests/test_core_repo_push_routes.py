import json

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


class _FakeUUID:
    def __init__(self, value):
        self.hex = value


def test_core_push_repo_uses_scenario_specific_core_config(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenarios.xml'
    xml_path.write_text('<Scenarios />', encoding='utf-8')

    init_calls = []
    schedule_calls = []

    monkeypatch.setattr(backend.uuid, 'uuid4', lambda: _FakeUUID('repo-progress-1'))
    monkeypatch.setattr(
        backend,
        '_parse_scenarios_xml',
        lambda path: {
            'core': {'host': 'global-host'},
            'scenarios': [
                {'name': 'Scenario 1', 'hitl': {'core': {'host': 'scenario-host', 'ssh_host': 'scenario-vm'}}},
            ],
        },
    )
    monkeypatch.setattr(backend, '_merge_core_configs', lambda *args, **kwargs: {'host': 'merged-host', 'ssh_host': 'scenario-vm'})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, scenario_norm: cfg)
    monkeypatch.setattr(backend, '_init_repo_push_progress', lambda *args, **kwargs: init_calls.append((args, kwargs)))
    monkeypatch.setattr(backend, '_schedule_repo_push_to_remote', lambda *args, **kwargs: schedule_calls.append((args, kwargs)))

    resp = client.post(
        '/core/push_repo',
        data={
            'xml_path': str(xml_path),
            'scenario': 'Scenario 1',
            'core_json': json.dumps({'host': 'override-host'}),
        },
    )

    payload = resp.get_json() or {}
    assert resp.status_code == 200
    assert payload.get('ok') is True
    assert payload.get('progress_id') == 'repo-progress-1'
    assert len(init_calls) == 1
    assert len(schedule_calls) == 1
    assert schedule_calls[0][0][0] == payload.get('progress_id')
    assert schedule_calls[0][0][1] == {'host': 'merged-host', 'ssh_host': 'scenario-vm'}


def test_core_push_repo_applies_stored_secret_before_schedule(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenarios.xml'
    xml_path.write_text('<Scenarios />', encoding='utf-8')

    schedule_calls = []
    secret_apply_calls = []

    monkeypatch.setattr(backend.uuid, 'uuid4', lambda: _FakeUUID('repo-progress-secret'))
    monkeypatch.setattr(
        backend,
        '_parse_scenarios_xml',
        lambda path: {
            'scenarios': [
                {
                    'name': 'Scenario Secret',
                    'hitl': {
                        'core': {
                            'ssh_host': 'stored-host',
                            'ssh_username': 'stored-user',
                            'core_secret_id': 'core-secret-1',
                        }
                    },
                },
            ],
        },
    )
    monkeypatch.setattr(
        backend,
        '_merge_core_configs',
        lambda *args, **kwargs: {
            'ssh_host': 'stored-host',
            'ssh_username': 'stored-user',
            'ssh_password': '',
            'core_secret_id': 'core-secret-1',
        },
    )

    def _fake_apply(cfg, scenario_norm):
        secret_apply_calls.append((dict(cfg), scenario_norm))
        enriched = dict(cfg)
        enriched['ssh_password'] = 'stored-pass'
        enriched['venv_bin'] = '/opt/core/venv/bin'
        return enriched

    monkeypatch.setattr(backend, '_apply_core_secret_to_config', _fake_apply)
    monkeypatch.setattr(backend, '_init_repo_push_progress', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_schedule_repo_push_to_remote', lambda *args, **kwargs: schedule_calls.append((args, kwargs)))

    resp = client.post(
        '/core/push_repo',
        json={
            'xml_path': str(xml_path),
            'scenario_name': 'Scenario Secret',
            'core': {'core_secret_id': 'core-secret-1', 'ssh_password': ''},
        },
    )

    payload = resp.get_json() or {}
    assert resp.status_code == 200
    assert payload.get('ok') is True
    assert secret_apply_calls == [(
        {
            'ssh_host': 'stored-host',
            'ssh_username': 'stored-user',
            'ssh_password': '',
            'core_secret_id': 'core-secret-1',
        },
        'Scenario Secret',
    )]
    assert schedule_calls[0][0][1]['ssh_password'] == 'stored-pass'
    assert schedule_calls[0][0][1]['venv_bin'] == '/opt/core/venv/bin'


def test_core_push_repo_reports_ssh_tunnel_error(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenarios.xml'
    xml_path.write_text('<Scenarios />', encoding='utf-8')

    updates = []

    monkeypatch.setattr(backend.uuid, 'uuid4', lambda: _FakeUUID('repo-progress-2'))
    monkeypatch.setattr(backend, '_parse_scenarios_xml', lambda path: {})
    monkeypatch.setattr(backend, '_merge_core_configs', lambda *args, **kwargs: {'host': 'merged-host'})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, scenario_norm: cfg)
    monkeypatch.setattr(backend, '_init_repo_push_progress', lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, '_update_repo_push_progress', lambda *args, **kwargs: updates.append((args, kwargs)))

    def _raise_tunnel(*args, **kwargs):
        raise backend._SSHTunnelError('ssh tunnel failed')

    monkeypatch.setattr(backend, '_schedule_repo_push_to_remote', _raise_tunnel)

    resp = client.post('/core/push_repo', data={'xml_path': str(xml_path)})

    payload = resp.get_json() or {}
    assert resp.status_code == 400
    assert payload.get('error') == 'ssh tunnel failed'
    assert updates and updates[0][0][0] == 'repo-progress-2'
    assert updates == [
        (
            ('repo-progress-2',),
            {'status': 'error', 'stage': 'error', 'detail': 'ssh tunnel failed'},
        )
    ]


def test_core_sessions_prepare_applies_stored_secret(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    applied = []
    captured = {}

    monkeypatch.setattr(
        backend,
        '_merge_core_configs',
        lambda *args, **kwargs: {
            'host': 'core-vm.example.test',
            'port': 50051,
            'ssh_host': 'core-vm.example.test',
            'ssh_port': 10000,
            'ssh_username': 'sampleuser',
            'ssh_password': '',
            'core_secret_id': 'core-secret-1',
        },
    )

    def _fake_apply(cfg, scenario_norm):
        applied.append((dict(cfg), scenario_norm))
        enriched = dict(cfg)
        enriched['ssh_password'] = 'stored-pass'
        return enriched

    monkeypatch.setattr(backend, '_apply_core_secret_to_config', _fake_apply)
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: dict(cfg))

    def _fake_list_sessions(host, port, cfg, errors=None, meta=None):
        captured.update({'host': host, 'port': port, 'cfg': dict(cfg)})
        return []

    monkeypatch.setattr(backend, '_list_active_core_sessions', _fake_list_sessions)

    resp = client.post(
        '/api/test/core_sessions/prepare',
        json={
            'scenario_name': 'Scenario Secret',
            'cleanup': False,
            'core': {'core_secret_id': 'core-secret-1', 'ssh_password': ''},
        },
    )

    data = resp.get_json() or {}
    assert resp.status_code == 200
    assert data.get('ok') is True
    assert data.get('active') is False
    assert applied == [(
        {
            'host': 'core-vm.example.test',
            'port': 50051,
            'ssh_host': 'core-vm.example.test',
            'ssh_port': 10000,
            'ssh_username': 'sampleuser',
            'ssh_password': '',
            'core_secret_id': 'core-secret-1',
        },
        'Scenario Secret',
    )]
    assert captured['cfg']['ssh_password'] == 'stored-pass'


def test_check_remote_repo_applies_stored_secret(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    opened = {}

    monkeypatch.setattr(
        backend,
        '_merge_core_configs',
        lambda cfg, include_password=True: {
            'ssh_host': 'core-vm.example.test',
            'ssh_port': 10000,
            'ssh_username': 'sampleuser',
            'ssh_password': '',
            'core_secret_id': 'core-secret-1',
        },
    )

    def _fake_apply(cfg, scenario_norm):
        enriched = dict(cfg)
        enriched['ssh_password'] = 'stored-pass'
        enriched['host'] = 'core-vm.example.test'
        enriched['port'] = 50051
        return enriched

    monkeypatch.setattr(backend, '_apply_core_secret_to_config', _fake_apply)
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: dict(cfg))

    class _FakeSftp:
        def stat(self, _path):
            return object()

        def close(self):
            return None

    class _FakeClient:
        def __init__(self, cfg):
            opened.update(cfg)

        def open_sftp(self):
            return _FakeSftp()

        def close(self):
            return None

    monkeypatch.setattr(backend, '_open_ssh_client', lambda cfg: _FakeClient(cfg))
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda sftp: '/tmp/repo')

    resp = client.post(
        '/core/check_remote_repo',
        json={
            'scenario_name': 'Scenario Secret',
            'core': {'core_secret_id': 'core-secret-1', 'ssh_password': ''},
        },
    )

    data = resp.get_json() or {}
    assert resp.status_code == 200
    assert data.get('ok') is True
    assert opened['ssh_password'] == 'stored-pass'