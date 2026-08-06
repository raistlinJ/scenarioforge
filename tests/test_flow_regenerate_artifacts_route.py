from webapp.app_backend import app
from webapp import app_backend as backend


class _FakeSftp:
    def __init__(self):
        self.put_calls = []

    def put(self, local, remote):
        self.put_calls.append((local, remote))

    def close(self):
        return None


class _FakeSshClient:
    def __init__(self):
        self.sftp = _FakeSftp()

    def open_sftp(self):
        return self.sftp

    def close(self):
        return None


def test_regenerate_flow_artifacts_uses_request_assignments_when_xml_is_unresolved(tmp_path, monkeypatch):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="demo"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    request_assignment = {
        'id': 'request_gen',
        'type': 'flag-generator',
        'node_id': 'docker-1',
        'run_dir': '/tmp/vulns/flag_generators_runs/request_gen',
        'outputs_manifest': '/tmp/vulns/flag_generators_runs/request_gen/outputs.json',
        'resolved_outputs': {'Flag(flag_id)': 'FLAG-123'},
        'resolved_inputs': {'seed': 'stable-seed'},
    }
    captured = {}

    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *_args, **_kwargs: {'flag_assignments': [{'id': 'xml_gen', 'node_id': 'docker-1'}]},
    )
    monkeypatch.setattr(
        backend,
        '_core_config_from_xml_path',
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        backend,
        '_select_core_config_for_page',
        lambda *_args, **_kwargs: {'ssh_host': 'core.local', 'ssh_username': 'core', 'ssh_password': 'pw'},
    )
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: dict(cfg or {}, ssh_enabled=True))
    monkeypatch.setattr(backend, '_open_ssh_client', lambda _cfg: _FakeSshClient())
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda _sftp: '/remote/repo')
    monkeypatch.setattr(backend, '_flow_assignment_missing_remote_paths', lambda _sftp, assignment: ['missing'] if assignment.get('id') == 'request_gen' else [])

    def _fake_regenerate(**kwargs):
        captured['assignments_override'] = kwargs.get('assignments_override')
        captured['verify_after'] = kwargs.get('verify_after')

    monkeypatch.setattr(backend, '_regenerate_missing_remote_flow_artifacts_for_plan', _fake_regenerate)

    with app.test_client() as client:
        login = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
        assert login.status_code in (302, 303)
        response = client.post(
            '/api/flag-sequencing/regenerate_flow_artifacts',
            json={
                'scenario': 'demo',
                'xml_path': str(xml_path),
                'flag_assignments': [request_assignment],
            },
        )

    assert response.status_code == 200, response.get_json()
    data = response.get_json() or {}
    assert data.get('ok') is True
    selected = captured.get('assignments_override') or []
    assert selected and selected[0].get('id') == 'request_gen'
    assert captured.get('verify_after') is False


def test_regenerate_flow_artifacts_restores_imported_bundle_payload_before_replay(tmp_path, monkeypatch):
    upload_root = tmp_path / 'uploads'
    restored_root = upload_root / 'reproduction-1' / 'artifacts' / '001'
    restored_root.mkdir(parents=True)
    artifact = restored_root / 'flag.txt'
    artifact.write_text('FLAG-123\n', encoding='utf-8')
    xml_path = upload_root / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="demo" /></Scenarios>', encoding='utf-8')
    remote_root = '/tmp/vulns/flag_generators_runs/demo'
    assignment = {
        'id': 'request_gen',
        'node_id': 'docker-1',
        'artifacts_dir': remote_root,
        'resolved_inputs': {'seed': 'stable-seed'},
        'resolved_outputs': {'Flag(flag_id)': 'FLAG-123'},
    }
    flow_state = {
        'flag_assignments': [assignment],
        'reproduction_artifact_sources': [
            {
                'source_path': remote_root,
                'restored_path': str(restored_root),
                'target_path': remote_root,
            }
        ],
    }
    fake_client = _FakeSshClient()
    regenerated = {}

    monkeypatch.setitem(app.config, 'UPLOAD_FOLDER', str(upload_root))
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *_args, **_kwargs: flow_state)
    monkeypatch.setattr(
        backend,
        '_core_config_from_xml_path',
        lambda *_args, **_kwargs: {'ssh_host': 'core.local', 'ssh_username': 'core', 'ssh_password': 'pw'},
    )
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: dict(cfg or {}, ssh_enabled=True))
    monkeypatch.setattr(backend, '_open_ssh_client', lambda _cfg: fake_client)
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda _sftp: '/remote/repo')
    monkeypatch.setattr(backend, '_remote_mkdirs', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_flow_assignment_missing_remote_paths', lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        backend,
        '_regenerate_missing_remote_flow_artifacts_for_plan',
        lambda **kwargs: regenerated.update(kwargs),
    )

    with app.test_client() as client:
        login = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
        assert login.status_code in (302, 303)
        response = client.post(
            '/api/flag-sequencing/regenerate_flow_artifacts',
            json={'scenario': 'demo', 'xml_path': str(xml_path)},
        )

    assert response.status_code == 200, response.get_json()
    assert fake_client.sftp.put_calls == [(str(artifact), f'{remote_root}/flag.txt')]
    assert regenerated.get('assignments_override') == [assignment]
