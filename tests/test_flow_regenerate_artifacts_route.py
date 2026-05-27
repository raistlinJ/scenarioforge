from webapp.app_backend import app
from webapp import app_backend as backend


class _FakeSftp:
    def close(self):
        return None


class _FakeSshClient:
    def open_sftp(self):
        return _FakeSftp()

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