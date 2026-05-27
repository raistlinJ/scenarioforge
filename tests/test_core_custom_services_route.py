from webapp import app_backend as backend

app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


class _FakeSSH:
    def close(self):
        return None


def test_custom_services_check_reports_missing(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_local_custom_service_names', lambda: ['CoreTGPrereqs', 'DockerDefaultRoute', 'Traffic'])
    monkeypatch.setattr(backend, '_open_ssh_client', lambda cfg: _FakeSSH())
    monkeypatch.setattr(backend, '_remote_core_service_names', lambda ssh_client, **kwargs: {'CoreTGPrereqs'})

    resp = client.post('/core/custom_services/check', json={
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        'scenario_name': 'Scenario Custom Services',
    })

    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert data['installed'] is False
    assert data['required_services'] == ['CoreTGPrereqs', 'DockerDefaultRoute', 'Traffic']
    assert data['missing_services'] == ['DockerDefaultRoute', 'Traffic']
    assert data['discovered_services'] == ['CoreTGPrereqs']


def test_custom_services_check_installs_and_rechecks(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_local_custom_service_names', lambda: ['CoreTGPrereqs', 'DockerDefaultRoute', 'Traffic'])
    monkeypatch.setattr(backend, '_open_ssh_client', lambda cfg: _FakeSSH())

    discoveries = [
        {'CoreTGPrereqs'},
        {'CoreTGPrereqs', 'DockerDefaultRoute', 'Traffic'},
    ]

    def _fake_remote_names(_ssh_client, **_kwargs):
        return discoveries.pop(0)

    installer_calls = []

    def _fake_install(_ssh_client, *, sudo_password, logger, core_cfg=None):
        installer_calls.append({'sudo_password': sudo_password, 'core_cfg': core_cfg})
        return {'modules': ['CoreTGPrereqs', 'DockerDefaultRoute', 'TrafficService'], 'services_dir': '/opt/core/services'}

    monkeypatch.setattr(backend, '_remote_core_service_names', _fake_remote_names)
    monkeypatch.setattr(backend, '_install_custom_services_to_core_vm', _fake_install)

    resp = client.post('/core/custom_services/check', json={
        'install': True,
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        'scenario_name': 'Scenario Custom Services',
    })

    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert data['installed'] is True
    assert data['missing_services'] == []
    assert data['install_custom_services']['services_dir'] == '/opt/core/services'
    assert installer_calls and installer_calls[0]['sudo_password'] == 'pw'


def test_custom_services_check_install_still_missing_returns_conflict(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_local_custom_service_names', lambda: ['CoreTGPrereqs', 'DockerDefaultRoute'])
    monkeypatch.setattr(backend, '_open_ssh_client', lambda cfg: _FakeSSH())
    monkeypatch.setattr(backend, '_remote_core_service_names', lambda _ssh_client, **_kwargs: {'CoreTGPrereqs'})
    monkeypatch.setattr(
        backend,
        '_install_custom_services_to_core_vm',
        lambda _ssh_client, *, sudo_password, logger, core_cfg=None: {'modules': ['CoreTGPrereqs']},
    )

    resp = client.post('/core/custom_services/check', json={
        'install': True,
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
    })

    assert resp.status_code == 409
    data = resp.get_json()
    assert data['ok'] is False
    assert data['missing_services'] == ['DockerDefaultRoute']
    assert data['error'] == 'Custom CORE services are still missing after install.'
