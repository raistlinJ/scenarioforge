from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


class _FakeChannel:
    def __init__(self, code):
        self._code = code

    def recv_exit_status(self):
        return self._code


class _FakeStream:
    def __init__(self, text, code=0):
        self._text = text
        self.channel = _FakeChannel(code)

    def read(self):
        return self._text.encode('utf-8')


class _FakeStdin:
    def __init__(self):
        self.writes = []
        self.closed = False

    def write(self, value):
        self.writes.append(value)

    def flush(self):
        return None

    def close(self):
        self.closed = True


class _FakeSSHClient:
    def __init__(self):
        self.commands = []
        self.closed = False

    def exec_command(self, command, timeout=None, get_pty=False):
        self.commands.append((command, timeout, get_pty))
        if 'systemctl restart core-daemon' in command:
            return _FakeStdin(), _FakeStream('', 0), _FakeStream('', 0)
        if 'systemctl is-active core-daemon' in command:
            return _FakeStdin(), _FakeStream('active\n', 0), _FakeStream('', 0)
        raise AssertionError(f'unexpected command: {command}')

    def close(self):
        self.closed = True


def test_restart_core_daemon_requires_ssh_host(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_select_core_config_for_page', lambda *args, **kwargs: {'ssh_host': ''})

    resp = client.post('/core/restart_core_daemon')

    assert resp.status_code == 400
    assert (resp.get_json() or {}).get('error') == 'No CORE VM configured via SSH.'


def test_restart_core_daemon_succeeds(monkeypatch):
    client = app.test_client()
    _login(client)

    ssh_client = _FakeSSHClient()

    monkeypatch.setattr(backend, '_normalize_scenario_label', lambda value: value)
    monkeypatch.setattr(
        backend,
        '_select_core_config_for_page',
        lambda *args, **kwargs: {'ssh_host': '127.0.0.1', 'ssh_password': 'pw'},
    )
    monkeypatch.setattr(backend, '_open_ssh_client', lambda core_cfg: ssh_client)
    monkeypatch.setattr(backend.time, 'sleep', lambda _seconds: None)

    resp = client.post('/core/restart_core_daemon?scenario=Scenario%202')

    payload = resp.get_json() or {}
    assert resp.status_code == 200
    assert payload.get('status') == 'ok'
    assert ssh_client.closed is True
    assert len(ssh_client.commands) >= 2
    assert any('systemctl restart core-daemon' in cmd for cmd, *_ in ssh_client.commands)


def test_restart_core_daemon_prompts_when_running(monkeypatch):
    client = app.test_client()
    _login(client)

    ssh_client = _FakeSSHClient()

    monkeypatch.setattr(backend, '_normalize_scenario_label', lambda value: value)
    monkeypatch.setattr(
        backend,
        '_select_core_config_for_page',
        lambda *args, **kwargs: {'ssh_host': '127.0.0.1', 'ssh_password': 'pw'},
    )
    monkeypatch.setattr(backend, '_open_ssh_client', lambda core_cfg: ssh_client)
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [1111])

    resp = client.post('/core/restart_core_daemon?scenario=Scenario%202')
    payload = resp.get_json() or {}

    assert resp.status_code == 409
    assert payload.get('ok') is False
    assert payload.get('code') == 'core_daemon_running'
    assert payload.get('daemon_pids') == [1111]
    assert ssh_client.closed is True


def test_restart_core_daemon_force_kill_then_restart(monkeypatch):
    client = app.test_client()
    _login(client)

    ssh_client = _FakeSSHClient()
    state = {'calls': 0}

    def _fake_collect(*_args, **_kwargs):
        state['calls'] += 1
        if state['calls'] == 1:
            return [2222]
        return []

    stop_calls = []

    def _fake_stop(ssh_client, *, sudo_password, pids, logger):
        stop_calls.append({'sudo_password': sudo_password, 'pids': list(pids)})
        return {'status': 'attempted'}

    monkeypatch.setattr(backend, '_normalize_scenario_label', lambda value: value)
    monkeypatch.setattr(
        backend,
        '_select_core_config_for_page',
        lambda *args, **kwargs: {'ssh_host': '127.0.0.1', 'ssh_password': 'pw'},
    )
    monkeypatch.setattr(backend, '_open_ssh_client', lambda core_cfg: ssh_client)
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', _fake_collect)
    monkeypatch.setattr(backend, '_stop_remote_core_daemon_conflict', _fake_stop)
    monkeypatch.setattr(backend.time, 'sleep', lambda _seconds: None)

    resp = client.post('/core/restart_core_daemon?scenario=Scenario%202', json={'force_kill_existing': True})
    payload = resp.get_json() or {}

    assert resp.status_code == 200
    assert payload.get('status') == 'ok'
    assert stop_calls and stop_calls[0]['sudo_password'] == 'pw'
    assert stop_calls[0]['pids'] == [2222]
    assert ssh_client.closed is True