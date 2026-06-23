from types import SimpleNamespace

from scenarioforge import cli


class DummyCore:
    def __init__(self, sessions):
        self._sessions = sessions

    def get_sessions(self):
        return list(self._sessions)


def test_core_state_str_normalizes_runtime_state():
    assert cli._core_state_str("RUNTIME_STATE") == "runtime_state"
    assert cli._core_state_str("SessionState.RUNTIME_STATE") == "runtime_state"
    assert cli._is_runtime_state("runtime_state") is True
    assert cli._is_runtime_state("RUNTIME_STATE") is True
    assert cli._is_configuration_state("SessionState.CONFIGURATION_STATE") is True


def test_wait_for_core_runtime_accepts_runtime_state():
    sess = SimpleNamespace(id=1, state="RUNTIME_STATE")
    core = DummyCore([sess])
    ok, st = cli._wait_for_core_runtime(core, 1, timeout_s=0.2, poll_s=0.05)
    assert ok is True
    assert cli._is_runtime_state(st) is True


def test_wait_for_core_runtime_honors_configured_timeout_above_40_seconds(monkeypatch):
    clock = {'now': 0.0}

    monkeypatch.setattr(cli.time, 'time', lambda: clock['now'])
    monkeypatch.setattr(
        cli.time,
        'sleep',
        lambda seconds: clock.__setitem__('now', clock['now'] + float(seconds)),
    )
    monkeypatch.setattr(cli, '_get_core_session_state', lambda *_args, **_kwargs: 'configuration')
    monkeypatch.setattr(cli, '_latest_core_daemon_session_state', lambda *_args, **_kwargs: '')

    ok, state = cli._wait_for_core_runtime(
        DummyCore([]),
        1,
        timeout_s=120.0,
        poll_s=5.0,
    )

    assert ok is False
    assert state == 'configuration'
    assert clock['now'] >= 120.0
