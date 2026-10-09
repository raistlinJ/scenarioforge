from types import SimpleNamespace
from scenarioforge.evaluation import reset


def test_reset_uses_authoritative_context_and_only_owned_session(monkeypatch):
    calls = []
    backend = SimpleNamespace(
        app=SimpleNamespace(logger="logger"),
        _require_core_ssh_credentials=lambda c: c,
        _list_active_core_sessions_via_remote_python=lambda *a, **k: (
            [] if calls else [{"id": 7}, {"id": 9}]
        ),
        _execute_remote_core_session_action=lambda cfg, action, session_id, **kw: calls.append(
            (cfg, action, session_id)
        )
        or {"status": "ok"},
    )
    monkeypatch.setattr(reset.cli, "_load_web_backend_module", lambda: backend)
    monkeypatch.setattr(
        reset.cli,
        "_build_cli_parser",
        lambda: SimpleNamespace(
            parse_args=lambda args: SimpleNamespace(xml="frozen.xml")
        ),
    )
    monkeypatch.setattr(
        reset.cli,
        "_resolve_cli_core_context",
        lambda *a, **kw: ("Lab", {"ssh_host": "actual-clone"}, True),
    )
    monkeypatch.setattr(reset.cli, "_cli_should_delegate_remote", lambda cfg: True)
    assert reset.reset_session("frozen.xml", "Lab", 7) == {"status": "ok"}
    assert calls == [({"ssh_host": "actual-clone"}, "delete", 7)]
