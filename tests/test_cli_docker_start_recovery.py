from scenarioforge import cli


def test_ensure_docker_nodes_running_restarts_not_running_nodes(monkeypatch):
    calls = []

    def fake_wait(names, *, timeout_s, poll_s):
        calls.append(("wait", list(names), timeout_s, poll_s))
        if len([call for call in calls if call[0] == "wait"]) == 1:
            return {
                "total": 2,
                "running": ["docker-3"],
                "not_running": ["docker-7"],
                "items": [
                    {"name": "docker-3", "running": True},
                    {"name": "docker-7", "running": False, "status": "exited"},
                ],
            }
        return {
            "total": 2,
            "running": ["docker-3", "docker-7"],
            "not_running": [],
            "items": [
                {"name": "docker-3", "running": True},
                {"name": "docker-7", "running": True, "status": "running"},
            ],
        }

    def fake_restart(names, *, restart_timeout_s):
        calls.append(("restart", list(names), restart_timeout_s))
        return [{"ok": True, "node": "docker-7"}]

    monkeypatch.delenv("CORETG_DOCKER_RESTART_NOT_RUNNING", raising=False)
    monkeypatch.setattr(cli, "_wait_for_docker_running", fake_wait)
    monkeypatch.setattr(cli, "_restart_not_running_docker_nodes", fake_restart)
    meta = {}

    result = cli._ensure_docker_nodes_running(
        ["docker-3", "docker-7"],
        docker_wait_s=45.0,
        generation_meta=meta,
    )

    assert result["not_running"] == []
    assert ("restart", ["docker-7"], 120.0) in calls
    assert meta["docker_nodes_start_recovery_attempts"] == [{"ok": True, "node": "docker-7"}]


def test_ensure_docker_nodes_running_can_disable_restart(monkeypatch):
    calls = []

    def fake_wait(names, *, timeout_s, poll_s):
        calls.append(("wait", list(names), timeout_s, poll_s))
        return {
            "total": 1,
            "running": [],
            "not_running": ["docker-7"],
            "items": [{"name": "docker-7", "running": False, "status": "exited"}],
        }

    def fake_restart(names, *, restart_timeout_s):
        calls.append(("restart", list(names), restart_timeout_s))
        return [{"ok": True, "node": "docker-7"}]

    monkeypatch.setenv("CORETG_DOCKER_RESTART_NOT_RUNNING", "0")
    monkeypatch.setattr(cli, "_wait_for_docker_running", fake_wait)
    monkeypatch.setattr(cli, "_restart_not_running_docker_nodes", fake_restart)

    result = cli._ensure_docker_nodes_running(["docker-7"], docker_wait_s=10.0)

    assert result["not_running"] == ["docker-7"]
    assert all(call[0] != "restart" for call in calls)
