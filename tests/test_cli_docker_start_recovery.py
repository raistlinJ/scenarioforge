import subprocess

from scenarioforge import cli


# --------------------------------------------------------------------------- #
# _docker_compose_restart_service must remove a dead same-named container
# before recreating it, or the recreate collides with its own corpse
# --------------------------------------------------------------------------- #
#
# CORE names a Docker node's container after the node (`docker-N`), and the
# generated compose file pins that same fixed `container_name:` rather than
# letting Compose derive it from a project name. `_docker_compose_restart_service`
# has no `-p` of its own, so `docker compose up -d <service>` here resolves to
# whatever project the compose file's directory implies -- not necessarily the
# project that originally created the container. Compose then tries to *create*
# a container under that fixed name, and Docker refuses: the exact scenario
# seen in a real eval run, where `docker-8` crashed under qemu emulation, the
# 45s liveness check caught it, and the recovery attempt below failed with
# "the container name /docker-8 is already in use" -- taking down the whole
# execute before post-execution validation ever ran.

def test_restart_service_removes_the_dead_container_before_recreating_it(monkeypatch, tmp_path):
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text("services: {}\n", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_run(args, *, timeout_s=20.0, allow_sudo_retry=True):
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(cli, "_run_docker_cmd", fake_run)
    monkeypatch.setattr(cli.shutil, "which", lambda _name: "/usr/bin/docker")

    result = cli._docker_compose_restart_service(str(compose_path), "docker-8")

    assert result["ok"] is True
    assert calls[0] == ["docker", "rm", "-f", "docker-8"], (
        "the dead container must be removed before compose tries to recreate it "
        "under the same fixed name"
    )
    assert calls[1][:4] == ["docker", "compose", "-f", str(compose_path)]
    assert calls[1][-2:] == ["-d", "docker-8"]


def test_restart_service_still_attempts_compose_up_when_rm_fails(monkeypatch, tmp_path):
    # A container that never existed makes `docker rm` fail (nothing to
    # remove) -- that must not block the recreate attempt that follows.
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text("services: {}\n", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_run(args, *, timeout_s=20.0, allow_sudo_retry=True):
        calls.append(list(args))
        if args[:2] == ["docker", "rm"]:
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(cli, "_run_docker_cmd", fake_run)
    monkeypatch.setattr(cli.shutil, "which", lambda _name: "/usr/bin/docker")

    result = cli._docker_compose_restart_service(str(compose_path), "docker-8")

    assert result["ok"] is True
    assert calls[0] == ["docker", "rm", "-f", "docker-8"]
    assert calls[1][:4] == ["docker", "compose", "-f", str(compose_path)]


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
