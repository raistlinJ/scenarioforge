import subprocess

import pytest

from scenarioforge.builders import topology


def test_preflight_runs_inject_helper_before_target_service(tmp_path, monkeypatch):
    compose_path = tmp_path / "docker-compose-docker-1.yml"
    compose_path.write_text(
        "\n".join(
            [
                "services:",
                "  docker-1:",
                "    image: alpine:3.19",
                "    command: ['sh', '-lc', 'sleep 60']",
                "  inject_copy:",
                "    image: alpine:3.19",
                "    command: ['sh', '-lc', 'true']",
                "volumes:",
                "  inject-flow-injects: {}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    calls: list[list[str]] = []

    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        call = [str(arg) for arg in args]
        calls.append(call)
        if call[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(args, 0, stdout="123 running\n")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(topology, "_docker_compose_cmd", lambda: ["docker", "compose"])
    monkeypatch.setattr(topology, "_docker_cmd", lambda: ["docker"])
    monkeypatch.setattr(topology, "_docker_sudo_password", lambda: None)
    monkeypatch.setattr(topology.subprocess, "run", fake_run)
    topology._PREFLIGHTED_DOCKER_NODE_COMPOSES.clear()

    topology._docker_compose_preflight(str(compose_path), node_name="docker-1")

    helper_index = next(
        idx for idx, call in enumerate(calls)
        if call[-3:] == ["up", "--no-build", "inject_copy"]
    )
    target_index = next(
        idx for idx, call in enumerate(calls)
        if call[-4:] == ["up", "-d", "--no-build", "docker-1"]
    )
    assert helper_index < target_index
    assert "inject_copy" not in calls[target_index][-4:]


def test_preflight_fails_when_inject_helper_exits_nonzero(tmp_path, monkeypatch):
    compose_path = tmp_path / "docker-compose-docker-1.yml"
    compose_path.write_text(
        "\n".join(
            [
                "services:",
                "  docker-1:",
                "    image: alpine:3.19",
                "    command: ['sh', '-lc', 'sleep 60']",
                "  inject_copy:",
                "    image: alpine:3.19",
                "    command: ['sh', '-lc', 'exit 1']",
                "",
            ]
        ),
        encoding="utf-8",
    )

    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        call = [str(arg) for arg in args]
        if call[-3:] == ["up", "--no-build", "inject_copy"]:
            return subprocess.CompletedProcess(args, 0, stdout="inject_copy-1 exited with code 1\n")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(topology, "_docker_compose_cmd", lambda: ["docker", "compose"])
    monkeypatch.setattr(topology, "_docker_cmd", lambda: ["docker"])
    monkeypatch.setattr(topology, "_docker_sudo_password", lambda: None)
    monkeypatch.setattr(topology.subprocess, "run", fake_run)
    topology._PREFLIGHTED_DOCKER_NODE_COMPOSES.clear()

    with pytest.raises(RuntimeError, match="inject helper failed"):
        topology._docker_compose_preflight(str(compose_path), node_name="docker-1")


def test_remote_docker_cleanup_prunes_unused_volumes():
    import inspect
    from webapp import app_backend as backend

    source = inspect.getsource(backend._run_cli_background_task)
    assert "docker volume prune -f" in source