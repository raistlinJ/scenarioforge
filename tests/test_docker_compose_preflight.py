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


def test_ensure_docker_node_compose_prepared_materializes_project_relative_file_bind(tmp_path, monkeypatch):
    source_dir = tmp_path / "source"
    source_nginx = source_dir / "nginx"
    source_nginx.mkdir(parents=True)
    (source_nginx / "default.conf").write_text("server { listen 80; }\n", encoding="utf-8")
    source_compose = source_dir / "docker-compose.yml"
    source_compose.write_text("services: {}\n", encoding="utf-8")

    legacy_compose = tmp_path / "docker-compose-docker-8.yml"
    project_dir = tmp_path / ".compose-projects" / "docker-8"
    project_compose = project_dir / "docker-compose.yml"
    stale_dir = project_dir / "nginx" / "default.conf"
    stale_dir.mkdir(parents=True)

    def fake_prepare(assignments, out_base="/tmp/vulns", compose_name="docker-compose.yml"):
        legacy_compose.write_text(
            "\n".join(
                [
                    "services:",
                    "  docker-8:",
                    "    image: nginx:1.25-alpine",
                    "    volumes:",
                    "      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return [str(legacy_compose)]

    import scenarioforge.utils.vuln_process as vuln_process

    monkeypatch.setattr(vuln_process, "prepare_compose_for_assignments", fake_prepare)
    monkeypatch.setattr(topology, "_docker_node_legacy_compose_path", lambda _node, _out_base="/tmp/vulns": str(legacy_compose))
    monkeypatch.setattr(topology, "_docker_node_compose_project_dir", lambda _node, _out_base="/tmp/vulns": str(project_dir))
    monkeypatch.setattr(topology, "_docker_node_compose_path", lambda _node, _out_base="/tmp/vulns": str(project_compose))
    monkeypatch.setattr(topology, "_docker_compose_preflight", lambda *_args, **_kwargs: None)
    topology._PREPARED_DOCKER_NODE_COMPOSES.clear()

    rec = {
        "Type": "docker-compose",
        "Name": "nginx-default-conf",
        "Path": str(source_compose),
    }

    topology._ensure_docker_node_compose_prepared("docker-8", rec)

    materialized = project_dir / "nginx" / "default.conf"
    assert materialized.is_file()
    assert materialized.read_text(encoding="utf-8") == "server { listen 80; }\n"
    assert project_compose.is_file()


def test_preflight_fails_before_docker_for_wrong_type_file_bind(tmp_path, monkeypatch):
    compose_dir = tmp_path / ".compose-projects" / "docker-8"
    bind_source = compose_dir / "nginx" / "default.conf"
    bind_source.mkdir(parents=True)
    compose_path = compose_dir / "docker-compose.yml"
    compose_path.write_text(
        "\n".join(
            [
                "services:",
                "  docker-8:",
                "    image: nginx:1.25-alpine",
                "    volumes:",
                "      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro",
                "",
            ]
        ),
        encoding="utf-8",
    )

    def fake_run(*_args, **_kwargs):
        raise AssertionError("docker should not run when bind source is wrong type")

    monkeypatch.setattr(topology, "_docker_compose_cmd", lambda: ["docker", "compose"])
    monkeypatch.setattr(topology, "_docker_cmd", lambda: ["docker"])
    monkeypatch.setattr(topology, "_docker_sudo_password", lambda: None)
    monkeypatch.setattr(topology.subprocess, "run", fake_run)
    topology._PREFLIGHTED_DOCKER_NODE_COMPOSES.clear()

    with pytest.raises(RuntimeError, match="bind-source preflight failed"):
        topology._docker_compose_preflight(str(compose_path), node_name="docker-8")


def test_remote_docker_cleanup_prunes_unused_volumes():
    import inspect
    from webapp import app_backend as backend

    source = inspect.getsource(backend._run_cli_background_task)
    assert "docker volume prune -f" in source
