from pathlib import Path
import json

from webapp import app_backend


def test_scan_compose_shell_command_safety_flags_unsafe_pid_expansion(tmp_path: Path) -> None:
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(
        """
services:
  node:
    image: alpine:3.20
    command: ['sh','-lc','rpcbind -w -f & RPCBIND_PID=$$!; trap kill $$RPCBIND_PID 2>/dev/null || true EXIT; ganesha.nfsd -F -L STDOUT -f /etc/ganesha/ganesha.conf || sleep infinity']
""".strip()
        + "\n",
        encoding="utf-8",
    )

    ok, issues = app_backend._scan_compose_shell_command_safety(str(compose_path))
    assert ok is False
    assert isinstance(issues, list) and issues
    markers = issues[0].get("markers") if isinstance(issues[0], dict) else []
    assert "double_dollar_pid_pattern" in (markers or [])


def test_scan_compose_shell_command_safety_allows_safe_command(tmp_path: Path) -> None:
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(
        """
services:
  node:
    image: alpine:3.20
    command: ['sh','-lc','rpcbind -w -f & ganesha.nfsd -F -L STDOUT -f /etc/ganesha/ganesha.conf || sleep infinity']
""".strip()
        + "\n",
        encoding="utf-8",
    )

    ok, issues = app_backend._scan_compose_shell_command_safety(str(compose_path))
    assert ok is True
    assert issues == []


def test_autofix_legacy_nfs_compose_shell_pattern_rewrites_command(tmp_path: Path) -> None:
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(
        """
services:
  node:
    image: alpine:3.20
    command: ['sh','-lc','rpcbind -w -f & RPCBIND_PID=$$!; trap kill $$RPCBIND_PID 2>/dev/null || true EXIT; ganesha.nfsd -F -L STDOUT -f /etc/ganesha/ganesha.conf || { echo "[coretg] ganesha failed; keeping container alive" >&2; sleep infinity; }']
""".strip()
        + "\n",
        encoding="utf-8",
    )

    changed = app_backend._autofix_legacy_nfs_compose_shell_pattern(str(compose_path))
    assert changed is True

    text = compose_path.read_text(encoding="utf-8")
    assert "RPCBIND_PID=$$!" not in text
    assert "trap kill $$RPCBIND_PID" not in text
    assert "rpcbind -w -f & ganesha.nfsd -F -L STDOUT -f /etc/ganesha/ganesha.conf || sleep infinity" in text

    ok, issues = app_backend._scan_compose_shell_command_safety(str(compose_path))
    assert ok is True
    assert issues == []


def test_flow_compose_preflight_autofixes_legacy_nfs_compose(tmp_path: Path, monkeypatch) -> None:
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(
        """
services:
  node:
    image: alpine:3.20
    command: ['sh','-lc','rpcbind -w -f & RPCBIND_PID=$$!; trap kill $$RPCBIND_PID 2>/dev/null || true EXIT; ganesha.nfsd -F -L STDOUT -f /etc/ganesha/ganesha.conf || sleep infinity']
""".strip()
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        app_backend,
        "_flow_compose_candidate_records",
        lambda xml_path, scenario_label: [
            {
                "path": str(compose_path),
                "node_id": "1",
                "generator_id": "nfs_sensitive_file",
            }
        ],
    )

    ok, err, meta = app_backend._flow_compose_shell_safety_preflight(
        str(tmp_path / "scenario.xml"),
        "Scenario1",
    )
    assert ok is True
    assert err is None
    assert isinstance(meta, dict)
    assert str(compose_path) in (meta.get("autofixed_paths") or [])

    final_text = compose_path.read_text(encoding="utf-8")
    assert "RPCBIND_PID=$$!" not in final_text


def test_autofix_legacy_nfs_compose_shell_pattern_with_escaped_quotes(tmp_path: Path) -> None:
    """Verify regex autofix handles escaped quotes in YAML docker-compose format."""
    compose_path = tmp_path / "docker-compose.yml"
    # This is the actual format from the failing remote compose file with escaped inner quotes
    compose_path.write_text(
        'services:\n'
        '  node:\n'
        '    build:\n'
        '      context: .\n'
        '      dockerfile: Dockerfile\n'
        '    command: [\'sh\',\'-lc\',\'rpcbind -w -f & RPCBIND_PID=$$!; trap kill $$RPCBIND_PID 2>/dev/null || true EXIT; ganesha.nfsd -F -L STDOUT -f /etc/ganesha/ganesha.conf || { echo "[coretg] ganesha failed; keeping container alive" >&2; sleep infinity; }\']\n'
        '    privileged: true\n'
        '    ports:\n'
        '      - "2049:2049"\n'
        '    volumes:\n'
        '      - ./exports:/exports\n'
        '      - ./ganesha.conf:/etc/ganesha/ganesha.conf:ro\n'
        '    hostname: nfs\n',
        encoding="utf-8",
    )

    changed = app_backend._autofix_legacy_nfs_compose_shell_pattern(str(compose_path))
    assert changed is True

    text = compose_path.read_text(encoding="utf-8")
    assert "RPCBIND_PID=$$!" not in text
    assert "trap kill $$RPCBIND_PID" not in text
    assert "rpcbind -w -f & ganesha.nfsd -F -L STDOUT -f /etc/ganesha/ganesha.conf || sleep infinity" in text

    ok, issues = app_backend._scan_compose_shell_command_safety(str(compose_path))
    assert ok is True
    assert issues == []


def test_run_cli_background_task_applies_flow_compose_preflight(tmp_path: Path, monkeypatch) -> None:
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text("<Scenarios/>\n", encoding="utf-8")

    run_id = "preflight-compose-order"
    app_backend.RUNS[run_id] = {"done": False, "returncode": None}

    called: dict[str, str] = {}

    def _fake_preflight(path: str, scenario_label: str | None):
        called["path"] = path
        called["scenario"] = str(scenario_label or "")
        return False, "blocked by test preflight", {"issues": [{"path": path}]}

    monkeypatch.setattr(app_backend, "_flow_compose_shell_safety_preflight", _fake_preflight)

    app_backend._run_cli_background_task(
        run_id,
        {
            "xml_path": str(xml_path),
            "flow_enabled": True,
            "scenario_name_hint": "Scenario1",
        },
    )

    assert called.get("path") == str(xml_path)
    assert called.get("scenario") == "Scenario1"
    meta = app_backend.RUNS.get(run_id) or {}
    assert meta.get("done") is True
    assert meta.get("returncode") == 1
    assert "blocked by test preflight" in str(meta.get("error") or "")
    assert isinstance(meta.get("preflight_compose"), dict)


def test_run_cli_background_task_applies_preflight_when_flow_disabled(tmp_path: Path, monkeypatch) -> None:
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text("<Scenarios/>\n", encoding="utf-8")

    run_id = "preflight-compose-flow-disabled"
    app_backend.RUNS[run_id] = {"done": False, "returncode": None}

    called: dict[str, str] = {}

    def _fake_preflight(path: str, scenario_label: str | None):
        called["path"] = path
        called["scenario"] = str(scenario_label or "")
        return False, "blocked even when flow disabled", {"issues": [{"path": path}]}

    monkeypatch.setattr(app_backend, "_flow_compose_shell_safety_preflight", _fake_preflight)

    app_backend._run_cli_background_task(
        run_id,
        {
            "xml_path": str(xml_path),
            "flow_enabled": False,
            "scenario_name_hint": "Scenario1",
        },
    )

    assert called.get("path") == str(xml_path)
    assert called.get("scenario") == "Scenario1"
    meta = app_backend.RUNS.get(run_id) or {}
    assert meta.get("done") is True
    assert meta.get("returncode") == 1
    assert "blocked even when flow disabled" in str(meta.get("error") or "")


def test_remote_flow_compose_preflight_blocks_unsafe_remote_compose(monkeypatch) -> None:
    monkeypatch.setattr(
        app_backend,
        "_flow_compose_candidate_records",
        lambda xml_path, scenario_label: [
            {
                "path": "/tmp/vulns/flag-node-generator/docker-compose.yml",
                "node_id": "7",
                "generator_id": "nfs_sensitive_file",
            }
        ],
    )

    class _DummyClient:
        def close(self) -> None:
            return None

    monkeypatch.setattr(app_backend, "_open_ssh_client", lambda core_cfg: _DummyClient())

    payload = {
        "checked": 1,
        "issues": [
            {
                "path": "/tmp/vulns/flag-node-generator/docker-compose.yml",
                "markers": ["double_dollar_pid_pattern"],
                "command_preview": "rpcbind -w -f & RPCBIND_PID=$$!",
            }
        ],
    }

    monkeypatch.setattr(
        app_backend,
        "_exec_ssh_command",
        lambda client, command, timeout=60.0: (0, json.dumps(payload), ""),
    )

    ok, err, meta = app_backend._flow_compose_shell_safety_preflight_remote(
        {"ssh_enabled": True, "ssh_host": "sampleuser", "ssh_username": "core", "ssh_password": "x"},
        "/tmp/scenario.xml",
        "Scenario1",
    )

    assert ok is False
    assert "blocked unsafe shell command pattern" in str(err or "")
    assert isinstance(meta, dict)
    issues = meta.get("issues") if isinstance(meta.get("issues"), list) else []
    assert issues and issues[0].get("node_id") == "7"


def test_remote_flow_compose_preflight_reports_autofixed_paths(monkeypatch) -> None:
    compose_path = "/tmp/vulns/flag_node_generators_runs/flow-scenario1/01_nfs_sensitive_file_docker-5/docker-compose.yml"
    monkeypatch.setattr(
        app_backend,
        "_flow_compose_candidate_records",
        lambda xml_path, scenario_label: [
            {
                "path": compose_path,
                "node_id": "7",
                "generator_id": "nfs_sensitive_file",
            }
        ],
    )

    class _DummyClient:
        def close(self) -> None:
            return None

    monkeypatch.setattr(app_backend, "_open_ssh_client", lambda core_cfg: _DummyClient())

    payload = {
        "checked": 1,
        "issues": [],
        "autofixed_paths": [compose_path],
    }

    monkeypatch.setattr(
        app_backend,
        "_exec_ssh_command",
        lambda client, command, timeout=60.0: (0, json.dumps(payload), ""),
    )

    ok, err, meta = app_backend._flow_compose_shell_safety_preflight_remote(
        {"ssh_enabled": True, "ssh_host": "sampleuser", "ssh_username": "core", "ssh_password": "x"},
        "/tmp/scenario.xml",
        "Scenario1",
    )

    assert ok is True
    assert err is None
    assert isinstance(meta, dict)
    assert compose_path in (meta.get("autofixed_remote_paths") or [])
