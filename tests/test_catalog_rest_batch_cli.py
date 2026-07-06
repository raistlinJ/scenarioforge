from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from scenarioforge.validation import catalog_rest_batch_cli as cli


class FakeResponse:
    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = {"content-type": "application/json"}

    def json(self) -> dict:
        return self._payload


class FakeSession:
    fail_names: set[str] = set()

    def __init__(self) -> None:
        self.start_payloads: list[tuple[str, dict]] = []

    def post(self, url: str, **kwargs):
        path = urlparse(url).path
        if path == "/login":
            return FakeResponse(302, {"ok": True})
        if path == "/api/core/credentials/get":
            return FakeResponse(
                200,
                {
                    "ok": True,
                    "credentials": {
                        "ssh_host": "12.0.0.100",
                        "ssh_username": "sampleuser",
                        "ssh_password": "samplepass",
                        "host": "12.0.0.100",
                        "port": 50051,
                    },
                },
            )
        if path == "/vuln_catalog_items/batch/start":
            payload = dict(kwargs.get("json") or {})
            self.start_payloads.append(("vulns", payload))
            return FakeResponse(200, {"ok": True, "run_id": "vuln-run", "selected_count": 2})
        if path == "/flag_catalog_items/batch/start":
            payload = dict(kwargs.get("json") or {})
            name = "flag-node-generators" if payload.get("kind") == "flag-node-generator" else "flag-generators"
            self.start_payloads.append((name, payload))
            run_id = "node-run" if name == "flag-node-generators" else "flag-run"
            return FakeResponse(200, {"ok": True, "run_id": run_id, "selected_count": 1})
        raise AssertionError(f"unexpected POST {path}")

    def get(self, url: str, **kwargs):
        path = urlparse(url).path
        params = kwargs.get("params") or {}
        run_id = str(params.get("run_id") or "")
        name_by_run_id = {
            "vuln-run": "vulns",
            "flag-run": "flag-generators",
            "node-run": "flag-node-generators",
        }
        name = name_by_run_id.get(run_id, "unknown")
        failed = 1 if name in self.fail_names else 0
        passed = 0 if failed else 1
        progress = {
            "total": 1,
            "completed": 1,
            "passed": passed,
            "failed": failed,
            "incomplete": 0,
            "skipped": 0,
            "pending": 0,
        }
        if path.endswith("/batch/status"):
            return FakeResponse(200, {"ok": True, "done": True, "status": "completed", "progress": progress})
        if path.endswith("/batch/export.json"):
            return FakeResponse(200, {"ok": True, "run_id": run_id, "progress": progress})
        raise AssertionError(f"unexpected GET {path}")


def _install_fake_session(monkeypatch):
    sessions: list[FakeSession] = []

    def _factory():
        session = FakeSession()
        sessions.append(session)
        return session

    monkeypatch.setattr(cli.requests, "Session", _factory)
    return sessions


def test_catalog_rest_batch_cli_runs_vuln_batch_and_writes_export(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CORETG_WEBUI_MODE", "vm")
    sessions = _install_fake_session(monkeypatch)
    core_json = {"ssh_host": "12.0.0.100", "ssh_username": "sampleuser", "ssh_password": "samplepass"}

    rc = cli.main(
        [
            "--target",
            "vulns",
            "--repo-root",
            str(tmp_path),
            "--out-dir",
            "batch-out",
            "--core-json",
            json.dumps(core_json),
        ]
    )

    assert rc == 0
    assert sessions[0].start_payloads == [
        (
            "vulns",
            {
                "scope": "unvalidated",
                "query": "",
                "include_disabled": False,
                "core": core_json,
            },
        )
    ]
    assert (tmp_path / "batch-out" / "vulns-vuln-run.json").is_file()


def test_catalog_rest_batch_cli_all_runs_vulns_and_both_flag_generator_kinds(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CORETG_WEBUI_MODE", "vm")
    sessions = _install_fake_session(monkeypatch)

    rc = cli.main(
        [
            "--target",
            "all",
            "--scope",
            "all_enabled",
            "--limit",
            "5",
            "--repo-root",
            str(tmp_path),
            "--out-dir",
            str(tmp_path / "reports"),
            "--core-json",
            '{"ssh_host":"h","ssh_username":"u","ssh_password":"p"}',
        ]
    )

    assert rc == 0
    assert [name for name, _payload in sessions[0].start_payloads] == [
        "vulns",
        "flag-generators",
        "flag-node-generators",
    ]
    assert sessions[0].start_payloads[1][1]["kind"] == "flag-generator"
    assert sessions[0].start_payloads[2][1]["kind"] == "flag-node-generator"
    assert all(payload["scope"] == "all_enabled" for _name, payload in sessions[0].start_payloads)
    assert all(payload["limit"] == 5 for _name, payload in sessions[0].start_payloads)


def test_catalog_rest_batch_cli_accepts_ui_scope_alias_all(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CORETG_WEBUI_MODE", "vm")
    sessions = _install_fake_session(monkeypatch)

    rc = cli.main(
        [
            "--target",
            "vulns",
            "--scope",
            "all",
            "--repo-root",
            str(tmp_path),
            "--out-dir",
            "",
            "--core-json",
            '{"ssh_host":"h","ssh_username":"u","ssh_password":"p"}',
        ]
    )

    assert rc == 0
    assert sessions[0].start_payloads[0][1]["scope"] == "all_enabled"


def test_catalog_rest_batch_cli_accepts_ui_scope_alias_untested(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CORETG_WEBUI_MODE", "vm")
    sessions = _install_fake_session(monkeypatch)

    rc = cli.main(
        [
            "--target",
            "vulns",
            "--scope",
            "untested",
            "--repo-root",
            str(tmp_path),
            "--out-dir",
            "",
            "--core-json",
            '{"ssh_host":"h","ssh_username":"u","ssh_password":"p"}',
        ]
    )

    assert rc == 0
    assert sessions[0].start_payloads[0][1]["scope"] == "unvalidated"


def test_catalog_rest_batch_cli_returns_nonzero_when_batch_reports_failure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CORETG_WEBUI_MODE", "vm")
    sessions = _install_fake_session(monkeypatch)
    FakeSession.fail_names = {"flag-generators"}
    try:
        rc = cli.main(
            [
                "--target",
                "flag-generators",
                "--repo-root",
                str(tmp_path),
                "--out-dir",
                "",
                "--core-json",
                '{"ssh_host":"h","ssh_username":"u","ssh_password":"p"}',
            ]
        )
    finally:
        FakeSession.fail_names = set()

    assert rc == 20
    assert sessions[0].start_payloads[0][0] == "flag-generators"


def test_catalog_rest_batch_cli_can_load_core_secret_hint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CORETG_WEBUI_MODE", "vm")
    sessions = _install_fake_session(monkeypatch)
    hint_path = tmp_path / "outputs" / "flag_generators_test_core_hint.json"
    hint_path.parent.mkdir(parents=True)
    hint_path.write_text(json.dumps({"core_secret_id": "core-secret-1"}), encoding="utf-8")

    rc = cli.main(
        [
            "--target",
            "vulns",
            "--repo-root",
            str(tmp_path),
            "--out-dir",
            "",
        ]
    )

    assert rc == 0
    payload = sessions[0].start_payloads[0][1]
    assert payload["core"]["ssh_host"] == "12.0.0.100"


def _clear_core_env(monkeypatch) -> None:
    for name in (
        "CORE_HOST",
        "CORE_PORT",
        "CORE_SSH_HOST",
        "CORE_SSH_PORT",
        "CORE_SSH_USERNAME",
        "CORE_SSH_PASSWORD",
        "CORETG_WEBUI_MODE",
        "CORETG_RUNTIME_MODE",
        "CORETG_BATCH_CORE_HOST",
        "CORETG_BATCH_CORE_PORT",
        "CORETG_BATCH_CORE_SSH_HOST",
        "CORETG_BATCH_CORE_SSH_PORT",
        "CORETG_BATCH_CORE_SSH_USERNAME",
        "CORETG_BATCH_CORE_SSH_PASSWORD",
        "CORETG_BATCH_CORE_VENV_BIN",
    ):
        monkeypatch.delenv(name, raising=False)


def test_catalog_rest_batch_cli_native_mode_requires_explicit_core_config(tmp_path: Path, monkeypatch) -> None:
    _clear_core_env(monkeypatch)
    sessions = _install_fake_session(monkeypatch)

    rc = cli.main(
        [
            "--target",
            "vulns",
            "--repo-root",
            str(tmp_path),
            "--out-dir",
            "",
        ]
    )

    assert rc == 11
    assert sessions[0].start_payloads == []


def test_catalog_rest_batch_cli_native_mode_accepts_core_flags(tmp_path: Path, monkeypatch) -> None:
    _clear_core_env(monkeypatch)
    sessions = _install_fake_session(monkeypatch)

    rc = cli.main(
        [
            "--target",
            "vulns",
            "--repo-root",
            str(tmp_path),
            "--out-dir",
            "",
            "--core-host",
            "10.0.0.50",
            "--core-port",
            "50051",
            "--core-ssh-host",
            "10.0.0.50",
            "--core-ssh-username",
            "corevm",
            "--core-ssh-password",
            "change-me",
            "--core-venv-bin",
            "/opt/core/venv/bin",
        ]
    )

    assert rc == 0
    payload = sessions[0].start_payloads[0][1]
    assert payload["core"] == {
        "ssh_host": "10.0.0.50",
        "ssh_port": 22,
        "ssh_username": "corevm",
        "ssh_password": "change-me",
        "host": "10.0.0.50",
        "port": 50051,
        "venv_bin": "/opt/core/venv/bin",
    }


def test_catalog_rest_batch_cli_core_flags_take_precedence_over_scenarioforge_env(tmp_path: Path, monkeypatch) -> None:
    _clear_core_env(monkeypatch)
    (tmp_path / ".scenarioforge.env").write_text(
        "\n".join(
            [
                "CORETG_WEBUI_MODE=vm",
                "CORE_SSH_HOST=10.0.0.50",
                "CORE_SSH_USERNAME=env-user",
                "CORE_SSH_PASSWORD=env-pass",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    sessions = _install_fake_session(monkeypatch)

    rc = cli.main(
        [
            "--target",
            "vulns",
            "--repo-root",
            str(tmp_path),
            "--out-dir",
            "",
            "--core-ssh-host",
            "10.0.0.51",
            "--core-ssh-username",
            "flag-user",
            "--core-ssh-password",
            "flag-pass",
        ]
    )

    assert rc == 0
    payload = sessions[0].start_payloads[0][1]
    assert payload["core"]["ssh_host"] == "10.0.0.51"
    assert payload["core"]["ssh_username"] == "flag-user"


def test_catalog_rest_batch_cli_reads_core_config_from_scenarioforge_env(tmp_path: Path, monkeypatch) -> None:
    _clear_core_env(monkeypatch)
    (tmp_path / ".scenarioforge.env").write_text(
        "\n".join(
            [
                "CORETG_WEBUI_MODE=vm",
                "CORE_HOST=10.0.0.50",
                "CORE_PORT=50051",
                "CORE_SSH_HOST=10.0.0.50",
                "CORE_SSH_PORT=22",
                "CORE_SSH_USERNAME=corevm",
                "CORE_SSH_PASSWORD=change-me",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    sessions = _install_fake_session(monkeypatch)

    rc = cli.main(
        [
            "--target",
            "vulns",
            "--repo-root",
            str(tmp_path),
            "--out-dir",
            "",
        ]
    )

    assert rc == 0
    payload = sessions[0].start_payloads[0][1]
    assert payload["core"] == {
        "ssh_host": "10.0.0.50",
        "ssh_port": 22,
        "ssh_username": "corevm",
        "ssh_password": "change-me",
        "host": "10.0.0.50",
        "port": 50051,
    }


def test_catalog_rest_batch_cli_errors_when_no_core_config_available_in_vm_mode(tmp_path: Path, monkeypatch) -> None:
    _clear_core_env(monkeypatch)
    monkeypatch.setenv("CORETG_WEBUI_MODE", "vm")
    sessions = _install_fake_session(monkeypatch)

    rc = cli.main(
        [
            "--target",
            "vulns",
            "--repo-root",
            str(tmp_path),
            "--out-dir",
            "",
        ]
    )

    assert rc == 11
    assert sessions[0].start_payloads == []
