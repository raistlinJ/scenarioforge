from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from scenarioforge.validation import catalog_batch_cli as cli


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


def test_catalog_batch_cli_runs_vuln_batch_and_writes_export(tmp_path: Path, monkeypatch) -> None:
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


def test_catalog_batch_cli_all_runs_vulns_and_both_flag_generator_kinds(tmp_path: Path, monkeypatch) -> None:
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


def test_catalog_batch_cli_accepts_ui_scope_alias_all(tmp_path: Path, monkeypatch) -> None:
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


def test_catalog_batch_cli_accepts_ui_scope_alias_untested(tmp_path: Path, monkeypatch) -> None:
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


def test_catalog_batch_cli_returns_nonzero_when_batch_reports_failure(tmp_path: Path, monkeypatch) -> None:
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


def test_catalog_batch_cli_can_load_core_secret_hint(tmp_path: Path, monkeypatch) -> None:
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
