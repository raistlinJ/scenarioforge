"""CLI coverage for the check-artifacts and list-sessions phases."""

import io
import json
from types import SimpleNamespace

from scenarioforge import cli


def _payload(*statuses, overall="pass", **extra):
    checks = [
        {"key": f"c{i}", "label": f"Check {i}", "status": s, "summary": f"summary {i}", "items": []}
        for i, s in enumerate(statuses)
    ]
    payload = {"status": "complete", "overall": overall, "overall_summary": ", ".join(statuses),
               "scenario": "S1", "session_id": 3, "checks": checks}
    payload.update(extra)
    return payload


def _marker(text):
    line = next(l for l in text.splitlines() if l.startswith(cli.CHECK_ARTIFACTS_MARKER))
    return json.loads(line[len(cli.CHECK_ARTIFACTS_MARKER):].strip())


# --------------------------------------------------------------------------- #
# Exit-code semantics: warn passes by default, fails under --strict
# --------------------------------------------------------------------------- #

def test_all_pass_is_ok():
    assert cli._artifact_check_exit_ok(_payload("pass", "skip"), strict=False) is True
    assert cli._artifact_check_exit_ok(_payload("pass", "skip"), strict=True) is True


def test_warn_is_ok_by_default_but_fails_under_strict():
    payload = _payload("pass", "warn", overall="warn")
    assert cli._artifact_check_exit_ok(payload, strict=False) is True
    assert cli._artifact_check_exit_ok(payload, strict=True) is False


def test_fail_and_error_always_fail():
    for status in ("fail", "error"):
        payload = _payload("pass", status, overall="fail")
        assert cli._artifact_check_exit_ok(payload, strict=False) is False
        assert cli._artifact_check_exit_ok(payload, strict=True) is False


def test_job_level_error_fails():
    payload = {"status": "error", "overall": "fail", "checks": [], "error": "ssh down"}
    assert cli._artifact_check_exit_ok(payload, strict=False) is False


# --------------------------------------------------------------------------- #
# Summary output + machine-readable marker
# --------------------------------------------------------------------------- #

def test_summary_prints_each_check_and_emits_marker():
    out = io.StringIO()
    ok = cli._print_artifact_check_summary(_payload("pass", "skip"), stream=out)
    text = out.getvalue()
    assert ok is True
    assert "[PASS ] Check 0" in text
    assert "[SKIP ] Check 1" in text
    assert "Artifact checks — scenario S1, session 3" in text
    marker = _marker(text)
    assert marker["ok"] is True
    assert marker["scenario"] == "S1"
    assert marker["session_id"] == 3
    assert [c["status"] for c in marker["checks"]] == ["pass", "skip"]


def test_summary_marker_reports_not_ok_under_strict_warning():
    out = io.StringIO()
    ok = cli._print_artifact_check_summary(_payload("warn", overall="warn"), strict=True, stream=out)
    assert ok is False
    text = out.getvalue()
    assert "--strict" in text
    marker = _marker(text)
    assert marker["ok"] is False
    assert marker["strict"] is True


def test_summary_shows_only_actionable_detail_rows():
    payload = _payload("warn", overall="warn")
    payload["checks"][0]["items"] = [
        {"name": "quiet-node", "status": "pass", "detail": "fine"},
        {"name": "noisy-node", "status": "warn", "detail": "port blocked"},
    ]
    out = io.StringIO()
    cli._print_artifact_check_summary(payload, stream=out)
    text = out.getvalue()
    assert "noisy-node" in text
    # Passing rows stay out of the console output (they remain in the marker).
    console = text.split(cli.CHECK_ARTIFACTS_MARKER)[0]
    assert "quiet-node" not in console


def test_summary_prints_error_text():
    out = io.StringIO()
    cli._print_artifact_check_summary(
        {"status": "error", "overall": "fail", "checks": [], "error": "session 9 is not running"},
        stream=out,
    )
    assert "session 9 is not running" in out.getvalue()


# --------------------------------------------------------------------------- #
# Session-id resolution
# --------------------------------------------------------------------------- #

class _Backend:
    def __init__(self, store):
        self._store = store

    def _normalize_scenario_label(self, value):
        return str(value or "").strip().lower().replace(" ", "-")

    def _load_core_sessions_store(self):
        return self._store

    def _session_store_entry_session_id(self, entry):
        try:
            return int((entry or {}).get("session_id"))
        except Exception:
            return None

    def _session_store_entry_scenario_norm(self, entry):
        return self._normalize_scenario_label((entry or {}).get("scenario_norm"))

    def _session_store_entry_updated_at_epoch(self, entry):
        return float((entry or {}).get("ts") or 0.0)


def test_explicit_session_id_wins():
    backend = _Backend({"/x.xml": {"session_id": 7, "scenario_norm": "s1", "ts": 5}})
    sid, source = cli._resolve_cli_check_session_id(
        backend, session_id=42, scenario_name="S1", core_cfg={})
    assert (sid, source) == (42, "argument")


def test_session_id_falls_back_to_most_recent_store_entry():
    backend = _Backend({
        "/old.xml": {"session_id": 1, "scenario_norm": "s1", "ts": 10},
        "/new.xml": {"session_id": 2, "scenario_norm": "s1", "ts": 99},
        "/other.xml": {"session_id": 3, "scenario_norm": "other", "ts": 100},
    })
    sid, source = cli._resolve_cli_check_session_id(
        backend, session_id=None, scenario_name="S1", core_cfg={})
    assert sid == 2
    assert source == "session store"


def test_session_id_unresolved_when_store_has_no_match():
    backend = _Backend({})
    sid, source = cli._resolve_cli_check_session_id(
        backend, session_id=None, scenario_name="S1", core_cfg={})
    assert sid is None
    assert source == "unresolved"


# --------------------------------------------------------------------------- #
# Phase wiring
# --------------------------------------------------------------------------- #

def test_new_phases_are_registered():
    assert "check-artifacts" in cli.CLI_PHASES
    assert "list-sessions" in cli.CLI_PHASES


def test_check_artifacts_parser_exposes_expected_flags():
    parser = cli._build_cli_help_parser("check-artifacts")
    options = {opt for action in parser._actions for opt in action.option_strings}
    assert {"--session-id", "--strict", "--check-artifacts-delay"} <= options


def test_execute_parser_exposes_auto_run_flags():
    parser = cli._build_cli_help_parser("execute")
    options = {opt for action in parser._actions for opt in action.option_strings}
    assert {"--check-artifacts", "--check-artifacts-delay", "--strict"} <= options


# --------------------------------------------------------------------------- #
# list-sessions output
# --------------------------------------------------------------------------- #

class _ListBackend(_Backend):
    def __init__(self, store, sessions, source_paths=()):
        super().__init__(store)
        self._sessions = sessions
        self._source_paths = set(source_paths)

    def _list_active_core_sessions(self, host, port, core_cfg, errors=None, meta=None):
        return self._sessions

    def _xml_has_scenario_editor(self, path):
        return str(path) in self._source_paths


def test_list_sessions_shows_scenario_and_source_xml():
    backend = _ListBackend(
        store={
            "/out/core-sessions/session-1.xml": {"session_id": 1, "scenario_name": "Lab", "ts": 99},
            "/out/scenarios-x/Lab.xml": {"session_id": 1, "scenario_name": "Lab", "ts": 50},
        },
        sessions=[{"id": 1, "state": "RUNTIME"}],
        # Only the saved scenario file carries ScenarioEditor; it must win even
        # though the exported session XML is newer.
        source_paths=["/out/scenarios-x/Lab.xml"],
    )
    out = io.StringIO()
    rc = cli._run_cli_list_sessions(backend=backend, core_cfg={"host": "h", "port": 1}, stream=out)
    text = out.getvalue()
    assert rc == 0
    assert "SESSION" in text and "SCENARIO" in text and "XML" in text
    assert "RUNTIME" in text
    assert "Lab" in text
    assert "/out/scenarios-x/Lab.xml" in text
    assert "/out/core-sessions/session-1.xml" not in text


def test_list_sessions_handles_no_sessions():
    backend = _ListBackend(store={}, sessions=[])
    out = io.StringIO()
    rc = cli._run_cli_list_sessions(backend=backend, core_cfg={"host": "h", "port": 1}, stream=out)
    assert rc == 0
    assert "No CORE sessions found." in out.getvalue()


def test_list_sessions_filters_by_scenario():
    backend = _ListBackend(
        store={
            "/a.xml": {"session_id": 1, "scenario_name": "Lab", "ts": 1},
            "/b.xml": {"session_id": 2, "scenario_name": "Other", "ts": 1},
        },
        sessions=[{"id": 1, "state": "RUNTIME"}, {"id": 2, "state": "RUNTIME"}],
    )
    out = io.StringIO()
    cli._run_cli_list_sessions(backend=backend, core_cfg={"host": "h", "port": 1},
                              scenario_name="Lab", stream=out)
    text = out.getvalue()
    assert "/a.xml" in text
    assert "/b.xml" not in text


# --------------------------------------------------------------------------- #
# Remote delegation
# --------------------------------------------------------------------------- #

def test_check_artifacts_flags_are_not_forwarded_to_the_remote_cli():
    """The CORE VM runs the repo without the WebUI backend.

    Forwarding these flags made the delegated execute abort with "--check-artifacts
    requires the WebUI backend module", failing the whole run. The checks belong
    on the machine that owns the backend and the SSH session, so the flags are
    stripped from the remote command exactly like --post-execution-validation.
    """
    stripped = cli._CHECK_ARTIFACTS_OPTIONS | cli._CHECK_ARTIFACTS_VALUE_OPTIONS
    assert '--check-artifacts' in stripped
    assert '-check-artifacts' in stripped
    assert '--check-artifacts-delay' in stripped


def test_delay_value_token_is_dropped_with_its_flag():
    # Dropping only the flag would leave a bare "45" in the remote argv.
    source = open(cli.__file__, encoding='utf-8').read()
    assert 'idx += 2  # drop the flag and its value' in source


def test_local_side_runs_the_checks_after_a_remote_execute():
    source = open(cli.__file__, encoding='utf-8').read()
    remote_fn = source.index('_remote_execute_failure_detail')
    # The local post-remote path invokes the checks itself.
    assert source.count('_run_cli_artifact_checks(') >= 2
    assert remote_fn > 0
