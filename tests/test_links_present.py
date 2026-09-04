"""The CLI fails cleanly when no CORE daemon is reachable.

This used to assert that a scenario report existed after running the CLI
against a closed port, on the stated premise that "a report should exist even
if session start failed". That premise is false: without a CORE session the
execute phase stops before any report is written.

It passed anyway, because it globbed `reports/` for *any* report and a
developer checkout accumulates them -- 131 in one working tree -- so it matched
a file from an unrelated earlier run and never inspected the run it had just
made. In CI, where `reports/` is empty and gitignored, it failed.

What is worth guarding is that the failure is orderly: a non-zero exit and no
traceback, rather than an exception escaping the topology builder.
"""

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_XML = REPO_ROOT / "examples" / "sample.xml"


@pytest.fixture(scope="module")
def cli_run():
    if not SAMPLE_XML.exists():
        pytest.skip("examples/sample.xml missing")

    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(REPO_ROOT))
    # This subprocess imports the runtime environment loader afresh, outside
    # pytest's per-test monkeypatch fixture. Pin it to local/native mode so a
    # developer's real .scenarioforge.env cannot redirect this closed-port
    # failure test to a provisioned CORE VM.
    env.update({
        "CORETG_WEBUI_MODE": "native",
        "CORETG_CLI_DISABLE_REMOTE_DELEGATION": "1",
        "CORE_HOST": "127.0.0.1",
        "CORE_PORT": "50051",
        "CORE_SSH_HOST": "",
        "CORE_SSH_USERNAME": "",
        "CORE_SSH_PASSWORD": "",
    })
    # A closed port: the run must reach the CORE connection attempt and stop
    # there, without a live daemon.
    cmd = [
        "python", "-m", "scenarioforge.cli",
        "--xml", str(SAMPLE_XML),
        "--host", "127.0.0.1",
        "--port", "50051",
    ]
    try:
        return subprocess.run(
            cmd, cwd=str(REPO_ROOT), env=env, check=False,
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        pytest.skip("python executable not available for subprocess execution")
    except subprocess.TimeoutExpired:
        pytest.fail("CLI did not return within 120s against an unreachable CORE host")


def test_cli_exits_non_zero_without_a_core_daemon(cli_run):
    assert cli_run.returncode != 0, (
        "the CLI reported success despite having no CORE session:\n"
        f"{(cli_run.stdout or '')[-2000:]}"
    )


def test_cli_does_not_crash_while_building_the_topology(cli_run):
    """An orderly refusal, not an exception escaping the builder."""
    combined = (cli_run.stdout or "") + (cli_run.stderr or "")
    assert "Traceback (most recent call last)" not in combined, (
        f"CLI raised instead of reporting a connection failure:\n{combined[-2000:]}"
    )


def test_no_report_is_claimed_when_no_session_ran(cli_run):
    """The inverse of the original assertion, and the true one."""
    combined = (cli_run.stdout or "") + (cli_run.stderr or "")
    assert "Scenario report written to" not in combined, (
        "a report was announced even though no CORE session was started"
    )
