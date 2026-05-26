from pathlib import Path


FULL_PREVIEW_SCRIPTS_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "full_preview_scripts.html"


def test_full_preview_run_status_404_stops_polling_with_clear_message() -> None:
    text = FULL_PREVIEW_SCRIPTS_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if (r.status === 404) {",
        "Run status unavailable (404). The run ID is no longer active, likely due to a server restart.",
        "setExecuteProgressUI({ status: 'Run status unavailable', meta: 'Run ID not found', barText: 'Stopped', animate: false });",
        "if (r2.status === 404) {",
        "Retry run status unavailable (404). The run ID is no longer active, likely due to a server restart.",
        "setExecuteProgressUI({ status: 'Retry status unavailable', meta: 'Run ID not found', barText: 'Stopped', animate: false });",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing run-status 404 handling snippets in full preview scripts: " + "; ".join(missing)


def test_full_preview_run_status_normalizes_success_checks() -> None:
    text = FULL_PREVIEW_SCRIPTS_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function getExecuteRunReturnCode(runStatus) {",
        "function didExecuteRunSucceed(runStatus) {",
        "if (summary && summary.ok === true) {",
        "const runSucceeded = didExecuteRunSucceed(data);",
        "const retryRunSucceeded = didExecuteRunSucceed(data2);",
        "const runCode = getExecuteRunReturnCode(data);",
        "const retryRunCode = getExecuteRunReturnCode(data2);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing normalized run-status success snippets in full preview scripts: " + "; ".join(missing)
