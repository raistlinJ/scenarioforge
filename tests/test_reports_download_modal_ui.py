from pathlib import Path


REPORTS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "reports.html"


def test_reports_download_actions_use_blocking_generation_modal() -> None:
    text = REPORTS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'id="reportGenerationModal"',
        'data-bs-backdrop="static"',
        'data-bs-keyboard="false"',
        "const reportGenerationState = {",
        "window.addEventListener('beforeunload', reportGenerationBeforeUnload);",
        "function showReportGenerationModal(kindLabel){",
        "function showReportGenerationError(message){",
        "showReportGenerationModal(reportDownloadLabel(link.dataset.kind));",
        "hideReportGenerationModal();",
        "showReportGenerationError(String(err && err.message || err));",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "reports.html is missing blocking generation modal wiring: " + "; ".join(missing)


def test_reports_download_actions_do_not_mutate_dropdown_item_text_to_preparing() -> None:
    text = REPORTS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    forbidden_snippets = [
        "const originalText = link.textContent || 'Download';",
        "link.textContent = 'Preparing…';",
        "link.textContent = originalText;",
    ]

    present = [snippet for snippet in forbidden_snippets if snippet in text]
    assert not present, "reports.html still mutates dropdown item text during generation: " + "; ".join(present)