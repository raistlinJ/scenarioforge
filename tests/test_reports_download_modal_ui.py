from pathlib import Path


REPORTS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "reports.html"
FLOW_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "flow.html"


def test_reports_download_actions_use_blocking_generation_modal() -> None:
    text = REPORTS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'id="reportGenerationModal"',
        'data-bs-backdrop="static"',
        'data-bs-keyboard="false"',
        "const reportGenerationState = {",
        "window.addEventListener('beforeunload', reportGenerationBeforeUnload);",
        "async function showReportGenerationModal(kindLabel){",
        "await waitForReportUiPaint();",
        "function setReportDownloadLinksBusy(busy){",
        "async function startReportArtifactDownload(blob, filename, kindLabel)",
        "Generated artifact was empty.",
        "The server returned an invalid attack graph PDF.",
        "function showReportGenerationError(message){",
        "await showReportGenerationModal(reportDownloadLabel(link.dataset.kind));",
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


def test_reports_and_flow_download_dropdowns_keep_shared_artifacts_in_sync() -> None:
    reports_text = REPORTS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    flow_text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    shared_artifacts = [
        ('flowDownloadAfb', 'afb', 'Attack Flow (afb)'),
        ('flowDownloadAttackGraphDot', 'attack-graph-dot', 'Attack Graph (dot)'),
        ('flowDownloadAttackGraphJson', 'attack-graph-json', 'Attack Graph (json)'),
        ('flowDownloadAttackGraphPdf', 'attack-graph-pdf', 'Attack Graph (pdf)'),
        ('flowDownloadParticipantGuide', 'participant-guide', 'Participant Steps Guide (html)'),
        ('flowDownloadFacilitatorGuide', 'facilitator-guide', 'Facilitator Guide (html)'),
        ('flowDownloadSolutionsScript', 'solutions-script', 'Solutions Script (sh)'),
    ]

    flow_positions = []
    report_positions = []
    for element_id, kind, label in shared_artifacts:
        flow_markup = f'id="{element_id}">{label}</a>'
        report_markup = f'data-kind="{kind}"'
        assert flow_markup in flow_text
        assert reports_text.count(report_markup) >= 2, f"Reports static and dynamic menus must include {kind}"
        assert reports_text.count(f'>{label}</a>') >= 2
        flow_positions.append(flow_text.index(flow_markup))
        report_positions.append(reports_text.index(report_markup))

    assert flow_positions == sorted(flow_positions)
    assert report_positions == sorted(report_positions)
