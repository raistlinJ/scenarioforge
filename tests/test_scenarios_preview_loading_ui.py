from pathlib import Path


SCENARIOS_PREVIEW_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "scenarios_preview.html"


def test_preview_loading_modal_includes_percentage_progress_ui() -> None:
    text = SCENARIOS_PREVIEW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'id="scenariosPreviewLoadingPercent"',
        'id="scenariosPreviewLoadingBar"',
        'function setPreviewLoadingProgress(percent, detail) {',
        'function startPreviewLoadingProgress(initialPercent, detail) {',
        "if (!previewExplicitReadyReceived) {",
        "setPreviewLoadingProgress(94, 'Rendering preview graph…');",
        "completePreviewLoading('postMessage', 'Preview ready.')",
        "const cachedState = (typeof window.CORETG_READ_LATEST_STATE_CACHE === 'function')",
        "setPreviewLoadingProgress(18, 'Using cached saved scenario state…');",
        "latestStateRefreshPromise = window.coretgRefreshScenarioStateFromXml(scenario, { updateHidden: true, xml_path: xmlPath })",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]

    assert not missing, 'Missing preview loading percentage UI wiring in scenarios_preview.html: ' + '; '.join(missing)


def test_preview_page_reuses_saved_xml_warning_and_execute_guard() -> None:
    text = SCENARIOS_PREVIEW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "window.coretgSyncSavedXmlWarningBadge({",
        "persist: false,",
        "allowStored: true,",
        "await window.coretgConfirmSavedXmlGroundTruth('Execute', {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]

    assert not missing, 'Missing preview saved-XML warning/guard wiring in scenarios_preview.html: ' + '; '.join(missing)