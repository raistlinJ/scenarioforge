from pathlib import Path


SCENARIOS_PREVIEW_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "scenarios_preview.html"


def test_preview_loading_modal_includes_percentage_progress_ui() -> None:
    text = SCENARIOS_PREVIEW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'id="scenariosPreviewLoadingPercent"',
        'id="scenariosPreviewLoadingBar"',
        'function setPreviewLoadingProgress(percent, detail) {',
        'function startPreviewLoadingProgress(initialPercent, detail) {',
        "completePreviewLoading('iframe-load', 'Preview ready.')",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]

    assert not missing, 'Missing preview loading percentage UI wiring in scenarios_preview.html: ' + '; '.join(missing)