from pathlib import Path


TABS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "scenarios_tabs.html"
INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"
LAYOUT_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "layout.html"


def test_state_source_badge_present_and_wired() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected = [
        'id="coretgStateSourceBadge"',
        'id="coretgSavedXmlWarningBadge"',
        'function updateStateSourceBadge(opts){',
        'function updateSavedXmlWarningBadge(opts){',
        'function syncSavedXmlWarningBadge(opts){',
        'function getPreviewPlanPathForScenario(scenarioName){',
        'function setPreviewPlanPathForScenario(scenarioName, previewPlanPath){',
        "preview_plan_path: path,",
        "State source: XML",
        "Unsaved edits: Preview/Execute use last saved XML",
        "updateStateSourceBadge({ scenario, xmlPath });",
        "window.coretgWriteSavedXmlGroundTruthWarning({",
        "window.coretgGetSavedXmlGroundTruthWarningState({ scenario, xmlPath, allowStored: true });",
        "const isScenarioTabRoute = (",
        "badge.classList.add('text-bg-danger');",
        "No XML path available (state cannot be confirmed from XML).",
        "window.coretgUpdateStateSourceBadge = updateStateSourceBadge;",
        "window.coretgUpdateSavedXmlWarningBadge = updateSavedXmlWarningBadge;",
        "window.coretgSyncSavedXmlWarningBadge = syncSavedXmlWarningBadge;",
    ]

    missing = [s for s in expected if s not in text]
    assert not missing, "Missing state-source badge wiring snippets: " + "; ".join(missing)


def test_index_wires_unsaved_saved_xml_warning() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected = [
        "window.coretgHasUnsavedChanges = function ()",
        "function updateSavedXmlGroundTruthWarning() {",
        "window.coretgSyncSavedXmlWarningBadge({",
        "Unsaved edits are present. Preview and Execute use the last saved XML until you save again.",
        "await window.coretgConfirmSavedXmlGroundTruth('Preview', {",
        "try { updateSavedXmlGroundTruthWarning(); } catch (e) { }",
    ]

    missing = [s for s in expected if s not in text]
    assert not missing, "Missing unsaved saved-XML warning wiring: " + "; ".join(missing)

    # The 'Execute' variant of the guard moved with execution itself: the
    # topology page no longer executes, so only its Preview guard lives here.
    assert "coretgConfirmSavedXmlGroundTruth('Execute'" not in text


def test_preview_page_execute_guards_against_unsaved_xml() -> None:
    """The Execute-time saved-XML guard follows execution to the preview page."""
    scripts = (
        Path(__file__).resolve().parent.parent
        / "webapp" / "templates" / "full_preview_scripts.html"
    ).read_text(encoding="utf-8", errors="ignore")

    assert "coretgConfirmSavedXmlGroundTruth?.('Execute', {" in scripts


def test_layout_exposes_saved_xml_ground_truth_helpers() -> None:
    text = LAYOUT_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected = [
        "const CORETG_SAVED_XML_WARNING_PREFIX = 'coretg_saved_xml_ground_truth_warning_v1::';",
        "window.coretgReadSavedXmlGroundTruthWarning = function (scenario)",
        "window.coretgWriteSavedXmlGroundTruthWarning = function (opts = {})",
        "window.coretgGetSavedXmlGroundTruthWarningState = function (opts = {})",
        "window.coretgConfirmSavedXmlGroundTruth = async function (actionLabel, opts = {})",
        "Continue with saved XML",
        "Save first if you want the current edits included.",
    ]

    missing = [s for s in expected if s not in text]
    assert not missing, "Missing saved-XML ground-truth layout helpers: " + "; ".join(missing)
