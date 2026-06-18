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
        "await window.coretgConfirmSavedXmlGroundTruth('Execute', {",
        "try { updateSavedXmlGroundTruthWarning(); } catch (e) { }",
    ]

    missing = [s for s in expected if s not in text]
    assert not missing, "Missing unsaved saved-XML warning wiring: " + "; ".join(missing)


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
