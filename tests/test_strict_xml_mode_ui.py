from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"
FLOW_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "flow.html"
TABS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "scenarios_tabs.html"


def test_index_disables_local_editor_snapshot_mode() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    assert "const USE_LOCAL_EDITOR_STATE = false;" in text
    assert "const ALLOW_LOCAL_EDITOR_PERSISTENCE = false;" in text


def test_index_autosave_scheduler_has_no_unreachable_guard() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    block = text.split("function scheduleAutoSaveXml(snapshot, coreState, scenarios) {", 1)[1].split("function", 1)[0]
    assert "return;\n        if (!ALLOW_LOCAL_EDITOR_PERSISTENCE) return;" not in block
    assert "if (!ALLOW_LOCAL_EDITOR_PERSISTENCE) return;" in block


def test_flow_restore_has_no_local_fallback() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    forbidden = [
        "fromLocal = window.coretgGetSavedFlowStateForScenario(scenarioName);",
        "if (localUsable) return fromLocal;",
    ]
    present = [s for s in forbidden if s in text]
    assert not present, "Flow restore should not use local cache fallback: " + "; ".join(present)


def test_tabs_flow_state_helpers_use_window_state_not_localstorage() -> None:
    text = TABS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    assert "const scenarios = (window.state && Array.isArray(window.state.scenarios)) ? window.state.scenarios : [];" in text
    assert "localStorage.setItem(FLOW_STATE_STORAGE_KEY" not in text


def test_index_rehydrate_latest_xml_pins_the_saved_xml_path() -> None:
    """A scenario carrying a saved XML path rehydrates from that exact source.

    This test previously asserted the opposite -- that rehydration must never
    pin a specific `xml_path`. Under XML-as-ground-truth that policy was
    reversed on purpose: re-resolving by scenario name can pick a different
    project file, so a saved path is now honoured. The template documents the
    change inline ("rehydrate from that exact project source instead of
    re-resolving by scenario name").
    """
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    block = text.split("async function rehydrateScenarioFromLatestXml(idx, scenarioName) {", 1)[1].split("const existing = state?.scenarios?.[idx];", 1)[0]
    assert "query.set('xml_path', preferredXmlPath);" in block
    assert "forceXmlPath: true" in block
    # Only pin when the scenario actually has one; otherwise resolve by name.
    assert "if (preferredXmlPath) {" in block
