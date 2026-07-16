from pathlib import Path


def test_scenarios_tabs_keep_selected_scenario_without_topology_editor_state() -> None:
    template = Path("webapp/templates/partials/scenarios_tabs.html").read_text(encoding="utf-8")

    assert "function resolveScenarioNameForTabNavigation()" in template
    assert "const saved = getLastSelectedScenario();" in template
    assert "const scen = resolveScenarioNameForTabNavigation();" in template
    assert "syncCurrentScenarioUrl(scen, xmlPath);" in template
    assert "const hasScenarios = !!(window.state" not in template
