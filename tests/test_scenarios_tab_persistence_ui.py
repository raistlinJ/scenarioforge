from pathlib import Path


def test_scenarios_tabs_keep_selected_scenario_without_topology_editor_state() -> None:
    template = Path("webapp/templates/partials/scenarios_tabs.html").read_text(encoding="utf-8")

    assert "function resolveScenarioNameForTabNavigation()" in template
    assert "const saved = getLastSelectedScenario();" in template
    assert "const scen = resolveScenarioNameForTabNavigation();" in template
    assert "syncCurrentScenarioUrl(scen, xmlPath);" in template
    assert "const hasScenarios = !!(window.state" not in template


def test_topology_continue_uses_the_current_selected_scenario() -> None:
    tabs_template = Path("webapp/templates/partials/scenarios_tabs.html").read_text(encoding="utf-8")
    topology_template = Path("webapp/templates/index.html").read_text(encoding="utf-8")

    assert "btn.dataset.coretgScenario = scen;" in tabs_template
    assert "action === 'continue' || action === 'continue-topology'" in tabs_template
    assert "window.coretgGetLastSelectedScenario?.()" in topology_template
    assert topology_template.index("window.coretgGetLastSelectedScenario?.()") < topology_template.index(
        "btn?.dataset?.coretgScenario"
    )
