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


def test_flag_node_generator_picker_can_limit_specific_choices_to_cached_images() -> None:
    topology_template = Path("webapp/templates/index.html").read_text(encoding="utf-8")

    assert 'id="flagNodeGeneratorCachedOnly"' in topology_template
    assert "flagNodeGeneratorPickerCachedOnly" in topology_template
    assert "generator._cached !== true" in topology_template


def test_topology_migrates_existing_projects_to_show_flag_node_generator_card() -> None:
    topology_template = Path("webapp/templates/index.html").read_text(encoding="utf-8")

    assert "function ensureTopologySectionSchema(scenario)" in topology_template
    assert "scenario.sections['Flag Node Generators'] = { density: 0.5, items: [] };" in topology_template
    assert "state.scenarios.forEach((scenario) => ensureTopologySectionSchema(scenario));" in topology_template


def test_adding_flag_node_generator_starts_a_random_count_one_row() -> None:
    topology_template = Path("webapp/templates/index.html").read_text(encoding="utf-8")

    start = topology_template.index('document.querySelectorAll(\'[data-action="add-item"]\')')
    end = topology_template.index('document.querySelectorAll(\'[data-action="toggle-collapse"]\')', start)
    add_handler = topology_template[start:end]
    assert "let defaultSelected = 'Random';" in add_handler
    assert "if (sec === 'Flag Node Generators')" not in add_handler
    assert "sec === 'Vulnerabilities' || sec === 'Flag Node Generators'" in topology_template
    assert "item.v_metric = 'Count'; item.v_count = 1;" in topology_template


def test_flag_node_generator_catalog_refreshes_topology_options_after_loading() -> None:
    topology_template = Path("webapp/templates/index.html").read_text(encoding="utf-8")

    start = topology_template.index("async function setupFlagNodeGenerators()")
    end = topology_template.index("async function openFlagNodeGeneratorPicker", start)
    loader = topology_template[start:end]
    assert "try { renderMain(); } catch (e) { }" in loader


def test_topology_prompts_before_removing_unavailable_flag_node_generator_rows() -> None:
    topology_template = Path("webapp/templates/index.html").read_text(encoding="utf-8")

    assert "promptToRemoveUnavailableTopologyGenerators" in topology_template
    assert "no longer installed" in topology_template
    assert "Remove those topology rows and save the corrected XML?" in topology_template
    assert "await autoSaveXml();" in topology_template


def test_specific_vuln_and_flag_node_generator_rows_keep_choose_controls_compact() -> None:
    topology_template = Path("webapp/templates/index.html").read_text(encoding="utf-8")

    assert 'class="d-flex flex-nowrap gap-2 align-items-center" style="min-width:250px"' in topology_template
    assert '<span class="small text-muted">${isVuln ? esc(nm ? `${nm}${descShort ? \' — \' + descShort : \'\'}\' : \'No selection\') : esc(nodegenName || \'No selection\')}</span>' not in topology_template
