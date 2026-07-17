import os
import tempfile

from scenarioforge.planning.orchestrator import compute_full_plan
from scenarioforge.planning.ai_topology_intent import compile_ai_topology_intent
from webapp import app_backend


def _xml() -> str:
    return """<Scenarios><Scenario name='Topology Node Generators'><ScenarioEditor>
      <section name='Node Information' density_count='2'><item selected='Docker' v_metric='Count' v_count='2'/></section>
      <section name='Routing' density='0'/><section name='Services' density='0'/><section name='Traffic' density='0'/>
      <section name='Vulnerabilities' density='0'><item selected='Specific' v_name='bash/CVE-2014-6271' v_metric='Count' v_count='1'/></section>
      <section name='Flag Node Generators' density='0'><item selected='Specific' g_id='git_deploy_key_repo' g_name='Git deploy key' v_metric='Count' v_count='1'/></section>
      <section name='Segmentation' density='0'/>
    </ScenarioEditor></Scenario></Scenarios>"""


def test_topology_selected_node_generators_are_additive_and_bound_to_hosts():
    with tempfile.NamedTemporaryFile('w', suffix='.xml', delete=False) as handle:
        handle.write(_xml())
        path = handle.name
    try:
        plan = compute_full_plan(path, scenario='Topology Node Generators', seed=7)
        # Base Docker count 2 + one vulnerability + one generator node.
        assert plan['role_counts']['Docker'] == 4
        assert plan['flag_node_generator_plan'] == {'git_deploy_key_repo': 1}

        preview = app_backend._build_full_preview_from_plan(plan, 7)
        selected = preview['flag_node_generators_by_node']
        assert list(selected.values()) == ['git_deploy_key_repo']
        selected_id = next(iter(selected))
        selected_host = next(host for host in preview['hosts'] if str(host['node_id']) == selected_id)
        assert selected_host['vulnerabilities'] == []
        assert selected_host['metadata']['flag_node_generator_id'] == 'git_deploy_key_repo'

        nodes, _links, _adj = app_backend._build_topology_graph_from_preview_plan(preview)
        selected_node = next(node for node in nodes if node['id'] == selected_id)
        assert selected_node['flag_node_generator_id'] == 'git_deploy_key_repo'
        assert selected_node['_topology_flag_node_generators_configured'] is True
        assert app_backend._flow_compose_docker_stats(nodes)['flag_node_generator_eligible_total'] == 1
    finally:
        os.unlink(path)


def test_topology_node_generator_selection_round_trips_through_scenario_xml():
    scenario = {
        'name': 'XML round trip',
        'base': {'filepath': ''},
        'hitl': {'enabled': False, 'interfaces': []},
        'sections': {
            'Node Information': {'density': 0, 'items': [{'selected': 'Docker', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0}]},
            'Routing': {'density': 0, 'items': []},
            'Services': {'density': 0, 'items': []},
            'Traffic': {'density': 0, 'items': []},
            'Vulnerabilities': {'density': 0, 'flag_type': 'text', 'items': []},
            'Flag Node Generators': {'density': 0, 'items': [
                {'selected': 'Specific', 'g_id': 'git_deploy_key_repo', 'g_name': 'Git deploy key', 'v_metric': 'Count', 'v_count': 2, 'factor': 1.0},
            ]},
            'Segmentation': {'density': 0, 'items': []},
        },
        'notes': '',
    }
    tree = app_backend._build_scenarios_xml({'scenarios': [scenario]})
    item = tree.getroot().find("./Scenario/ScenarioEditor/section[@name='Flag Node Generators']/item")
    assert item is not None
    assert item.attrib == {
        'selected': 'Specific', 'factor': '1.000', 'g_id': 'git_deploy_key_repo',
        'g_name': 'Git deploy key', 'v_metric': 'Count', 'v_count': '2',
    }

    editor = tree.getroot().find('./Scenario/ScenarioEditor')
    restored = app_backend._parse_scenario_editor(editor)
    assert restored['sections']['Flag Node Generators']['items'] == [
        {'selected': 'Specific', 'factor': 1.0, 'g_id': 'git_deploy_key_repo',
         'g_name': 'Git deploy key', 'v_metric': 'Count', 'v_count': 2},
    ]


def test_ai_topology_scaffold_seeds_requested_flag_node_generators():
    compiled = compile_ai_topology_intent('Build a network with two flag-node-generators.')
    assert 'Flag Node Generators' in compiled.locked_sections
    assert compiled.section_payloads['Flag Node Generators'] == {
        'density': 0.0,
        'items': [{'selected': 'Random', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2}],
    }
