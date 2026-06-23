from scenarioforge.builders.topology import _canonicalize_routing_items
from scenarioforge.parsers.routing import parse_routing_info
from scenarioforge.planning.orchestrator import compute_full_plan
from scenarioforge.types import RoutingInfo


def test_routing_parser_uses_section_node_count_min_when_items_absent(tmp_path):
    xml_path = tmp_path / "routing_bounds.xml"
    xml_path.write_text(
        """
<Scenarios>
  <Scenario name="S1">
    <ScenarioEditor>
      <section name="Node Information" density_count="10" base_nodes="10" total_nodes="10">
        <item selected="Workstation" factor="1.0" />
      </section>
      <section name="Routing" density="0.0" node_count_min_enabled="true" node_count_min="3" />
    </ScenarioEditor>
  </Scenario>
</Scenarios>
""".strip(),
        encoding="utf-8",
    )

    density, items = parse_routing_info(str(xml_path), "S1")

    assert density == 0.0
    assert len(items) == 1
    assert items[0].abs_count == 3
    assert items[0].protocol == ""

    plan = compute_full_plan(str(xml_path), scenario="S1", seed=123, include_breakdowns=True)
    assert int(plan.get("routers_planned") or 0) == 3
    assert plan["breakdowns"]["router"]["simple_plan"] == {}
    assert "Routing" not in plan["breakdowns"]["router"]["simple_plan"]


def test_topology_boundary_repairs_legacy_routing_service():
    routing_items = [
        RoutingInfo(
            protocol="Routing",
            factor=0.0,
            abs_count=1,
            r2r_mode="",
            r2r_edges=0,
            r2s_mode="",
            r2s_edges=0,
            r2s_hosts_min=0,
            r2s_hosts_max=0,
        )
    ]

    repaired = _canonicalize_routing_items(routing_items)

    assert repaired[0].protocol == ""


def test_routing_parser_treats_legacy_selected_routing_as_unset(tmp_path):
    xml_path = tmp_path / "legacy-routing.xml"
    xml_path.write_text(
        """
<Scenarios>
  <Scenario name="S1">
    <ScenarioEditor>
      <section name="Routing">
        <item selected="Routing" v_metric="Count" v_count="2" />
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>
""".strip(),
        encoding="utf-8",
    )

    density, items = parse_routing_info(str(xml_path), "S1")

    assert density == 0.0
    assert len(items) == 1
    assert items[0].abs_count == 2
    assert items[0].protocol == ""
