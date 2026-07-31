"""A FlagGenSlot must not be assigned a generator the planner invented.

The planning layer has no view of the installed generator catalog. Drawing a
'Random' slot entry through compute_vulnerability_plan resolves it against
DEFAULT_RANDOM_VULNS -- vulnerability names such as "SSHCreds" -- which are not
generators. A slot carrying one matches nothing in the candidate pool, which
empties that chain position and fails the entire flow sequence with
"No distinct compatible generator assignment could be made...".
"""

from __future__ import annotations

from scenarioforge.planning.vulnerability_plan import (
    VulnerabilityItem,
    compute_vulnerability_plan,
)

# The names compute_vulnerability_plan invents for a 'Random' draw. They are
# vulnerabilities, and must never appear as flag-node-generator ids.
RANDOM_VULN_NAMES = {'SSHCreds', 'Bashbug', 'FileArtifact', 'Incompetence'}


def _plan_for(xml_path: str, scenario: str):
    from scenarioforge.planning.orchestrator import compute_full_plan

    return compute_full_plan(xml_path, scenario)


def test_random_draw_still_yields_vulnerability_names() -> None:
    """Pins the upstream behaviour this bug relied on, so the cause stays visible."""
    plan, _breakdown = compute_vulnerability_plan(
        10,
        0.5,
        [VulnerabilityItem(name='Random', density=0.5, abs_count=1,
                           kind='Random', factor=0.0, metric='Count')],
    )
    assert set(plan) & RANDOM_VULN_NAMES, (
        'compute_vulnerability_plan no longer resolves Random to vulnerability '
        'names; the FlagGenSlot guard may need revisiting'
    )


def test_flag_gen_slots_do_not_inject_invented_generator_ids(tmp_path) -> None:
    """A FlagGenSlot row must not add a generator entry to the plan."""
    from scenarioforge.planning.orchestrator import compute_full_plan

    xml = tmp_path / 'slotscenario.xml'
    xml.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<Scenarios>
  <Scenario name="SlotScenario" density_count="10">
    <section name="Node Information" density_count="10">
      <item selected="FlagGenSlot" factor="1.000" v_metric="Count" v_count="2" />
    </section>
    <section name="Flag Node Generators" density="0.000" />
  </Scenario>
</Scenarios>
""",
        encoding='utf-8',
    )

    plan = compute_full_plan(str(xml), 'SlotScenario')
    nodegen_plan = plan.get('flag_node_generator_plan') or {}

    assert not (set(nodegen_plan) & RANDOM_VULN_NAMES), (
        f'FlagGenSlot injected invented generator ids: {nodegen_plan}'
    )
    # The slot still exists as reserved topology capacity.
    assert int((plan.get('role_counts') or {}).get('FlagGenSlot', 0)) == 2


def test_flag_gen_slots_stay_additive_to_declared_generator_rows(tmp_path) -> None:
    """Slots add capacity; they never absorb a declared generator's Docker host."""
    from scenarioforge.planning.orchestrator import compute_full_plan

    xml = tmp_path / 'additive.xml'
    xml.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<Scenarios>
  <Scenario name="Additive" density_count="20">
    <section name="Node Information" density_count="20">
      <item selected="FlagGenSlot" factor="1.000" v_metric="Count" v_count="3" />
    </section>
    <section name="Flag Node Generators" density="0.000">
      <item selected="Specific" factor="1.000" g_id="alpha" g_name="Alpha" v_metric="Count" v_count="2" />
    </section>
  </Scenario>
</Scenarios>
""",
        encoding='utf-8',
    )

    plan = compute_full_plan(str(xml), 'Additive')
    roles = plan.get('role_counts') or {}
    nodegen_plan = plan.get('flag_node_generator_plan') or {}

    assert nodegen_plan.get('alpha') == 2, nodegen_plan
    assert int(roles.get('FlagGenSlot', 0)) == 3
    # The two declared generators keep their own Docker hosts rather than being
    # absorbed into the three slots.
    assert int(roles.get('Docker', 0)) >= 2, roles
