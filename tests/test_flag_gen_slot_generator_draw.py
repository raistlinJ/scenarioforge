"""A FlagGenSlot must not be assigned a generator the planner invented.

The planning layer has no view of the installed generator catalog. Drawing a
'Random' slot entry through compute_vulnerability_plan resolves it against
DEFAULT_RANDOM_VULNS -- vulnerability names such as "SSHCreds" -- which are not
generators. A slot carrying one matches nothing in the candidate pool, which
empties that chain position and fails the entire flow sequence with
"No distinct compatible generator assignment could be made...".
"""

from __future__ import annotations

from pathlib import Path

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


def _preview_hosts(xml_text: str, tmp_path, name: str = 'S', seed: int = 1):
    """Build a preview the way the webapp does, and return its hosts."""
    from scenarioforge.planning.orchestrator import compute_full_plan
    from webapp import app_backend as backend

    xml = tmp_path / f'{name}.xml'
    xml.write_text(xml_text, encoding='utf-8')
    plan = compute_full_plan(str(xml), 'S', seed=seed)
    preview = backend._build_full_preview_from_plan(plan, seed)
    return plan, (preview.get('hosts') or [])


def _scenario_xml(node_items: str, section_name: str, section_items: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Scenarios><Scenario name="S" density_count="30">\n'
        f'<section name="Node Information" density_count="30">{node_items}</section>\n'
        f'<section name="{section_name}" density="0.500">{section_items}</section>\n'
        '</Scenario></Scenarios>\n'
    )


def test_declared_generators_are_not_absorbed_into_flag_gen_slots(tmp_path) -> None:
    """5 declared generators + 1 slot is 6 challenge hosts, not 5.

    Netting slots against declared demand made a declared generator land *on*
    the slot, so the scenario came up a challenge node short and had no free
    slot left for flag-sequencing.
    """
    _plan, hosts = _preview_hosts(
        _scenario_xml(
            '<item selected="FlagGenSlot" factor="1.0" v_metric="Count" v_count="1" />',
            'Flag Node Generators',
            '<item selected="Specific" factor="1.0" g_id="a" g_name="A" v_metric="Count" v_count="5" />',
        ),
        tmp_path,
        name='gen_absorb',
    )

    assert len(hosts) == 6, [h.get('name') for h in hosts]
    slots = [h for h in hosts if str(h.get('role') or '') == 'FlagGenSlot']
    assert len(slots) == 1
    # The slot stays free: Flow assigns it, the planner must not.
    assert not (slots[0].get('metadata') or {}).get('flag_node_generator_id')
    # Every declared generator still got its own Docker host.
    declared = [h for h in hosts if (h.get('metadata') or {}).get('flag_node_generator_id')]
    assert len(declared) == 5


def test_vulnerability_slots_do_not_materialize_duplicate_hosts(tmp_path) -> None:
    """Vuln slots net out, because the planner already asked for one vuln each.

    Nothing downstream can assign a vulnerability, so unlike a generator slot
    the demand is counted up front and the slot *is* the host for it.
    """
    _plan, hosts = _preview_hosts(
        _scenario_xml(
            '<item selected="VulnerabilitySlot" factor="1.0" v_metric="Count" v_count="2" />',
            'Vulnerabilities',
            '<item selected="Random" factor="1.0" v_metric="Count" v_count="3" />',
        ),
        tmp_path,
        name='vuln_dup',
    )

    assert len(hosts) == 5, [h.get('name') for h in hosts]
    # No dead nodes: every host carries a vulnerability.
    assert all(h.get('vulnerabilities') for h in hosts), [
        (h.get('name'), h.get('vulnerabilities')) for h in hosts
    ]


def test_random_vulnerabilities_come_from_the_installed_catalog(tmp_path) -> None:
    """A Random vuln row must name something that actually exists.

    An unresolvable name silently degrades its host to a plain Docker node with
    no vulnerability on it.
    """
    from scenarioforge.utils.vuln_process import load_vuln_catalog

    repo_root = str(Path(__file__).resolve().parents[1])
    catalog = {
        str(entry.get('Name') or '').strip()
        for entry in (load_vuln_catalog(repo_root) or [])
        if isinstance(entry, dict)
    }
    if not catalog:
        import pytest

        pytest.skip('no vulnerability catalog installed')

    plan, _hosts = _preview_hosts(
        _scenario_xml(
            '',
            'Vulnerabilities',
            '<item selected="Random" factor="1.0" v_metric="Count" v_count="3" />',
        ),
        tmp_path,
        name='vuln_random',
    )
    drawn = set(plan.get('vulnerability_plan') or {})

    assert drawn, plan.get('vulnerability_plan')
    assert not (drawn & RANDOM_VULN_NAMES), f'placeholder names leaked: {drawn}'
    assert drawn <= catalog, f'names not in the installed catalog: {drawn - catalog}'


def test_random_vulnerability_draw_is_seed_stable(tmp_path) -> None:
    """Preview/execute parity depends on the same seed drawing the same vulns."""
    xml = _scenario_xml(
        '',
        'Vulnerabilities',
        '<item selected="Random" factor="1.0" v_metric="Count" v_count="3" />',
    )
    first, _ = _preview_hosts(xml, tmp_path, name='seed_a', seed=7)
    second, _ = _preview_hosts(xml, tmp_path, name='seed_b', seed=7)
    assert first.get('vulnerability_plan') == second.get('vulnerability_plan')
