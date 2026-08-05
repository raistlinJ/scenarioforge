"""An explicit Segmentation count must survive into the plan.

`compute_full_plan` serialises each Segmentation row for `build_full_preview`,
which rebuilds `SegmentationInfo` from it. That serialisation carried only
`selected` and `factor`, so every explicit count arrived as zero. The planner
then saw no count rows at all, fell back to density-weighted slots, and drew
each slot's service at random from the rows' kinds.

The visible damage: a scenario asking for "2 Firewall, 1 NAT" could plan two NAT
rules and no firewall rule (p = 0.25 with two equally weighted kinds). With no
blocking rule nothing is walled off, so pivot access has no subnet to give an
entrance to and the artifact check reports "no pivot providers" on a scenario
whose editor plainly asked for firewalls -- and the outcome changed from one
Generate to the next, because it was a coin flip.
"""

from __future__ import annotations

import collections
import random
import tempfile

import pytest

from scenarioforge.parsers.segmentation import parse_segmentation_info
from scenarioforge.types import NodeInfo, SegmentationInfo
from scenarioforge.utils.segmentation import plan_and_apply_segmentation


SEGMENTATION_XML = """<Scenarios>
  <Scenario name="S1">
    <ScenarioEditor>
      <BaseScenario/>
      <section name="Segmentation" density="0.5" explicit_count="3" count_rows="2">
        <item selected="Firewall" factor="1.000" v_metric="Count" v_count="2"
              pivot_enabled="true" pivot_provider="flag-node-generator"/>
        <item selected="NAT" factor="1.000" v_metric="Count" v_count="1"/>
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""


@pytest.fixture()
def scenario_xml(tmp_path):
    path = tmp_path / "seg.xml"
    path.write_text(SEGMENTATION_XML, encoding="utf-8")
    return str(path)


def _serialize_like_the_orchestrator(items):
    """Mirror `compute_full_plan`'s row serialisation, read from the source."""
    import re
    from pathlib import Path

    source = Path("scenarioforge/planning/orchestrator.py").read_text(encoding="utf-8")
    assert "'abs_count': int(getattr(si, 'abs_count', 0) or 0)" in source, (
        "the serialisation must carry abs_count, or explicit counts are lost"
    )
    assert re.search(r"raw_items_serialized'\]\s*=\s*\[", source)
    return [
        {'selected': si.name, 'factor': si.factor,
         'abs_count': int(getattr(si, 'abs_count', 0) or 0)}
        for si in items
    ]


def test_counts_survive_serialisation(scenario_xml):
    _density, items = parse_segmentation_info(scenario_xml, "S1")
    serial = _serialize_like_the_orchestrator(items)
    by_name = {row['selected']: row for row in serial}
    assert by_name['Firewall']['abs_count'] == 2
    assert by_name['NAT']['abs_count'] == 1


def _rebuild_like_full_preview(serial):
    """`build_full_preview` reads `abs_count` off each serialised row."""
    return [
        SegmentationInfo(name=(row.get('selected') or '').strip(),
                         factor=float(row.get('factor') or 0.0),
                         abs_count=int(row.get('abs_count') or 0))
        for row in serial
        if (row.get('selected') or '').strip()
    ]


def _topology():
    routers = [NodeInfo(node_id=i, ip4=f"10.0.{i}.1/24", role="Router") for i in range(1, 6)]
    hosts = [NodeInfo(node_id=10 + i, ip4=f"10.0.{1 + (i % 5)}.{10 + i}/24", role="Docker")
             for i in range(15)]
    return routers, hosts


def _plan_types(seg_objs, density, seed):
    routers, hosts = _topology()
    random.seed(seed)
    with tempfile.TemporaryDirectory() as out_dir:
        summary = plan_and_apply_segmentation(
            object(), routers, hosts, density, seg_objs,
            nat_mode="SNAT", out_dir=out_dir, include_hosts=False,
        )
    return [str((r.get('rule') or {}).get('type')) for r in summary.get('rules', [])]


def test_an_explicit_count_is_honoured_not_redrawn(scenario_xml):
    """One NAT was asked for, so exactly one NAT is planned -- every time."""
    density, items = parse_segmentation_info(scenario_xml, "S1")
    seg_objs = _rebuild_like_full_preview(_serialize_like_the_orchestrator(items))
    assert [(s.name, s.abs_count) for s in seg_objs] == [("Firewall", 2), ("NAT", 1)]

    for seed in range(8):
        types = collections.Counter(_plan_types(seg_objs, density, seed))
        assert types['nat'] == 1, f"seed {seed} drew {types['nat']} NAT rules, expected exactly 1"


def test_a_firewall_row_actually_walls_something_off(scenario_xml):
    """The failure this whole test file exists for.

    Without the count the two rows were weighted coin flips, so a run could end
    up all-NAT and wall off nothing at all.
    """
    density, items = parse_segmentation_info(scenario_xml, "S1")
    seg_objs = _rebuild_like_full_preview(_serialize_like_the_orchestrator(items))
    walling = {'subnet_block', 'host_block', 'protect_internal'}
    for seed in range(8):
        types = _plan_types(seg_objs, density, seed)
        assert walling.intersection(types), f"seed {seed} planned no blocking rule: {types}"


def test_dropping_the_count_is_what_broke_it(scenario_xml):
    """Pin the mechanism, so a future serialisation change is caught here.

    With `abs_count` stripped the planner has no count rows, falls back to
    density slots, and picks each slot's service by weight -- which is how an
    all-NAT plan became reachable.
    """
    density, items = parse_segmentation_info(scenario_xml, "S1")
    stripped = [{'selected': si.name, 'factor': si.factor} for si in items]
    seg_objs = _rebuild_like_full_preview(stripped)
    assert all(s.abs_count == 0 for s in seg_objs)

    seen_all_nat = False
    for seed in range(24):
        types = _plan_types(seg_objs, density, seed)
        if types and all(t == 'nat' for t in types):
            seen_all_nat = True
            break
    assert seen_all_nat, "expected the stripped form to be able to plan an all-NAT policy"
