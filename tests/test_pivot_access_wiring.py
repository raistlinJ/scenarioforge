"""The "accessible by pivot" toggle is wired from XML/UI/CLI into the planner."""

import xml.etree.ElementTree as ET
from pathlib import Path

from scenarioforge.parsers.segmentation import parse_segmentation_accessible_by_pivot
from scenarioforge.types import NodeInfo
from scenarioforge.utils import segmentation as seg


def _write_xml(tmp_path, attrs=""):
    xml = f"""<Scenarios>
  <Scenario name="S1">
    <section name="Segmentation" density="0.5"{attrs}/>
  </Scenario>
</Scenarios>"""
    path = tmp_path / "scen.xml"
    path.write_text(xml, encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------- #
# Reading the toggle out of a scenario
# --------------------------------------------------------------------------- #

def test_toggle_defaults_off_so_existing_scenarios_are_unchanged(tmp_path):
    assert parse_segmentation_accessible_by_pivot(_write_xml(tmp_path), "S1") is False


def test_toggle_reads_true(tmp_path):
    path = _write_xml(tmp_path, ' accessible_by_pivot="true"')
    assert parse_segmentation_accessible_by_pivot(path, "S1") is True


def test_toggle_accepts_the_usual_truthy_spellings(tmp_path):
    for raw in ("1", "yes", "on", "TRUE"):
        path = _write_xml(tmp_path, f' accessible_by_pivot="{raw}"')
        assert parse_segmentation_accessible_by_pivot(path, "S1") is True, raw
    for raw in ("0", "no", "off", "false", ""):
        path = _write_xml(tmp_path, f' accessible_by_pivot="{raw}"')
        assert parse_segmentation_accessible_by_pivot(path, "S1") is False, raw


def test_toggle_missing_section_or_file_is_false(tmp_path):
    assert parse_segmentation_accessible_by_pivot(str(tmp_path / "nope.xml"), "S1") is False
    empty = tmp_path / "empty.xml"
    empty.write_text('<Scenarios><Scenario name="S1"/></Scenarios>', encoding="utf-8")
    assert parse_segmentation_accessible_by_pivot(str(empty), "S1") is False


# --------------------------------------------------------------------------- #
# The planner acts on it
# --------------------------------------------------------------------------- #

def _summary_with_block():
    return {"rules": [{
        "node_id": 1, "service": "Segmentation",
        "rule": {"type": "subnet_block", "src": "10.0.140.0/24",
                 "dst": "172.21.240.0/24", "default_deny": True},
    }]}


def _hosts():
    return [
        NodeInfo(node_id=2, ip4="172.21.240.2/24", role="FlagGenSlot"),
        NodeInfo(node_id=6, ip4="172.21.240.6/24", role="Docker"),
        NodeInfo(node_id=9, ip4="10.0.140.6/24", role="Docker"),
    ]


def _entries():
    """Node 6 already serves SSH, so it is a reusable provider with an address."""
    from scenarioforge.utils.pivot_access import ENTRY_SSH, PivotEntry
    return {6: [PivotEntry(kind=ENTRY_SSH, port=22)]}


def test_apply_pivot_access_appends_allow_rules_and_a_report(tmp_path):
    summary = _summary_with_block()
    seg._apply_pivot_access(
        summary=summary,
        hosts=_hosts(),
        routers=[NodeInfo(node_id=1, ip4="172.21.240.1/24", role="Router")],
        out_dir=str(tmp_path),
        session=None,
        entry_points=_entries(),
        lookup_node_name=lambda nid: f"node-{nid}",
    )
    allows = [r for r in summary["rules"] if r["rule"].get("type") == "allow"]
    assert allows, "pivot access should have opened a path"
    assert all(r["rule"]["reason"] == "pivot-access" for r in allows)
    # The chosen provider is the non-slot node, and it is reported.
    report = summary["pivot_access"]
    assert report["provider_count"] == 1
    assert report["providers"][0]["node_name"] == "node-6"
    assert report["providers"][0]["consumes_slot"] is False


def test_apply_pivot_access_writes_an_idempotent_script(tmp_path):
    summary = _summary_with_block()
    seg._apply_pivot_access(
        summary=summary,
        hosts=_hosts(),
        routers=[NodeInfo(node_id=1, ip4="172.21.240.1/24", role="Router")],
        out_dir=str(tmp_path),
        session=None,
        entry_points=_entries(),
        lookup_node_name=lambda nid: f"node-{nid}",
    )
    scripts = sorted(Path(tmp_path).glob("seg_pivot_*.py"))
    assert scripts, "expected a pivot script per node"
    body = scripts[0].read_text(encoding="utf-8")
    assert "iptables -I" in body and "-j ACCEPT" in body
    # -C check before -A/-I is what makes re-running safe.
    assert "build_check" in body


def test_apply_pivot_access_does_nothing_when_nothing_is_walled_off(tmp_path):
    summary = {"rules": [{"node_id": 1, "service": "Segmentation",
                          "rule": {"type": "nat", "internal": "10.0.0.0/24"}}]}
    seg._apply_pivot_access(
        summary=summary, hosts=_hosts(), routers=[], out_dir=str(tmp_path),
        session=None, lookup_node_name=lambda nid: f"node-{nid}",
    )
    assert "pivot_access" not in summary
    assert len(summary["rules"]) == 1


def test_planner_accepts_the_toggle_without_it_changing_default_behaviour(tmp_path):
    # Off by default: the signature gained a parameter, not a behaviour change.
    import inspect
    sig = inspect.signature(seg.plan_and_apply_segmentation)
    assert sig.parameters["accessible_by_pivot"].default is False
    assert sig.parameters["pivot_ssh_port"].default == 22


# --------------------------------------------------------------------------- #
# CLI + UI surfaces
# --------------------------------------------------------------------------- #

def test_cli_exposes_the_flag():
    src = Path("scenarioforge/cli.py").read_text(encoding="utf-8")
    assert "'--seg-accessible-by-pivot'" in src
    assert "accessible_by_pivot=_seg_accessible_by_pivot(args)" in src


def test_cli_flag_or_xml_enables_it():
    from scenarioforge.cli import _seg_accessible_by_pivot

    class Args:
        seg_accessible_by_pivot = True
        xml = ""
        scenario = None

    assert _seg_accessible_by_pivot(Args()) is True

    class Off(Args):
        seg_accessible_by_pivot = False

    assert _seg_accessible_by_pivot(Off()) is False


def test_ui_renders_the_toggle_only_for_segmentation():
    html = Path("webapp/templates/index.html").read_text(encoding="utf-8")
    assert "Accessible by pivot" in html
    assert 'data-field="accessible_by_pivot"' in html
    block = html[html.index("const pivotOn ="):]
    assert "never consume vulnerability or flag-node-generator slot capacity" in block[:1400]
    # Change (not input) drives it, so one click does not write state twice.
    handler = html[html.index("field === 'accessible_by_pivot'"):]
    assert "ev?.type === 'input'" in handler[:300]


def test_backend_round_trips_the_toggle_through_xml():
    src = Path("webapp/app_backend.py").read_text(encoding="utf-8")
    # Written only when on, so untouched scenarios keep their markup.
    assert 'sec_el.set("accessible_by_pivot", "true")' in src
    assert 'entry["accessible_by_pivot"]' in src


def test_section_element_carries_the_attribute_when_enabled():
    # Guards the exact attribute name the parser looks for.
    el = ET.fromstring('<section name="Segmentation" density="0.5" accessible_by_pivot="true"/>')
    assert el.get("accessible_by_pivot") == "true"


def test_provider_nodes_get_the_segmentation_service_enabled(tmp_path, monkeypatch):
    # Segmentation scripts are run by the Segmentation service, which is on
    # routers only by default. Without enabling it on the provider its INPUT
    # allow is written and never applied, so the path opens across the routers
    # and is dropped on arrival.
    enabled: list[tuple[int, str]] = []

    def _fake_ensure(session, node_id, service_name, node_obj=None):
        enabled.append((int(node_id), str(service_name)))
        return True

    monkeypatch.setattr(seg, 'ensure_service', _fake_ensure)
    summary = _summary_with_block()
    seg._apply_pivot_access(
        summary=summary,
        hosts=_hosts(),
        routers=[NodeInfo(node_id=1, ip4="172.21.240.1/24", role="Router")],
        out_dir=str(tmp_path),
        session=object(),                      # any non-None session
        entry_points=_entries(),
        lookup_node_name=lambda nid: f"node-{nid}",
    )
    # The provider already serves SSH, so only Segmentation is enabled -- that
    # is what runs its own generated script.
    assert (6, 'Segmentation') in enabled
    # The enforcing router needs it too, for the FORWARD half.
    assert (1, 'Segmentation') in enabled


def test_no_services_are_touched_without_a_session(tmp_path, monkeypatch):
    calls: list = []
    monkeypatch.setattr(seg, 'ensure_service', lambda *a, **k: calls.append(a))
    seg._apply_pivot_access(
        summary=_summary_with_block(), hosts=_hosts(),
        routers=[NodeInfo(node_id=1, ip4="172.21.240.1/24", role="Router")],
        out_dir=str(tmp_path), session=None,
        lookup_node_name=lambda nid: f"node-{nid}",
    )
    assert calls == []
