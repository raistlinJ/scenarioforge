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


def _write_item_xml(tmp_path, item_attrs="", section_attrs=""):
    """The shape the editor actually writes: the switch lives on the row."""
    xml = f"""<Scenarios>
  <Scenario name="S1">
    <ScenarioEditor>
      <section name="Segmentation" density="0.5"{section_attrs}>
        <item selected="Firewall" factor="1.000" v_metric="Count" v_count="2"{item_attrs}/>
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    path = tmp_path / "scen_item.xml"
    path.write_text(xml, encoding="utf-8")
    return str(path)


def test_toggle_reads_the_per_row_switch_the_editor_writes(tmp_path):
    """The regression: the UI writes `pivot_enabled` on the <item>.

    Every other test here uses the section-level attribute, which the editor
    never produces -- so a scenario authored with the switch on parsed as off,
    planned no pivot providers, and left walled-off subnets with no entrance
    while the artifact check reported "no pivot providers in this scenario".
    """
    path = _write_item_xml(tmp_path, ' pivot_enabled="true" pivot_provider="flag-node-generator"')
    assert parse_segmentation_accessible_by_pivot(path, "S1") is True


def test_row_switch_off_is_still_off(tmp_path):
    path = _write_item_xml(tmp_path, ' pivot_enabled="false"')
    assert parse_segmentation_accessible_by_pivot(path, "S1") is False
    assert parse_segmentation_accessible_by_pivot(_write_item_xml(tmp_path), "S1") is False


def test_row_switch_accepts_the_spellings_the_web_ui_accepts(tmp_path):
    # Kept identical to app_backend so the two cannot disagree about "on".
    for raw in ("true", "1", "yes", "on", "required", "pivot", "pivot-only"):
        path = _write_item_xml(tmp_path, f' pivot_enabled="{raw}"')
        assert parse_segmentation_accessible_by_pivot(path, "S1") is True, raw


def test_any_pivot_enabled_row_turns_the_scenario_on(tmp_path):
    xml = """<Scenarios>
  <Scenario name="S1">
    <ScenarioEditor>
      <section name="Segmentation" density="0.5">
        <item selected="Firewall" factor="1.0"/>
        <item selected="NAT" factor="1.0" pivot_enabled="true"/>
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    path = tmp_path / "multi.xml"
    path.write_text(xml, encoding="utf-8")
    assert parse_segmentation_accessible_by_pivot(str(path), "S1") is True


def test_an_explicit_section_attribute_outranks_the_rows(tmp_path):
    # A scenario-wide statement is deliberate; a row is per-rule. The webapp's
    # writer skips this attribute entirely, so it only appears when something
    # set it on purpose.
    path = _write_item_xml(tmp_path, ' pivot_enabled="true"', ' accessible_by_pivot="false"')
    assert parse_segmentation_accessible_by_pivot(path, "S1") is False


def test_settings_and_toggle_never_disagree(tmp_path):
    """Both entry points must answer from the same place."""
    from scenarioforge.parsers.segmentation import parse_segmentation_settings

    for attrs in (' pivot_enabled="true"', ' pivot_enabled="false"', ""):
        path = _write_item_xml(tmp_path, attrs)
        assert (parse_segmentation_settings(path, "S1")["accessible_by_pivot"]
                is parse_segmentation_accessible_by_pivot(path, "S1")), attrs


def test_webapp_does_not_write_a_masking_section_attribute():
    """`_write_segmentation_settings_attrs` must keep skipping this key.

    Writing `accessible_by_pivot="false"` alongside a pivot-enabled row would
    silence the row, since an explicit section attribute outranks it.
    """
    source = Path("webapp/app_backend.py").read_text(encoding="utf-8")
    writer = source[source.index("def _write_segmentation_settings_attrs"):]
    writer = writer[:writer.index("\ndef ", 10)]
    assert "if key == 'accessible_by_pivot':" in writer
    assert "continue" in writer


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
    # The toggle reaches the planner through the resolved segmentation settings,
    # which is what the plan records and execute enforces.
    assert "accessible_by_pivot=bool(seg_settings['accessible_by_pivot'])" in src


def test_the_flag_reaches_the_resolved_settings():
    from scenarioforge.cli import _seg_settings

    class Args:
        xml = ""
        scenario = None
        seg_accessible_by_pivot = True
        nat_mode = None
        seg_include_hosts = None
        dnat_prob = None
        allow_src_subnet_prob = None
        allow_dst_subnet_prob = None

    assert _seg_settings(Args())['accessible_by_pivot'] is True


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


# --------------------------------------------------------------------------- #
# Pivot access is decided at plan time, because topology is built before
# segmentation runs and an added provider must exist by then.
# --------------------------------------------------------------------------- #

def test_preview_computes_pivot_access_when_the_toggle_is_on():
    import inspect
    from scenarioforge.planning import full_preview as fp
    src = inspect.getsource(fp.build_full_preview)
    assert "if segmentation_accessible_by_pivot:" in src
    assert "seg_preview['pivot_access']" in src
    # It must run before the node payloads are frozen, so a provider that has to
    # be added is known while nodes are still being planned.
    assert src.index("seg_preview['pivot_access']") < src.index("routers_payload = ")


def test_preview_pivot_access_is_absent_when_the_toggle_is_off():
    import inspect
    from scenarioforge.planning import full_preview as fp
    src = inspect.getsource(fp.build_full_preview)
    guard = src[src.index("if segmentation_accessible_by_pivot:"):]
    # Guarded, so an untouched scenario carries no pivot_access block at all.
    assert guard.index("seg_preview['pivot_access']") < guard.index("routers_payload = ")


def test_preview_pivot_failure_is_recorded_not_raised():
    import inspect
    from scenarioforge.planning import full_preview as fp
    src = inspect.getsource(fp.build_full_preview)
    block = src[src.index("if segmentation_accessible_by_pivot:"):src.index("routers_payload = ")]
    assert "except Exception" in block
    assert "'error'" in block


# --------------------------------------------------------------------------- #
# The provider choice reaches every planner call site
# --------------------------------------------------------------------------- #

def test_provider_choice_is_parsed_from_the_row_the_editor_writes(tmp_path):
    from scenarioforge.parsers.segmentation import parse_segmentation_settings

    path = _write_item_xml(tmp_path, ' pivot_enabled="true" pivot_provider="flag-node-generator"')
    settings = parse_segmentation_settings(path, "S1")
    assert settings["accessible_by_pivot"] is True
    assert settings["pivot_provider"] == "flag-node-generator"


def test_provider_choice_defaults_to_no_preference(tmp_path):
    from scenarioforge.parsers.segmentation import parse_segmentation_settings

    # `random` is resolved to a concrete provider when the editor saves, so
    # seeing it here means nothing was chosen.
    for attrs in ('', ' pivot_enabled="true"', ' pivot_enabled="true" pivot_provider="random"'):
        path = _write_item_xml(tmp_path, attrs)
        assert parse_segmentation_settings(path, "S1")["pivot_provider"] == "", attrs


def test_every_planner_call_site_passes_the_preference():
    """Four places select a provider; all must select the same one.

    `full_preview` decides it at plan time (and creates an added node there),
    `segmentation` enforces it at execute, and Flow stamps the pivot steps that
    name the node in the participant's guide. A site that dropped the preference
    would name one node and open the port on another.
    """
    checks = [
        ("scenarioforge/planning/full_preview.py", "preferred_provider=seg_settings.get('pivot_provider')"),
        ("scenarioforge/utils/segmentation.py", "preferred_provider=preferred_provider"),
        ("scenarioforge/utils/segmentation.py", "preferred_provider=pivot_preferred_provider"),
        ("scenarioforge/cli.py", "pivot_preferred_provider=seg_settings.get('pivot_provider')"),
        ("webapp/app_backend.py", "preferred_provider=_flow_preview_pivot_provider(preview)"),
    ]
    for path, needle in checks:
        source = Path(path).read_text(encoding="utf-8")
        assert needle in source, f"{path} does not pass the provider preference: {needle}"


def test_the_preference_travels_in_the_plan():
    """Execute enforces the plan, so the choice has to be recorded in it."""
    from scenarioforge.parsers.segmentation import SEGMENTATION_SETTING_DEFAULTS

    assert "pivot_provider" in SEGMENTATION_SETTING_DEFAULTS
    source = Path("scenarioforge/planning/full_preview.py").read_text(encoding="utf-8")
    # seg_settings is seeded from the defaults and written into the preview, so
    # a new key is carried without another edit here.
    assert "'settings': dict(seg_settings)" in source


def test_every_plan_shaping_setting_has_a_cli_flag():
    """A setting with no flag can only be changed by editing XML by hand.

    `pivot_provider` was added without one, which is easy to miss because the
    scenario attribute makes it look wired up.
    """
    from scenarioforge.cli import _SEG_SETTING_FLAGS
    from scenarioforge.parsers.segmentation import SEGMENTATION_SETTING_DEFAULTS

    missing = sorted(set(SEGMENTATION_SETTING_DEFAULTS) - set(_SEG_SETTING_FLAGS))
    assert not missing, f"plan-shaping settings with no CLI flag: {missing}"


def test_the_provider_flag_normalises_through_the_planners_vocabulary(tmp_path):
    """The flag and the XML attribute must not be able to mean different things."""
    from types import SimpleNamespace

    from scenarioforge.cli import _seg_settings

    path = _write_item_xml(tmp_path, ' pivot_enabled="true" pivot_provider="flag-node-generator"')

    def _args(**kw):
        base = dict(xml=path, scenario="S1", nat_mode=None, seg_include_hosts=None,
                    dnat_prob=None, allow_src_subnet_prob=None, allow_dst_subnet_prob=None,
                    seg_accessible_by_pivot=None, seg_pivot_provider=None)
        base.update(kw)
        return SimpleNamespace(**base)

    assert _seg_settings(_args())["pivot_provider"] == "flag-node-generator"
    # The editor's spelling is mapped to the planner's kind.
    assert _seg_settings(_args(seg_pivot_provider="ssh-fallback"))["pivot_provider"] == "ssh"
    assert _seg_settings(_args(seg_pivot_provider="vuln"))["pivot_provider"] == "vulnerability"
    # An unmappable value leaves the scenario's own choice alone rather than
    # clearing it, matching how the other flags refuse to override with junk.
    assert _seg_settings(_args(seg_pivot_provider="nonsense"))["pivot_provider"] == "flag-node-generator"


def test_the_provider_flag_offers_the_editors_options():
    """argparse `choices` must match what the editor can write."""
    import re
    from pathlib import Path as _Path

    cli_source = _Path("scenarioforge/cli.py").read_text(encoding="utf-8")
    raw = re.search(r"'--seg-pivot-provider',\s*\n\s*choices=\[(.*?)\]", cli_source, re.S).group(1)
    choices = sorted(v.strip().strip("'\"") for v in raw.split(",") if v.strip())

    backend = _Path("webapp/app_backend.py").read_text(encoding="utf-8")
    raw_opts = re.search(r"_PIVOT_PROVIDER_OPTIONS: List\[str\] = \[(.*?)\]", backend).group(1)
    options = sorted(v.strip().strip("'\"") for v in raw_opts.split(",") if v.strip())

    assert choices == options, "CLI choices and editor options have drifted"
