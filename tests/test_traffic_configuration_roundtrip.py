"""Traffic rows must survive planning, saved preview, and runtime configs."""

import json
import os
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest

from scenarioforge.planning import full_preview
from scenarioforge.planning.orchestrator import compute_full_plan
from scenarioforge.types import NodeInfo, TrafficInfo
from scenarioforge.utils.traffic import generate_traffic_scripts


def _scenario(tmp_path, rows):
    root = ET.fromstring('''<Scenarios><Scenario name="Traffic regression" density_count="4">
      <ScenarioEditor>
        <section name="Node Information"><item selected="Workstation" factor="1"/></section>
        <section name="Traffic" density="1"/>
      </ScenarioEditor>
    </Scenario></Scenarios>''')
    section = root.find(".//section[@name='Traffic']")
    for row in rows:
        ET.SubElement(section, "item", **{key: str(value) for key, value in row.items()})
    path = tmp_path / "traffic.xml"
    ET.ElementTree(root).write(path)
    return path


@pytest.fixture
def preview_scratch(tmp_path, monkeypatch):
    # Preview normally copies artifacts to shared /tmp runtime staging roots.
    # Keep these tests in their own scratch space and skip that optional copy.
    original_makedirs = os.makedirs

    def makedirs(path, *args, **kwargs):
        if str(path) in ("/tmp/traffic", "/tmp/segmentation"):
            raise PermissionError("runtime staging is isolated in this test")
        return original_makedirs(path, *args, **kwargs)

    monkeypatch.setattr(full_preview, "os", SimpleNamespace(**{**vars(os), "makedirs": makedirs}))
    monkeypatch.setattr(full_preview.tempfile, "gettempdir", lambda: str(tmp_path))


def test_planner_keeps_protocol_and_each_rows_parameters(tmp_path):
    path = _scenario(tmp_path, [
        dict(selected="UDP", factor=0.25, pattern="poisson", rate_kbps=37.5,
             period_s=2.5, jitter_pct=17, content_type="audio"),
        dict(selected="UDP", factor=0, v_metric="Count", v_count=3,
             pattern="burst", rate_kbps=91, period_s=4.5, jitter_pct=7, content_type="photo"),
    ])
    plan = compute_full_plan(str(path), scenario="Traffic regression", seed=42)
    assert plan["traffic_plan"] == [
        dict(kind="UDP", factor=0.25, abs_count=0, pattern="poisson", rate_kbps=37.5,
             period_s=2.5, jitter_pct=17, content="audio"),
        dict(kind="UDP", factor=0, abs_count=3, pattern="burst", rate_kbps=91,
             period_s=4.5, jitter_pct=7, content="photo"),
    ]


def test_density_generation_uses_every_traffic_row(tmp_path):
    hosts = [NodeInfo(node_id=i, ip4=f"10.0.0.{i}/24", role="Host") for i in (1, 2, 3)]
    items = [TrafficInfo(kind="UDP", factor=0.5, pattern="poisson", rate_kbps=37.5,
                         period_s=2.5, jitter_pct=17, content_type="audio"),
             TrafficInfo(kind="TCP", factor=0.5, pattern="burst", rate_kbps=91,
                         period_s=4.5, jitter_pct=7, content_type="photo")]
    generate_traffic_scripts(hosts, 1.0, items, out_dir=str(tmp_path))
    flows = json.loads((tmp_path / "traffic_summary.json").read_text())["flows"]
    assert len(flows) == len(hosts) * len(items)
    for host in hosts:
        actual = {(flow["protocol"], flow["pattern"], flow["rate_kbps"], flow["period_s"],
                   flow["jitter_pct"], flow["content_type"])
                  for flow in flows if flow["src_id"] == host.node_id}
        assert actual == {("UDP", "poisson", 37.5, 2.5, 17, "audio"),
                          ("TCP", "burst", 91, 4.5, 7, "photo")}


@pytest.mark.parametrize("random_fields", [True, False])
def test_udp_rows_survive_saved_preview_and_runtime_configs(tmp_path, preview_scratch, random_fields):
    from webapp import app_backend
    from scenarioforge.cli import _planned_traffic_flows

    if random_fields:
        rows = [dict(selected="UDP", factor=0.5, content_type="Random", pattern="Random")
                for _ in range(2)]
    else:
        rows = [dict(selected="UDP", factor=0, v_metric="Count", v_count=1,
                     content_type=content, pattern=pattern, rate_kbps=rate,
                     period_s=period, jitter_pct=jitter)
                for content, pattern, rate, period, jitter in
                [("audio", "poisson", 37.5, 2.5, 17), ("photo", "burst", 91, 4.5, 7)]]
    path = _scenario(tmp_path, rows)
    result = app_backend._planner_persist_flow_plan(
        xml_path=str(path), scenario="Traffic regression", seed=42)
    assert result["persisted"], result.get("persist_error")
    saved = json.loads(ET.parse(path).find(".//PlanPreview").text)["full_preview"]
    assert [item["kind"] for item in saved["traffic_plan"]] == ["UDP", "UDP"]
    flows = saved["traffic_summary"]["flows"]
    assert len(flows) == (4 if random_fields else 2)
    assert {flow["protocol"] for flow in flows} == {"UDP"}
    if random_fields:
        # Random subfields are drawn independently, without changing protocol.
        assert len({(flow["rate_kbps"], flow["period_s"], flow["jitter_pct"]) for flow in flows}) > 1
    else:
        assert {(flow["pattern"], flow["rate_kbps"], flow["period_s"], flow["jitter_pct"], flow["content_type"])
                for flow in flows} == {("poisson", 37.5, 2.5, 17, "audio"),
                                      ("burst", 91, 4.5, 7, "photo")}

    runtime = tmp_path / "runtime"
    hosts = [NodeInfo(node_id=host["node_id"], ip4=host["ip4"], role=host["role"])
             for host in saved["hosts"]]
    generate_traffic_scripts(hosts, 0, [], out_dir=str(runtime),
                             planned_flows=_planned_traffic_flows(saved))
    actual = json.loads((runtime / "traffic_summary.json").read_text())["flows"]
    assert len(actual) == len(flows)
    for expected, flow in zip(flows, actual):
        for key in ("protocol", "pattern", "rate_kbps", "period_s", "jitter_pct", "content_type"):
            assert flow[key] == expected[key]
    configs = [json.loads(config.read_text()) for config in runtime.glob("traffic_*.json")
               if config.name != "traffic_summary.json"]
    assert configs
    assert all(flow["protocol"] == "UDP" for config in configs for flow in config["flows"])
    expected_senders = {(flow["src_id"], flow["dst_port"]): flow for flow in flows}
    for config in configs:
        for flow in config["flows"]:
            if flow["role"] != "sender":
                continue
            expected = expected_senders[(int(config["node_id"]), flow["port"])]
            for key in ("protocol", "pattern", "rate_kbps", "period_s", "jitter_pct", "content_type"):
                assert flow[key] == expected[key]
