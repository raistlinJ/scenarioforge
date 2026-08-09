"""A planned flow must land on the topology that this run actually built.

The plan decides who talks to whom, on which protocol, port and rate, and
execute replays exactly that instead of drawing again. Addresses are not part of
that decision: they belong to the topology built in this run. When a plan
carried addresses from a different draw, senders dialled IPs no node owned, so
the flows never connected -- and the artifact check, which matches flows to
running nodes by address, reported "traffic source node not found for <ip>" for
every one of them.
"""

import json
from pathlib import Path

from scenarioforge.types import NodeInfo
from scenarioforge.utils.traffic import generate_traffic_scripts


PLANNED = [{
    "src_id": 2, "dst_id": 1, "protocol": "TCP",
    "src_ip": "172.30.96.14", "dst_ip": "172.30.96.15", "dst_port": 5013,
    "pattern": "continuous", "rate_kbps": 64.0, "period_s": 10.0,
    "jitter_pct": 0.0, "content_type": "text",
}]


def _summary(out_dir):
    return json.loads((Path(out_dir) / "traffic_summary.json").read_text(encoding="utf-8"))


def _configs(out_dir):
    return {p.name: json.loads(p.read_text(encoding="utf-8"))
            for p in Path(out_dir).glob("traffic_*.json")}


def test_planned_addresses_are_rebound_to_the_running_nodes(tmp_path):
    hosts = [NodeInfo(node_id=1, ip4="10.7.0.11/24", role="Host"),
             NodeInfo(node_id=2, ip4="10.7.0.12/24", role="Host")]

    generate_traffic_scripts(hosts, 0.0, [], out_dir=str(tmp_path),
                             planned_flows=[dict(f) for f in PLANNED])

    flow = _summary(tmp_path)["flows"][0]
    assert flow["src_ip"] == "10.7.0.12"
    assert flow["dst_ip"] == "10.7.0.11"
    # The plan's own decisions are untouched.
    assert (flow["src_id"], flow["dst_id"], flow["dst_port"]) == (2, 1, 5013)
    assert flow["protocol"] == "TCP" and flow["rate_kbps"] == 64.0

    # The sender's agent config is what actually dials, so it must carry the
    # corrected address too.
    sender = _configs(tmp_path)["traffic_2.json"]
    sending = [f for f in sender["flows"] if f["role"] == "sender"]
    assert [f["host"] for f in sending] == ["10.7.0.11"]


def test_addresses_that_already_match_are_left_alone(tmp_path):
    hosts = [NodeInfo(node_id=1, ip4="172.30.96.15/24", role="Host"),
             NodeInfo(node_id=2, ip4="172.30.96.14/24", role="Host")]

    generate_traffic_scripts(hosts, 0.0, [], out_dir=str(tmp_path),
                             planned_flows=[dict(f) for f in PLANNED])

    flow = _summary(tmp_path)["flows"][0]
    assert flow["src_ip"] == "172.30.96.14"
    assert flow["dst_ip"] == "172.30.96.15"


def test_endpoints_absent_from_this_run_keep_their_planned_address(tmp_path):
    # Only node 2 is a traffic host here; node 1's address cannot be looked up,
    # and inventing one would be worse than replaying what the plan recorded.
    hosts = [NodeInfo(node_id=2, ip4="10.7.0.12/24", role="Host")]

    generate_traffic_scripts(hosts, 0.0, [], out_dir=str(tmp_path),
                             planned_flows=[dict(f) for f in PLANNED])

    flow = _summary(tmp_path)["flows"][0]
    assert flow["src_ip"] == "10.7.0.12"
    assert flow["dst_ip"] == "172.30.96.15"


def test_no_hosts_at_all_replays_the_plan_unchanged(tmp_path):
    generate_traffic_scripts([], 0.0, [], out_dir=str(tmp_path),
                             planned_flows=[dict(f) for f in PLANNED])

    flow = _summary(tmp_path)["flows"][0]
    assert flow["src_ip"] == "172.30.96.14"
    assert flow["dst_ip"] == "172.30.96.15"
