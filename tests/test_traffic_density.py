import json
import tempfile
from pathlib import Path

from scenarioforge.utils.traffic import generate_traffic_scripts
from scenarioforge.types import NodeInfo, TrafficInfo


def _hosts(n):
    return [NodeInfo(node_id=i + 1, ip4=f"10.0.0.{i+1}/24", role="Host") for i in range(n)]


def _count_sender_hosts(result):
    """Nodes that own at least one outbound flow.

    Traffic is driven by one agent config per node rather than a script per
    flow, so the role is read from the config instead of inferred from a
    `_s<n>.py` filename.
    """
    sender_hosts = set()
    for node_id, files in result.items():
        for path in files:
            if not str(path).endswith(".json"):
                continue
            config = json.loads(Path(path).read_text(encoding="utf-8"))
            if any(flow.get("role") == "sender" for flow in config.get("flows", [])):
                sender_hosts.add(node_id)
                break
    return len(sender_hosts)


def test_density_one_selects_all_hosts():
    hosts = _hosts(5)
    items = [TrafficInfo(kind="TCP", factor=1.0)]
    with tempfile.TemporaryDirectory() as td:
        result = generate_traffic_scripts(hosts, 1.0, items, out_dir=td)
        assert _count_sender_hosts(result) == len(hosts)


def test_density_near_one_rounds_to_all():
    hosts = _hosts(5)
    items = [TrafficInfo(kind="TCP", factor=1.0)]
    with tempfile.TemporaryDirectory() as td:
        result = generate_traffic_scripts(hosts, 0.999, items, out_dir=td)
        assert _count_sender_hosts(result) == len(hosts)
