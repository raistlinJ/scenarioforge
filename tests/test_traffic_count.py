import json
import tempfile
from pathlib import Path

from scenarioforge.utils.traffic import generate_traffic_scripts
from scenarioforge.types import NodeInfo, TrafficInfo


def _hosts(n):
    return [NodeInfo(node_id=i + 1, ip4=f"10.0.0.{i+1}/24", role="Host") for i in range(n)]


def _roles(result):
    """Return (sender node ids, receiver node ids) from the agent configs.

    Each node gets one config listing every flow it takes part in, so the role
    is read from the config rather than inferred from a per-flow filename.
    """
    senders, receivers = set(), set()
    for node_id, files in result.items():
        for path in files:
            if not str(path).endswith(".json"):
                continue
            config = json.loads(Path(path).read_text(encoding="utf-8"))
            for flow in config.get("flows", []):
                if flow.get("role") == "sender":
                    senders.add(node_id)
                elif flow.get("role") == "receiver":
                    receivers.add(node_id)
    return senders, receivers


def _count_pairs(result):
    senders, receivers = _roles(result)
    return min(len(senders), len(receivers))


def test_one_traffic_pair_with_abs_count():
    hosts = _hosts(3)
    items = [TrafficInfo(kind="TCP", factor=0.0, abs_count=1)]
    with tempfile.TemporaryDirectory() as td:
        result = generate_traffic_scripts(hosts, density=0.0, items=items, out_dir=td)
        # Read inside the context: the assertions inspect the generated configs.
        assert _count_pairs(result) == 1
