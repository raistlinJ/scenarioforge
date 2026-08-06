import json

from scenarioforge.types import NodeInfo
from scenarioforge.utils.segmentation import (
    verify_flows_allowed,
    write_allow_rules_for_compose_ports,
    write_allow_rules_for_flows,
)


class _DummyServices:
    def __init__(self):
        self._data = {}

    def _key(self, node):
        return getattr(node, "id", node)

    def get(self, node):
        return self._data.get(self._key(node), [])

    def set(self, node, services):
        self._data[self._key(node)] = list(services)


class _DummyNode:
    def __init__(self, node_id: int, name: str):
        self.id = node_id
        self.name = name
        self.services = []


class _DummySession:
    def __init__(self, nodes):
        self.nodes = {node.id: node for node in nodes}
        self.services = _DummyServices()

    def get_node(self, node_id):
        return self.nodes.get(node_id)


def test_segmentation_allow_rules_are_idempotent_and_unblock_traffic(tmp_path):
    routers = [
        NodeInfo(node_id=100, ip4="10.0.0.1/24", role="Router"),
    ]
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Workstation"),
        NodeInfo(node_id=2, ip4="10.0.1.10/24", role="Workstation"),
    ]

    out_dir = tmp_path / "segmentation"
    out_dir.mkdir()

    segmentation_summary = {
        "rules": [
            {
                "node_id": 100,
                "service": "Segmentation",
                "rule": {
                    "type": "nat",
                    "internal": "10.0.0.0/24",
                    "external": "0.0.0.0/0",
                    "mode": "SNAT",
                    "egress_ip": "10.0.0.1",
                    "default_deny": True,
                    "chain": "FORWARD",
                },
                "script": str(out_dir / "seg_nat_100_1.py"),
            },
            {
                "node_id": 2,
                "service": "Segmentation",
                "rule": {
                    "type": "none",
                    "default_deny": True,
                    "chain": "INPUT",
                },
                "script": str(out_dir / "seg_none_2_1.py"),
            },
        ]
    }
    (out_dir / "segmentation_summary.json").write_text(json.dumps(segmentation_summary), encoding="utf-8")

    traffic_summary = {
        "flows": [
            {
                "src_id": 1,
                "dst_id": 2,
                "src_ip": "10.0.0.10",
                "dst_ip": "10.0.1.10",
                "dst_port": 8080,
                "protocol": "tcp",
            }
        ]
    }
    traffic_path = tmp_path / "traffic_summary.json"
    traffic_path.write_text(json.dumps(traffic_summary), encoding="utf-8")

    first = write_allow_rules_for_flows(
        session=None,
        routers=routers,
        hosts=hosts,
        traffic_summary_path=str(traffic_path),
        out_dir=str(out_dir),
        src_subnet_prob=0.0,
        dst_subnet_prob=0.0,
    )
    assert len(first.get("rules") or []) == 3

    second = write_allow_rules_for_flows(
        session=None,
        routers=routers,
        hosts=hosts,
        traffic_summary_path=str(traffic_path),
        out_dir=str(out_dir),
        src_subnet_prob=0.0,
        dst_subnet_prob=0.0,
    )
    assert second.get("rules") == []

    summary_after = json.loads((out_dir / "segmentation_summary.json").read_text("utf-8"))
    allow_rules = [
        rule for rule in (summary_after.get("rules") or [])
        if ((rule.get("rule") or {}).get("type") == "allow")
    ]
    assert len(allow_rules) == 3

    verification = verify_flows_allowed(
        traffic_summary_path=str(traffic_path),
        segmentation_summary_path=str(out_dir / "segmentation_summary.json"),
        out_path=str(out_dir / "allow_verification.json"),
    )
    assert verification.get("blocked_count") == 0


def test_runtime_allow_scripts_do_not_overwrite_preview_scripts(tmp_path):
    out_dir = tmp_path / "segmentation"
    out_dir.mkdir()
    existing = out_dir / "seg_allow_2_1.py"
    existing.write_text("# preview allow\n", encoding="utf-8")
    (out_dir / "segmentation_summary.json").write_text(
        json.dumps({
            "rules": [{
                "node_id": 2,
                "rule": {"type": "none", "default_deny": True, "chain": "INPUT"},
            }]
        }),
        encoding="utf-8",
    )
    traffic_path = tmp_path / "traffic_summary.json"
    traffic_path.write_text(
        json.dumps({
            "flows": [{
                "src_id": 1,
                "dst_id": 2,
                "src_ip": "10.0.0.10",
                "dst_ip": "10.0.1.10",
                "dst_port": 8080,
                "protocol": "tcp",
            }]
        }),
        encoding="utf-8",
    )

    write_allow_rules_for_flows(
        session=None,
        routers=[],
        hosts=[
            NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Workstation"),
            NodeInfo(node_id=2, ip4="10.0.1.10/24", role="Workstation"),
        ],
        traffic_summary_path=str(traffic_path),
        out_dir=str(out_dir),
        src_subnet_prob=0.0,
        dst_subnet_prob=0.0,
        include_hosts=True,
    )

    assert existing.read_text(encoding="utf-8") == "# preview allow\n"
    assert (out_dir / "seg_allow_2_2.py").exists()


def test_allow_rules_accept_postrouting_source_after_masquerade(tmp_path):
    routers = [
        NodeInfo(node_id=100, ip4="10.0.0.1/24", role="Router"),
        NodeInfo(node_id=101, ip4="10.0.2.1/24", role="Router"),
    ]
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Workstation"),
        NodeInfo(node_id=2, ip4="10.0.2.10/24", role="Workstation"),
    ]
    out_dir = tmp_path / "segmentation"
    out_dir.mkdir()
    (out_dir / "segmentation_summary.json").write_text(
        json.dumps({
            "rules": [
                {
                    "node_id": 100,
                    "rule": {
                        "type": "nat",
                        "internal": "10.0.0.0/24",
                        "external": "10.0.2.0/24",
                        "mode": "MASQUERADE",
                        "default_deny": True,
                        "chain": "FORWARD",
                    },
                },
                {
                    "node_id": 101,
                    "rule": {"type": "none", "default_deny": True, "chain": "FORWARD"},
                },
                {
                    "node_id": 2,
                    "rule": {"type": "none", "default_deny": True, "chain": "INPUT"},
                },
            ]
        }),
        encoding="utf-8",
    )
    traffic_path = tmp_path / "traffic_summary.json"
    traffic_path.write_text(
        json.dumps({
            "flows": [{
                "src_id": 1,
                "dst_id": 2,
                "src_ip": "10.0.0.10",
                "dst_ip": "10.0.2.10",
                "dst_port": 5009,
                "protocol": "tcp",
            }]
        }),
        encoding="utf-8",
    )

    result = write_allow_rules_for_flows(
        session=None,
        routers=routers,
        hosts=hosts,
        traffic_summary_path=str(traffic_path),
        out_dir=str(out_dir),
        src_subnet_prob=0.0,
        dst_subnet_prob=0.0,
    )

    observed = {
        (entry["node_id"], entry["rule"]["chain"], entry["rule"]["src"])
        for entry in result["rules"]
    }
    assert (2, "INPUT", "0.0.0.0/0") in observed
    assert (100, "FORWARD", "10.0.0.10") in observed
    assert (101, "FORWARD", "0.0.0.0/0") in observed
    assert (1, "OUTPUT", "10.0.0.10") in observed

    downstream_script = "\n".join(
        path.read_text("utf-8") for path in out_dir.glob("seg_allow_101_*.py")
    )
    assert (
        "iptables -I FORWARD 1 -p tcp -s 0.0.0.0/0 "
        "-d 10.0.2.10 --dport 5009 -j ACCEPT"
    ) in downstream_script


def test_compose_ports_for_vulns_and_flag_node_generators_are_allowed_idempotently(tmp_path):
    vuln_compose = tmp_path / "vuln-compose.yml"
    vuln_compose.write_text(
        """
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80/tcp"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    flag_node_compose = tmp_path / "flag-node-compose.yml"
    flag_node_compose.write_text(
        """
services:
  challenge:
    image: alpine:latest
    expose:
      - "2222/tcp"
      - "5353/udp"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    routers = [NodeInfo(node_id=100, ip4="10.0.0.1/24", role="Router")]
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Docker"),
        NodeInfo(node_id=2, ip4="10.0.1.10/24", role="Docker"),
    ]
    session = _DummySession([
        _DummyNode(100, "router-1"),
        _DummyNode(1, "vuln-node"),
        _DummyNode(2, "flag-node"),
    ])

    out_dir = tmp_path / "segmentation"
    out_dir.mkdir()
    segmentation_summary = {
        "rules": [
            {
                "node_id": 100,
                "service": "Segmentation",
                "rule": {"type": "nat", "default_deny": True, "chain": "FORWARD"},
                "script": str(out_dir / "seg_nat_100_1.py"),
            },
            {
                "node_id": 1,
                "service": "Segmentation",
                "rule": {"type": "none", "default_deny": True, "chain": "INPUT"},
                "script": str(out_dir / "seg_none_1_1.py"),
            },
            {
                "node_id": 2,
                "service": "Segmentation",
                "rule": {"type": "none", "default_deny": True, "chain": "INPUT"},
                "script": str(out_dir / "seg_none_2_1.py"),
            },
        ]
    }
    (out_dir / "segmentation_summary.json").write_text(json.dumps(segmentation_summary), encoding="utf-8")

    docker_nodes = {
        "vuln-node": {
            "Name": "Demo Vulnerability",
            "Type": "docker-compose",
            "Path": str(vuln_compose),
            "CoreTGVulnAssignment": "1",
        },
        "flag-node": {
            "Name": "Demo Flag Node Generator",
            "Type": "docker-compose",
            "Path": str(flag_node_compose),
            "Vector": "flag-nodegen",
        },
    }

    first = write_allow_rules_for_compose_ports(
        session=session,
        routers=routers,
        hosts=hosts,
        docker_nodes=docker_nodes,
        out_dir=str(out_dir),
    )
    assert len(first.get("rules") or []) == 6

    second = write_allow_rules_for_compose_ports(
        session=session,
        routers=routers,
        hosts=hosts,
        docker_nodes=docker_nodes,
        out_dir=str(out_dir),
    )
    assert second.get("rules") == []

    summary_after = json.loads((out_dir / "segmentation_summary.json").read_text("utf-8"))
    compose_allow_rules = [
        rule for rule in (summary_after.get("rules") or [])
        if (rule.get("rule") or {}).get("reason") == "compose_port"
    ]
    assert len(compose_allow_rules) == 6

    observed = {
        (
            rule.get("node_id"),
            (rule.get("rule") or {}).get("chain"),
            (rule.get("rule") or {}).get("proto"),
            int((rule.get("rule") or {}).get("port")),
            (rule.get("rule") or {}).get("dst"),
        )
        for rule in compose_allow_rules
    }
    assert (1, "INPUT", "tcp", 80, "10.0.0.10") in observed
    assert (100, "FORWARD", "tcp", 80, "10.0.0.10") in observed
    assert (2, "INPUT", "tcp", 2222, "10.0.1.10") in observed
    assert (100, "FORWARD", "tcp", 2222, "10.0.1.10") in observed
    assert (2, "INPUT", "udp", 5353, "10.0.1.10") in observed
    assert (100, "FORWARD", "udp", 5353, "10.0.1.10") in observed

    script_text = "\n".join(
        (out_dir / path.name).read_text("utf-8")
        for path in out_dir.glob("seg_compose_allow_*.py")
    )
    assert "iptables -I INPUT 1 -p tcp -s 0.0.0.0/0 --dport 80 -j ACCEPT" in script_text
    assert "iptables -I FORWARD 1 -p udp -s 0.0.0.0/0 -d 10.0.1.10 --dport 5353 -j ACCEPT" in script_text
