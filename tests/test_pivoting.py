import json

from scenarioforge.cli import (
    _apply_pivoting_to_docker_nodes,
    _flow_pivot_items_from_state,
    _runtime_pivot_items,
)
from scenarioforge.parsers.pivoting import parse_pivoting_info
from scenarioforge.sequencer.chain import validate_chain_doc, validate_linear_chain
from scenarioforge.sequencer.dag import build_dag
from scenarioforge.types import NodeInfo, PivotInfo
from scenarioforge.utils.vuln_process import extract_compose_ports, prepare_compose_for_assignments
from scenarioforge.utils.segmentation import write_allow_rules_for_compose_ports


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


def _pivot_summary_to_chain_doc(summary):
    rules = summary.get("rules") or []
    pivot_names = []
    for entry in rules:
        for pivot_name in entry.get("pivot_nodes") or []:
            if pivot_name not in pivot_names:
                pivot_names.append(pivot_name)
    challenges = []
    for pivot_name in pivot_names:
        pivot_rule = next(entry for entry in rules if pivot_name in (entry.get("pivot_nodes") or []))
        challenges.append({
            "challenge_id": f"pivot-{pivot_name}",
            "kind": "flag-generator",
            "requires": [{"artifact": artifact} for artifact in (pivot_rule.get("requires") or [])],
            "produces": [
                {"name": artifact, "artifact": artifact}
                for artifact in (pivot_rule.get("produces") or [])
                if artifact.startswith("Pivot(") or artifact.startswith("Shell(")
            ],
            "plugin": f"provider-{pivot_name}",
        })
    for entry in rules:
        pivot_name = (entry.get("pivot_nodes") or [""])[0]
        challenges.append({
            "challenge_id": f"target-{entry.get('target_node')}",
            "kind": "flag-node-generator",
            "requires": [
                {"artifact": artifact, "source": f"pivot-{pivot_name}"}
                for artifact in (entry.get("target_requires") or [])
            ],
            "produces": [],
            "plugin": f"target-{entry.get('target_node')}",
        })
    return {"challenges": challenges}


def test_parse_pivoting_info_accepts_pivot_contract(tmp_path):
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text(
        """
<Scenarios>
  <Scenario name="Pivot Demo">
    <ScenarioEditor>
      <section name="Pivoting" density="1.0">
        <item selected="RCE Pivot" factor="1.0" pivot_node="jump-web" target_node="internal-db" target_ports="5432" target_protocols="tcp" target_exposure="pivot-only" source_scope="host" produces="Shell(jump-web),Pivot(jump-web)" requires="WebRCE(jump-web)" />
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>
""".strip(),
        encoding="utf-8",
    )

    density, items = parse_pivoting_info(str(xml_path), "Pivot Demo")

    assert density == 1.0
    assert len(items) == 1
    assert items[0].name == "RCE Pivot"
    assert items[0].pivot_node == "jump-web"
    assert items[0].target_node == "internal-db"
    assert items[0].target_ports == "5432"
    assert items[0].target_protocols == "tcp"
    assert items[0].exposure == "pivot-only"
    assert items[0].produces == "Shell(jump-web),Pivot(jump-web)"
    assert items[0].origin == "pivoting"


def test_parse_pivoting_info_synthesizes_segmentation_shortcut(tmp_path):
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text(
        """
<Scenarios>
    <Scenario name="Pivot Demo">
        <ScenarioEditor>
            <section name="Segmentation" density="1.0">
                <item selected="Firewall" factor="1.0" pivot_enabled="true" pivot_provider="random" />
            </section>
        </ScenarioEditor>
    </Scenario>
</Scenarios>
""".strip(),
        encoding="utf-8",
    )

    density, items = parse_pivoting_info(str(xml_path), "Pivot Demo")

    assert density == 1.0
    assert len(items) == 1
    assert items[0].name == "Firewall"
    assert items[0].pivot_node == ""
    assert items[0].target_node == ""
    assert items[0].target_ports == ""
    assert items[0].access_provider == "random"
    assert items[0].origin == "segmentation"


def test_runtime_pivot_items_leave_segmentation_to_pivot_access():
    explicit = PivotInfo(
        name="Explicit pivot",
        pivot_node="jump-web",
        target_node="internal-db",
    )
    segmentation = PivotInfo(
        name="Firewall Pivot",
        access_provider="ssh-fallback",
        origin="segmentation",
    )
    flow_state = {
        "flow_enabled": True,
        "flag_assignments": [{
            "name": "Flow target",
            "node_name": "internal-api",
            "pivot": [{
                "role": "target",
                "source": "jump-web",
                "target": "internal-api",
                "provider": "vulnerability",
            }],
        }],
    }

    items = _runtime_pivot_items([segmentation, explicit], flow_state)

    assert [item.name for item in items] == ["Explicit pivot", "Flow target"]
    assert all(item.origin != "segmentation" for item in items)


def test_apply_pivoting_to_docker_nodes_marks_target_exposure():
    session = _DummySession([
        _DummyNode(1, "jump-web"),
        _DummyNode(2, "internal-db"),
    ])
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Web"),
        NodeInfo(node_id=2, ip4="10.0.1.20/24", role="Docker"),
    ]
    docker_nodes = {
        "internal-db": {
            "Name": "Internal DB",
            "Type": "docker-compose",
            "Path": "/tmp/internal-db.yml",
        }
    }

    summary = _apply_pivoting_to_docker_nodes(
        session=session,
        hosts=hosts,
        docker_nodes=docker_nodes,
        pivot_items=[
            PivotInfo(
                name="RCE Pivot",
                pivot_node="jump-web",
                target_node="internal-db",
                target_ports="5432",
                target_protocols="tcp",
                exposure="pivot-only",
            )
        ],
    )

    assert summary["warnings"] == []
    assert summary["nodes"] == ["internal-db"]
    assert docker_nodes["internal-db"]["SegmentationExposure"] == "pivot-only"
    assert docker_nodes["internal-db"]["SegmentationSources"] == ["10.0.0.10"]
    assert docker_nodes["internal-db"]["SegmentationPorts"] == ["5432"]
    assert docker_nodes["internal-db"]["SegmentationProtocols"] == ["tcp"]
    assert docker_nodes["internal-db"]["PivotRequires"] == ["Pivot(jump-web)"]
    assert summary["rules"][0]["target_requires"] == ["Pivot(jump-web)"]


def test_flow_pivot_targets_feed_runtime_exposure_metadata():
    flow_state = {
        "flow_enabled": True,
        "flag_assignments": [
            {
                "node_name": "jump-web",
                "pivot": [
                    {
                        "role": "source",
                        "source": "jump-web",
                        "target": "internal-db",
                        "provider": "vulnerability",
                    }
                ],
            },
            {
                "name": "Internal database challenge",
                "node_name": "internal-db",
                "pivot": [
                    {
                        "role": "target",
                        "source": "jump-web",
                        "target": "internal-db",
                        "provider": "vulnerability",
                        "requires": ["Pivot(jump-web)"],
                        "target_ports": [],
                        "target_protocols": [],
                        "exposure": "pivot-only",
                    }
                ],
            },
        ],
    }

    pivot_items = _flow_pivot_items_from_state(flow_state)

    assert len(pivot_items) == 1
    assert pivot_items[0].pivot_node == "jump-web"
    assert pivot_items[0].target_node == "internal-db"
    assert pivot_items[0].target_ports == ""

    session = _DummySession([
        _DummyNode(1, "jump-web"),
        _DummyNode(2, "internal-db"),
    ])
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Docker"),
        NodeInfo(node_id=2, ip4="10.0.1.20/24", role="Docker"),
    ]
    docker_nodes = {
        "jump-web": {
            "Name": "Existing vulnerability",
            "Type": "docker-compose",
            "Path": "/tmp/jump-web.yml",
            "Vector": "vulnerability",
        },
        "internal-db": {
            "Name": "Internal DB",
            "Type": "docker-compose",
            "Path": "/tmp/internal-db.yml",
        },
    }

    summary = _apply_pivoting_to_docker_nodes(
        session=session,
        hosts=hosts,
        docker_nodes=docker_nodes,
        pivot_items=pivot_items,
    )

    assert summary["warnings"] == []
    assert docker_nodes["internal-db"]["SegmentationExposure"] == "pivot-only"
    assert docker_nodes["internal-db"]["SegmentationSources"] == ["10.0.0.10"]
    assert docker_nodes["internal-db"]["PivotRequires"] == ["Pivot(jump-web)"]


def test_flow_pivot_uses_preview_names_when_live_session_has_no_node_lookup():
    class _SessionWithoutNodeNames:
        def get_node(self, _node_id):
            return None

    hosts = [
        NodeInfo(node_id=16, ip4="10.0.0.10/24", role="Docker"),
        NodeInfo(node_id=18, ip4="10.0.1.20/24", role="Docker"),
    ]
    docker_nodes = {
        "docker-13": {
            "Name": "Existing flag generator",
            "Type": "docker-compose",
            "Path": "/tmp/docker-13.yml",
            "Vector": "flag-nodegen",
        },
        "flaggenslot-15": {
            "Name": "Pivot target",
            "Type": "docker-compose",
            "Path": "/tmp/flaggenslot-15.yml",
        },
    }

    summary = _apply_pivoting_to_docker_nodes(
        session=_SessionWithoutNodeNames(),
        hosts=hosts,
        docker_nodes=docker_nodes,
        pivot_items=[
            PivotInfo(
                name="Flow pivot",
                pivot_node="docker-13",
                target_node="flaggenslot-15",
                exposure="pivot-only",
                access_provider="ssh-fallback",
            )
        ],
        node_names_by_id={16: "docker-13", 18: "flaggenslot-15"},
    )

    assert summary["nodes"] == ["flaggenslot-15"]
    assert docker_nodes["flaggenslot-15"]["SegmentationSources"] == ["10.0.0.10"]


def test_compose_allow_uses_preview_names_when_live_session_has_no_node_lookup(tmp_path):
    class _SessionWithoutNodeNames:
        def get_node(self, _node_id):
            return None

    compose_path = tmp_path / "target-compose.yml"
    compose_path.write_text(
        "services:\n  node:\n    image: alpine:3.19\n    expose:\n      - '8080/tcp'\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "segmentation"
    out_dir.mkdir()
    (out_dir / "segmentation_summary.json").write_text(
        json.dumps({
            "rules": [{
                "node_id": 100,
                "service": "Segmentation",
                "rule": {"type": "nat", "default_deny": True, "chain": "FORWARD"},
                "script": str(out_dir / "seg_nat_100_1.py"),
            }]
        }),
        encoding="utf-8",
    )
    result = write_allow_rules_for_compose_ports(
        session=_SessionWithoutNodeNames(),
        routers=[NodeInfo(node_id=100, ip4="10.0.0.1/24", role="Router")],
        hosts=[
            NodeInfo(node_id=16, ip4="10.0.0.10/24", role="Docker"),
            NodeInfo(node_id=18, ip4="10.0.1.20/24", role="Docker"),
        ],
        docker_nodes={
            "flaggenslot-15": {
                "Name": "Pivot target",
                "Path": str(compose_path),
                "SegmentationExposure": "pivot-only",
                "SegmentationSources": ["10.0.0.10"],
            }
        },
        out_dir=str(out_dir),
        node_names_by_id={16: "docker-13", 18: "flaggenslot-15"},
    )

    rules = [entry.get("rule") or {} for entry in (result.get("rules") or [])]
    assert len(rules) == 1
    assert rules[0]["src"] == "10.0.0.10"
    assert rules[0]["dst"] == "10.0.1.20"
    assert rules[0]["port"] == 8080


def test_apply_pivoting_ssh_fallback_assigns_docker_ssh_container():
    session = _DummySession([
        _DummyNode(1, "jump-web"),
        _DummyNode(2, "internal-db"),
    ])
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Web"),
        NodeInfo(node_id=2, ip4="10.0.1.20/24", role="Docker"),
    ]
    docker_nodes = {
        "jump-web": {
            "Name": "standard-ubuntu-docker-core",
            "Type": "docker-compose",
            "Path": "/tmp/standard.yml",
            "Vector": "standard",
        },
        "internal-db": {
            "Name": "Internal DB",
            "Type": "docker-compose",
            "Path": "/tmp/internal-db.yml",
        }
    }

    summary = _apply_pivoting_to_docker_nodes(
        session=session,
        hosts=hosts,
        docker_nodes=docker_nodes,
        pivot_items=[
            PivotInfo(
                name="SSH Pivot",
                pivot_node="jump-web",
                target_node="internal-db",
                target_ports="5432",
                target_protocols="tcp",
                access_provider="ssh-fallback",
            )
        ],
    )

    assert summary["warnings"] == []
    assert summary["ssh_fallback_nodes"] == ["jump-web"]
    assert summary["ssh_service_nodes"] == []
    assert session.services.get(1) == []
    assert docker_nodes["jump-web"]["Name"] == "pivot-ssh-container"
    assert docker_nodes["jump-web"]["Vector"] == "pivot-ssh-fallback"
    assert docker_nodes["jump-web"]["compose_ports"] == [{"service": "pivot_ssh", "protocol": "tcp", "port": 2222}]
    assert docker_nodes["internal-db"]["PivotAccessProvider"] == "ssh-fallback"
    assert docker_nodes["jump-web"]["PivotProduces"] == ["Shell(jump-web)", "Pivot(jump-web)"]
    assert docker_nodes["internal-db"]["PivotRequires"] == ["Pivot(jump-web)"]


def test_apply_pivoting_random_provider_infers_source_and_targets():
    session = _DummySession([
        _DummyNode(1, "jump-web"),
        _DummyNode(2, "internal-db"),
        _DummyNode(3, "internal-api"),
    ])
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Docker"),
        NodeInfo(node_id=2, ip4="10.0.1.20/24", role="Docker"),
        NodeInfo(node_id=3, ip4="10.0.1.30/24", role="Docker"),
    ]
    docker_nodes = {
        "jump-web": {
            "Name": "standard-ubuntu-docker-core",
            "Type": "docker-compose",
            "Path": "/tmp/standard.yml",
            "Vector": "standard",
        },
        "internal-db": {
            "Name": "Internal DB",
            "Type": "docker-compose",
            "Path": "/tmp/internal-db.yml",
        },
        "internal-api": {
            "Name": "Internal API",
            "Type": "docker-compose",
            "Path": "/tmp/internal-api.yml",
        },
    }

    summary = _apply_pivoting_to_docker_nodes(
        session=session,
        hosts=hosts,
        docker_nodes=docker_nodes,
        pivot_items=[PivotInfo(name="Firewall", access_provider="random")],
    )

    assert summary["warnings"] == []
    assert summary["ssh_fallback_nodes"] == ["jump-web"]
    assert summary["nodes"] == ["internal-api", "internal-db"]
    assert docker_nodes["jump-web"]["Name"] == "pivot-ssh-container"
    assert docker_nodes["jump-web"]["PivotProduces"] == ["Shell(jump-web)", "Pivot(jump-web)"]
    for target_name in ("internal-db", "internal-api"):
        assert docker_nodes[target_name]["SegmentationExposure"] == "pivot-only"
        assert docker_nodes[target_name]["SegmentationSources"] == ["10.0.0.10"]
        assert docker_nodes[target_name]["PivotAccessProvider"] == "ssh-fallback"
        assert docker_nodes[target_name]["PivotRequires"] == ["Pivot(jump-web)"]

    chain_doc = _pivot_summary_to_chain_doc(summary)
    ok, errors, norm = validate_chain_doc(chain_doc)
    assert ok, errors
    ok_linear, linear_errors = validate_linear_chain(norm)
    assert ok_linear, linear_errors

    plugins_by_id = {}
    for challenge in chain_doc["challenges"]:
        plugins_by_id[challenge["plugin"]] = {
            "requires": [req["artifact"] for req in (challenge.get("requires") or [])],
            "produces": list(challenge.get("produces") or []),
        }
    dag, dag_errors = build_dag(chain_doc["challenges"], plugins_by_id=plugins_by_id)
    assert dag_errors == []
    assert dag is not None
    assert dag.order[0] == "pivot-jump-web"
    assert set(dag.order[1:]) == {"target-internal-api", "target-internal-db"}
    assert {edge.artifact for edge in dag.edges} == {"Pivot(jump-web)"}


def test_docker_ssh_fallback_compose_prepares_and_exposes_ssh_port(tmp_path):
    session = _DummySession([
        _DummyNode(1, "jump-web"),
        _DummyNode(2, "internal-db"),
    ])
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Docker"),
        NodeInfo(node_id=2, ip4="10.0.1.20/24", role="Docker"),
    ]
    docker_nodes = {
        "jump-web": {
            "Name": "standard-ubuntu-docker-core",
            "Type": "docker-compose",
            "Path": "/tmp/standard.yml",
            "Vector": "standard",
        },
        "internal-db": {
            "Name": "Internal DB",
            "Type": "docker-compose",
            "Path": "/tmp/internal-db.yml",
        },
    }

    _apply_pivoting_to_docker_nodes(
        session=session,
        hosts=hosts,
        docker_nodes=docker_nodes,
        pivot_items=[
            PivotInfo(
                name="SSH Pivot",
                pivot_node="jump-web",
                target_node="internal-db",
                target_ports="5432",
                target_protocols="tcp",
                access_provider="ssh-fallback",
            )
        ],
    )

    created = prepare_compose_for_assignments({"jump-web": docker_nodes["jump-web"]}, out_base=str(tmp_path))

    assert len(created) == 1
    compose_text = (tmp_path / "docker-compose-jump-web.yml").read_text("utf-8")
    assert "lscr.io/linuxserver/openssh-server" in compose_text
    assert "network_mode: none" in compose_text
    assert "2222/tcp" in compose_text
    assert "  jump-web:" in compose_text
    assert "  pivot_ssh:" not in compose_text
    ports = extract_compose_ports(docker_nodes["jump-web"], out_base=str(tmp_path))
    assert any(port.get("protocol") == "tcp" and port.get("port") == 2222 for port in ports)


def test_pivot_only_compose_ports_are_allowed_only_from_pivot(tmp_path):
    compose_path = tmp_path / "internal-compose.yml"
    compose_path.write_text(
        """
services:
  db:
    image: postgres:16
    expose:
      - "5432/tcp"
      - "8080/tcp"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    routers = [NodeInfo(node_id=100, ip4="10.0.0.1/24", role="Router")]
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Web"),
        NodeInfo(node_id=2, ip4="10.0.1.20/24", role="Docker"),
    ]
    session = _DummySession([
        _DummyNode(100, "router-1"),
        _DummyNode(1, "jump-web"),
        _DummyNode(2, "internal-db"),
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
                "node_id": 2,
                "service": "Segmentation",
                "rule": {"type": "none", "default_deny": True, "chain": "INPUT"},
                "script": str(out_dir / "seg_none_2_1.py"),
            },
        ]
    }
    (out_dir / "segmentation_summary.json").write_text(json.dumps(segmentation_summary), encoding="utf-8")

    docker_nodes = {
        "internal-db": {
            "Name": "Internal DB",
            "Type": "docker-compose",
            "Path": str(compose_path),
            "SegmentationExposure": "pivot-only",
            "SegmentationSources": ["10.0.0.10"],
            "SegmentationPorts": ["5432"],
            "SegmentationProtocols": ["tcp"],
        }
    }

    result = write_allow_rules_for_compose_ports(
        session=session,
        routers=routers,
        hosts=hosts,
        docker_nodes=docker_nodes,
        out_dir=str(out_dir),
    )

    assert len(result.get("rules") or []) == 2
    summary_after = json.loads((out_dir / "segmentation_summary.json").read_text("utf-8"))
    pivot_rules = [
        entry for entry in summary_after.get("rules", [])
        if (entry.get("rule") or {}).get("reason") == "compose_port"
    ]
    assert len(pivot_rules) == 2
    observed = {
        (
            entry.get("node_id"),
            (entry.get("rule") or {}).get("chain"),
            (entry.get("rule") or {}).get("src"),
            int((entry.get("rule") or {}).get("port")),
            (entry.get("rule") or {}).get("exposure"),
        )
        for entry in pivot_rules
    }
    assert (2, "INPUT", "10.0.0.10", 5432, "pivot-only") in observed
    assert (100, "FORWARD", "10.0.0.10", 5432, "pivot-only") in observed
    assert all((entry.get("rule") or {}).get("src") != "0.0.0.0/0" for entry in pivot_rules)
    assert all(int((entry.get("rule") or {}).get("port")) == 5432 for entry in pivot_rules)

    script_text = "\n".join(path.read_text("utf-8") for path in out_dir.glob("seg_compose_allow_*.py"))
    assert "iptables -I INPUT 1 -p tcp -s 10.0.0.10 --dport 5432 -j ACCEPT" in script_text
    assert "iptables -I FORWARD 1 -p tcp -s 10.0.0.10 -d 10.0.1.20 --dport 5432 -j ACCEPT" in script_text
    assert "0.0.0.0/0" not in script_text
    assert "--dport 8080" not in script_text


def test_pivot_compose_allow_widens_source_after_masquerade(tmp_path):
    compose_path = tmp_path / "mongo-compose.yml"
    compose_path.write_text(
        "services:\n  db:\n    image: mongo:latest\n    expose:\n      - '17017/tcp'\n",
        encoding="utf-8",
    )
    routers = [
        NodeInfo(node_id=100, ip4="10.0.0.1/24", role="Router"),
        NodeInfo(node_id=101, ip4="192.168.1.1/24", role="Router"),
    ]
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Docker"),
        NodeInfo(node_id=2, ip4="192.168.1.20/24", role="Docker"),
    ]
    session = _DummySession([
        _DummyNode(100, "router-1"), _DummyNode(101, "router-2"),
        _DummyNode(1, "jump"), _DummyNode(2, "db"),
    ])
    out_dir = tmp_path / "segmentation"
    out_dir.mkdir()
    summary = {
        "rules": [
            {
                "node_id": 100,
                "service": "Segmentation",
                "rule": {
                    "type": "nat", "default_deny": True, "chain": "FORWARD",
                    "internal": "10.0.0.0/24", "external": "192.168.1.0/24",
                },
                "script": str(out_dir / "seg_nat_100_1.py"),
            },
            {
                "node_id": 101,
                "service": "Segmentation",
                "rule": {"type": "nat", "default_deny": True, "chain": "FORWARD"},
                "script": str(out_dir / "seg_nat_101_1.py"),
            },
            {
                "node_id": 2,
                "service": "Segmentation",
                "rule": {"type": "none", "default_deny": True, "chain": "INPUT"},
                "script": str(out_dir / "seg_none_2_1.py"),
            },
        ]
    }
    (out_dir / "segmentation_summary.json").write_text(json.dumps(summary), encoding="utf-8")
    docker_nodes = {
        "db": {
            "Name": "Mongo Export",
            "Type": "docker-compose",
            "Path": str(compose_path),
            "SegmentationExposure": "pivot-only",
            "SegmentationSources": ["10.0.0.10"],
            "SegmentationPorts": ["17017"],
        }
    }

    result = write_allow_rules_for_compose_ports(
        session=session,
        routers=routers,
        hosts=hosts,
        docker_nodes=docker_nodes,
        out_dir=str(out_dir),
    )

    observed = {
        (entry["node_id"], entry["rule"]["chain"], entry["rule"]["src"])
        for entry in result["rules"]
    }
    assert (100, "FORWARD", "10.0.0.10") in observed
    assert (101, "FORWARD", "0.0.0.0/0") in observed
    assert (2, "INPUT", "0.0.0.0/0") in observed
