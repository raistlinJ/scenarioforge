from webapp import app_backend


def _plugins_by_id():
    return {
        "pivot-rce": {
            "plugin_id": "pivot-rce",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": [],
            "produces": [],
            "inputs": {},
        },
        "db-flag": {
            "plugin_id": "db-flag",
            "plugin_type": "flag-node-generator",
            "version": "1.0",
            "requires": [],
            "produces": [],
            "inputs": {},
        },
    }


def _preview():
    return {
        "seed": 7,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "host_router_map": {},
        "r2r_links_preview": [],
        "hosts": [
            {
                "node_id": "jump",
                "name": "jump-web",
                "role": "Docker",
                "ip4": "10.0.0.10",
                "vulnerabilities": [{"name": "rce"}],
            },
            {
                "node_id": "db",
                "name": "internal-db",
                "role": "Docker",
                "ip4": "10.0.1.20",
                "vulnerabilities": [],
            },
        ],
    }


def test_flow_pivot_context_adds_chain_io_hints_and_validates():
    preview = _preview()
    chain_nodes = [
        {"id": "jump", "name": "jump-web", "type": "docker", "is_vuln": True},
        {"id": "db", "name": "internal-db", "type": "docker", "is_vuln": False},
    ]
    assignments = [
        {"node_id": "jump", "id": "pivot-rce", "type": "flag-generator", "inputs": [], "outputs": [], "requires": [], "produces": []},
        {"node_id": "db", "id": "db-flag", "type": "flag-node-generator", "inputs": [], "outputs": [], "requires": [], "produces": []},
    ]
    pivot_context = {
        "metadata": {
            "pivoting": {
                "rules": [
                    {
                        "name": "RCE Pivot",
                        "pivot_nodes": ["jump-web"],
                        "target_node": "internal-db",
                        "access_provider": "vulnerability",
                        "produces": ["Shell(jump-web)", "Pivot(jump-web)"],
                        "target_requires": ["Pivot(jump-web)"],
                        "target_ports": ["5432"],
                    }
                ]
            }
        }
    }

    enriched = app_backend._flow_apply_pivot_context_to_assignments(
        assignments,
        chain_nodes,
        preview=preview,
        pivot_context=pivot_context,
        scenario_label="pivot-demo",
    )

    source, target = enriched
    assert "Shell(jump-web)" in source.get("outputs", [])
    assert "Pivot(jump-web)" in source.get("produces", [])
    assert "Pivot(jump-web)" in target.get("inputs", [])
    assert "Pivot(jump-web)" in target.get("requires", [])
    assert any("Pivot source" in str(hint) for hint in source.get("hints", []))
    assert any("Pivot required" in str(hint) for hint in target.get("hints", []))
    assert source.get("pivot_outputs") == ["Pivot(jump-web)", "Shell(jump-web)"]
    assert target.get("pivot_inputs") == ["Pivot(jump-web)"]

    ok, errors = app_backend._flow_validate_chain_order_by_requires_produces(
        chain_nodes,
        enriched,
        scenario_label="pivot-demo",
        plugins_by_id_override=_plugins_by_id(),
    )
    assert ok, errors


def test_flow_pivot_context_requires_source_before_target():
    preview = _preview()
    chain_nodes = [
        {"id": "db", "name": "internal-db", "type": "docker", "is_vuln": False},
        {"id": "jump", "name": "jump-web", "type": "docker", "is_vuln": True},
    ]
    assignments = [
        {"node_id": "db", "id": "db-flag", "type": "flag-node-generator", "inputs": [], "outputs": [], "requires": [], "produces": []},
        {"node_id": "jump", "id": "pivot-rce", "type": "flag-generator", "inputs": [], "outputs": [], "requires": [], "produces": []},
    ]
    pivot_context = {
        "metadata": {
            "pivoting": {
                "rules": [
                    {
                        "pivot_nodes": ["jump-web"],
                        "target_node": "internal-db",
                        "produces": ["Shell(jump-web)", "Pivot(jump-web)"],
                        "target_requires": ["Pivot(jump-web)"],
                    }
                ]
            }
        }
    }

    enriched = app_backend._flow_apply_pivot_context_to_assignments(
        assignments,
        chain_nodes,
        preview=preview,
        pivot_context=pivot_context,
        scenario_label="pivot-demo",
    )

    ok, errors = app_backend._flow_validate_chain_order_by_requires_produces(
        chain_nodes,
        enriched,
        scenario_label="pivot-demo",
        plugins_by_id_override=_plugins_by_id(),
    )
    assert not ok
    assert any("Pivot(jump-web)" in error for error in errors)


def test_flow_pivot_context_infers_simplified_planner_shortcut():
    preview = _preview()
    chain_nodes = [
        {"id": "jump", "name": "jump-web", "type": "docker", "is_vuln": True},
        {"id": "db", "name": "internal-db", "type": "docker", "is_vuln": False},
    ]
    assignments = [
        {"node_id": "jump", "id": "pivot-rce", "type": "flag-generator", "inputs": [], "outputs": [], "requires": [], "produces": []},
        {"node_id": "db", "id": "db-flag", "type": "flag-node-generator", "inputs": [], "outputs": [], "requires": [], "produces": []},
    ]
    pivot_context = {
        "breakdowns": {
            "pivoting": {
                "raw_items_serialized": [
                    {"selected": "Firewall", "factor": 1.0, "access_provider": "random"}
                ]
            }
        }
    }

    enriched = app_backend._flow_apply_pivot_context_to_assignments(
        assignments,
        chain_nodes,
        preview=preview,
        pivot_context=pivot_context,
        scenario_label="pivot-demo",
    )

    assert "Pivot(jump-web)" in enriched[0].get("outputs", [])
    assert "Pivot(jump-web)" in enriched[1].get("inputs", [])
    assert any(entry.get("role") == "target" for entry in enriched[1].get("pivot", []))


def test_flow_topology_inclusion_adds_all_vuln_nodes_past_initial_length():
    nodes = [
        {"id": "worker", "name": "worker", "type": "docker", "is_vuln": False},
        {"id": "web", "name": "web", "type": "docker", "is_vuln": True, "vulnerabilities": ["rce"]},
        {"id": "api", "name": "api", "type": "docker", "vulnerabilities": ["token-leak"]},
    ]

    expanded, info = app_backend._flow_expand_chain_for_topology_requirements(
        nodes,
        [nodes[0]],
        {"hosts": []},
        include_all_topology_vulns=True,
    )

    assert [node.get("id") for node in expanded] == ["worker", "web", "api"]
    assert info["effective_length"] == 3
    assert info["added_vuln_node_ids"] == ["web", "api"]


def test_flow_topology_inclusion_adds_pivot_source_before_target():
    preview = _preview()
    nodes = [
        {"id": "jump", "name": "jump-web", "type": "docker", "is_vuln": True, "ip4": "10.0.0.10"},
        {"id": "db", "name": "internal-db", "type": "docker", "is_vuln": False, "ip4": "10.0.1.20"},
    ]
    pivot_context = {
        "metadata": {
            "pivoting": {
                "rules": [
                    {
                        "name": "RCE Pivot",
                        "pivot_nodes": ["jump-web"],
                        "target_node": "internal-db",
                        "access_provider": "vulnerability",
                    }
                ]
            }
        }
    }

    expanded, info = app_backend._flow_expand_chain_for_topology_requirements(
        nodes,
        [nodes[1]],
        preview,
        include_all_topology_pivots=True,
        pivot_context=pivot_context,
    )

    assert [node.get("id") for node in expanded] == ["jump", "db"]
    assert info["effective_length"] == 2
    assert info["added_pivot_node_ids"] == ["jump"]
