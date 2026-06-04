from webapp import app_backend
from webapp import flow_prepare_preview_execute
from webapp import flow_prepare_preview_helpers


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


def test_flow_reorder_repairs_pivot_target_before_source():
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

    ordered_nodes, ordered_assignments, debug = app_backend._flow_reorder_chain_by_generator_dag(
        chain_nodes,
        enriched,
        scenario_label="pivot-demo",
        dependency_level=3,
        plugins_by_id_override=_plugins_by_id(),
        return_debug=True,
    )

    assert [node.get("id") for node in ordered_nodes] == ["jump", "db"]
    assert [assignment.get("node_id") for assignment in ordered_assignments] == ["jump", "db"]
    assert (debug or {}).get("strategy") == "high_dependency_greedy"
    ok, errors = app_backend._flow_validate_chain_order_by_requires_produces(
        ordered_nodes,
        ordered_assignments,
        scenario_label="pivot-demo",
        plugins_by_id_override=_plugins_by_id(),
    )
    assert ok, errors


def test_prepare_chain_repairs_explicit_pivot_target_before_source(monkeypatch):
    preview = _preview()
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

    def _assignments(_preview, chain_nodes, _scenario_label, **_kwargs):
        assignments = []
        for node in chain_nodes:
            node_id = str(node.get("id") or "")
            if node_id == "jump":
                assignments.append({"node_id": "jump", "id": "pivot-rce", "type": "flag-generator", "inputs": [], "outputs": [], "requires": [], "produces": []})
            else:
                assignments.append({"node_id": node_id, "id": "db-flag", "type": "flag-node-generator", "inputs": [], "outputs": [], "requires": [], "produces": []})
        return assignments

    monkeypatch.setattr(app_backend, "_flow_compute_flag_assignments", _assignments)
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", _plugins_by_id)

    result = flow_prepare_preview_execute._prepare_chain_and_assignments(
        app_backend,
        backend=app_backend,
        helpers=flow_prepare_preview_helpers,
        j={"chain_ids": ["db", "jump"], "debug_dag": True},
        preview=preview,
        flow_state_for_prepare={},
        scenario_label="pivot-demo",
        scenario_norm="pivot-demo",
        preset="",
        preset_steps=[],
        mode="preview",
        best_effort=True,
        allow_node_duplicates=False,
        length=2,
        requested_length=2,
        dependency_level=3,
        initial_facts_override=None,
        goal_facts_override=None,
        base_plan_path="",
        pivot_context=pivot_context,
    )

    assert result.get("response") is None
    assert [node.get("id") for node in result.get("chain_nodes") or []] == ["jump", "db"]
    assert [assignment.get("node_id") for assignment in result.get("flag_assignments") or []] == ["jump", "db"]
    assert result.get("flow_valid") is True, result.get("flow_errors")
    assert result.get("flags_enabled") is True
    assert "repaired" in str(result.get("warning") or "").lower()


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


def test_flow_pivot_context_accepts_full_preview_pivot_provider_key():
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
        "full_preview": {
            "pivoting_plan": {
                "raw_items_serialized": [
                    {"selected": "Firewall", "factor": 1.0, "pivot_provider": "random"}
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
    assert enriched[1].get("pivot", [])[0].get("provider") == "random"


def test_flow_pivot_context_infers_from_node_pivot_annotations():
    preview = _preview()
    chain_nodes = [
        {
            "id": "jump",
            "name": "jump-web",
            "type": "docker",
            "is_vuln": True,
            "PivotProduces": ["Shell(jump-web)", "Pivot(jump-web)"],
        },
        {
            "id": "db",
            "name": "internal-db",
            "type": "docker",
            "is_vuln": False,
            "PivotRequires": ["Pivot(jump-web)"],
            "PivotAccessProvider": "ssh-fallback",
            "SegmentationExposure": "pivot-only",
        },
    ]
    assignments = [
        {"node_id": "jump", "id": "pivot-rce", "type": "flag-generator", "inputs": [], "outputs": [], "requires": [], "produces": []},
        {"node_id": "db", "id": "db-flag", "type": "flag-node-generator", "inputs": [], "outputs": [], "requires": [], "produces": []},
    ]

    enriched = app_backend._flow_apply_pivot_context_to_assignments(
        assignments,
        chain_nodes,
        preview=preview,
        pivot_context={},
        scenario_label="pivot-demo",
    )

    assert "Pivot(jump-web)" in enriched[0].get("outputs", [])
    assert "Pivot(jump-web)" in enriched[1].get("inputs", [])
    assert any(entry.get("provider") == "ssh-fallback" for entry in enriched[1].get("pivot", []))


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
