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

    progress_messages = []

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
        flow_progress=progress_messages.append,
    )

    assert result.get("response") is None
    assert [node.get("id") for node in result.get("chain_nodes") or []] == ["jump", "db"]
    assert [assignment.get("node_id") for assignment in result.get("flag_assignments") or []] == ["jump", "db"]
    assert result.get("flow_valid") is True, result.get("flow_errors")
    assert result.get("flags_enabled") is True
    assert "repaired" in str(result.get("warning") or "").lower()
    joined_progress = "\n".join(progress_messages)
    assert "Solve: building topology graph from preview plan" in joined_progress
    assert "Solve: repairing explicit chain ids=db,jump" in joined_progress
    assert "Solve: reordering chain by dependency DAG" in joined_progress
    assert "Solve complete:" in joined_progress


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


def test_pivot_apply_skips_requires_when_source_not_in_chain():
    """Pivot source nodes absent from the chain must not add Pivot facts as
    hard generator dependencies.  Adding them when the producer is missing
    from the chain permanently invalidates the dependency order check and
    blocks all flag execution (the real-world 7-node chain_ids=19,22,21,17,16,20,18 bug).
    """
    # Topology: docker-11 -> [19, 22], docker-13 -> [19, 22, 21, 17, 16, 20]
    # Chain contains only the TARGET nodes (11 and 13 are NOT in the chain).
    chain_nodes = [
        {"id": "19", "name": "docker-19", "type": "docker",
         "PivotRequires": ["Pivot(docker-11)", "Pivot(docker-13)"],
         "SegmentationExposure": "pivot-only"},
        {"id": "22", "name": "docker-22", "type": "docker",
         "PivotRequires": ["Pivot(docker-11)", "Pivot(docker-13)"],
         "SegmentationExposure": "pivot-only"},
        {"id": "21", "name": "docker-21", "type": "docker",
         "PivotRequires": ["Pivot(docker-13)"],
         "SegmentationExposure": "pivot-only"},
        {"id": "18", "name": "docker-18", "type": "docker"},
    ]
    assignments = [
        {"node_id": "19", "id": "db-flag", "type": "flag-node-generator",
         "inputs": [], "outputs": [], "requires": [], "produces": []},
        {"node_id": "22", "id": "db-flag", "type": "flag-node-generator",
         "inputs": [], "outputs": [], "requires": [], "produces": []},
        {"node_id": "21", "id": "db-flag", "type": "flag-node-generator",
         "inputs": [], "outputs": [], "requires": [], "produces": []},
        {"node_id": "18", "id": "db-flag", "type": "flag-node-generator",
         "inputs": [], "outputs": [], "requires": [], "produces": []},
    ]
    # No pivot source nodes (11 or 13) appear in chain_nodes.
    enriched = app_backend._flow_apply_pivot_context_to_assignments(
        assignments,
        chain_nodes,
        preview=None,
        pivot_context={},
        scenario_label="missing-source-test",
    )

    # Pivot metadata hints may still be added, but NEVER hard dependencies
    # for facts whose producer is outside the chain.
    for a in enriched:
        assert "Pivot(docker-11)" not in (a.get("inputs") or []), (
            f"node {a['node_id']} should not require Pivot(docker-11) - source 11 not in chain"
        )
        assert "Pivot(docker-13)" not in (a.get("inputs") or []), (
            f"node {a['node_id']} should not require Pivot(docker-13) - source 13 not in chain"
        )
        assert "Pivot(docker-11)" not in (a.get("requires") or []), (
            f"node {a['node_id']} should not have Pivot(docker-11) in requires"
        )
        assert "Pivot(docker-13)" not in (a.get("requires") or []), (
            f"node {a['node_id']} should not have Pivot(docker-13) in requires"
        )

    # The chain order validation must now pass with no "before they are produced" errors.
    # (Unknown-plugin warnings are expected since we pass no plugin registry here.)
    _, errors = app_backend._flow_validate_chain_order_by_requires_produces(
        chain_nodes, enriched, scenario_label="missing-source-test",
    )
    pivot_order_errors = [e for e in (errors or []) if "before they are produced" in str(e)]
    assert not pivot_order_errors, (
        f"Chain should have no 'before they are produced' errors when pivot sources are absent: {pivot_order_errors}"
    )


def test_pivot_apply_prunes_saved_requires_when_source_not_in_chain():
    """Saved Flow state can already contain stale Pivot facts.  When the
    producer is absent from the execution chain those facts must be removed
    from both requires and inputs before order validation runs.
    """
    chain_nodes = [
        {"id": "21", "name": "docker-21", "type": "docker", "PivotRequires": ["Pivot(docker-11)"]},
        {"id": "19", "name": "docker-19", "type": "docker", "PivotRequires": ["Pivot(docker-11)"]},
        {"id": "20", "name": "docker-20", "type": "docker", "PivotRequires": ["Pivot(docker-11)"]},
        {"id": "16", "name": "docker-16", "type": "docker"},
    ]
    assignments = [
        {"node_id": "21", "id": "db-flag", "type": "flag-node-generator",
         "inputs": ["Pivot(docker-11)"], "outputs": [], "requires": ["Pivot(docker-11)"], "produces": []},
        {"node_id": "19", "id": "db-flag", "type": "flag-node-generator",
         "inputs": ["Pivot(docker-11)"], "outputs": [], "requires": ["Pivot(docker-11)"], "produces": []},
        {"node_id": "20", "id": "db-flag", "type": "flag-node-generator",
         "inputs": ["Pivot(docker-11)"], "outputs": [], "requires": ["Pivot(docker-11)"], "produces": []},
        {"node_id": "16", "id": "db-flag", "type": "flag-node-generator",
         "inputs": [], "outputs": [], "requires": [], "produces": []},
    ]
    preview = {
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "host_router_map": {},
        "r2r_links_preview": [],
        "hosts": [
            {"node_id": "11", "name": "docker-11", "role": "Docker", "ip4": "10.0.0.11"},
            {"node_id": "21", "name": "docker-21", "role": "Docker", "ip4": "10.0.0.21"},
            {"node_id": "19", "name": "docker-19", "role": "Docker", "ip4": "10.0.0.19"},
            {"node_id": "20", "name": "docker-20", "role": "Docker", "ip4": "10.0.0.20"},
            {"node_id": "16", "name": "docker-16", "role": "Docker", "ip4": "10.0.0.16"},
        ],
    }
    pivot_context = {
        "metadata": {
            "pivoting": {
                "rules": [
                    {
                        "pivot_nodes": ["docker-11"],
                        "target_node": target,
                        "produces": ["Shell(docker-11)", "Pivot(docker-11)"],
                        "target_requires": ["Pivot(docker-11)"],
                    }
                    for target in ("docker-21", "docker-19", "docker-20")
                ]
            }
        }
    }

    enriched = app_backend._flow_apply_pivot_context_to_assignments(
        assignments,
        chain_nodes,
        preview=preview,
        pivot_context=pivot_context,
        scenario_label="stale-missing-source-test",
    )

    for node_id in ("21", "19", "20"):
        assignment = next(a for a in enriched if a["node_id"] == node_id)
        assert "Pivot(docker-11)" not in (assignment.get("inputs") or [])
        assert "Pivot(docker-11)" not in (assignment.get("requires") or [])

    ok, errors = app_backend._flow_validate_chain_order_by_requires_produces(
        chain_nodes,
        enriched,
        scenario_label="stale-missing-source-test",
        plugins_by_id_override=_plugins_by_id(),
    )
    assert ok, errors


def test_pivot_apply_prunes_saved_requires_without_matching_rule():
    """A saved assignment may carry a stale Pivot fact even when current
    pivot metadata does not produce a rule for that missing source.
    """
    chain_nodes = [
        {"id": "16", "name": "docker-16", "type": "docker"},
        {"id": "18", "name": "docker-18", "type": "docker"},
        {"id": "21", "name": "docker-21", "type": "docker"},
        {"id": "22", "name": "docker-22", "type": "docker"},
        {"id": "17", "name": "docker-17", "type": "docker"},
        {"id": "19", "name": "docker-19", "type": "docker"},
        {"id": "20", "name": "docker-20", "type": "docker"},
    ]
    assignments = [
        {"node_id": "16", "id": "db-flag", "type": "flag-node-generator",
         "inputs": ["Pivot(docker-13)"], "outputs": [], "requires": ["Pivot(docker-13)"], "produces": []},
        *[
            {"node_id": node_id, "id": "db-flag", "type": "flag-node-generator",
             "inputs": [], "outputs": [], "requires": [], "produces": []}
            for node_id in ("18", "21", "22", "17", "19", "20")
        ],
    ]

    enriched = app_backend._flow_apply_pivot_context_to_assignments(
        assignments,
        chain_nodes,
        preview=None,
        pivot_context={},
        scenario_label="stale-pivot-no-rule-test",
    )

    first = enriched[0]
    assert "Pivot(docker-13)" not in (first.get("inputs") or [])
    assert "Pivot(docker-13)" not in (first.get("requires") or [])

    ok, errors = app_backend._flow_validate_chain_order_by_requires_produces(
        chain_nodes,
        enriched,
        scenario_label="stale-pivot-no-rule-test",
        plugins_by_id_override=_plugins_by_id(),
    )
    assert ok, errors


def test_pivot_apply_prunes_self_alias_requires_without_matching_rule():
    """A stale pivot fact can point at the current node's display alias.

    In live plans node ids may be numeric while names keep docker-* aliases; a
    node must not require its own pivot fact before it can execute.
    """
    chain_nodes = [
        {"id": "16", "name": "docker-13", "type": "docker"},
        {"id": "18", "name": "docker-18", "type": "docker"},
        {"id": "20", "name": "docker-20", "type": "docker"},
        {"id": "22", "name": "docker-22", "type": "docker"},
        {"id": "21", "name": "docker-21", "type": "docker"},
        {"id": "17", "name": "docker-17", "type": "docker"},
        {"id": "19", "name": "docker-19", "type": "docker"},
    ]
    assignments = [
        {"node_id": "16", "id": "db-flag", "type": "flag-node-generator",
         "inputs": ["Pivot(docker-13)"], "outputs": [], "requires": ["Pivot(docker-13)"], "produces": []},
        *[
            {"node_id": node_id, "id": "db-flag", "type": "flag-node-generator",
             "inputs": [], "outputs": [], "requires": [], "produces": []}
            for node_id in ("18", "20", "22", "21", "17", "19")
        ],
    ]

    enriched = app_backend._flow_apply_pivot_context_to_assignments(
        assignments,
        chain_nodes,
        preview=None,
        pivot_context={},
        scenario_label="stale-self-pivot-no-rule-test",
    )

    first = enriched[0]
    assert "Pivot(docker-13)" not in (first.get("inputs") or [])
    assert "Pivot(docker-13)" not in (first.get("requires") or [])

    ok, errors = app_backend._flow_validate_chain_order_by_requires_produces(
        chain_nodes,
        enriched,
        scenario_label="stale-self-pivot-no-rule-test",
        plugins_by_id_override=_plugins_by_id(),
    )
    assert ok, errors


def test_pivot_apply_consolidates_multi_source_hints():
    """When a node is a pivot target of multiple source nodes, only a single
    consolidated 'Pivot required' hint should appear - not one per source rule.
    """
    # docker-14 is reachable via both docker-11 and docker-13 (two rules).
    chain_nodes = [
        {"id": "docker-11", "name": "docker-11 @ 10.51.145.4", "type": "docker"},
        {"id": "docker-13", "name": "docker-13 @ 10.82.34.4", "type": "docker"},
        {"id": "docker-14", "name": "docker-14 @ 172.29.115.4", "type": "docker",
         "PivotRequires": ["Pivot(docker-11 @ 10.51.145.4)", "Pivot(docker-13 @ 10.82.34.4)"],
         "SegmentationExposure": "pivot-only"},
    ]
    assignments = [
        {"node_id": "docker-11", "id": "pivot-rce", "type": "flag-generator",
         "inputs": [], "outputs": [], "requires": [], "produces": []},
        {"node_id": "docker-13", "id": "pivot-rce", "type": "flag-generator",
         "inputs": [], "outputs": [], "requires": [], "produces": []},
        {"node_id": "docker-14", "id": "db-flag", "type": "flag-node-generator",
         "inputs": [], "outputs": [], "requires": [], "produces": []},
    ]
    pivot_context = {
        "metadata": {
            "pivoting": {
                "rules": [
                    {
                        "source_id": "docker-11",
                        "source_name": "docker-11 @ 10.51.145.4",
                        "target_id": "docker-14",
                        "target_name": "docker-14 @ 172.29.115.4",
                        "produces": ["Pivot(docker-11 @ 10.51.145.4)"],
                        "target_requires": ["Pivot(docker-11 @ 10.51.145.4)"],
                        "access_provider": "vulnerability",
                    },
                    {
                        "source_id": "docker-13",
                        "source_name": "docker-13 @ 10.82.34.4",
                        "target_id": "docker-14",
                        "target_name": "docker-14 @ 172.29.115.4",
                        "produces": ["Pivot(docker-13 @ 10.82.34.4)"],
                        "target_requires": ["Pivot(docker-13 @ 10.82.34.4)"],
                        "access_provider": "vulnerability",
                    },
                ]
            }
        }
    }

    enriched = app_backend._flow_apply_pivot_context_to_assignments(
        assignments, chain_nodes, preview=None, pivot_context=pivot_context,
        scenario_label="multi-pivot-hint-test",
    )

    target_assignment = next(a for a in enriched if a["node_id"] == "docker-14")
    pivot_hints = [h for h in (target_assignment.get("hints") or []) if "Pivot required" in h]

    assert len(pivot_hints) == 1, (
        f"Expected exactly one consolidated 'Pivot required' hint, got {len(pivot_hints)}: {pivot_hints}"
    )
    # The single hint must name both sources.
    combined_hint = pivot_hints[0]
    assert "docker-11" in combined_hint, f"Expected docker-11 in hint: {combined_hint}"
    assert "docker-13" in combined_hint, f"Expected docker-13 in hint: {combined_hint}"
