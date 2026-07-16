from webapp import app_backend


def test_flow_reorder_chain_by_generator_dag_reorders_nodes_and_updates_next_fields():
    chain_nodes = [
        {"id": "n2", "name": "Node 2", "type": "docker"},
        {"id": "n1", "name": "Node 1", "type": "docker"},
    ]

    # n2 depends on artifact produced by n1.
    flag_assignments = [
        {
            "node_id": "n2",
            "id": "g_consumer",
            "name": "Consumer",
            "type": "flag-generator",
            "inputs": ["Knowledge(token)"],
            "outputs": [],
            "hint_template": "Next: {{NEXT_NODE_ID}}",
        },
        {
            "node_id": "n1",
            "id": "g_producer",
            "name": "Producer",
            "type": "flag-generator",
            "inputs": [],
            "outputs": ["Knowledge(token)"],
            "hint_template": "Next: {{NEXT_NODE_ID}}",
        },
    ]

    plugins_by_id = {
        "g_producer": {
            "plugin_id": "g_producer",
            "plugin_type": "flag-generator",
            "version": "test",
            "requires": [],
            "produces": [{"artifact": "Knowledge(token)"}],
            "inputs": {},
        },
        "g_consumer": {
            "plugin_id": "g_consumer",
            "plugin_type": "flag-generator",
            "version": "test",
            "requires": ["Knowledge(token)"],
            "produces": [],
            "inputs": {},
        },
    }

    progress_messages = []
    new_chain, new_assignments, dag_debug = app_backend._flow_reorder_chain_by_generator_dag(
        chain_nodes,
        flag_assignments,
        scenario_label="scenario",
        plugins_by_id_override=plugins_by_id,
        return_debug=True,
        flow_progress=progress_messages.append,
    )

    assert [n["id"] for n in new_chain] == ["n1", "n2"]
    assert [a["node_id"] for a in new_assignments] == ["n1", "n2"]
    assert any("DAG: start nodes=2 assignments=2" in msg for msg in progress_messages)
    assert any("DAG: trying greedy reorder for invalid current chain" in msg for msg in progress_messages)
    assert any("DAG: DAG reorder complete" in msg for msg in progress_messages)

    assert new_assignments[0]["next_node_id"] == "n2"
    assert new_assignments[1]["next_node_id"] == ""
    assert "Next: n2" in (new_assignments[0].get("hint") or "")

    assert isinstance(dag_debug, dict)
    assert dag_debug.get("ok") is True
    assert dag_debug.get("order") == ["n1", "n2"]
    edges = dag_debug.get("edges")
    assert isinstance(edges, list)
    assert any(e.get("src") == "n1" and e.get("dst") == "n2" and e.get("artifact") == "Knowledge(token)" for e in edges)


def test_flow_dependency_level_prefers_real_generator_io_contracts(monkeypatch):
    preview = {
        "seed": 101,
        "hosts": [
            {"node_id": "n1", "name": "Node 1", "role": "Docker", "vulnerabilities": ["demo/CVE-1"]},
            {"node_id": "n2", "name": "Node 2", "role": "Docker", "vulnerabilities": ["demo/CVE-2"]},
        ],
    }
    chain_nodes = [
        {"id": "n1", "name": "Node 1", "type": "docker", "vulnerabilities": ["demo/CVE-1"]},
        {"id": "n2", "name": "Node 2", "type": "docker", "vulnerabilities": ["demo/CVE-2"]},
    ]
    producer = {
        "id": "producer",
        "name": "Producer",
        "inputs": [],
        "outputs": [{"name": "Knowledge(token)"}],
        "language": "python",
        "_source_name": "test",
    }
    consumer = {
        "id": "consumer",
        "name": "Consumer",
        "inputs": [{"name": "Knowledge(token)", "required": True}],
        "outputs": [{"name": "Flag(flag_id)"}],
        "language": "python",
        "_source_name": "test",
    }
    independent = {
        "id": "independent",
        "name": "Independent",
        "inputs": [],
        "outputs": [{"name": "Flag(flag_id)"}],
        "language": "python",
        "_source_name": "test",
    }
    plugins_by_id = {
        "producer": {"requires": [], "produces": [{"artifact": "Knowledge(token)"}]},
        "consumer": {"requires": ["Knowledge(token)"], "produces": [{"artifact": "Flag(flag_id)"}]},
        "independent": {"requires": [], "produces": [{"artifact": "Flag(flag_id)"}]},
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([producer, consumer, independent], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: plugins_by_id)

    dependent_assignments = app_backend._flow_compute_flag_assignments(
        preview,
        chain_nodes,
        "scenario",
        seed_override=101,
        disallow_generator_reuse=True,
        dependency_level=5,
    )
    assert [item.get("id") for item in dependent_assignments] == ["producer", "consumer"]
    assert dependent_assignments[1].get("requires") == ["Knowledge(token)"]

    independent_assignments = app_backend._flow_compute_flag_assignments(
        preview,
        chain_nodes,
        "scenario",
        seed_override=101,
        disallow_generator_reuse=True,
        dependency_level=1,
    )
    assert len(independent_assignments) == 2
    assert independent_assignments[1].get("id") != "consumer"


def test_flow_generator_selection_is_seeded_weighted_not_hard_ranked(monkeypatch):
    """Broad-output starters should be preferred, but not selected every time."""
    preview = {
        "hosts": [{"node_id": "d1", "name": "Docker 1", "role": "Docker", "vulnerabilities": []}],
    }
    chain_nodes = [{"id": "d1", "name": "Docker 1", "type": "docker", "is_vuln": False}]
    broad = {
        "id": "broad",
        "name": "Broad starter",
        "inputs": [],
        "outputs": [{"name": f"Fact({index})"} for index in range(10)],
        "_source_name": "test",
    }
    narrow = {
        "id": "narrow",
        "name": "Narrow starter",
        "inputs": [],
        "outputs": [{"name": "Fact(one)"}],
        "_source_name": "test",
    }
    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([broad, narrow], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})

    selected = [
        app_backend._flow_compute_flag_assignments(
            preview,
            chain_nodes,
            "scenario",
            seed_override=seed,
        )[0]["id"]
        for seed in range(128)
    ]

    assert set(selected) == {"broad", "narrow"}
    assert selected.count("broad") > selected.count("narrow")


def test_high_dependency_reorder_preserves_adjacent_dependency_pairs():
    chain_nodes = [
        {"id": "n1", "name": "Node 1", "type": "docker"},
        {"id": "n2", "name": "Node 2", "type": "docker"},
        {"id": "n3", "name": "Node 3", "type": "docker"},
        {"id": "n4", "name": "Node 4", "type": "docker"},
    ]
    flag_assignments = [
        {
            "node_id": "n1",
            "id": "producer_a",
            "name": "Producer A",
            "type": "flag-generator",
            "requires": [],
            "produces": ["Credential(user, password)"],
            "outputs": ["Credential(user, password)"],
            "hint_template": "Next: {{NEXT_NODE_ID}}",
        },
        {
            "node_id": "n2",
            "id": "consumer_a",
            "name": "Consumer A",
            "type": "flag-generator",
            "requires": ["Credential(user, password)"],
            "inputs": ["Credential(user, password)"],
            "hint_template": "Next: {{NEXT_NODE_ID}}",
        },
        {
            "node_id": "n3",
            "id": "producer_b",
            "name": "Producer B",
            "type": "flag-generator",
            "requires": [],
            "produces": ["Credential(user, password)"],
            "outputs": ["Credential(user, password)"],
            "hint_template": "Next: {{NEXT_NODE_ID}}",
        },
        {
            "node_id": "n4",
            "id": "consumer_b",
            "name": "Consumer B",
            "type": "flag-generator",
            "requires": ["Credential(user, password)"],
            "inputs": ["Credential(user, password)"],
            "hint_template": "Next: {{NEXT_NODE_ID}}",
        },
    ]
    plugins_by_id = {
        "producer_a": {
            "plugin_id": "producer_a",
            "plugin_type": "flag-generator",
            "requires": [],
            "produces": [{"artifact": "Credential(user, password)"}],
        },
        "consumer_a": {
            "plugin_id": "consumer_a",
            "plugin_type": "flag-generator",
            "requires": ["Credential(user, password)"],
            "produces": [],
        },
        "producer_b": {
            "plugin_id": "producer_b",
            "plugin_type": "flag-generator",
            "requires": [],
            "produces": [{"artifact": "Credential(user, password)"}],
        },
        "consumer_b": {
            "plugin_id": "consumer_b",
            "plugin_type": "flag-generator",
            "requires": ["Credential(user, password)"],
            "produces": [],
        },
    }

    new_chain, new_assignments, dag_debug = app_backend._flow_reorder_chain_by_generator_dag(
        chain_nodes,
        flag_assignments,
        scenario_label="scenario",
        dependency_level=5,
        plugins_by_id_override=plugins_by_id,
        return_debug=True,
    )

    assert [node["id"] for node in new_chain] == ["n1", "n2", "n3", "n4"]
    assert [assignment["id"] for assignment in new_assignments] == ["producer_a", "consumer_a", "producer_b", "consumer_b"]
    assert dag_debug and dag_debug.get("strategy") == "high_dependency_preserve"
    assert new_assignments[0]["next_node_id"] == "n2"
    assert new_assignments[2]["next_node_id"] == "n4"
