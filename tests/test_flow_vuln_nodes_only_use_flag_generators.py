import os
import shutil
import tempfile
import uuid

import pytest

from webapp import app_backend


def test_flow_vuln_nodes_only_use_flag_generators(monkeypatch: pytest.MonkeyPatch):
    scenario = f"zz-flow-vuln-only-flaggen-{uuid.uuid4().hex[:8]}"

    # Preview with two hosts: one vuln-bearing docker, one non-vuln docker.
    preview = {
        "seed": 0,
        "hosts": [
            {"node_id": "h1", "name": "dockervuln-1", "role": "Docker", "vulnerabilities": [{"name": "docker-compose:web"}]},
            {"node_id": "h2", "name": "host-2", "role": "Docker", "vulnerabilities": []},
        ],
    }

    flag_gen = {
        "id": "fg1",
        "name": "FlagGen",
        "inputs": [],
        "outputs": [{"name": "Flag(flag_id)", "required": False}],
        "hint_levels": {"low": ["Next: {{NEXT_NODE_ID}}"]},
        "language": "python",
        "_source_name": "test",
    }
    node_gen = {
        "id": "ng1",
        "name": "NodeGen",
        "inputs": [],
        "outputs": [],
        "hint_levels": {"low": ["Next: {{NEXT_NODE_ID}}"]},
        "language": "python",
        "_source_name": "test",
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([flag_gen], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([node_gen], []))

    chain_nodes = [
        {"id": "h1", "name": "dockervuln-1", "type": "docker", "is_vuln": True},
        {"id": "h2", "name": "host-2", "type": "docker", "is_vuln": False},
    ]

    assignments = app_backend._flow_compute_flag_assignments(preview, chain_nodes, scenario)
    assert len(assignments) == 2

    a1 = assignments[0]
    assert a1["node_id"] == "h1"
    assert a1["type"] == "flag-generator"
    assert a1.get("generator_catalog") == "flag_generators"

    a2 = assignments[1]
    assert a2["node_id"] == "h2"
    assert a2["type"] == "flag-node-generator"
    assert a2.get("generator_catalog") == "flag_node_generators"


def test_attackflow_preview_docker_only_uses_flag_node_generators(monkeypatch: pytest.MonkeyPatch):
    scenario = f"zz-flow-docker-only-nodegen-{uuid.uuid4().hex[:8]}"

    preview = {
        "seed": 3,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "d1", "name": "docker-1", "role": "Docker", "vulnerabilities": []},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }

    node_gen = {
        "id": "ng1",
        "name": "NodeGen",
        "inputs": [],
        "outputs": [],
        "hint_levels": {"low": ["Next: {{NEXT_NODE_ID}}"]},
        "language": "python",
        "_source_name": "test",
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([node_gen], []))

    full_preview = {
        "seed": 3,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "d1", "name": "docker-1", "role": "Docker", "vulnerabilities": []},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }

    chain_nodes = [
        {"id": "d1", "name": "docker-1", "type": "docker", "is_vuln": False},
        {"id": "d1", "name": "docker-1", "type": "docker", "is_vuln": False},
    ]
    assignments = app_backend._flow_compute_flag_assignments(preview, chain_nodes, scenario)
    assert len(assignments) == 2
    assert {a["type"] for a in assignments} == {"flag-node-generator"}

    xml_path, plan_dir = _seed_xml_plan_for_vuln_test(scenario, full_preview)
    payload = {
        "full_preview": full_preview,
        "metadata": {"xml_path": xml_path, "scenario": scenario, "seed": full_preview.get("seed")},
    }
    ok, err = app_backend._update_plan_preview_in_xml(xml_path, scenario, payload)
    assert ok, err

    try:
        app_backend.app.config["TESTING"] = True
        client = app_backend.app.test_client()
        login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login_resp.status_code in (302, 303)

        resp = client.get(
            "/api/flag-sequencing/attackflow_preview",
            query_string={
                "scenario": scenario,
                "length": 2,
                "preview_plan": xml_path,
                "allow_node_duplicates": "1",
            },
        )
        data = resp.get_json() or {}
        assert resp.status_code == 200, data
        assert data.get("ok") is True, data

        chain = data.get("chain") or []
        assignments = data.get("flag_assignments") or []
        assert len(chain) == 2
        assert all(not bool(node.get("is_vuln")) for node in chain)
        assert len(assignments) == 2
        assert {a.get("type") for a in assignments} == {"flag-node-generator"}
        assert {a.get("generator_catalog") for a in assignments} == {"flag_node_generators"}
        assert {a.get("id") for a in assignments} == {"ng1"}
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


def test_attackflow_preview_adds_missing_vulnerability_to_saved_flow(monkeypatch: pytest.MonkeyPatch):
    """A stale saved chain cannot omit a vulnerability node from the Flow."""
    scenario = f"zz-required-vuln-{uuid.uuid4().hex[:8]}"
    full_preview = {
        "seed": 5,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "worker", "name": "worker", "role": "Docker", "vulnerabilities": []},
            {"node_id": "web", "name": "web", "role": "Docker", "vulnerabilities": ["bash/CVE-2014-6271"]},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }
    stale_flow = {
        "scenario": scenario,
        "length": 1,
        "chain": [{"id": "worker", "name": "worker", "type": "docker"}],
        "flag_assignments": [{"node_id": "worker", "id": "nodegen", "type": "flag-node-generator"}],
    }
    xml_path, plan_dir = _seed_xml_plan_for_vuln_test(scenario, full_preview, stale_flow)

    def _fake_assignments(_preview, chain_nodes, _scenario_label, **_kwargs):
        return [
            {
                "node_id": str(node.get("id") or ""),
                "id": f"generator-{node.get('id')}",
                "type": "flag-generator" if app_backend._flow_node_is_vuln(node) else "flag-node-generator",
                "inputs": [],
                "outputs": ["Flag(flag_id)"],
                "requires": [],
                "produces": [],
            }
            for node in chain_nodes
        ]

    monkeypatch.setattr(app_backend, "_flow_compute_flag_assignments", _fake_assignments)
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (True, []))
    monkeypatch.setattr(app_backend, "_flow_reorder_chain_by_generator_dag", lambda chain, assignments, **kwargs: (chain, assignments, {}))

    try:
        app_backend.app.config["TESTING"] = True
        client = app_backend.app.test_client()
        login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login_resp.status_code in (302, 303)

        resp = client.get(
            "/api/flag-sequencing/attackflow_preview",
            query_string={"scenario": scenario, "length": 1, "preview_plan": xml_path, "prefer_flow": "1"},
        )
        data = resp.get_json() or {}
        assert resp.status_code == 200, data
        assert [node.get("id") for node in data.get("chain", [])] == ["worker", "web"]
        assert [assignment.get("type") for assignment in data.get("flag_assignments", [])] == [
            "flag-node-generator",
            "flag-generator",
        ]
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


def _seed_xml_plan_for_vuln_test(scenario: str, full_preview: dict, flow_meta: dict | None = None) -> tuple[str, str]:
    td = tempfile.mkdtemp(prefix="coretg-vuln-only-")
    xml_path = os.path.join(td, f"{scenario}.xml")
    xml = f"""<Scenarios>
<Scenario name='{scenario}'>
    <ScenarioEditor>
        <section name='Node Information'>
            <item selected='Docker' v_metric='Count' v_count='2'/>
        </section>
        <section name='Routing' density='0.0'></section>
        <section name='Services' density='0.0'></section>
        <section name='Vulnerabilities' density='0.0'></section>
        <section name='Segmentation' density='0.0'></section>
        <section name='Traffic' density='0.0'></section>
    </ScenarioEditor>
</Scenario>
</Scenarios>"""
    with open(xml_path, "w", encoding="utf-8") as f:
        f.write(xml)
    payload: dict = {
        "full_preview": full_preview,
        "metadata": {"xml_path": xml_path, "scenario": scenario, "seed": full_preview.get("seed")},
    }
    if isinstance(flow_meta, dict) and flow_meta:
        payload["metadata"]["flow"] = flow_meta
    ok, err = app_backend._update_plan_preview_in_xml(xml_path, scenario, payload)
    assert ok, err
    if isinstance(flow_meta, dict) and flow_meta:
        ok2, err2 = app_backend._update_flow_state_in_xml(xml_path, scenario, flow_meta)
        assert ok2, err2
    return xml_path, td


def test_attackflow_preview_rejects_flag_generator_on_non_vuln_node():
    """attackflow_preview must return 422 when a flag-generator is assigned to a non-vulnerability node."""
    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-vuln-only-reject-{uuid.uuid4().hex[:8]}"
    full_preview = {
        'seed': 1,
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'hosts': [
            {'node_id': 'nv1', 'name': 'plain-docker', 'role': 'Docker', 'vulnerabilities': []},
        ],
        'host_router_map': {},
        'r2r_links_preview': [],
    }
    flow_meta = {
        'scenario': scenario,
        'length': 1,
        'chain': [{'id': 'nv1', 'name': 'plain-docker', 'type': 'docker'}],
        'flag_assignments': [
            {
                'node_id': 'nv1',
                'id': 'textfile_username_password',
                'type': 'flag-generator',  # wrong: non-vuln node cannot use flag-generator
            }
        ],
        'modified_at': '2026-01-01T00:00:00Z',
    }
    plan_path, plan_dir = _seed_xml_plan_for_vuln_test(scenario, full_preview, flow_meta)
    try:
        resp = client.get('/api/flag-sequencing/attackflow_preview', query_string={
            'scenario': scenario,
            'length': 1,
            'preview_plan': plan_path,
            'prefer_flow': '1',
        })
        data = resp.get_json() or {}
        assert resp.status_code == 422, (
            f"Expected 422 for flag-generator on non-vuln node, got {resp.status_code}: {data}"
        )
        assert data.get('ok') is False
        assert 'flag-generator requires vulnerability node' in (data.get('error') or '')
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


def test_attackflow_preview_rejects_flag_node_generator_on_vuln_node():
    """attackflow_preview must return 422 when a flag-node-generator is assigned to a vulnerability node."""
    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-vuln-only-nodegen-{uuid.uuid4().hex[:8]}"
    full_preview = {
        'seed': 2,
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'hosts': [
            {'node_id': 'v1', 'name': 'vuln-docker', 'role': 'Docker', 'vulnerabilities': ['xstream/CVE-2021-29505']},
        ],
        'host_router_map': {},
        'r2r_links_preview': [],
    }
    flow_meta = {
        'scenario': scenario,
        'length': 1,
        'chain': [{'id': 'v1', 'name': 'vuln-docker', 'type': 'docker'}],
        'flag_assignments': [
            {
                'node_id': 'v1',
                'id': 'nfs_sensitive_file',
                'type': 'flag-node-generator',  # wrong: vuln node cannot use flag-node-generator
            }
        ],
        'modified_at': '2026-01-01T00:00:00Z',
    }
    plan_path, plan_dir = _seed_xml_plan_for_vuln_test(scenario, full_preview, flow_meta)
    try:
        resp = client.get('/api/flag-sequencing/attackflow_preview', query_string={
            'scenario': scenario,
            'length': 1,
            'preview_plan': plan_path,
            'prefer_flow': '1',
        })
        data = resp.get_json() or {}
        assert resp.status_code == 422, (
            f"Expected 422 for flag-node-generator on vuln node, got {resp.status_code}: {data}"
        )
        assert data.get('ok') is False
        assert 'must be flag-generator' in (data.get('error') or '')
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


def test_attackflow_preview_uses_compatible_saved_chain_when_chain_ids_drift(monkeypatch: pytest.MonkeyPatch):
    """Saved XML may contain stale chain_ids alongside a still-valid chain.

    The guide/export preview should keep the assignment order that fits generator
    placement rules instead of reassigning saved generators by stale chain_ids.
    """
    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-vuln-chain-drift-{uuid.uuid4().hex[:8]}"
    full_preview = {
        'seed': 4,
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'hosts': [
            {'node_id': '16', 'name': 'docker-11', 'role': 'Docker', 'vulnerabilities': []},
            {'node_id': '17', 'name': 'docker-12', 'role': 'Docker', 'vulnerabilities': ['saltstack/CVE-2020-16846']},
            {'node_id': '18', 'name': 'docker-13', 'role': 'Docker', 'vulnerabilities': ['git/CVE-2017-8386']},
            {'node_id': '19', 'name': 'docker-14', 'role': 'Docker', 'vulnerabilities': []},
        ],
        'host_router_map': {},
        'r2r_links_preview': [],
    }
    node_gen_1 = {
        'id': 'nodegen_a',
        'name': 'NodeGen A',
        'inputs': [],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'language': 'python',
        '_source_name': 'test',
    }
    node_gen_2 = {
        'id': 'nodegen_b',
        'name': 'NodeGen B',
        'inputs': [],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'language': 'python',
        '_source_name': 'test',
    }
    flag_gen_1 = {
        'id': 'flaggen_a',
        'name': 'FlagGen A',
        'inputs': [],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'language': 'python',
        '_source_name': 'test',
    }
    flag_gen_2 = {
        'id': 'flaggen_b',
        'name': 'FlagGen B',
        'inputs': [],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'language': 'python',
        '_source_name': 'test',
    }
    monkeypatch.setattr(app_backend, '_flag_generators_from_enabled_sources', lambda: ([flag_gen_1, flag_gen_2], []))
    monkeypatch.setattr(app_backend, '_flag_node_generators_from_enabled_sources', lambda: ([node_gen_1, node_gen_2], []))
    monkeypatch.setattr(
        app_backend,
        '_flow_enabled_plugin_contracts_by_id',
        lambda: {
            'nodegen_a': {'requires': [], 'produces': []},
            'nodegen_b': {'requires': [], 'produces': []},
            'flaggen_a': {'requires': [], 'produces': []},
            'flaggen_b': {'requires': [], 'produces': []},
        },
    )

    flow_meta = {
        'scenario': scenario,
        'length': 4,
        'chain': [
            {'id': '16', 'name': 'docker-11', 'type': 'docker'},
            {'id': '17', 'name': 'docker-12', 'type': 'docker'},
            {'id': '18', 'name': 'docker-13', 'type': 'docker'},
            {'id': '19', 'name': 'docker-14', 'type': 'docker'},
        ],
        # Stale order from a later client-side save; pairing assignments by this
        # list would place node generators on vulnerability nodes.
        'chain_ids': ['17', '19', '16', '18'],
        'flag_assignments': [
            {'node_id': '16', 'id': 'nodegen_a', 'type': 'flag-node-generator', 'outputs': ['Flag(flag_id)']},
            {'node_id': '17', 'id': 'flaggen_a', 'type': 'flag-generator', 'outputs': ['Flag(flag_id)'], 'vulnerabilities': ['git/CVE-2017-8386']},
            {'node_id': '18', 'id': 'flaggen_b', 'type': 'flag-generator', 'outputs': ['Flag(flag_id)'], 'vulnerabilities': ['saltstack/CVE-2020-16846']},
            {'node_id': '19', 'id': 'nodegen_b', 'type': 'flag-node-generator', 'outputs': ['Flag(flag_id)']},
        ],
        'modified_at': '2026-01-01T00:00:00Z',
    }
    plan_path, plan_dir = _seed_xml_plan_for_vuln_test(scenario, full_preview, flow_meta)
    try:
        resp = client.get('/api/flag-sequencing/attackflow_preview', query_string={
            'scenario': scenario,
            'length': 4,
            'preview_plan': plan_path,
            'prefer_flow': '1',
        })
        data = resp.get_json() or {}
        assert resp.status_code == 200, data
        assert data.get('ok') is True, data
        assert [node.get('id') for node in (data.get('chain') or [])] == ['16', '17', '18', '19']
        assignments = data.get('flag_assignments') or []
        assert [assignment.get('node_id') for assignment in assignments] == ['16', '17', '18', '19']
        assert [assignment.get('type') for assignment in assignments] == [
            'flag-node-generator',
            'flag-generator',
            'flag-generator',
            'flag-node-generator',
        ]
        assert assignments[1].get('vulnerabilities') == ['saltstack/CVE-2020-16846']
        assert assignments[2].get('vulnerabilities') == ['git/CVE-2017-8386']
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)


def test_prepare_preview_for_execute_preserves_docker_only_chain(monkeypatch: pytest.MonkeyPatch):
    """Test that prepare_preview_for_execute doesn't re-select Docker-only chains.
    
    This is a regression test for the bug where a Docker-only chain (3 non-vuln Docker nodes)
    was being re-selected during execute, causing flag-generators to be assigned instead of
    flag-node-generators.
    
    The fix ensures that when preset_steps is empty, non-vuln Docker nodes are recognized
    as requiring flag-node-generators and are not replaced with vulnerability nodes.
    """
    app_backend.app.config['TESTING'] = True
    client = app_backend.app.test_client()

    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-docker-only-execute-{uuid.uuid4().hex[:8]}"
    
    # Three non-vulnerability Docker nodes
    full_preview = {
        'seed': 999,
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'hosts': [
            {'node_id': 'd1', 'name': 'docker-1', 'role': 'Docker', 'vulnerabilities': []},
            {'node_id': 'd2', 'name': 'docker-2', 'role': 'Docker', 'vulnerabilities': []},
            {'node_id': 'd3', 'name': 'docker-3', 'role': 'Docker', 'vulnerabilities': []},
        ],
        'host_router_map': {},
        'r2r_links_preview': [],
    }

    # Mock generators
    node_gen = {
        'id': 'nfs_test',
        'name': 'NFS Test',
        'inputs': [],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'hint_levels': {'low': ['Next: {{NEXT_NODE_ID}}']},
        'language': 'python',
        '_source_name': 'test',
    }
    
    monkeypatch.setattr(app_backend, '_flag_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(app_backend, '_flag_node_generators_from_enabled_sources', lambda: ([node_gen], []))

    plan_path, plan_dir = _seed_xml_plan_for_vuln_test(scenario, full_preview)
    try:
        # Call prepare_preview_for_execute with Docker-only chain (no preset)
        resp = client.post(
            '/api/flag-sequencing/prepare_preview_for_execute',
            json={
                'scenario': scenario,
                'length': 3,
                'preview_plan': plan_path,
                'chain_ids': ['d1', 'd2', 'd3'],  # Provide explicit chain
                'allow_node_duplicates': True,
                'best_effort': True,
            },
        )
        
        data = resp.get_json() or {}
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {data.get('error', data)}"
        assert data.get('ok') is True, f"Expected ok=True: {data.get('error', data)}"
        
        # Check that chain wasn't re-selected
        warning = data.get('warning') or ''
        assert 'incompatible' not in warning.lower(), (
            f"Chain should NOT be re-selected for Docker-only nodes, but got warning: {warning}"
        )
        
        # Check that all assignments use flag-node-generators
        assignments = data.get('flag_assignments') or []
        assert len(assignments) == 3, f"Expected 3 assignments, got {len(assignments)}"
        
        for assign in assignments:
            assert assign.get('type') == 'flag-node-generator', (
                f"All Docker nodes must use flag-node-generators, "
                f"but got type={assign.get('type')} for node {assign.get('node_id')}"
            )
            assert assign.get('generator_catalog') == 'flag_node_generators', (
                f"All Docker nodes must use flag_node_generators catalog, "
                f"but got {assign.get('generator_catalog')} for node {assign.get('node_id')}"
            )
    finally:
        shutil.rmtree(plan_dir, ignore_errors=True)
