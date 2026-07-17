import json
import os
import tempfile
import uuid

from webapp import app_backend
from webapp.app_backend import app


def _write_xml(tmpdir: str, *, scenario: str) -> str:
    xml = f"""<Scenarios>
  <Scenario name='{scenario}'>
    <ScenarioEditor>
      <section name='Node Information'>
        <item selected='Docker' v_metric='Count' v_count='2'/>
        <item selected='Server' v_metric='Count' v_count='1'/>
      </section>
      <section name='Routing' density='0.0'></section>
      <section name='Services' density='0.0'></section>
      <section name='Vulnerabilities' density='0.0'>
                <item selected='Specific' v_metric='Count' v_count='2' v_name='VulnA' v_path='https://example.com/vuln-a' factor='1.0'/>
      </section>
      <section name='Segmentation' density='0.0'></section>
      <section name='Traffic' density='0.0'></section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    path = os.path.join(tmpdir, f"{scenario}.xml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(xml)
    return path


def test_specific_count_vulns_show_in_preview_and_flow_attackflow_preview(tmp_path):
    """Regression: Specific + Count rows must populate preview vuln assignments.

    Preview tabs and Flag Sequencing rely on preview artifacts; this test asserts we
    can build a flow chain when the preview plan contains basic connectivity.
    """

    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-vuln-specific-count-flow-{uuid.uuid4().hex[:10]}"

    with tempfile.TemporaryDirectory() as td:
        xml_path = _write_xml(td, scenario=scenario)
        assert os.path.exists(xml_path)

        # 1) Compute preview
        resp = client.post("/api/plan/preview_full", json={"xml_path": xml_path, "scenario": scenario})
        assert resp.status_code == 200
        payload = resp.get_json() or {}
        assert payload.get("ok") is True, payload

        full_preview = payload.get("full_preview") or {}
        vuln_by_node = full_preview.get("vulnerabilities_by_node") or {}
        assert vuln_by_node, "expected vulnerabilities_by_node to be non-empty"

        hosts = full_preview.get("hosts") or []
        docker_host_ids = [
            str(h.get("node_id"))
            for h in hosts
            if str(h.get("node_id") or "") and (h.get("role") or "").strip().lower() == "docker"
        ]
        assert len(docker_host_ids) >= 2

        # Ensure vulnerabilities are reflected in preview for flow planning.
        assert len([str(k) for k in vuln_by_node.keys() if str(k)]) >= 1

        # 2) Persist a preview plan artifact that is connected.
        # Minimal XMLs can yield a preview without enough link metadata for Flow to
        # build a multi-hop chain. Inject a simple switch that connects two docker hosts.
        s1 = "s1"
        full_preview["switches"] = [{"node_id": s1, "name": "switch-1"}]
        full_preview["switches_detail"] = [{"switch_id": s1, "router_id": "", "hosts": docker_host_ids[:2]}]

        plan_payload = {
            "full_preview": full_preview,
            "metadata": {
                "xml_path": xml_path,
                "scenario": scenario,
                "seed": full_preview.get("seed"),
            },
        }
        ok, err = app_backend._update_plan_preview_in_xml(xml_path, scenario, plan_payload)
        assert ok, err
        plan_path = xml_path

        try:
            # 3) Flow preview should succeed and produce a chain.
            flow = client.get(
                "/api/flag-sequencing/attackflow_preview",
                query_string={"scenario": scenario, "length": 2, "preview_plan": plan_path},
            )
            assert flow.status_code == 200
            data = flow.get_json() or {}
            assert data.get("ok") is True, data
            chain = data.get("chain") or []
            assert len(chain) == 2, chain
        finally:
            pass


def test_flow_attackflow_preview_without_starter_catalog_generates_chain(tmp_path):
    """Flow preview should still build a node chain when no bundled catalog exists."""
    scenario = f"specific_count_flow_preset_{uuid.uuid4().hex[:6]}"
    xml_path = _write_xml(str(tmp_path), scenario=scenario)

    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    full_preview = {
        "seed": 123,
        "hosts": [
            {"node_id": "h1", "name": "docker-1", "role": "Docker", "vulnerabilities": [{"id": "v1"}], "ipv4": ["10.0.0.1/24"]},
            {"node_id": "h2", "name": "docker-2", "role": "Docker", "vulnerabilities": [], "ipv4": ["10.0.0.2/24"]},
            {"node_id": "h3", "name": "docker-3", "role": "Docker", "vulnerabilities": [{"id": "v3"}], "ipv4": ["10.0.0.3/24"]},
        ],
        "routers": [],
        "switches": [{"node_id": "s1", "name": "switch-1"}],
        "switches_detail": [{"switch_id": "s1", "router_id": "", "hosts": ["h1", "h2", "h3"]}],
    }

    plan_payload = {
        "full_preview": full_preview,
        "metadata": {"xml_path": xml_path, "scenario": scenario, "seed": full_preview.get("seed")},
    }
    ok, err = app_backend._update_plan_preview_in_xml(xml_path, scenario, plan_payload)
    assert ok, err
    plan_path = xml_path

    try:
        flow = client.get(
            "/api/flag-sequencing/attackflow_preview",
            query_string={
                "scenario": scenario,
                "length": 2,
                "preview_plan": plan_path,
            },
        )
        assert flow.status_code == 200
        data = flow.get_json() or {}
        assert data.get("ok") is True, data
        chain = data.get("chain") or []
        assert len(chain) == 2, chain
    finally:
        pass


def test_flow_preset_steps_no_longer_assume_bundled_sample_catalog():
    assert app_backend._flow_preset_steps('sample') == []
    assert app_backend._flow_preset_steps('sample_reverse_nfs_ssh') == []


def test_pick_flag_chain_nodes_for_preset_avoids_vuln_for_node_generator_step():
    steps = [
        {'id': 'artifact_source', 'kind': 'flag-generator', 'catalog': 'flag_generators'},
        {'id': 'node_challenge', 'kind': 'flag-node-generator', 'catalog': 'flag_node_generators'},
        {'id': 'artifact_followup', 'kind': 'flag-generator', 'catalog': 'flag_generators'},
    ]

    nodes = []
    for i in range(1, 8):
        nodes.append({'id': f'd{i}', 'name': f'docker-{i}', 'type': 'DOCKER', 'is_vuln': False})
    for i in range(1, 6):
        nodes.append({'id': f'v{i}', 'name': f'vuln-{i}', 'type': 'DOCKER', 'is_vuln': True})

    adj = {n['id']: set() for n in nodes}
    chain_nodes = app_backend._pick_flag_chain_nodes_for_preset(nodes, adj, steps=steps)
    assert len(chain_nodes) == 3

    # Middle step is a flag-node-generator; must not be a vuln node.
    assert bool(chain_nodes[1].get('is_vuln')) is False


def test_pick_flag_chain_nodes_for_explicit_steps_supports_compose_docker_and_is_vulnerability():
    steps = [
        {'id': 'artifact_source', 'kind': 'flag-generator', 'catalog': 'flag_generators'},
        {'id': 'node_challenge', 'kind': 'flag-node-generator', 'catalog': 'flag_node_generators'},
        {'id': 'artifact_followup', 'kind': 'flag-generator', 'catalog': 'flag_generators'},
    ]

    nodes = [
        {
            'id': 'v1',
            'name': 'vuln-1',
            'type': 'DOCKER',
            'is_vulnerability': True,
            'vulnerabilities': [{'id': 'CVE-1'}],
        },
        {
            'id': 'd1',
            'name': 'docker-1',
            'type': 'HOST',
            'compose': 'services:\n  app:\n    image: alpine:latest\n',
            'is_vulnerability': False,
            'vulnerabilities': [],
        },
        {
            'id': 'v2',
            'name': 'vuln-2',
            'type': 'HOST',
            'is_vulnerability': True,
            'vulnerabilities': [{'id': 'CVE-2'}],
        },
    ]

    adj = {n['id']: {'v1', 'd1', 'v2'} - {n['id']} for n in nodes}
    chain_nodes = app_backend._pick_flag_chain_nodes_for_preset(nodes, adj, steps=steps)

    assert len(chain_nodes) == 3
    assert bool(app_backend._flow_node_is_vuln(chain_nodes[0])) is True
    assert bool(app_backend._flow_node_is_docker_role(chain_nodes[1])) is True
    assert bool(app_backend._flow_node_is_vuln(chain_nodes[1])) is False
    assert bool(app_backend._flow_node_is_vuln(chain_nodes[2])) is True


def test_flow_attackflow_preview_with_many_vulns_does_not_error(tmp_path):
    """Regression: Flow preview should not fail when many vuln docker nodes exist."""
    scenario = f"specific_count_flow_preset_many_vulns_{uuid.uuid4().hex[:6]}"
    xml_path = _write_xml(str(tmp_path), scenario=scenario)

    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    hosts = []
    for i in range(1, 8):
        hosts.append({"node_id": f"h{i}", "name": f"docker-{i}", "role": "Docker", "vulnerabilities": []})
    for i in range(1, 6):
        hosts.append({"node_id": f"v{i}", "name": f"vuln-{i}", "role": "Docker", "vulnerabilities": [{"id": "dummy"}]})

    full_preview = {
        "seed": 123,
        "hosts": hosts,
        "routers": [],
        "switches": [{"node_id": "s1", "name": "switch-1"}],
        "switches_detail": [{"switch_id": "s1", "router_id": "", "hosts": [h["node_id"] for h in hosts]}],
    }

    plan_payload = {
        "full_preview": full_preview,
        "metadata": {"xml_path": xml_path, "scenario": scenario, "seed": full_preview.get("seed")},
    }
    ok, err = app_backend._update_plan_preview_in_xml(xml_path, scenario, plan_payload)
    assert ok, err
    plan_path = xml_path

    try:
        flow = client.get(
            "/api/flag-sequencing/attackflow_preview",
            query_string={
                "scenario": scenario,
                "length": 3,
                "preview_plan": plan_path,
            },
        )
        assert flow.status_code == 200
        data = flow.get_json() or {}
        assert data.get("ok") is True, data
        chain = data.get("chain") or []
        # Topology-selected vulnerabilities are mandatory Flow challenges, so
        # the requested length is raised to the five vulnerability nodes.
        assert len(chain) == 5, chain
    finally:
        pass


def test_flow_attackflow_preview_length2_generates_chain(tmp_path):
    """Regression: length=2 should generate a chain when requirements are met."""
    scenario = f"specific_count_flow_sample_alias_{uuid.uuid4().hex[:6]}"
    xml_path = _write_xml(str(tmp_path), scenario=scenario)

    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    full_preview = {
        "seed": 321,
        "hosts": [
            {"node_id": "h1", "name": "docker-1", "role": "Docker", "vulnerabilities": [{"id": "v1"}], "ipv4": ["10.0.1.1/24"]},
            {"node_id": "h2", "name": "docker-2", "role": "Docker", "vulnerabilities": [], "ipv4": ["10.0.1.2/24"]},
            {"node_id": "h3", "name": "docker-3", "role": "Docker", "vulnerabilities": [{"id": "v3"}], "ipv4": ["10.0.1.3/24"]},
        ],
        "routers": [],
        "switches": [{"node_id": "s1", "name": "switch-1"}],
        "switches_detail": [{"switch_id": "s1", "router_id": "", "hosts": ["h1", "h2", "h3"]}],
    }

    plan_payload = {
        "full_preview": full_preview,
        "metadata": {"xml_path": xml_path, "scenario": scenario, "seed": full_preview.get("seed")},
    }
    ok, err = app_backend._update_plan_preview_in_xml(xml_path, scenario, plan_payload)
    assert ok, err

    flow = client.get(
        "/api/flag-sequencing/attackflow_preview",
        query_string={
            "scenario": scenario,
            "length": 2,
            "preview_plan": xml_path,
        },
    )
    assert flow.status_code == 200
    data = flow.get_json() or {}
    assert data.get("ok") is True, data
    chain = data.get("chain") or []
    assert len(chain) == 2, chain
