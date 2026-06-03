import os
import uuid

import pytest

from webapp import app_backend
from webapp.app_backend import app


def _login(client):
    resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert resp.status_code in (302, 303)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_sequence_preview_include_all_topology_vulns_expands_and_persists(monkeypatch):
    app.config["TESTING"] = True
    client = app.test_client()
    _login(client)

    scenario = f"zz-topology-inclusion-{uuid.uuid4().hex[:10]}"
    full_preview = {
        "seed": 123,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "worker", "name": "worker", "role": "Docker", "type": "docker", "ip4": "10.0.0.10", "vulnerabilities": []},
            {"node_id": "web", "name": "web", "role": "Docker", "type": "docker", "ip4": "10.0.0.11", "vulnerabilities": ["rce"]},
            {"node_id": "api", "name": "api", "role": "Docker", "type": "docker", "ip4": "10.0.0.12", "vulnerabilities": ["token-leak"]},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }
    plan_payload = {"full_preview": full_preview, "metadata": {"scenario": scenario, "seed": 123}}

    plans_dir = os.path.join(app_backend._outputs_dir(), "plans")
    os.makedirs(plans_dir, exist_ok=True)
    tmp_xml = os.path.join(plans_dir, f"plan_{scenario}.xml")

    def _fake_pick(nodes, _adj, length=5):
        return [next(node for node in nodes if str(node.get("id") or "") == "worker")]

    def _fake_assignments(_preview, chain_nodes, _scenario_label, **_kwargs):
        out = []
        for index, node in enumerate(chain_nodes or []):
            node_id = str((node or {}).get("id") or "")
            is_vuln = app_backend._flow_node_is_vuln(node)
            out.append(
                {
                    "node_id": node_id,
                    "id": f"gen_{index}_{node_id}",
                    "generator_id": f"gen_{index}_{node_id}",
                    "name": f"Generator {node_id}",
                    "type": "flag-generator" if is_vuln else "flag-node-generator",
                    "generator_catalog": "flag_generators" if is_vuln else "flag_node_generators",
                    "inputs": [],
                    "outputs": ["Flag(flag_id)"],
                    "requires": [],
                    "produces": [],
                }
            )
        return out

    monkeypatch.setattr(app_backend, "_pick_flag_chain_nodes", _fake_pick)
    monkeypatch.setattr(app_backend, "_flow_compute_flag_assignments", _fake_assignments)
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (True, []))
    monkeypatch.setattr(app_backend, "_flow_reorder_chain_by_generator_dag", lambda chain, assignments, **kwargs: (chain, assignments, {}))

    try:
        with open(tmp_xml, "w", encoding="utf-8") as file_obj:
            file_obj.write(
                f"""<Scenarios>\n  <Scenario name=\"{scenario}\">\n    <ScenarioEditor>\n      <section name=\"Node Information\">\n        <item selected=\"Docker\" factor=\"3\" />\n      </section>\n    </ScenarioEditor>\n  </Scenario>\n</Scenarios>"""
            )
        ok, err = app_backend._update_plan_preview_in_xml(tmp_xml, scenario, plan_payload)
        assert ok is True, err

        resp = client.post(
            "/api/flag-sequencing/sequence_preview_plan",
            json={
                "scenario": scenario,
                "length": 1,
                "preview_plan": tmp_xml,
                "include_all_topology_vulns": True,
                "allow_node_duplicates": False,
            },
        )
        assert resp.status_code == 200, resp.get_json()
        data = resp.get_json() or {}
        assert data.get("ok") is True, data
        assert data.get("requested_length") == 1
        assert data.get("length") == 3
        assert [entry.get("id") for entry in data.get("chain", [])] == ["worker", "web", "api"]
        assert data.get("topology_inclusion", {}).get("added_vuln_node_ids") == ["web", "api"]

        flow_state = app_backend._flow_state_from_xml_path(tmp_xml, scenario)
        assert flow_state.get("include_all_topology_vulns") is True
        assert flow_state.get("include_all_topology_pivots") is False
        assert [entry.get("id") for entry in flow_state.get("chain", [])] == ["worker", "web", "api"]
    finally:
        try:
            os.remove(tmp_xml)
        except Exception:
            pass