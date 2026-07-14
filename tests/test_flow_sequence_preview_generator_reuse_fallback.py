import os
import json
import uuid

import pytest

from webapp.app_backend import app
from webapp import app_backend


def test_sequence_preview_streams_json_and_coalesces_duplicate_request_ids(monkeypatch):
    """A lost response must not make a retry run the same sequence twice."""
    app.config["TESTING"] = True
    original_normalize = app_backend._normalize_scenario_label
    normalize_calls = 0

    def _counting_normalize(value):
        nonlocal normalize_calls
        normalize_calls += 1
        return original_normalize(value)

    monkeypatch.setattr(app_backend, "_normalize_scenario_label", _counting_normalize)
    request_id = f"single-flight-{uuid.uuid4().hex}"
    payload = {"scenario": "", "sequence_request_id": request_id, "progress_id": "progress-a"}

    for _ in range(2):
        with app.test_request_context("/api/flag-sequencing/sequence_preview_plan", method="POST", json=payload):
            response = app.view_functions["api_flow_sequence_preview_plan"]()
            body = response.get_data()
        assert response.status_code == 200
        assert body.startswith(b" \n")
        assert json.loads(body.decode("utf-8"))["error"] == "No scenario specified."

    assert normalize_calls == 1


def test_prepare_preview_streams_json_and_coalesces_duplicate_request_ids(monkeypatch):
    """A lost resolve response must not start another resolve/generator run."""
    app.config["TESTING"] = True
    original_normalize = app_backend._normalize_scenario_label
    normalize_calls = 0

    def _counting_normalize(value):
        nonlocal normalize_calls
        normalize_calls += 1
        return original_normalize(value)

    monkeypatch.setattr(app_backend, "_normalize_scenario_label", _counting_normalize)
    request_id = f"resolve-single-flight-{uuid.uuid4().hex}"
    payload = {"scenario": "", "resolve_request_id": request_id, "progress_id": "progress-a"}

    for _ in range(2):
        with app.test_request_context("/api/flag-sequencing/prepare_preview_for_execute", method="POST", json=payload):
            response = app.view_functions["api_flow_prepare_preview_for_execute"]()
            body = response.get_data()
        assert response.status_code == 200
        assert body.startswith(b" \n")
        assert json.loads(body.decode("utf-8"))["error"] == "No scenario specified."

    assert normalize_calls == 1


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_sequence_preview_plan_hard_fails_when_duplicate_generators_disallowed(monkeypatch):
    app.config["TESTING"] = True
    client = app.test_client()

    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (302, 303)

    scenario = f"zz-seq-fallback-{uuid.uuid4().hex[:10]}"
    full_preview = {
        "seed": 101,
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "hosts": [
            {"node_id": "h1", "name": "h1", "role": "Docker", "ip4": "10.10.10.2", "vulnerabilities": ["vuln-1"]},
            {"node_id": "h2", "name": "h2", "role": "Docker", "ip4": "10.10.10.3", "vulnerabilities": ["vuln-2"]},
        ],
        "host_router_map": {},
        "r2r_links_preview": [],
    }

    plan_payload = {"full_preview": full_preview, "metadata": {"scenario": scenario, "seed": 101}}

    plans_dir = os.path.join(app_backend._outputs_dir(), "plans")
    os.makedirs(plans_dir, exist_ok=True)
    tmp_xml = os.path.join(plans_dir, f"plan_{scenario}.xml")

    assignment_modes: list[bool] = []

    def _fake_flow_compute_assignments(_preview, chain, _scenario_label, **kwargs):
        disallow = bool(kwargs.get("disallow_generator_reuse", True))
        assignment_modes.append(disallow)
        out = []
        for node in (chain or []):
            nid = str((node or {}).get("id") or "")
            out.append({
                "node_id": nid,
                "id": "dup_generator",
                "generator_id": "dup_generator",
                "name": "Duplicate Generator",
                "type": "flag-generator",
                "generator_catalog": "flag_generators",
                "resolved_outputs": {"Flag(flag_id)": f"FLAG{{{nid or 'x'}}}"},
            })
        return out

    monkeypatch.setattr(app_backend, "_flow_compute_flag_assignments", _fake_flow_compute_assignments)
    monkeypatch.setattr(app_backend, "_flow_validate_chain_order_by_requires_produces", lambda *args, **kwargs: (True, []))

    try:
        with open(tmp_xml, "w", encoding="utf-8") as f:
            f.write(
                f"""<Scenarios>\n  <Scenario name=\"{scenario}\">\n    <ScenarioEditor>\n      <section name=\"Node Information\">\n        <item selected=\"Workstation\" factor=\"1\" />\n      </section>\n    </ScenarioEditor>\n  </Scenario>\n</Scenarios>"""
            )
        ok, err = app_backend._update_plan_preview_in_xml(tmp_xml, scenario, plan_payload)
        assert ok is True, err

        resp = client.post(
            "/api/flag-sequencing/sequence_preview_plan",
            json={
                "scenario": scenario,
                "length": 2,
                "preview_plan": tmp_xml,
                "allow_node_duplicates": False,
            },
        )
        assert resp.status_code == 200, resp.get_json()
        data = resp.get_json() or {}
        assert data.get("ok") is False
        assert data.get("validation_error") is True
        assert "duplicate generators detected" in str(data.get("error") or "").lower()
        assert assignment_modes
        assert all(mode is True for mode in assignment_modes)
    finally:
        try:
            os.remove(tmp_xml)
        except Exception:
            pass
