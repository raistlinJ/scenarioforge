import json
import xml.etree.ElementTree as ET

from webapp import app_backend


def _write_preview_xml(tmp_path, flow_state=None):
    full_preview = {
        "hosts": [
            {"node_id": 3, "name": "docker-3", "role": "Docker", "vulnerabilities": []},
            {"node_id": 4, "name": "docker-4", "role": "Docker", "vulnerabilities": ["bash/CVE-2014-6271"]},
        ],
        "routers": [],
        "switches": [],
        "switches_detail": [],
    }
    root = ET.Element("Scenarios")
    scenario = ET.SubElement(root, "Scenario", {"name": "Scenario3"})
    editor = ET.SubElement(scenario, "ScenarioEditor")
    ET.SubElement(editor, "PlanPreview").text = json.dumps({"full_preview": full_preview, "metadata": {"scenario": "Scenario3"}})
    if flow_state is not None:
        sequencing = ET.SubElement(editor, "FlagSequencing")
        ET.SubElement(sequencing, "FlowState").text = json.dumps(flow_state)
    path = tmp_path / "scenario3.xml"
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
    return path, full_preview


def test_flow_state_save_rejects_nonvuln_flag_generator_and_missing_vulnerability(tmp_path):
    xml_path, _preview = _write_preview_xml(tmp_path)
    invalid_state = {
        "scenario": "Scenario3",
        "flow_enabled": True,
        "length": 1,
        "chain_ids": ["3"],
        "flag_assignments": [{"node_id": "3", "id": "hash_shadow_credential", "type": "flag-generator"}],
    }

    ok, error = app_backend._update_flow_state_in_xml(str(xml_path), "Scenario3", invalid_state)

    assert not ok
    assert "missing required vulnerability node" in error.lower()


def test_flow_state_save_accepts_single_required_vulnerability_node(tmp_path):
    xml_path, _preview = _write_preview_xml(tmp_path)
    valid_state = {
        "scenario": "Scenario3",
        "flow_enabled": True,
        "length": 1,
        "chain_ids": ["4"],
        "flag_assignments": [{"node_id": "4", "id": "hash_shadow_credential", "type": "flag-generator"}],
    }

    ok, error = app_backend._update_flow_state_in_xml(str(xml_path), "Scenario3", valid_state)

    assert ok, error
    saved = app_backend._flow_state_from_xml_path(str(xml_path), "Scenario3")
    assert saved and saved["chain_ids"] == ["4"]
    raw = json.loads(ET.parse(xml_path).find('.//FlowState').text)
    assert raw['chain'][0]['id'] == '4'
    assert raw['chain_ids'] == ['4']
    from scenarioforge import cli
    assert cli._flow_state_from_xml(str(xml_path), 'Scenario3')['chain'][0]['id'] == '4'


def test_prefer_flow_rejects_existing_invalid_state_instead_of_expanding_it(tmp_path):
    invalid_state = {
        "scenario": "Scenario3",
        "flow_enabled": True,
        "length": 1,
        "chain_ids": ["3"],
        "flag_assignments": [{"node_id": "3", "id": "hash_shadow_credential", "type": "flag-generator"}],
    }
    xml_path, _preview = _write_preview_xml(tmp_path, invalid_state)
    app_backend.app.config["TESTING"] = True
    client = app_backend.app.test_client()
    login = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login.status_code in (302, 303)

    response = client.get(
        "/api/flag-sequencing/attackflow_preview",
        query_string={"scenario": "Scenario3", "xml_path": str(xml_path), "prefer_flow": "1"},
    )

    data = response.get_json() or {}
    assert response.status_code == 422
    assert "missing required vulnerability node" in str(data.get("error") or "").lower()


def test_cli_reads_legacy_save_preview_chain_ids(tmp_path):
    from scenarioforge import cli
    xml_path, _ = _write_preview_xml(tmp_path, {
        'flow_enabled': True, 'chain_ids': ['4'],
        'flag_assignments': [{'node_id': '4', 'id': '131', 'type': 'flag-node-generator'}],
    })
    state = cli._flow_state_from_xml(str(xml_path), 'Scenario3')
    assert state['chain'] == [{'id': '4', 'name': '4'}]


def test_cli_does_not_resurrect_topology_dirty_sequence(tmp_path):
    from scenarioforge import cli
    xml_path, _ = _write_preview_xml(tmp_path, {
        'chain_ids': ['4'], 'chain': [{'id': '4'}], 'topology_dirty': True,
    })
    state = cli._flow_state_from_xml(str(xml_path), 'Scenario3')
    assert state['chain'] == [] and state['chain_ids'] == []
