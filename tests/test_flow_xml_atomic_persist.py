import json
import xml.etree.ElementTree as ET

from webapp import app_backend as backend


def test_flow_xml_updates_replace_read_only_target(tmp_path) -> None:
    scenario_name = 'Scenario1'
    xml_path = tmp_path / 'Scenario1.xml'
    xml_path.write_text(
        f'<Scenarios><Scenario name="{scenario_name}"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )
    xml_path.chmod(0o444)

    plan_payload = {
        'full_preview': {'hosts': [], 'routers': [], 'switches': []},
        'metadata': {'scenario': scenario_name, 'seed': 101},
    }
    ok, err = backend._update_plan_preview_in_xml(str(xml_path), scenario_name, plan_payload)
    assert ok, err

    flow_state = {
        'scenario': scenario_name,
        'flow_valid': True,
        'flag_assignments': [
            {
                'node_id': 'docker-1',
                'id': 'dummy-generator',
                'type': 'flag-generator',
                'resolved_outputs': {'Flag(flag_id)': 'FLAG{test}'},
            }
        ],
    }
    ok, err = backend._update_flow_state_in_xml(str(xml_path), scenario_name, flow_state)
    assert ok, err

    assert (xml_path.stat().st_mode & 0o777) == 0o444

    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    plan_el = root.find('./Scenario/ScenarioEditor/PlanPreview')
    flow_el = root.find('./Scenario/ScenarioEditor/FlagSequencing/FlowState')
    assert plan_el is not None and (plan_el.text or '').strip()
    assert flow_el is not None and (flow_el.text or '').strip()

    persisted_plan = json.loads(plan_el.text)
    persisted_flow = json.loads(flow_el.text)
    assert persisted_plan.get('metadata', {}).get('scenario') == scenario_name
    assert persisted_flow.get('flag_assignments', [{}])[0].get('id') == 'dummy-generator'