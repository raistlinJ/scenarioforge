from flask import Flask

from webapp.routes import planner


def test_ensure_plan_prefers_latest_xml_for_scenario(tmp_path):
    latest_xml = tmp_path / 'latest.xml'
    latest_xml.write_text('<Scenarios />', encoding='utf-8')
    captured = {}

    app = Flask(__name__)

    planner.register(
        app,
        planner_persist_flow_plan=lambda **kwargs: captured.setdefault('kwargs', kwargs) or {
            'xml_path': kwargs.get('xml_path'),
            'scenario': kwargs.get('scenario'),
            'seed': kwargs.get('seed'),
            'preview_plan_path': str(latest_xml),
        },
        normalize_scenario_label=lambda value: str(value or '').strip().lower(),
        latest_xml_path_for_scenario=lambda _scenario_norm: str(latest_xml),
        resolve_preexecute_xml_path=lambda _xml_path, _scenario: str(latest_xml),
    )

    client = app.test_client()
    resp = client.post('/api/planner/ensure_plan', json={'xml_path': '/tmp/stale.xml', 'scenario': 'Demo', 'seed': 9})

    assert resp.status_code == 200
    assert captured['kwargs']['xml_path'] == str(latest_xml)