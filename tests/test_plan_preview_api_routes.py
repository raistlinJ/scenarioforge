from flask import Flask
import xml.etree.ElementTree as ET

from webapp.routes import plan_preview_api


def _passthrough_resolve_xml(xml_path, scenario=None):
    return str(xml_path or '')


def test_persist_flow_plan_route_returns_payload_from_planner():
    app = Flask(__name__)
    plan_preview_api.register(
        app,
        backend_module=type(
            'BackendModule',
            (),
            {
                '_resolve_preexecute_xml_path': staticmethod(_passthrough_resolve_xml),
                '_planner_persist_flow_plan': staticmethod(
                    lambda **kwargs: {
                        'xml_path': kwargs.get('xml_path'),
                        'scenario': kwargs.get('scenario'),
                        'seed': kwargs.get('seed'),
                        'preview_plan_path': '/tmp/plan.xml',
                    }
                ),
            },
        )(),
    )

    client = app.test_client()
    resp = client.post('/api/plan/persist_flow_plan', json={'xml_path': '/tmp/demo.xml', 'scenario': 'Demo', 'seed': 17})

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload == {
        'ok': True,
        'xml_path': '/tmp/demo.xml',
        'scenario': 'Demo',
        'seed': 17,
        'preview_plan_path': '/tmp/plan.xml',
    }


def test_persist_flow_plan_route_requires_xml_path():
    app = Flask(__name__)
    plan_preview_api.register(
        app,
        backend_module=type(
            'BackendModule',
            (),
            {
                '_resolve_preexecute_xml_path': staticmethod(_passthrough_resolve_xml),
                '_planner_persist_flow_plan': staticmethod(lambda **kwargs: kwargs),
            },
        )(),
    )

    client = app.test_client()
    resp = client.post('/api/plan/persist_flow_plan', json={'scenario': 'Demo'})

    assert resp.status_code == 400
    payload = resp.get_json()
    assert payload == {'ok': False, 'error': 'xml_path missing'}


def test_persist_flow_plan_route_prefers_latest_xml_for_scenario(tmp_path):
    latest_xml = tmp_path / 'latest.xml'
    latest_xml.write_text('<Scenarios />', encoding='utf-8')
    captured = {}

    app = Flask(__name__)
    plan_preview_api.register(
        app,
        backend_module=type(
            'BackendModule',
            (),
            {
                '_resolve_preexecute_xml_path': staticmethod(lambda _xml_path, _scenario=None: str(latest_xml)),
                '_planner_persist_flow_plan': staticmethod(
                    lambda **kwargs: captured.setdefault('kwargs', kwargs) or {
                        'xml_path': kwargs.get('xml_path'),
                        'scenario': kwargs.get('scenario'),
                        'seed': kwargs.get('seed'),
                        'preview_plan_path': '/tmp/plan.xml',
                    }
                ),
            },
        )(),
    )

    client = app.test_client()
    resp = client.post('/api/plan/persist_flow_plan', json={'xml_path': '/tmp/stale.xml', 'scenario': 'Demo', 'seed': 17})

    assert resp.status_code == 200
    assert captured['kwargs']['xml_path'] == str(latest_xml)


def test_preview_full_route_prefers_latest_xml_for_scenario(tmp_path):
    latest_xml = tmp_path / 'latest.xml'
    latest_xml.write_text('<Scenarios />', encoding='utf-8')
    captured = {}

    def _load_preview_payload(xml_path, scenario=None):
        captured['xml_path'] = xml_path
        return {
            'full_preview': {'seed': 7, 'hosts': [{'node_id': 1}]},
            'metadata': {'seed': 7},
        }

    app = Flask(__name__)
    plan_preview_api.register(
        app,
        backend_module=type(
            'BackendModule',
            (),
            {
                '_resolve_preexecute_xml_path': staticmethod(lambda _xml_path, _scenario=None: str(latest_xml)),
                '_load_preview_payload_from_path': staticmethod(_load_preview_payload),
                '_flow_state_from_xml_path': staticmethod(lambda xml_path, scenario=None: {'chain_ids': ['1']}),
                '_flow_repair_saved_flow_for_preview': staticmethod(lambda preview, flow_meta: {'repaired': True}),
            },
        )(),
    )

    client = app.test_client()
    resp = client.post('/api/plan/preview_full', json={'xml_path': '/tmp/stale.xml', 'scenario': 'Demo'})

    assert resp.status_code == 200
    assert captured['xml_path'] == str(latest_xml)


def test_preview_full_route_requires_xml_path_when_no_inline_scenarios():
    app = Flask(__name__)
    plan_preview_api.register(
        app,
        backend_module=type(
            'BackendModule',
            (),
            {
                '_resolve_preexecute_xml_path': staticmethod(_passthrough_resolve_xml),
            },
        )(),
    )

    client = app.test_client()
    resp = client.post('/api/plan/preview_full', json={'scenario': 'Demo'})

    assert resp.status_code == 400
    payload = resp.get_json()
    assert payload == {'ok': False, 'error': 'xml_path missing'}


def test_preview_full_route_returns_embedded_preview_without_recompute():
    app = Flask(__name__)
    plan_preview_api.register(
        app,
        backend_module=type(
            'BackendModule',
            (),
            {
                '_resolve_preexecute_xml_path': staticmethod(_passthrough_resolve_xml),
                '_load_preview_payload_from_path': staticmethod(
                    lambda xml_path, scenario=None: {
                        'full_preview': {'seed': 7, 'hosts': [{'node_id': 1}]},
                        'metadata': {'seed': 7},
                    }
                ),
                '_flow_state_from_xml_path': staticmethod(lambda xml_path, scenario=None: {'chain_ids': ['1']}),
                '_attach_latest_flow_into_full_preview': staticmethod(lambda preview, scenario=None: {'attached': True}),
                '_flow_repair_saved_flow_for_preview': staticmethod(lambda preview, flow_meta: {'repaired': True}),
            },
        )(),
    )

    client = app.test_client()
    resp = client.post('/api/plan/preview_full', json={'xml_path': __file__, 'scenario': 'Demo'})

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload['ok'] is True
    assert payload['full_preview'] == {'seed': 7, 'hosts': [{'node_id': 1}]}
    assert payload['plan'] == {}
    assert payload['breakdowns'] is None
    assert payload['flow_meta'] == {'repaired': True}


def test_preview_full_route_limits_inline_builder_payload_to_requested_scenario(tmp_path):
    captured = {}

    def build_scenarios_xml(payload):
        scenarios = payload.get('scenarios') or []
        captured['names'] = [str((sc or {}).get('name') or '') for sc in scenarios if isinstance(sc, dict)]
        root = ET.Element('Scenarios')
        for scen in scenarios:
            if not isinstance(scen, dict):
                continue
            ET.SubElement(root, 'Scenario', name=str(scen.get('name') or ''))
        return ET.ElementTree(root)

    app = Flask(__name__)
    plan_preview_api.register(
        app,
        backend_module=type(
            'BackendModule',
            (),
            {
                '_resolve_preexecute_xml_path': staticmethod(_passthrough_resolve_xml),
                '_normalize_scenario_label': staticmethod(lambda value: str(value or '').strip().lower()),
                '_normalize_core_config': staticmethod(lambda core, include_password=True: core),
                '_build_scenarios_xml': staticmethod(build_scenarios_xml),
                '_local_timestamp_safe': staticmethod(lambda: '06-17-26-12-00-00'),
                '_outputs_dir': staticmethod(lambda: str(tmp_path)),
                'secure_filename': staticmethod(lambda value: str(value or '').replace(' ', '_')),
                'ET': ET,
                '_load_preview_payload_from_path': staticmethod(
                    lambda xml_path, scenario=None: {
                        'full_preview': {'seed': 11, 'hosts': []},
                        'metadata': {'seed': 11},
                    }
                ),
                '_flow_state_from_xml_path': staticmethod(lambda xml_path, scenario=None: None),
                '_attach_latest_flow_into_full_preview': staticmethod(lambda preview, scenario=None: {'attached': True}),
                '_flow_repair_saved_flow_for_preview': staticmethod(lambda preview, flow_meta: flow_meta),
            },
        )(),
    )

    client = app.test_client()
    resp = client.post(
        '/api/plan/preview_full',
        json={
            'scenario': 'Beta',
            'scenarios': [
                {'name': 'Alpha', 'sections': {'Node Information': {'items': []}}},
                {'name': 'Beta', 'sections': {'Node Information': {'items': []}}},
            ],
        },
    )

    assert resp.status_code == 200
    assert resp.get_json()['ok'] is True
    assert captured['names'] == ['Beta']


def test_preview_full_route_skips_latest_flow_lookup_when_current_xml_has_no_flow_state():
    app = Flask(__name__)
    plan_preview_api.register(
        app,
        backend_module=type(
            'BackendModule',
            (),
            {
                '_resolve_preexecute_xml_path': staticmethod(_passthrough_resolve_xml),
                '_load_preview_payload_from_path': staticmethod(
                    lambda xml_path, scenario=None: {
                        'full_preview': {'seed': 13, 'hosts': [{'node_id': 1}]},
                        'metadata': {'seed': 13},
                    }
                ),
                '_flow_state_from_xml_path': staticmethod(lambda xml_path, scenario=None: None),
            },
        )(),
    )

    client = app.test_client()
    resp = client.post('/api/plan/preview_full', json={'xml_path': __file__, 'scenario': 'Demo'})

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload['ok'] is True
    assert payload['full_preview'] == {'seed': 13, 'hosts': [{'node_id': 1}]}
    assert payload['flow_meta'] == {}