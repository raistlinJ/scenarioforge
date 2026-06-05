from types import SimpleNamespace
import os

from flask import Flask

from webapp.routes import flag_sequencing_exports


def _build_backend(**overrides):
    backend = SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _flow_state_from_latest_xml=lambda scenario_norm: None,
        _flow_state_from_xml_path=lambda xml_path, scenario_label: None,
        _planner_get_plan=lambda scenario_norm: None,
        _latest_preview_plan_for_scenario_norm_origin=lambda scenario_norm, origin='planner': None,
        _latest_preview_plan_for_scenario_norm=lambda scenario_norm: None,
        _load_preview_payload_from_path=lambda path, scenario: {},
        _attach_latest_flow_into_plan_payload=lambda payload, scenario: None,
        _first_valid_ipv4=lambda value: str(value or '').strip() or None,
        _flow_normalize_fact_override=lambda value: value,
        _flow_normalize_dependency_level=lambda value: value,
        _flow_compute_flag_assignments=lambda preview, chain_nodes, scenario_label, initial_facts_override=None, goal_facts_override=None: [],
        _flow_apply_pivot_context_to_assignments=lambda flag_assignments, chain_nodes, **kwargs: flag_assignments,
        _flow_reorder_chain_by_generator_dag=lambda chain_nodes, flag_assignments, **kwargs: (chain_nodes, flag_assignments, {}),
        _flow_validate_chain_order_by_requires_produces=lambda chain_nodes, flag_assignments, scenario_label=None: (True, []),
        _attack_flow_builder_afb_for_chain=lambda **kwargs: {'kind': 'afb', 'nodes': len(kwargs.get('chain_nodes') or [])},
        _attack_graph_for_chain=lambda **kwargs: {'nodes': [node.get('id') for node in (kwargs.get('chain_nodes') or [])]},
        _attack_graph_dot=lambda graph: 'digraph G {}',
        _attack_graph_pdf_base64=lambda dot: 'cGRm',
        os=os,
    )
    for name, value in overrides.items():
        setattr(backend, name, value)
    return backend


def _make_client(backend=None):
    app = Flask(__name__)
    app.config['TESTING'] = True
    flag_sequencing_exports.register(app, backend_module=backend or _build_backend())
    return app.test_client()


def test_afb_from_chain_returns_export_payload():
    client = _make_client()

    resp = client.post(
        '/api/flag-sequencing/afb_from_chain',
        json={
            'scenario': 'Demo Scenario',
            'chain': [
                {'id': 'n1', 'name': 'First', 'type': 'host', 'is_vuln': True},
                {'id': 'n2', 'name': 'Second', 'type': 'docker'},
            ],
        },
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body['ok'] is True
    assert body['scenario'] == 'Demo Scenario'
    assert body['length'] == 2
    assert body['afb'] == {'kind': 'afb', 'nodes': 2}
    assert body['attack_graph'] == {'nodes': ['n1', 'n2']}
    assert body['attack_graph_dot'] == 'digraph G {}'
    assert body['attack_graph_pdf_base64'] == 'cGRm'
    assert body['flags_enabled'] is True



def test_afb_from_chain_builds_exports_from_repaired_visual_order():
    captured = {}

    def validate(chain_nodes, flag_assignments, scenario_label=None):
        order = [node.get('id') for node in chain_nodes]
        if order == ['source', 'target']:
            return True, []
        return False, ["target: requires ['Token(source)'] before they are produced"]

    def reorder(chain_nodes, flag_assignments, **kwargs):
        node_by_id = {node.get('id'): node for node in chain_nodes}
        assignment_by_node = {assignment.get('node_id'): assignment for assignment in flag_assignments}
        order = ['source', 'target']
        return [node_by_id[node_id] for node_id in order], [assignment_by_node[node_id] for node_id in order], {'ok': True}

    def build_afb(**kwargs):
        captured['afb_chain'] = [node.get('id') for node in kwargs.get('chain_nodes') or []]
        captured['afb_assignments'] = [assignment.get('node_id') for assignment in kwargs.get('flag_assignments') or []]
        return {'chain_order': captured['afb_chain']}

    def build_graph(**kwargs):
        captured['graph_chain'] = [node.get('id') for node in kwargs.get('chain_nodes') or []]
        captured['graph_assignments'] = [assignment.get('node_id') for assignment in kwargs.get('flag_assignments') or []]
        return {'chain_order': captured['graph_chain']}

    client = _make_client(_build_backend(
        _flow_validate_chain_order_by_requires_produces=validate,
        _flow_reorder_chain_by_generator_dag=reorder,
        _attack_flow_builder_afb_for_chain=build_afb,
        _attack_graph_for_chain=build_graph,
    ))

    resp = client.post(
        '/api/flag-sequencing/afb_from_chain',
        json={
            'scenario': 'Demo Scenario',
            'chain': [
                {'id': 'target', 'name': 'Target', 'type': 'docker'},
                {'id': 'source', 'name': 'Source', 'type': 'docker'},
            ],
            'flag_assignments': [
                {'node_id': 'target', 'id': 'gen-target', 'requires': ['Token(source)']},
                {'node_id': 'source', 'id': 'gen-source', 'produces': ['Token(source)']},
            ],
        },
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert [node['id'] for node in body['chain']] == ['source', 'target']
    assert [assignment['node_id'] for assignment in body['flag_assignments']] == ['source', 'target']
    assert body['afb'] == {'chain_order': ['source', 'target']}
    assert body['attack_graph'] == {'chain_order': ['source', 'target']}
    assert captured['afb_chain'] == ['source', 'target']
    assert captured['afb_assignments'] == ['source', 'target']
    assert captured['graph_chain'] == ['source', 'target']
    assert captured['graph_assignments'] == ['source', 'target']
    assert body['flow_valid'] is True
    assert body['flags_enabled'] is True