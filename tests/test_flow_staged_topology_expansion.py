import json
import os
import tempfile
import uuid

import pytest

from webapp import app_backend
from webapp.app_backend import app


def _login(client):
    response = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert response.status_code in (302, 303)


def _fake_assignments(_preview, chain_nodes, _scenario, **_kwargs):
    assignments = []
    for index, node in enumerate(chain_nodes or []):
        node_id = str(node.get('id') or '')
        is_vuln = app_backend._flow_node_is_vuln(node)
        requested = str(node.get('flag_node_generator_id') or '').strip()
        generator_id = 'fg-vuln' if is_vuln else (requested or f'ng-generic-{index}')
        assignments.append(
            {
                'node_id': node_id,
                'id': generator_id,
                'generator_id': generator_id,
                'name': generator_id,
                'type': 'flag-generator' if is_vuln else 'flag-node-generator',
                'generator_catalog': 'flag_generators' if is_vuln else 'flag_node_generators',
                'inputs': [],
                'outputs': ['Flag(flag_id)'],
                'requires': [],
                'produces': [],
            }
        )
    return assignments


def _write_xml(path, scenario, *, generic_docker_count=1, include_vulnerability=True, include_fng=True):
    vuln = (
        '<section name="Vulnerabilities" density="0.0">'
        '<item selected="Specific" factor="1.000" v_metric="Count" v_count="1" '
        'v_name="example/CVE-2024-0001" v_path="/tmp/example-compose.yml"/>'
        '</section>'
        if include_vulnerability
        else '<section name="Vulnerabilities" density="0.0"/>'
    )
    fng = (
        '<section name="Flag Node Generators" density="0.0">'
        '<item selected="Specific" factor="1.000" v_metric="Count" v_count="1" '
        'g_id="ng-topology" g_name="Topology generator"/>'
        '</section>'
        if include_fng
        else '<section name="Flag Node Generators" density="0.0"/>'
    )
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(
            f'''<?xml version="1.0" encoding="utf-8"?>
<Scenarios>
  <Scenario name="{scenario}">
    <ScenarioEditor>
      <section name="Node Information">
        <item selected="Docker" factor="1.000" v_metric="Count" v_count="{generic_docker_count}"/>
      </section>
      <section name="Routing" density="0.0"/>
      <section name="Services" density="0.0"/>
      {vuln}
      {fng}
      <section name="Segmentation" density="0.0"/>
      <section name="Traffic" density="0.0"/>
    </ScenarioEditor>
  </Scenario>
</Scenarios>'''
        )


def _post_sequence(client, payload):
    response = client.post('/api/flag-sequencing/sequence_preview_plan', json=payload)
    assert response.status_code == 200
    return response.get_json() or {}


@pytest.mark.filterwarnings('ignore::DeprecationWarning')
def test_topology_vulnerability_and_node_generator_form_two_steps_without_duplicates(monkeypatch):
    """The two mandatory topology slots are a valid two-step chain on their own."""
    app.config['TESTING'] = True
    client = app.test_client()
    _login(client)

    scenario = f'zz-flow-topology-only-{uuid.uuid4().hex[:10]}'
    with tempfile.TemporaryDirectory(prefix='flow-topology-only-') as directory:
        xml_path = os.path.join(directory, f'{scenario}.xml')
        # Both selected topology items are additive Docker slots.  There is no
        # ordinary Docker node available to pad the chain.
        _write_xml(xml_path, scenario, generic_docker_count=0)
        app_backend._planner_persist_flow_plan(xml_path=xml_path, scenario=scenario, seed=2468)

        # Model the Bash + git_deploy_key_repo shape: the vulnerability
        # generator provides the credential required by the explicitly chosen
        # topology node generator.  This must remain a valid two-node chain
        # without relaxing the no-duplicates setting.
        flag_generator = {
            'id': 'fg-vuln', 'name': 'Vulnerability flag generator',
            'inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
            'outputs': [
                {'name': 'Flag(flag_id)'},
                {'name': 'Credential(user, password)'},
            ],
            'language': 'python',
        }
        node_generator = {
            'id': 'ng-topology', 'name': 'Topology node generator',
            'inputs': [
                {'name': 'seed', 'type': 'string', 'required': True},
                {'name': 'node_name', 'type': 'string', 'required': True},
                {
                    'name': 'Credential(user, password)',
                    'type': 'string',
                    'required': True,
                    'flow_supply_when_first': True,
                },
            ],
            'outputs': [{'name': 'Flag(flag_id)'}],
            'language': 'python',
        }
        monkeypatch.setattr(app_backend, '_flag_generators_from_enabled_sources', lambda: ([flag_generator], []))
        monkeypatch.setattr(app_backend, '_flag_node_generators_from_enabled_sources', lambda: ([node_generator], []))

        generated = _post_sequence(
            client,
            {
                'scenario': scenario,
                # The server must raise this to the two specified topology
                # items; it must not require duplicate nodes or generators.
                'length': 1,
                'preview_plan': xml_path,
                'chain_expansion_mode': 'strict',
                'allow_node_duplicates': False,
            },
        )

        assert generated.get('ok') is True, generated
        assert generated.get('requested_length') == 2
        assert generated.get('length') == 2
        chain = generated.get('chain') or []
        assert len({str(node.get('id') or '') for node in chain}) == 2
        assignments = generated.get('flag_assignments') or []
        assert {assignment.get('id') for assignment in assignments} == {'fg-vuln', 'ng-topology'}
        assert assignments[1].get('id') == 'ng-topology'
        assert 'Credential(user, password)' in (assignments[1].get('inputs') or [])


@pytest.mark.filterwarnings('ignore::DeprecationWarning')
def test_topology_items_can_begin_parallel_branches_without_duplicates(monkeypatch):
    """A branch-start input must not be mistaken for a duplicate-capacity failure."""
    app.config['TESTING'] = True
    client = app.test_client()
    _login(client)

    scenario = f'zz-flow-topology-parallel-{uuid.uuid4().hex[:10]}'
    with tempfile.TemporaryDirectory(prefix='flow-topology-parallel-') as directory:
        xml_path = os.path.join(directory, f'{scenario}.xml')
        _write_xml(xml_path, scenario, generic_docker_count=0)
        app_backend._planner_persist_flow_plan(xml_path=xml_path, scenario=scenario, seed=97531)

        flag_generator = {
            'id': 'fg-vuln', 'name': 'Vulnerability flag generator',
            'inputs': [{'name': 'seed', 'type': 'string', 'required': True}],
            'outputs': [{'name': 'Flag(flag_id)'}], 'language': 'python',
        }
        node_generator = {
            'id': 'ng-topology', 'name': 'Topology generator with branch input',
            'inputs': [
                {'name': 'seed', 'type': 'string', 'required': True},
                {
                    'name': 'APIKey(service)', 'type': 'string', 'required': True,
                    'flow_supply_when_first': True,
                },
            ],
            'outputs': [{'name': 'Flag(flag_id)'}], 'language': 'python',
        }
        monkeypatch.setattr(app_backend, '_flag_generators_from_enabled_sources', lambda: ([flag_generator], []))
        monkeypatch.setattr(app_backend, '_flag_node_generators_from_enabled_sources', lambda: ([node_generator], []))

        generated = _post_sequence(
            client,
            {
                'scenario': scenario,
                'length': 2,
                'preview_plan': xml_path,
                'chain_expansion_mode': 'strict',
                'allow_node_duplicates': False,
            },
        )

        assert generated.get('ok') is True, generated
        assignments = generated.get('flag_assignments') or []
        branch_assignment = next(item for item in assignments if item.get('id') == 'ng-topology')
        assert branch_assignment.get('chain_supplied_parallel_start') is True
        assert branch_assignment.get('chain_supplied_inputs') == ['APIKey(service)']


def test_unmarked_required_input_is_not_assigned_as_a_fallback(monkeypatch):
    """A dependency consumer cannot run until its required fact is available."""
    node_generator = {
        'id': 'ng-key-consumer',
        'name': 'Key consumer',
        'inputs': [{'name': 'Key(service)', 'type': 'string', 'required': True}],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'language': 'python',
    }
    monkeypatch.setattr(app_backend, '_flag_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(app_backend, '_flag_node_generators_from_enabled_sources', lambda: ([node_generator], []))

    preview = {
        'hosts': [{'node_id': '1', 'role': 'Docker', 'vulnerabilities': []}],
    }
    chain_nodes = [{
        'id': '1', 'name': 'docker-1', 'type': 'docker', 'role': 'Docker',
        '_topology_flag_node_generators_configured': True,
        'flag_node_generator_id': 'ng-key-consumer',
    }]

    assert app_backend._flow_compute_flag_assignments(
        preview,
        chain_nodes,
        'strict-required-input',
        disallow_generator_reuse=False,
    ) == []


def test_unreachable_explicit_goal_does_not_fall_back_to_a_non_goal_assignment(monkeypatch):
    """An explicit Flow goal must be met, rather than silently ignored."""
    flag_generator = {
        'id': 'fg-ordinary',
        'name': 'Ordinary vulnerability generator',
        'inputs': [],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'language': 'python',
    }
    monkeypatch.setattr(app_backend, '_flag_generators_from_enabled_sources', lambda: ([flag_generator], []))
    monkeypatch.setattr(app_backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))

    preview = {
        'hosts': [{'node_id': '1', 'role': 'Docker', 'vulnerabilities': ['example/CVE-2024-0001']}],
    }
    chain_nodes = [{
        'id': '1', 'name': 'docker-1', 'type': 'docker', 'role': 'Docker',
        'is_vuln': True,
    }]

    assert app_backend._flow_compute_flag_assignments(
        preview,
        chain_nodes,
        'strict-goal',
        goal_facts_override={'fields': ['Key(service)']},
    ) == []


@pytest.mark.filterwarnings('ignore::DeprecationWarning')
def test_flow_requires_confirmation_before_reusing_existing_docker_and_syncs_xml(monkeypatch):
    app.config['TESTING'] = True
    client = app.test_client()
    _login(client)

    scenario = f'zz-flow-staged-existing-{uuid.uuid4().hex[:10]}'
    with tempfile.TemporaryDirectory(prefix='flow-staged-existing-') as directory:
        xml_path = os.path.join(directory, f'{scenario}.xml')
        _write_xml(xml_path, scenario, generic_docker_count=1)
        result = app_backend._planner_persist_flow_plan(xml_path=xml_path, scenario=scenario, seed=31337)
        assert isinstance(result.get('full_preview'), dict)

        monkeypatch.setattr(app_backend, '_flow_compute_flag_assignments', _fake_assignments)
        monkeypatch.setattr(app_backend, '_flow_reorder_chain_by_generator_dag', lambda chain, assignments, **_kwargs: (chain, assignments, {}))
        monkeypatch.setattr(app_backend, '_flow_validate_chain_order_by_requires_produces', lambda *_args, **_kwargs: (True, []))

        strict = _post_sequence(
            client,
            {
                'scenario': scenario,
                'length': 3,
                'preview_plan': xml_path,
                'chain_expansion_mode': 'strict',
                'sequence_request_id': f'{scenario}-strict',
            },
        )
        assert strict.get('ok') is False
        assert strict.get('confirmation_required') is True
        assert strict.get('expansion_stage') == 'existing_docker'
        offer = strict.get('chain_expansion_offer') or {}
        assert offer.get('existing_docker_available') == 1
        assert offer.get('additional_items_needed') == 1

        before_unconfirmed = open(xml_path, 'rb').read()
        unconfirmed = _post_sequence(
            client,
            {
                'scenario': scenario,
                'length': 3,
                'preview_plan': xml_path,
                'chain_expansion_mode': 'existing_docker',
                'sequence_request_id': f'{scenario}-unconfirmed',
            },
        )
        assert unconfirmed.get('ok') is False
        assert open(xml_path, 'rb').read() == before_unconfirmed

        generated = _post_sequence(
            client,
            {
                'scenario': scenario,
                'length': 3,
                'preview_plan': xml_path,
                'chain_expansion_mode': 'existing_docker',
                'topology_fingerprint': offer.get('topology_fingerprint'),
                'expansion_request_id': f'{scenario}-expand',
                'sequence_request_id': f'{scenario}-existing',
            },
        )
        assert generated.get('ok') is True, generated
        expansion = generated.get('chain_expansion') or {}
        assert expansion.get('mode') == 'existing_docker'
        assert len(expansion.get('converted_existing_docker_node_ids') or []) == 1
        assert expansion.get('topology_changed') is False

        saved_state = app_backend._flow_state_from_xml_path(xml_path, scenario)
        saved_preview = app_backend._load_plan_preview_from_xml(xml_path, scenario)
        assert isinstance(saved_state, dict)
        assert isinstance(saved_preview, dict)
        assert (saved_preview.get('metadata') or {}).get('flow') == saved_state
        assert (saved_state.get('chain_expansion') or {}).get('mode') == 'existing_docker'

        # An older UI client can save the normal resolved state without the
        # newer audit fields; XML remains the source of truth for those fields.
        legacy_state = dict(saved_state)
        legacy_state.pop('chain_expansion', None)
        legacy_state.pop('topology_inclusion', None)
        preserved = client.post(
            '/api/flag-sequencing/save_flow_state_to_xml',
            json={'scenario': scenario, 'xml_path': xml_path, 'flow_state': legacy_state},
        )
        assert preserved.status_code == 200, preserved.get_json()
        preserved_state = app_backend._flow_state_from_xml_path(xml_path, scenario) or {}
        assert (preserved_state.get('chain_expansion') or {}).get('mode') == 'existing_docker'
        assert (preserved_state.get('topology_inclusion') or {}).get('converted_existing_docker_node_ids')

        # Planner refreshes are another active writer; they must preserve the
        # same XML-backed FlowState rather than rebuilding only PlanPreview.
        app_backend._planner_persist_flow_plan(xml_path=xml_path, scenario=scenario, seed=31337)
        planner_state = app_backend._flow_state_from_xml_path(xml_path, scenario) or {}
        planner_preview = app_backend._load_plan_preview_from_xml(xml_path, scenario) or {}
        assert (planner_state.get('chain_expansion') or {}).get('mode') == 'existing_docker'
        assert (planner_preview.get('metadata') or {}).get('flow') == planner_state


@pytest.mark.filterwarnings('ignore::DeprecationWarning')
def test_flow_add_docker_stage_updates_spec_preview_and_is_idempotent(monkeypatch):
    app.config['TESTING'] = True
    client = app.test_client()
    _login(client)

    scenario = f'zz-flow-staged-add-{uuid.uuid4().hex[:10]}'
    with tempfile.TemporaryDirectory(prefix='flow-staged-add-') as directory:
        xml_path = os.path.join(directory, f'{scenario}.xml')
        # The vulnerability and FNG consume their own additive Docker slots;
        # no ordinary Docker slot exists yet for the third requested item.
        _write_xml(xml_path, scenario, generic_docker_count=0)
        app_backend._planner_persist_flow_plan(xml_path=xml_path, scenario=scenario, seed=4242)

        monkeypatch.setattr(app_backend, '_flow_compute_flag_assignments', _fake_assignments)
        monkeypatch.setattr(app_backend, '_flow_reorder_chain_by_generator_dag', lambda chain, assignments, **_kwargs: (chain, assignments, {}))
        monkeypatch.setattr(app_backend, '_flow_validate_chain_order_by_requires_produces', lambda *_args, **_kwargs: (True, []))

        strict = _post_sequence(
            client,
            {
                'scenario': scenario,
                'length': 3,
                'preview_plan': xml_path,
                'chain_expansion_mode': 'strict',
                'sequence_request_id': f'{scenario}-strict',
            },
        )
        assert strict.get('expansion_stage') == 'existing_docker'
        first_offer = strict.get('chain_expansion_offer') or {}
        assert first_offer.get('existing_docker_available') == 0

        existing = _post_sequence(
            client,
            {
                'scenario': scenario,
                'length': 3,
                'preview_plan': xml_path,
                'chain_expansion_mode': 'existing_docker',
                'topology_fingerprint': first_offer.get('topology_fingerprint'),
                'sequence_request_id': f'{scenario}-existing',
            },
        )
        assert existing.get('ok') is False
        assert existing.get('expansion_stage') == 'add_docker'
        second_offer = existing.get('chain_expansion_offer') or {}
        assert second_offer.get('additional_items_needed') == 1

        expansion_request_id = f'{scenario}-add-once'
        generated = _post_sequence(
            client,
            {
                'scenario': scenario,
                'length': 3,
                'preview_plan': xml_path,
                'chain_expansion_mode': 'add_docker',
                'topology_fingerprint': second_offer.get('topology_fingerprint'),
                'expansion_request_id': expansion_request_id,
                'sequence_request_id': f'{scenario}-add',
            },
        )
        assert generated.get('ok') is True, generated
        expansion = generated.get('chain_expansion') or {}
        assert expansion.get('mode') == 'add_docker'
        assert expansion.get('topology_changed') is True
        assert expansion.get('added_docker_nodes') == 1
        assert isinstance(generated.get('full_preview'), dict)

        parsed = app_backend._parse_scenarios_xml(xml_path)
        scenario_payload = next(item for item in parsed['scenarios'] if item.get('name') == scenario)
        docker_counts = [
            int(item.get('v_count') or 0)
            for item in scenario_payload['sections']['Node Information']['items']
            if item.get('selected') == 'Docker' and item.get('v_metric') == 'Count'
        ]
        assert sum(docker_counts) == 1
        assert any(
            str(item.get('request_id') or '') == expansion_request_id
            for item in (scenario_payload.get('flow_expansion') or [])
        )

        saved_state = app_backend._flow_state_from_xml_path(xml_path, scenario)
        saved_preview = app_backend._load_plan_preview_from_xml(xml_path, scenario)
        assert (saved_preview.get('metadata') or {}).get('flow') == saved_state
        assert (saved_state.get('chain_expansion') or {}).get('mode') == 'add_docker'

        # The confirmed expansion request is durable/idempotent.  Calling the
        # lower-level operation again cannot append another Count row.
        ok, repeated, message = app_backend._flow_add_docker_nodes_and_rebuild_preview_in_xml(
            xml_path=xml_path,
            scenario_label=scenario,
            additional_docker_nodes=1,
            expansion_request_id=expansion_request_id,
            seed=4242,
        )
        assert ok is True, message
        assert repeated.get('already_applied') is True
        reparsed = app_backend._parse_scenarios_xml(xml_path)
        reparsed_scenario = next(item for item in reparsed['scenarios'] if item.get('name') == scenario)
        repeated_counts = [
            int(item.get('v_count') or 0)
            for item in reparsed_scenario['sections']['Node Information']['items']
            if item.get('selected') == 'Docker' and item.get('v_metric') == 'Count'
        ]
        assert sum(repeated_counts) == 1


@pytest.mark.filterwarnings('ignore::DeprecationWarning')
def test_flow_rejects_a_stale_expansion_confirmation_without_mutating_xml(monkeypatch):
    app.config['TESTING'] = True
    client = app.test_client()
    _login(client)

    scenario = f'zz-flow-staged-stale-{uuid.uuid4().hex[:10]}'
    with tempfile.TemporaryDirectory(prefix='flow-staged-stale-') as directory:
        xml_path = os.path.join(directory, f'{scenario}.xml')
        _write_xml(xml_path, scenario, generic_docker_count=1)
        app_backend._planner_persist_flow_plan(xml_path=xml_path, scenario=scenario, seed=44)
        monkeypatch.setattr(app_backend, '_flow_compute_flag_assignments', _fake_assignments)
        monkeypatch.setattr(app_backend, '_flow_reorder_chain_by_generator_dag', lambda chain, assignments, **_kwargs: (chain, assignments, {}))
        monkeypatch.setattr(app_backend, '_flow_validate_chain_order_by_requires_produces', lambda *_args, **_kwargs: (True, []))

        strict = _post_sequence(
            client,
            {
                'scenario': scenario,
                'length': 3,
                'preview_plan': xml_path,
                'chain_expansion_mode': 'strict',
                'sequence_request_id': f'{scenario}-strict',
            },
        )
        old_fingerprint = (strict.get('chain_expansion_offer') or {}).get('topology_fingerprint')
        assert old_fingerprint

        # Simulate a topology refresh/change occurring while the confirmation
        # modal is open.  The old approval must not be applied to it.
        plan_payload = app_backend._load_plan_preview_from_xml(xml_path, scenario)
        plan_payload['full_preview']['hosts'].append(
            {'node_id': 'new-host', 'name': 'docker-new', 'role': 'Docker', 'vulnerabilities': []}
        )
        ok, message = app_backend._update_plan_preview_in_xml(xml_path, scenario, plan_payload)
        assert ok, message
        before_retry = open(xml_path, 'rb').read()

        stale = _post_sequence(
            client,
            {
                'scenario': scenario,
                'length': 3,
                'preview_plan': xml_path,
                'chain_expansion_mode': 'existing_docker',
                'topology_fingerprint': old_fingerprint,
                'sequence_request_id': f'{scenario}-stale',
            },
        )
        assert stale.get('ok') is False
        assert stale.get('stale_confirmation') is True
        assert open(xml_path, 'rb').read() == before_retry


def test_docker_expansion_planning_failure_leaves_xml_unchanged(monkeypatch):
    scenario = f'zz-flow-staged-atomic-{uuid.uuid4().hex[:10]}'
    with tempfile.TemporaryDirectory(prefix='flow-staged-atomic-') as directory:
        xml_path = os.path.join(directory, f'{scenario}.xml')
        _write_xml(xml_path, scenario, generic_docker_count=0)
        before = open(xml_path, 'rb').read()

        from scenarioforge.planning import orchestrator

        def _raise_planning_error(*_args, **_kwargs):
            raise RuntimeError('planned failure')

        monkeypatch.setattr(orchestrator, 'compute_full_plan', _raise_planning_error)
        ok, _result, message = app_backend._flow_add_docker_nodes_and_rebuild_preview_in_xml(
            xml_path=xml_path,
            scenario_label=scenario,
            additional_docker_nodes=1,
            expansion_request_id=f'{scenario}-atomic',
            seed=1,
        )
        assert ok is False
        assert 'planned failure' in message
        assert open(xml_path, 'rb').read() == before
