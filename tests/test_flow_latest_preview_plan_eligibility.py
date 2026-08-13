from pathlib import Path

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_latest_preview_plan_reports_core_and_topology_reasons_when_unavailable(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')

    payload = {
        'metadata': {'scenario': 'Scenario One'},
        'full_preview': {
            'hosts': [],
            'vulnerabilities_by_node': {},
        },
    }

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: {'validated': False, 'ssh_enabled': True})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_load_scenario_hitl_validation_from_disk', lambda: {})
    monkeypatch.setattr(backend, '_select_latest_core_secret_record', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', lambda: [])

    resp = client.get('/api/flag-sequencing/latest_preview_plan', query_string={'scenario': 'Scenario One'})
    assert resp.status_code == 422
    data = resp.get_json()
    assert data['flow_eligible'] is False
    assert 'CORE VM must be validated in VM / Access.' in data['flow_eligibility_reasons']
    assert 'Topology must include Docker or vulnerability nodes.' in data['flow_eligibility_reasons']
    assert 'No vulnerabilities are available in the Vulnerability Catalog.' in data['flow_eligibility_reasons']


def test_latest_preview_plan_reports_missing_flag_generators_for_vuln_nodes(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')

    payload = {
        'metadata': {'scenario': 'Scenario One'},
        'full_preview': {
            'hosts': [
                {'id': 'docker-1', 'role': 'docker', 'vulnerabilities': ['vuln-a']},
            ],
            'vulnerabilities_by_node': {'docker-1': ['vuln-a']},
        },
    }

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: {'validated': True, 'ssh_enabled': True})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', lambda: [{'Name': 'Example Vuln'}])

    resp = client.get('/api/flag-sequencing/latest_preview_plan', query_string={'scenario': 'Scenario One'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['flow_eligible'] is False
    assert data['vuln_count'] == 1
    assert data['flag_generator_count'] == 0
    assert 'No enabled flag-generators are available for vulnerability nodes.' in data['flow_eligibility_reasons']


def test_latest_preview_plan_reports_topology_selected_node_generator_count(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')

    payload = {
        'metadata': {'scenario': 'Scenario One'},
        'full_preview': {
            'hosts': [
                {'node_id': 'vuln-1', 'role': 'docker', 'vulnerabilities': ['vuln-a']},
                {'node_id': 'nodegen-1', 'role': 'docker', 'vulnerabilities': []},
                {'node_id': 'generic-1', 'role': 'docker', 'vulnerabilities': []},
            ],
            'vulnerabilities_by_node': {'vuln-1': ['vuln-a']},
            'flag_node_generators_by_node': {'nodegen-1': 'node-generator-a'},
        },
    }

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: {'validated': True, 'ssh_enabled': True})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([{'id': 'flag-generator-a'}], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([{'id': 'node-generator-a'}], []))
    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', lambda selectable_only=True: [{'Name': 'Example Vuln'}])

    resp = client.get('/api/flag-sequencing/latest_preview_plan', query_string={'scenario': 'Scenario One'})
    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data['vuln_count'] == 1
    assert data['topology_flag_node_generator_count'] == 1
    assert data['generic_docker_count'] == 1


def test_latest_preview_plan_reports_no_validated_tested_vulns_when_catalog_is_present_but_unselectable(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')

    payload = {
        'metadata': {'scenario': 'Scenario One'},
        'full_preview': {
            'hosts': [
                {'id': 'docker-1', 'role': 'docker', 'vulnerabilities': ['vuln-a']},
            ],
            'vulnerabilities_by_node': {'docker-1': ['vuln-a']},
        },
    }

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: {'validated': True, 'ssh_enabled': True})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([{'id': 'fg-1'}], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))

    def _fake_load_backend_vuln_catalog_items(*, selectable_only=True):
        if selectable_only:
            return []
        return [{'Name': 'Example Vuln', 'eligible_for_selection': False}]

    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', _fake_load_backend_vuln_catalog_items)

    resp = client.get('/api/flag-sequencing/latest_preview_plan', query_string={'scenario': 'Scenario One'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['vuln_catalog_count'] == 0
    assert data['vuln_catalog_total_count'] == 1
    assert 'No validated/tested vulnerabilities are currently eligible in the Vulnerability Catalog. Validate at least one vulnerability to use vulnerability-based flag sequencing.' in data['flow_eligibility_reasons']


def test_latest_preview_plan_uses_vm_runtime_defaults_without_reporting_core_unvalidated(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')
    payload = {
        'metadata': {'scenario': 'Scenario One'},
        'full_preview': {
            'hosts': [
                {'id': 'docker-1', 'role': 'docker', 'vulnerabilities': ['vuln-a']},
            ],
            'vulnerabilities_by_node': {'docker-1': ['vuln-a']},
        },
    }

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(backend, '_webui_runtime_mode', lambda: 'vm')
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        backend,
        '_select_core_config_for_page',
        lambda *_args, **_kwargs: {
            'host': '127.0.0.1',
            'port': 50051,
            'ssh_enabled': True,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'corevm',
        },
    )
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_load_scenario_hitl_validation_from_disk', lambda: {})
    monkeypatch.setattr(backend, '_select_latest_core_secret_record', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([{'id': 'fg-1'}], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))

    def _fake_load_backend_vuln_catalog_items(*, selectable_only=True):
        if selectable_only:
            return []
        return [{'Name': 'Example Vuln', 'eligible_for_selection': False}]

    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', _fake_load_backend_vuln_catalog_items)

    resp = client.get('/api/flag-sequencing/latest_preview_plan', query_string={'scenario': 'Scenario One'})

    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data['core_validated'] is True
    assert 'CORE VM must be validated in VM / Access.' not in data['flow_eligibility_reasons']
    assert 'No validated/tested vulnerabilities are currently eligible in the Vulnerability Catalog. Validate at least one vulnerability to use vulnerability-based flag sequencing.' in data['flow_eligibility_reasons']


def test_latest_preview_plan_accepts_run_remote_query_flag(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')

    payload = {
        'metadata': {'scenario': 'Scenario One'},
        'full_preview': {
            'hosts': [],
            'vulnerabilities_by_node': {},
        },
    }

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: {'validated': False, 'ssh_enabled': True})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_load_scenario_hitl_validation_from_disk', lambda: {})
    monkeypatch.setattr(backend, '_select_latest_core_secret_record', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', lambda: [])

    resp = client.get(
        '/api/flag-sequencing/latest_preview_plan',
        query_string={'scenario': 'Scenario One', 'run_remote': '1'},
    )

    assert resp.status_code == 422
    data = resp.get_json()
    assert data['core_validated'] is False
    assert data['flow_eligible'] is False


def test_latest_preview_plan_returns_not_modified_when_cache_key_matches(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')

    payload = {
        'metadata': {'scenario': 'Scenario One'},
        'full_preview': {
            'hosts': [
                {'id': 'docker-1', 'role': 'docker', 'vulnerabilities': []},
            ],
            'role_counts': {'Docker': 1},
            'vulnerabilities_by_node': {},
        },
    }

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: payload)
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: {'validated': True, 'ssh_enabled': True})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([{'id': 'fg-1'}], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([{'id': 'fng-1'}], []))
    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', lambda selectable_only=True: [])

    first = client.get('/api/flag-sequencing/latest_preview_plan', query_string={'scenario': 'Scenario One'})
    assert first.status_code == 200
    first_data = first.get_json() or {}
    cache_key = str(first_data.get('data_cache_key') or '')
    assert cache_key

    second = client.get(
        '/api/flag-sequencing/latest_preview_plan',
        query_string={'scenario': 'Scenario One', 'if_data_cache_key': cache_key},
    )
    assert second.status_code == 200
    second_data = second.get_json() or {}
    assert second_data.get('ok') is True
    assert second_data.get('not_modified') is True
    assert second_data.get('data_cache_key') == cache_key


def test_latest_preview_plan_computes_summary_from_topology_without_embedded_preview(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    xml_path = tmp_path / 'Scenario2.xml'
    xml_path.write_text(
        """<Scenarios><Scenario name='Scenario2'><ScenarioEditor>
        <section name='Node Information'>
          <item selected='Docker' v_metric='Count' v_count='5'/>
        </section>
        <section name='Routing' density='0.0'/>
        <section name='Services' density='0.0'/>
        <section name='Traffic' density='0.0'/>
        <section name='Vulnerabilities' density='0.0'>
          <item selected='Specific' v_metric='Count' v_count='2'
                v_name='example/vuln' v_path='https://example.invalid/vuln'/>
        </section>
        <section name='Flag Node Generators' density='0.0'>
          <item selected='Specific' v_metric='Count' v_count='1'
                g_id='example-generator' g_name='Example generator'/>
        </section>
        <section name='Segmentation' density='0.0'/>
        </ScenarioEditor></Scenario></Scenarios>""",
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))
    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_args, **_kwargs: {'validated': True, 'ssh_enabled': True})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_args, **_kwargs: cfg)
    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([{'id': 'fg-1'}], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([{'id': 'fng-1'}], []))
    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', lambda selectable_only=True: [{'Name': 'Example Vuln'}])

    resp = client.get(
        '/api/flag-sequencing/latest_preview_plan',
        query_string={'scenario': 'Scenario 2', 'xml_path': str(xml_path)},
    )

    assert resp.status_code == 200
    data = resp.get_json() or {}
    assert data['preview_source'] == 'topology_xml'
    assert data['preview_plan_path'] == ''
    assert data['specified_flag_node_generator_total'] == 1
    assert data['specified_vulnerability_total'] == 2
    assert data['flag_gen_slot_total'] == 0
    assert data['vulnerability_slot_total'] == 0
    assert data['docker_slot_total'] == 5
    assert data['mandatory_challenge_total'] == 3
    assert data['docker_count'] == 8
