from webapp.app_backend import app


def _scenario_button_order(body: str) -> list[str]:
    marker = 'data-scen-name="'
    names: list[str] = []
    cursor = 0
    while True:
        idx = body.find(marker, cursor)
        if idx == -1:
            break
        start = idx + len(marker)
        end = body.find('"', start)
        if end == -1:
            break
        names.append(body[start:end])
        cursor = end + 1
    return names


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_flag_pages_use_catalog_only_source(monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    monkeypatch.setattr(
        backend,
        '_load_run_history',
        lambda: [{'scenario_names': ['NewScenario1'], 'scenario_name': 'NewScenario1'}],
    )

    def fake_catalog_for_user(history, user=None):
        if history is None:
            return (
                ['NewScenario12'],
                {'newscenario12': set()},
                {},
            )
        return (
            ['NewScenario1', 'NewScenario12'],
            {'newscenario1': set(), 'newscenario12': set()},
            {},
        )

    monkeypatch.setattr(backend, '_scenario_catalog_for_user', fake_catalog_for_user)

    resp_flow = client.get('/scenarios/flag-sequencing')
    assert resp_flow.status_code == 200
    body_flow = resp_flow.get_data(as_text=True)
    assert 'NewScenario12' in body_flow
    assert '?scenario=NewScenario1"' not in body_flow
    assert 'value="NewScenario1"' not in body_flow

    resp_preview = client.get('/scenarios/preview')
    assert resp_preview.status_code == 200
    body_preview = resp_preview.get_data(as_text=True)
    assert 'NewScenario12' in body_preview
    assert '?scenario=NewScenario1"' not in body_preview
    assert 'value="NewScenario1"' not in body_preview


def test_preview_preserves_catalog_scenarios_when_active_xml_is_single_scenario(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    scenario1_xml = tmp_path / 'Scenario1.xml'
    scenario3_xml = tmp_path / 'Scenario3.xml'
    scenario1_xml.write_text(
        '<Scenarios><Scenario name="Scenario1"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )
    scenario3_xml.write_text(
        '<Scenarios><Scenario name="Scenario3"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )

    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda _history, user=None: (
            ['Scenario1', 'Scenario3'],
            {'scenario1': {str(scenario1_xml)}, 'scenario3': {str(scenario3_xml)}},
            {},
        ),
    )
    monkeypatch.setattr(
        backend,
        '_latest_xml_path_for_scenario',
        lambda norm: str(scenario1_xml) if norm == 'scenario1' else str(scenario3_xml) if norm == 'scenario3' else '',
    )

    resp = client.get('/scenarios/preview?scenario=Scenario1&xml_path=' + str(scenario1_xml))
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    assert 'data-scen-name="Scenario1"' in body
    assert 'data-scen-name="Scenario3"' in body
    assert f'data-xml-path="{scenario3_xml}"' in body


def test_flow_and_preview_use_same_natural_scenario_order(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    scenario2_xml = tmp_path / 'Scenario2.xml'
    scenario3_xml = tmp_path / 'Scenario3.xml'
    scenario10_xml = tmp_path / 'Scenario10.xml'
    scenario2_xml.write_text(
        '<Scenarios><Scenario name="Scenario2"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )
    scenario3_xml.write_text(
        '<Scenarios><Scenario name="Scenario3"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )
    scenario10_xml.write_text(
        '<Scenarios><Scenario name="Scenario10"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )

    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda _history, user=None: (
            ['Scenario10', 'Scenario3'],
            {'scenario10': {str(scenario10_xml)}, 'scenario3': {str(scenario3_xml)}},
            {},
        ),
    )
    monkeypatch.setattr(
        backend,
        '_latest_xml_path_for_scenario',
        lambda norm: str(scenario2_xml) if norm == 'scenario2' else str(scenario3_xml) if norm == 'scenario3' else str(scenario10_xml) if norm == 'scenario10' else '',
    )

    flow_resp = client.get('/scenarios/flag-sequencing?scenario=Scenario2&xml_path=' + str(scenario2_xml))
    preview_resp = client.get('/scenarios/preview?scenario=Scenario2&xml_path=' + str(scenario2_xml))

    assert flow_resp.status_code == 200
    assert preview_resp.status_code == 200
    expected = ['Scenario2', 'Scenario3', 'Scenario10']
    assert _scenario_button_order(flow_resp.get_data(as_text=True)) == expected
    assert _scenario_button_order(preview_resp.get_data(as_text=True)) == expected
