import html
import json
import re

from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def _payload_from_response_body(body: str) -> dict:
    match = re.search(r'<script id="payload-data" type="application/json">(.*?)</script>', body, re.S)
    assert match, 'payload-data script not found'
    return json.loads(html.unescape(match.group(1)))


def test_index_does_not_force_single_scenario_xml_without_explicit_scenario(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    anatest_xml = tmp_path / 'Anatest.xml'
    anatest_xml.write_text(
        '<Scenarios><Scenario name="Anatest"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )

    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda _history, user=None: (
            ['Scenario A', 'Anatest'],
            {'scenario a': set(), 'anatest': {str(anatest_xml)}},
            {},
        ),
    )
    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda norm: str(anatest_xml) if norm == 'scenario a' else '')

    resp = client.get('/')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert '"Scenario A"' in body
    assert '"Anatest"' in body


def test_index_prefers_explicit_xml_path_query(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    xml_a = tmp_path / 'A.xml'
    xml_b = tmp_path / 'B.xml'
    xml_a.write_text('<Scenarios><Scenario name="Scenario A"><ScenarioEditor/></Scenario></Scenarios>', encoding='utf-8')
    xml_b.write_text('<Scenarios><Scenario name="Anatest"><ScenarioEditor/></Scenario></Scenarios>', encoding='utf-8')

    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda _history, user=None: (
            ['Scenario A', 'Anatest'],
            {'scenario a': {str(xml_a)}, 'anatest': {str(xml_b)}},
            {},
        ),
    )

    resp = client.get('/?xml_path=' + str(xml_b))
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert '"Anatest"' in body
    payload = _payload_from_response_body(body)
    names = [s.get('name') for s in payload.get('scenarios', []) if isinstance(s, dict)]
    assert set(names) == {'Scenario A', 'Anatest'}


def test_index_merges_single_result_xml_with_multi_scenario_snapshot(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    xml_scenario2 = tmp_path / 'Scenario2.xml'
    xml_scenario2.write_text(
        '<Scenarios><Scenario name="Scenario2"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )

    snapshot = {
        'scenarios': [
            {'name': 'Scenario1', 'sections': {'Node Information': {'items': []}}, 'density_count': 10},
            {'name': 'Scenario2', 'sections': {'Node Information': {'items': []}}, 'density_count': 10},
        ],
        'active_index': 1,
        'result_path': str(xml_scenario2),
        'project_key_hint': str(xml_scenario2),
    }

    monkeypatch.setattr(backend, '_load_editor_state_snapshot', lambda user=None: snapshot)
    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda _history, user=None: (
            ['Scenario1', 'Scenario2'],
            {'scenario1': set(), 'scenario2': {str(xml_scenario2)}},
            {},
        ),
    )

    resp = client.get('/?scenario=Scenario2')
    assert resp.status_code == 200
    payload = _payload_from_response_body(resp.get_data(as_text=True))
    names = [s.get('name') for s in payload.get('scenarios', []) if isinstance(s, dict)]

    assert names == ['Scenario1', 'Scenario2']
    assert payload.get('result_path') == str(xml_scenario2)
