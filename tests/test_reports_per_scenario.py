import json
import os

from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_reports_data_is_single_scenario(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    def fake_outputs_dir():
        return str(outdir)

    monkeypatch.setattr(backend, '_outputs_dir', fake_outputs_dir)

    # Legacy-ish entry: scenario_names contains multiple names but scenario_name is the active one.
    # NOTE: backend.RUN_HISTORY_PATH is computed at import time, so patch it too.
    run_history_path = outdir / 'run_history.json'
    monkeypatch.setattr(backend, 'RUN_HISTORY_PATH', str(run_history_path))
    run_history_path.write_text(
        json.dumps([
            {
                'timestamp': '2025-12-26T00:00:00Z',
                'mode': 'async',
                'scenario_name': 'Alpha',
                'scenario_names': ['Alpha', 'Beta'],
                'xml_path': str(tmp_path / 'outputs' / 'scenarios.xml'),
                'returncode': 0,
            }
        ]),
        encoding='utf-8',
    )

    resp = client.get('/reports_data')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'history' in data
    assert len(data['history']) == 1
    entry = data['history'][0]
    assert entry.get('scenario_names') == ['Alpha']


def test_reports_data_backfills_preview_plan_from_summary_metadata(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)
    run_history_path = outdir / 'run_history.json'
    xml_path = outdir / 'scenario.xml'
    summary_path = tmp_path / 'scenario_report.json'
    xml_path.write_text('<Scenarios><Scenario name="Alpha"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    summary_path.write_text(
        json.dumps({'counts': {}, 'metadata': {'xml_path': str(xml_path), 'preview_host_total': 1}}),
        encoding='utf-8',
    )
    run_history_path.write_text(
        json.dumps([
            {
                'timestamp': '2025-12-26T00:00:00Z',
                'mode': 'async',
                'scenario_name': 'Alpha',
                'scenario_names': ['Alpha'],
                'xml_path': str(xml_path),
                'scenario_xml_path': str(xml_path),
                'summary_path': str(summary_path),
                'preview_plan_path': '',
                'returncode': 0,
            }
        ]),
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, 'RUN_HISTORY_PATH', str(run_history_path))

    resp = client.get('/reports_data')
    assert resp.status_code == 200
    data = resp.get_json()
    entry = data['history'][0]
    assert entry.get('preview_plan_path') == str(xml_path)


def test_reports_data_backfills_preview_plan_from_embedded_xml(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)
    run_history_path = outdir / 'run_history.json'
    xml_path = outdir / 'scenario.xml'
    xml_path.write_text(
        '<Scenarios><Scenario name="Alpha"><ScenarioEditor><PlanPreview>{"full_preview":{"hosts":[]},"metadata":{}}</PlanPreview></ScenarioEditor></Scenario></Scenarios>',
        encoding='utf-8',
    )
    run_history_path.write_text(
        json.dumps([
            {
                'timestamp': '2025-12-26T00:00:00Z',
                'mode': 'async',
                'scenario_name': 'Alpha',
                'scenario_names': ['Alpha'],
                'xml_path': str(xml_path),
                'scenario_xml_path': str(xml_path),
                'preview_plan_path': '',
                'returncode': 0,
            }
        ]),
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, 'RUN_HISTORY_PATH', str(run_history_path))

    resp = client.get('/reports_data')
    assert resp.status_code == 200
    data = resp.get_json()
    entry = data['history'][0]
    assert entry.get('preview_plan_path') == str(xml_path)


def test_reports_data_backfills_preview_plan_from_flow_validation_signal(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)
    run_history_path = outdir / 'run_history.json'
    xml_path = outdir / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Alpha"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    run_history_path.write_text(
        json.dumps([
            {
                'timestamp': '2025-12-26T00:00:00Z',
                'mode': 'async',
                'scenario_name': 'Alpha',
                'scenario_names': ['Alpha'],
                'xml_path': str(xml_path),
                'scenario_xml_path': str(xml_path),
                'preview_plan_path': '',
                'returncode': 0,
                'validation_summary': {
                    'generator_validation_detail': [{'node_id': 'docker-1'}],
                    'inject_files_expected_by_node': {'docker-1': ['/flow_injects/flag.txt']},
                },
            }
        ]),
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, 'RUN_HISTORY_PATH', str(run_history_path))

    resp = client.get('/reports_data')
    assert resp.status_code == 200
    data = resp.get_json()
    entry = data['history'][0]
    assert entry.get('preview_plan_path') == str(xml_path)


def test_reports_page_completed_run_without_report_has_downloads_and_no_summary_spinner(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)

    from webapp import app_backend as backend

    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)
    run_history_path = outdir / 'run_history.json'
    xml_path = outdir / 'scenario.xml'
    session_path = outdir / 'core-post' / 'session.xml'
    bundle_path = outdir / 'scenario_bundle.zip'
    xml_path.write_text('<Scenarios><Scenario name="Alpha"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    session_path.parent.mkdir(parents=True, exist_ok=True)
    session_path.write_text('<session />', encoding='utf-8')
    bundle_path.write_bytes(b'PK\x05\x06' + (b'\x00' * 18))
    run_history_path.write_text(
        json.dumps([
            {
                'timestamp': '2026-05-26T00:00:00Z',
                'mode': 'async',
                'scenario_name': 'Alpha',
                'scenario_names': ['Alpha'],
                'xml_path': str(xml_path),
                'scenario_xml_path': str(xml_path),
                'session_xml_path': str(session_path),
                'post_xml_path': str(session_path),
                'full_scenario_path': str(bundle_path),
                'report_path': None,
                'summary_path': None,
                'returncode': 0,
            }
        ]),
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, 'RUN_HISTORY_PATH', str(run_history_path))

    resp = client.get('/reports')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'Full Scenario Bundle' in body
    assert 'Summarizing, please wait' not in body
