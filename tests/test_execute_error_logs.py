import json

from webapp import app_backend as backend


def test_build_execute_error_logs_filters_inject_details_to_missing_nodes(tmp_path, monkeypatch):
    outdir = tmp_path / 'outputs'
    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, '_local_timestamp_display', lambda: '2026-06-18T17:04:52+00:00')

    validation = {
        'ok': False,
        'injects_missing': ['docker-11'],
        'injects_detail': [
            'docker-8: 1 file(s) in /flow_injects (e.g., /flow_injects/operator_pin.hash); expected /flow_injects/operator_pin.hash',
            'docker-10: 1 file(s) in /flow_injects (e.g., /flow_injects/.env.backup); expected /flow_injects/.env.backup',
            'docker-11: 0 file(s) in /flow_injects; expected /flow_injects/site; missing expected /flow_injects/site; debug: MISSING_DIR:/flow_injects',
            'docker-13: 3 file(s) in /flow_injects (e.g., /flow_injects/service/repo/deploy.env); expected /flow_injects/service',
        ],
    }

    logs = backend._build_execute_error_logs(run_id='run-1', validation=validation)

    inject_log = next(entry for entry in logs if entry.get('key') == 'injects_missing')
    with open(inject_log['path'], 'r', encoding='utf-8') as fh:
        payload = json.load(fh)

    assert payload['items'] == ['docker-11']
    assert payload['details'] == [
        'docker-11: 0 file(s) in /flow_injects; expected /flow_injects/site; missing expected /flow_injects/site; debug: MISSING_DIR:/flow_injects'
    ]