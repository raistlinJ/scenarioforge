from pathlib import Path

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_api_flow_progress_filters_relevant_lines(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    logs_dir = tmp_path / 'logs'
    logs_dir.mkdir(parents=True)
    log_path = logs_dir / 'webui-9090.log'
    log_path.write_text(
        '\n'.join(
            [
                'ordinary line',
                '[flow.progress] started',
                'Repo upload completed',
                '[remote-sync] copied artifact',
                '[flow.phase] running',
            ]
        ),
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(tmp_path))

    resp = client.get('/api/flag-sequencing/flow_progress')

    assert resp.status_code == 200
    assert resp.get_json() == {
        'ok': True,
        'lines': [
            '[flow.progress] started',
            'Repo upload completed',
            '[remote-sync] copied artifact',
            '[flow.phase] running',
        ],
    }


def test_api_flow_progress_filters_by_progress_id(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    logs_dir = tmp_path / 'logs'
    logs_dir.mkdir(parents=True)
    log_path = logs_dir / 'webui-9090.log'
    log_path.write_text(
        '\n'.join(
            [
                '[flow.progress] progress_id=seq-old elapsed=0.01s Phase: selecting chain nodes',
                '[flow.progress] progress_id=seq-new elapsed=0.02s Phase: building topology graph',
                '[flow.progress] progress_id=seq-new elapsed=0.03s Phase: computing generator assignments',
                '[flow.progress] unrelated legacy line',
            ]
        ),
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(tmp_path))

    resp = client.get('/api/flag-sequencing/flow_progress?progress_id=seq-new')

    assert resp.status_code == 200
    assert resp.get_json() == {
        'ok': True,
        'lines': [
            '[flow.progress] progress_id=seq-new elapsed=0.02s Phase: building topology graph',
            '[flow.progress] progress_id=seq-new elapsed=0.03s Phase: computing generator assignments',
        ],
    }