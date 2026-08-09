from webapp import app_backend as backend


def _write_catalog(outdir, body: str) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / 'scenario_catalog.json').write_text(body, encoding='utf-8')


def test_force_empty_catalog_does_not_synthesize_default_scenario(monkeypatch, tmp_path):
    """Deleting every scenario must not leave a phantom "Scenario 1".

    The synthesized scenario has no XML on disk, so Flag sequencing would reject
    Generate with "No XML found for this scenario".
    """
    outdir = tmp_path / 'outputs'
    _write_catalog(outdir, '{"names":[],"sources":{},"force_empty":true}')

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, '_load_run_history', lambda: [])

    payload = backend._prepare_payload_for_index(
        {'result_path': None, 'core': backend._default_core_dict()},
        user={'role': 'admin'},
    )

    assert payload['scenario_catalog_force_empty'] is True
    assert payload['scenarios'] == []


def test_fresh_install_still_gets_default_scenario(monkeypatch, tmp_path):
    """No catalog at all is a fresh install, which should still seed Scenario 1."""
    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, '_load_run_history', lambda: [])

    payload = backend._prepare_payload_for_index(
        {'result_path': None, 'core': backend._default_core_dict()},
        user={'role': 'admin'},
    )

    assert payload['scenario_catalog_force_empty'] is False
    assert [s.get('name') for s in payload['scenarios']] == ['Scenario 1']
