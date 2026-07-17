import json
from pathlib import Path

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


FLAG_CATALOG_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / 'webapp' / 'templates' / 'flag_catalog.html'
GENERATOR_CATALOG_TABS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / 'webapp' / 'templates' / 'partials' / 'generator_catalog_tabs.html'


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_flag_catalog_page_groups_installed_ids_by_kind(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(
        backend,
        '_load_installed_generator_packs_state',
        lambda: {
            'packs': [
                {
                    'id': 'pack-1',
                    'installed': [
                        {'kind': 'flag-generator', 'id': 'alpha'},
                        {'kind': 'flag-generator', 'id': 'alpha'},
                        {'kind': 'flag-node-generator', 'id': 'beta'},
                    ],
                }
            ]
        },
    )
    monkeypatch.setattr(backend, '_save_installed_generator_packs_state', lambda state: None)
    monkeypatch.setattr(backend, '_flag_generators_from_all_installed_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_all_installed_sources', lambda: ([], []))

    resp = client.get('/flag_catalog')

    assert resp.status_code == 200
    page = resp.get_data(as_text=True)
    assert 'pack-1' in page
    assert 'flag-generator' in page
    assert 'flag-node-generator' in page
    assert 'Batch Test' in page
    assert 'id="flagBatchScope"' in page
    assert 'Unvalidated / Incomplete' in page
    assert 'packInstallSuccessAlert' in page
    assert 'packImportUrlForm' in page
    assert 'packUploadProgressTitle' in page


def test_flag_catalog_batch_status_discovers_active_run_without_saved_id() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert "const url = targetRunId" in text
    assert ": '/flag_catalog_items/batch/status';" in text
    assert "function fetchFlagBatchActiveRun()" in text
    assert "'/flag_catalog_items/batch/active'" in text
    assert "'/flag_catalog_items/batch/stop_active'" in text
    assert 'Stop it and start a new batch?' in text


def test_flag_catalog_escape_html_handles_numeric_batch_counts() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert "return String(str == null ? '' : str).replace" in text
    assert '${escapeHtml(value)}</span>' in text


def test_flag_catalog_filters_include_compose_dependency_metadata() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'function generatorTableSearchText(g)' in text
    assert 'groupedNameSearchText(g.inputs)' in text
    assert 'return generatorTableSearchText(g).toLowerCase().includes(q);' in text
    assert 'function composeDependencySearchText(item)' in text
    assert 'missing_required_files' in text
    assert 'has:missing' in text
    assert 'composeDependencySearchText(g)' in text
    assert 'composeDependencySearchText(item)' in text
    assert 'id="genBatchEnableBtn"' in text
    assert 'id="nodeGenBatchEnableBtn"' in text
    assert 'id="genDependencyRecheckBtn"' in text
    assert 'id="nodeGenDependencyRecheckBtn"' in text
    assert '/api/generator_catalog/recheck_dependencies' in text


def test_flag_catalog_batch_results_include_running_active_item() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert '<option value="running">Running</option>' in text
    assert 'function flagBatchResultsWithActive(payload)' in text
    assert "status: 'running'" in text
    assert "reason: 'Running'" in text
    assert "const statusRank = { running: -1" in text
    assert '<span class="badge text-bg-primary">Running</span>' in text
    assert 'renderFlagBatchResults(flagBatchResultsWithActive(payload));' in text


def test_flag_catalog_batch_stop_uses_static_modal_and_single_flight() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'id="flagBatchStopModal"' in text
    assert 'data-bs-backdrop="static"' in text
    assert 'id="flagBatchStopCloseBtn" data-bs-dismiss="modal" disabled' in text
    assert 'stopInProgress: false' in text
    assert 'function showFlagBatchStopModal(runId)' in text
    assert 'async function waitForFlagBatchDone(runId)' in text
    assert 'if (flagBatchState.stopInProgress) return;' in text
    assert 'stopBtn.disabled = isStopping;' in text
    assert "stopBtn.textContent = isStopping ? 'Stopping…' : 'Stop Batch';" in text


def test_flag_catalog_entire_catalog_download_warns_before_starting() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'id="downloadEntireFlagCatalogBtn"' in text
    assert "url_for('generator_packs_export_all')" in text
    assert "startEntireCatalogDownload(event, 'Flag Catalog', this)" in text
    assert "function startEntireCatalogDownload(ev, catalogName, linkEl)" in text
    assert "url.searchParams.set('download_token', token);" in text
    assert "CORETG_HIDE_NAV_LOADING" in text
    assert "coretg_catalog_download_token" in text
    assert 'This could take a long time and could be very large depending on the number of catalog items.' in text
    assert text.index('id="packImportUrlForm"') < text.index('id="downloadEntireFlagCatalogBtn"')
    assert 'col-auto ms-md-auto' in text


def test_flag_catalog_template_handles_duplicate_conflict_rows() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'submitPackUninstall(packId, packLabel)' in text
    assert 'Duplicate ID' in text
    assert 'Uninstall Pack' in text


def test_generator_catalog_tabs_use_bootstrap_tab_triggers() -> None:
    text = GENERATOR_CATALOG_TABS_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'id="flagGeneratorsTab"' in text
    assert 'data-bs-toggle="tab"' in text
    assert 'href="#flagGenerators"' in text
    assert 'aria-controls="flagGenerators"' in text
    assert 'href="#flagGenSources"' in text
    assert 'href="#flagNodeGenerators"' in text
    assert 'href="#flagBatch"' in text


def test_flag_catalog_template_redacts_sensitive_test_log_lines() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'function _redactSensitiveTestLine(line, extraTokens = [])' in text
    assert '_redactSensitiveTestLine(line)' in text


def test_flag_catalog_tables_offer_persistent_colored_notes() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert text.count('>Notes</th>') == 2
    assert 'id="flagCatalogNoteModal"' in text
    assert 'id="flagCatalogNoteClear"' in text
    assert 'data-note-color="red"' in text
    assert 'data-note-color="yellow"' in text
    assert 'data-note-color="green"' in text
    assert '/api/flag_generators/set_note' in text
    assert '/api/flag_node_generators/set_note' in text
    assert 'function updateFlagCatalogNoteRow' in text
    assert 'const hasColor = [\'red\', \'yellow\', \'green\'].includes(suppliedColor);' in text


def test_flag_catalog_batch_reuses_core_session_prompt() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'const FLAG_CATALOG_VM_MODE = FLAG_CATALOG_RUNTIME_MODE === \'vm\';' in text
    assert 'async function resolveFlagBatchCoreConfig()' in text
    assert 'if (FLAG_CATALOG_VM_MODE)' in text
    assert 'const flagBatchScopeEl = flagBatchEl(\'flagBatchScope\');' in text
    assert 'scope: payload.scope' in text
    assert "filters.scope === 'failed'" in text
    assert 'const canProceed = await ensureCoreVmReadyForGenTest(creds);' in text
    assert "if (metaEl) metaEl.textContent = 'Batch run cancelled.';" in text


def test_flag_catalog_vm_mode_skips_single_test_credential_modal() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'const creds = FLAG_CATALOG_VM_MODE ? {} : await promptGenTestCreds();' in text
    assert '.scenarioforge.env, exactly as generation and execution do.' in text


def test_flag_catalog_template_exposes_selection_and_log_controls() -> None:
    text = FLAG_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'id="genCheckAll"' in text
    assert 'id="nodeGenCheckAll"' in text
    assert 'id="genBatchOverrideSuccessBtn"' in text
    assert 'id="nodeGenBatchOverrideFailBtn"' in text
    assert 'href="${escapeHtml(g.log_download_url)}"' in text


def test_flag_generators_data_includes_duplicate_installed_pack_entries(tmp_path, monkeypatch):
    install_root = tmp_path / 'installed_generators'
    duplicate_a = install_root / 'flag_generators' / 'p_pack_a__5'
    duplicate_b = install_root / 'flag_generators' / 'p_pack_b__6'
    duplicate_a.mkdir(parents=True)
    duplicate_b.mkdir(parents=True)

    manifest_text = """manifest_version: 1
id: 5
kind: flag-generator
name: Mario HTTP Drop
description: duplicate test entry
language: python
inputs:
  - name: seed
    type: string
artifacts:
  produces:
    - Flag(flag_id)
injects: []
"""
    (duplicate_a / 'manifest.yaml').write_text(manifest_text, encoding='utf-8')
    (duplicate_b / 'manifest.yaml').write_text(manifest_text.replace('id: 5', 'id: 6'), encoding='utf-8')
    (duplicate_a / '.coretg_pack.json').write_text(json.dumps({
        'pack_id': 'pack-a',
        'pack_label': 'Pack A',
        'generator_id': '5',
        'source_generator_id': 'mario_http_drop',
    }), encoding='utf-8')
    (duplicate_b / '.coretg_pack.json').write_text(json.dumps({
        'pack_id': 'pack-b',
        'pack_label': 'Pack B',
        'generator_id': '6',
        'source_generator_id': 'mario_http_drop',
    }), encoding='utf-8')

    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))
    monkeypatch.setattr(backend, '_flag_generators_from_all_installed_sources', lambda: ([], [
        {'error': 'duplicate generator id: mario_http_drop', 'path': str(duplicate_a / 'manifest.yaml')},
        {'error': 'duplicate generator id: mario_http_drop', 'path': str(duplicate_b / 'manifest.yaml')},
    ]))
    monkeypatch.setattr(backend, '_load_installed_generator_packs_state', lambda: {
        'packs': [
            {
                'id': 'pack-a',
                'label': 'Pack A',
                'installed': [
                    {'kind': 'flag-generator', 'path': str(duplicate_a), 'id': '5'},
                ],
            },
            {
                'id': 'pack-b',
                'label': 'Pack B',
                'installed': [
                    {'kind': 'flag-generator', 'path': str(duplicate_b), 'id': '6'},
                ],
            },
        ]
    })

    client = app.test_client()
    _login(client)
    resp = client.get('/flag_generators_data')

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get('errors') == []
    generators = payload.get('generators') or []
    assert len(generators) == 2
    assert {g.get('id') for g in generators if isinstance(g, dict)} == {'mario_http_drop'}
    assert {g.get('_pack_id') for g in generators if isinstance(g, dict)} == {'pack-a', 'pack-b'}
    assert all(g.get('_duplicate_conflict') is True for g in generators if isinstance(g, dict))


def test_flag_generators_data_exposes_persisted_log_metadata(monkeypatch, tmp_path):
    outputs_dir = tmp_path / 'outputs'
    installed_dir = outputs_dir / 'installed_generators'
    installed_dir.mkdir(parents=True)
    log_dir = outputs_dir / 'test-logs'
    log_dir.mkdir(parents=True)
    log_path = log_dir / 'generator.log'
    log_path.write_text('generator log\n', encoding='utf-8')

    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(installed_dir))
    monkeypatch.setattr(backend, '_flag_generators_from_all_installed_sources', lambda: ([{
        'id': 'demo-gen',
        'name': 'Demo Generator',
        '_source_path': str(tmp_path / 'manifest.yaml'),
    }], []))
    monkeypatch.setattr(backend, '_is_installed_generator_view', lambda gen: True)
    monkeypatch.setattr(backend, '_annotate_disabled_state', lambda generators, kind: [{
        **generators[0],
        '_validated_ok': True,
        '_validated_incomplete': False,
        '_validated_at': 'now',
        '_last_test_log_path': str(log_path),
        '_last_test_log_filename': 'generator.log',
    }])
    monkeypatch.setattr(backend, '_load_installed_generator_packs_state', lambda: {'packs': []})

    client = app.test_client()
    _login(client)
    resp = client.get('/flag_generators_data')

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    generator = payload['generators'][0]
    assert generator['validated_ok'] is True
    assert generator['validated_incomplete'] is False
    assert generator['validated_at'] == 'now'
    assert generator['log_download_url'] == '/api/generator_catalog/test_log?kind=flag-generator&generator_id=demo-gen'


def test_generator_catalog_test_log_download_returns_copied_log(monkeypatch, tmp_path):
    outputs_dir = tmp_path / 'outputs'
    installed_dir = outputs_dir / 'installed_generators'
    installed_dir.mkdir(parents=True)
    log_dir = outputs_dir / 'test-logs'
    log_dir.mkdir(parents=True)
    log_path = log_dir / 'generator.log'
    log_path.write_text('generator log\n', encoding='utf-8')

    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(installed_dir))
    monkeypatch.setattr(backend, '_load_installed_generator_packs_state', lambda: {
        'packs': [
            {
                'id': 'pack-1',
                'installed': [
                    {
                        'kind': 'flag-generator',
                        'id': 'demo-gen',
                        'last_test_log_path': str(log_path),
                        'last_test_log_filename': 'generator.log',
                    }
                ],
            }
        ]
    })

    client = app.test_client()
    _login(client)
    resp = client.get('/api/generator_catalog/test_log?kind=flag-generator&generator_id=demo-gen')

    assert resp.status_code == 200
    assert resp.headers['Content-Disposition'].startswith('attachment;')
    assert resp.data.decode('utf-8') == 'generator log\n'


def test_data_sources_page_is_still_renderable(monkeypatch):
    client = app.test_client()
    _login(client)

    resp = client.get('/data_sources')

    assert resp.status_code == 200
    assert 'data' in resp.get_data(as_text=True).lower()
