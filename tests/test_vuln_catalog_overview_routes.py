from pathlib import Path

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


VULN_CATALOG_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / 'webapp' / 'templates' / 'vuln_catalog.html'


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_vuln_catalog_page_renders_active_catalog(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_load_vuln_catalogs_state',
        lambda: {'active_id': 'cat-1', 'catalogs': [{'id': 'cat-1', 'label': 'Catalog One'}]},
    )
    monkeypatch.setattr(backend, '_get_repo_root', lambda: '/tmp/repo')
    monkeypatch.setattr(backend, '_load_vuln_catalog_route', lambda repo_root: ['a', 'b'], raising=False)

    resp = client.get('/vuln_catalog_page')

    assert resp.status_code == 200
    page = resp.get_data(as_text=True)
    assert 'Catalog One' in page
    assert 'Batch Test' in page
    assert 'Export JSON' in page
    assert 'Export Markdown' in page
    assert 'Copy Summary' in page
    assert 'Filter Results By Category' in page
    assert 'Filter Results By Status' in page
    assert 'Sort Results' in page
    assert 'Clear' in page


def test_vuln_catalog_filters_include_compose_dependency_metadata() -> None:
    text = VULN_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'function _vulnCatalogTableSearchText(item)' in text
    assert 'return _vulnCatalogTableSearchText(it).toLowerCase().includes(filter);' in text
    assert 'function _composeDependencySearchText(item)' in text
    assert 'missing_required_files' in text
    assert 'has:missing' in text
    assert '_composeDependencySearchText(item)' in text


def test_vuln_catalog_items_data_returns_active_items(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    outputs_dir = tmp_path / 'outputs' / 'test-logs'
    outputs_dir.mkdir(parents=True)
    log_path = outputs_dir / 'sample.log'
    log_path.write_text('sample log\n', encoding='utf-8')

    pack_dir = tmp_path / 'pack'
    item_dir = pack_dir / 'vulhub' / 'sample'
    item_dir.mkdir(parents=True)
    (item_dir / 'README.md').write_text('# Demo', encoding='utf-8')

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_load_vuln_catalogs_state', lambda: {'active_id': 'cat-1', 'catalogs': [{'id': 'cat-1', 'label': 'Catalog One'}]})
    monkeypatch.setattr(backend, '_get_active_vuln_catalog_entry', lambda state: {'id': 'cat-1', 'label': 'Catalog One', 'from_source': 'demo'})
    monkeypatch.setattr(
        backend,
        '_normalize_vuln_catalog_items',
        lambda entry: [{
            'id': 7,
            'name': 'Sample',
            'rel_dir': 'vulhub/sample',
            'dir_rel': 'vulhub/sample',
            'disabled': False,
            'validated_ok': True,
            'validated_incomplete': False,
            'validated_at': 'now',
            'last_test_log_path': str(log_path),
            'last_test_log_filename': 'sample.log',
        }],
    )
    monkeypatch.setattr(backend, '_vuln_catalog_pack_content_dir', lambda catalog_id: str(pack_dir))
    monkeypatch.setattr(backend, '_safe_path_under', lambda base_dir, subpath: str(Path(base_dir) / subpath))
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))

    resp = client.get('/vuln_catalog_items_data')

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload['ok'] is True
    assert payload['active']['id'] == 'cat-1'
    assert payload['items'][0]['id'] == 7
    assert payload['items'][0]['name'] == 'vulhub/sample'
    assert payload['items'][0]['validated_incomplete'] is False
    assert payload['items'][0]['log_download_url'] == '/vuln_catalog_items/test/log?item_id=7'
    assert payload['items'][0]['readme_url'].endswith('/vuln_catalog_packs/readme/cat-1/vulhub/sample/README.md')


def test_vuln_catalog_item_test_log_download_returns_copied_log(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    outputs_dir = tmp_path / 'outputs' / 'test-logs'
    outputs_dir.mkdir(parents=True)
    log_path = outputs_dir / 'sample.log'
    log_path.write_text('line one\nline two\n', encoding='utf-8')

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_load_vuln_catalogs_state', lambda: {'active_id': 'cat-1', 'catalogs': [{'id': 'cat-1', 'label': 'Catalog One'}]})
    monkeypatch.setattr(backend, '_get_active_vuln_catalog_entry', lambda state: {'id': 'cat-1', 'label': 'Catalog One'})
    monkeypatch.setattr(
        backend,
        '_normalize_vuln_catalog_items',
        lambda entry: [{
            'id': 7,
            'name': 'Sample',
            'last_test_log_path': str(log_path),
            'last_test_log_filename': 'sample.log',
        }],
    )
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))

    resp = client.get('/vuln_catalog_items/test/log?item_id=7')

    assert resp.status_code == 200
    assert resp.headers['Content-Disposition'].startswith('attachment;')
    assert resp.data.decode('utf-8') == 'line one\nline two\n'


def test_vuln_catalog_template_redacts_sensitive_test_log_lines() -> None:
    text = VULN_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'function _redactSensitiveVulnLogLine(line, extraTokens = [])' in text
    assert 'const text = _redactSensitiveVulnLogLine(line);' in text


def test_vuln_catalog_batch_reuses_core_session_prompt() -> None:
    text = VULN_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'const VULN_CATALOG_VM_MODE = VULN_CATALOG_RUNTIME_MODE === \'vm\';' in text
    assert 'async function resolveVulnBatchCoreConfig()' in text
    assert 'if (VULN_CATALOG_VM_MODE)' in text
    assert 'const canProceed = await _ensureCoreVmReadyForVulnTest(creds);' in text
    assert "_setText('vulnBatchMeta', 'Batch run cancelled.');" in text


def test_vuln_catalog_template_exposes_selection_and_log_controls() -> None:
    text = VULN_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'id="vulnCatalogCheckAll"' in text
    assert 'id="vulnDependencyRecheckBtn"' in text
    assert 'id="vulnBatchEnableSelectedBtn"' in text
    assert 'id="vulnBatchDisableSelectedBtn"' in text
    assert 'id="vulnBatchOverrideSuccessBtn"' in text
    assert 'id="vulnBatchOverrideFailBtn"' in text
    assert 'href="${escapeHtml(it.log_download_url)}"' in text
    assert '/vuln_catalog_items/recheck_dependencies' in text


def test_vuln_catalog_batch_mutate_enable_rewrites_enabled_csv(monkeypatch):
    client = app.test_client()
    _login(client)
    state = {
        'active_id': 'cat1',
        'catalogs': [
            {
                'id': 'cat1',
                'label': 'Catalog One',
                'compose_items': [
                    {'id': 1, 'name': 'alpha', 'disabled': True, 'compose_rel': 'a/docker-compose.yml'},
                    {'id': 2, 'name': 'beta', 'disabled': False, 'compose_rel': 'b/docker-compose.yml'},
                ],
            }
        ],
    }
    captured = {}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_load_vuln_catalogs_state', lambda: state)
    monkeypatch.setattr(backend, '_get_active_vuln_catalog_entry', lambda loaded: loaded['catalogs'][0])
    monkeypatch.setattr(backend, '_normalize_vuln_catalog_items', lambda entry: list(entry.get('compose_items') or []))

    def fake_write_csv(*, catalog_id, items):
        captured['catalog_id'] = catalog_id
        captured['csv_items'] = list(items)
        return ['outputs/installed_vuln_catalogs/cat1/vuln_list_w_url.csv']

    monkeypatch.setattr(backend, '_write_vuln_catalog_csv_from_items', fake_write_csv)
    monkeypatch.setattr(backend, '_write_vuln_catalogs_state', lambda saved_state: captured.setdefault('state', saved_state))

    resp = client.post('/vuln_catalog_items/batch_mutate', json={'action': 'enable', 'item_ids': [1]})

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload['ok'] is True
    assert payload['updated'] == [1]
    items = state['catalogs'][0]['compose_items']
    assert items[0]['disabled'] is False
    assert state['catalogs'][0]['csv_paths'] == ['outputs/installed_vuln_catalogs/cat1/vuln_list_w_url.csv']
    assert captured['catalog_id'] == 'cat1'
    assert [item['id'] for item in captured['csv_items']] == [1, 2]


def test_vuln_catalog_entire_catalog_download_warns_before_starting() -> None:
    text = VULN_CATALOG_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    assert 'id="downloadEntireVulnCatalogBtn"' in text
    assert "url_for('vuln_catalog_packs_export_all')" in text
    assert "startEntireCatalogDownload(event, 'Vulnerability Catalog', this)" in text
    assert "function startEntireCatalogDownload(ev, catalogName, linkEl)" in text
    assert "url.searchParams.set('download_token', token);" in text
    assert "CORETG_HIDE_NAV_LOADING" in text
    assert "coretg_catalog_download_token" in text
    assert 'This could take a long time and could be very large depending on the number of catalog items.' in text
    assert text.index('id="vulnPackImportUrlForm"') < text.index('id="downloadEntireVulnCatalogBtn"')
    assert 'col-auto ms-md-auto' in text
