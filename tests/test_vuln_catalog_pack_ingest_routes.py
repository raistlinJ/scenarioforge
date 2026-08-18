import io
import json
import zipfile
from pathlib import Path

from werkzeug.datastructures import MultiDict

from webapp import app_backend as backend
from webapp.routes import vuln_catalog_pack_ingest as ingest


app = backend.app
app.config.setdefault('TESTING', True)



def _make_zip(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return buf.getvalue()


def test_safe_vuln_catalog_zip_extraction_preserves_regular_executable_bits(tmp_path):
    archive_path = tmp_path / 'catalog.zip'
    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo('bash/CVE-2014-6271/victim.cgi')
        info.create_system = 3  # Unix permissions are stored in external_attr.
        info.external_attr = 0o100755 << 16
        archive.writestr(info, '#!/bin/bash\necho vulnerable\n')

    extracted_dir = tmp_path / 'content'
    backend._safe_extract_zip_to_dir(str(archive_path), str(extracted_dir))

    assert (extracted_dir / 'bash/CVE-2014-6271/victim.cgi').stat().st_mode & 0o777 == 0o755


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_vuln_catalog_pack_upload_ajax_missing_input_returns_400(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)

    resp = client.post(
        '/vuln_catalog_packs/upload',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
        data={},
        content_type='multipart/form-data',
    )

    assert resp.status_code == 400
    payload = resp.get_json()
    assert payload['ok'] is False
    assert payload['error'].startswith('No vulnerability catalog folder or ZIP selected.')
    # The diagnostic tail is what distinguishes an empty body from parts that
    # arrived but were unusable, so keep asserting that it is present.
    assert 'Request carried 0 repo_files part(s)' in payload['error']


def test_vuln_catalog_pack_upload_rejects_folder_and_zip_together(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_install_vuln_catalog_zip_file',
        lambda **kwargs: (_ for _ in ()).throw(AssertionError('install should not run')),
    )

    response = client.post(
        '/vuln_catalog_packs/upload',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
        data=MultiDict([
            ('zip_file', (io.BytesIO(b'PK\x03\x04demo'), 'catalog.zip')),
            ('repo_paths', 'catalog/docker-compose.yml'),
            ('repo_files', (io.BytesIO(b'services: {}\n'), 'docker-compose.yml')),
        ]),
        content_type='multipart/form-data',
    )

    assert response.status_code == 400
    assert response.get_json() == {
        'ok': False,
        'error': 'Select either a vulnerability catalog folder or a ZIP, not both.',
    }


def test_vuln_catalog_folder_upload_allows_more_than_flask_default_form_parts(monkeypatch):
    client = app.test_client()
    _login(client)
    captured = {}

    def fake_install(*, zip_file_path, label, origin):
        with zipfile.ZipFile(zip_file_path, 'r') as archive:
            captured['count'] = len(archive.namelist())
        return {'id': 'large-folder-catalog'}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_install_vuln_catalog_zip_file', fake_install)

    upload = MultiDict([('repo_label', 'large-folder')])
    for index in range(501):
        upload.add('repo_paths', f'large-folder/demo-{index}/docker-compose.yml')
        upload.add('repo_files', (io.BytesIO(b'services: {}\n'), 'docker-compose.yml'))

    response = client.post(
        '/vuln_catalog_packs/upload',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
        data=upload,
        content_type='multipart/form-data',
    )

    assert response.status_code == 200
    assert response.get_json()['catalog_id'] == 'large-folder-catalog'
    assert captured['count'] == 501


def test_vuln_catalog_pack_upload_ajax_installs_zip(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)
    captured = {}

    def fake_install(*, zip_file_path, label, origin):
        captured['zip_file_path'] = zip_file_path
        captured['label'] = label
        captured['origin'] = origin
        captured['exists_during_install'] = Path(zip_file_path).exists()
        return {'id': 'catalog-123'}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_install_vuln_catalog_zip_file', fake_install)

    resp = client.post(
        '/vuln_catalog_packs/upload',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
        data={'zip_file': (io.BytesIO(b'PK\x03\x04demo'), '../danger demo.zip')},
        content_type='multipart/form-data',
    )

    assert resp.status_code == 200
    assert resp.get_json() == {
        'ok': True,
        'message': 'Vulnerability catalog pack installed.',
        'catalog_id': 'catalog-123',
        'import_method': 'upload',
        'uploaded_file_count': 0,
        'discovered_compose_count': 0,
        'installed_catalog_count': 1,
        'installed_vulnerability_count': 0,
        'missing_required_file_count': 0,
        'bundle_failures': [],
    }
    assert captured['origin'] == 'upload'
    assert captured['label'] == 'danger_demo.zip'
    assert captured['exists_during_install'] is True
    assert not Path(captured['zip_file_path']).exists()


def test_vuln_catalog_folder_upload_installs_with_relative_paths(monkeypatch):
    client = app.test_client()
    _login(client)
    captured = {}

    def fake_install(*, zip_file_path, label, origin):
        captured['label'] = label
        captured['origin'] = origin
        with zipfile.ZipFile(zip_file_path, 'r') as archive:
            captured['names'] = set(archive.namelist())
            captured['compose'] = archive.read('downloaded-vulns/web/demo/docker-compose.yml')
        return {'id': 'catalog-folder'}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_install_vuln_catalog_zip_file', fake_install)

    response = client.post(
        '/vuln_catalog_packs/upload',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
        data=MultiDict([
            ('repo_label', 'downloaded-vulns'),
            ('repo_paths', 'downloaded-vulns/web/demo/docker-compose.yml'),
            ('repo_paths', 'downloaded-vulns/web/demo/README.md'),
            ('repo_files', (io.BytesIO(b'services: {}\n'), 'docker-compose.yml')),
            ('repo_files', (io.BytesIO(b'# Demo\n'), 'README.md')),
        ]),
        content_type='multipart/form-data',
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['catalog_id'] == 'catalog-folder'
    assert payload['import_method'] == 'folder-upload'
    assert payload['uploaded_file_count'] == 2
    assert payload['discovered_compose_count'] == 1
    assert captured == {
        'label': 'downloaded-vulns',
        'origin': 'folder-upload',
        'names': {
            'downloaded-vulns/web/demo/docker-compose.yml',
            'downloaded-vulns/web/demo/README.md',
        },
        'compose': b'services: {}\n',
    }


def test_vuln_catalog_folder_upload_rejects_unsafe_relative_path(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_install_vuln_catalog_zip_file',
        lambda **kwargs: (_ for _ in ()).throw(AssertionError('install should not run')),
    )

    response = client.post(
        '/vuln_catalog_packs/upload',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
        data=MultiDict([
            ('repo_label', 'unsafe-vulns'),
            ('repo_paths', 'unsafe-vulns/../docker-compose.yml'),
            ('repo_files', (io.BytesIO(b'services: {}\n'), 'docker-compose.yml')),
        ]),
        content_type='multipart/form-data',
    )

    assert response.status_code == 400
    assert 'unsafe path' in response.get_json()['error']


def test_vuln_catalog_pack_upload_ajax_reports_bundle_count(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(
        backend,
        '_install_vuln_catalog_zip_file',
        lambda **kwargs: {'id': 'catalog-123', 'bundle_count': 2},
    )

    resp = client.post(
        '/vuln_catalog_packs/upload',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
        data={'zip_file': (io.BytesIO(b'PK\x03\x04demo'), 'vulnerability_catalog.zip')},
        content_type='multipart/form-data',
    )

    assert resp.status_code == 200
    assert resp.get_json() == {
        'ok': True,
        'message': 'Installed 2 vulnerability catalog pack(s) from bundle.',
        'catalog_id': 'catalog-123',
        'import_method': 'upload',
        'uploaded_file_count': 0,
        'discovered_compose_count': 0,
        'installed_catalog_count': 2,
        'installed_vulnerability_count': 0,
        'missing_required_file_count': 0,
        'bundle_failures': [],
    }


def test_vuln_catalog_export_all_bundle_upload_installs_nested_catalogs(monkeypatch, tmp_path):
    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(tmp_path / 'outputs'))
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))

    alpha_zip = _make_zip({
        'alpha/docker-compose.yml': 'services: {}\n',
        '.scenarioforge/catalog_notes.json': json.dumps({
            'version': 1,
            'notes': [{'compose_rel': 'alpha/docker-compose.yml', 'note': 'verify before use', 'note_color': 'yellow'}],
        }),
    })
    beta_zip = _make_zip({'beta/docker-compose.yml': 'services: {}\n'})
    bundle_zip = _make_zip(
        {
            'catalogs/alpha.zip': alpha_zip,
            'catalogs/beta.zip': beta_zip,
            'catalogs.json': json.dumps({
                'catalogs': [
                    {'archive': 'catalogs/alpha.zip', 'label': 'Alpha Catalog'},
                    {'archive': 'catalogs/beta.zip', 'label': 'Beta Catalog'},
                ]
            }),
        }
    )
    bundle_path = tmp_path / 'vulnerability_catalog.zip'
    bundle_path.write_bytes(bundle_zip)

    entry = backend._install_vuln_catalog_zip_file(
        zip_file_path=str(bundle_path),
        label='vulnerability_catalog.zip',
        origin='upload',
    )

    assert entry['bundle_count'] == 2
    assert len(entry['installed_catalog_ids']) == 2
    state = backend._load_vuln_catalogs_state()
    catalogs = state.get('catalogs') or []
    assert [catalog.get('label') for catalog in catalogs] == ['Alpha Catalog', 'Beta Catalog']
    assert all(catalog.get('compose_count') == 1 for catalog in catalogs)
    assert catalogs[0]['compose_items'][0]['note'] == 'verify before use'
    assert catalogs[0]['compose_items'][0]['note_color'] == 'yellow'


def test_vuln_catalog_pack_import_url_blocks_unsafe_url(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_is_safe_remote_zip_url', lambda url: (False, 'host not allowed'))
    monkeypatch.setattr(
        backend,
        '_download_zip_from_url',
        lambda url: (_ for _ in ()).throw(AssertionError('download should not run')),
    )

    resp = client.post('/vuln_catalog_packs/import_url', data={'zip_url': 'https://blocked.example/demo.zip'})

    assert resp.status_code == 302
    assert resp.headers['Location'].endswith('/vuln_catalog_page')


def test_vuln_catalog_pack_import_url_installs_downloaded_zip(monkeypatch):
    client = app.test_client()
    _login(client)
    captured = {}

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_is_safe_remote_zip_url', lambda url: (True, ''))
    monkeypatch.setattr(backend, '_download_zip_from_url', lambda url: b'zip-bytes')

    def fake_install(*, zip_bytes, label, origin):
        captured['zip_bytes'] = zip_bytes
        captured['label'] = label
        captured['origin'] = origin
        return {'id': 'catalog-789'}

    monkeypatch.setattr(backend, '_install_vuln_catalog_zip_bytes', fake_install)

    resp = client.post('/vuln_catalog_packs/import_url', data={'zip_url': 'https://example.com/packs/demo.zip'})

    assert resp.status_code == 302
    assert resp.headers['Location'].endswith('/vuln_catalog_page')
    assert captured == {
        'zip_bytes': b'zip-bytes',
        'label': 'demo.zip',
        'origin': 'https://example.com/packs/demo.zip',
    }


def test_vuln_catalog_pack_import_url_ajax_returns_detailed_summary(monkeypatch):
    client = app.test_client()
    _login(client)

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_is_safe_remote_zip_url', lambda url: (True, ''))
    monkeypatch.setattr(backend, '_download_zip_from_url', lambda url: b'zip-bytes')
    monkeypatch.setattr(
        backend,
        '_install_vuln_catalog_zip_bytes',
        lambda **kwargs: {
            'id': 'catalog-789',
            'compose_count': 7,
            'missing_required_file_count': 2,
        },
    )

    response = client.post(
        '/vuln_catalog_packs/import_url',
        data={'zip_url': 'https://example.com/packs/demo.zip'},
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
    )

    assert response.status_code == 200
    assert response.get_json() == {
        'ok': True,
        'message': 'Vulnerability catalog pack installed from URL.',
        'catalog_id': 'catalog-789',
        'import_method': 'url',
        'downloaded_bytes': 9,
        'installed_catalog_count': 1,
        'installed_vulnerability_count': 7,
        'missing_required_file_count': 2,
        'bundle_failures': [],
    }


def test_vulnerability_import_and_export_preserve_original_categories(tmp_path, monkeypatch):
    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(tmp_path / 'outputs'))
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))

    source_zip = tmp_path / 'vulnerability-source.zip'
    source_zip.write_bytes(_make_zip({
        'download-main/web/auth/login-demo/docker-compose.yml': (
            'services:\n'
            '  web:\n'
            '    image: nginx:alpine\n'
        ),
    }))
    entry = backend._install_vuln_catalog_zip_file(
        zip_file_path=str(source_zip),
        label='vulnerability-source.zip',
        origin='upload',
    )

    item = (entry.get('compose_items') or [])[0]
    assert item['category'] == 'download-main/web/auth'
    assert item['compose_rel'] == 'download-main/web/auth/login-demo/docker-compose.yml'

    client = app.test_client()
    _login(client)
    response = client.get(f"/vuln_catalog_packs/download/{entry['id']}")
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data), 'r') as exported_zip:
        names = set(exported_zip.namelist())
        layout = json.loads(exported_zip.read('.scenarioforge/catalog_layout.json').decode('utf-8'))
    assert 'download-main/web/auth/login-demo/docker-compose.yml' in names
    assert layout['items'] == [{
        'category': 'download-main/web/auth',
        'compose_rel': 'download-main/web/auth/login-demo/docker-compose.yml',
    }]

    roundtrip_zip = tmp_path / 'vulnerability-roundtrip.zip'
    roundtrip_zip.write_bytes(response.data)
    restored = backend._install_vuln_catalog_zip_file(
        zip_file_path=str(roundtrip_zip),
        label='vulnerability-roundtrip.zip',
        origin='upload',
    )
    restored_item = (restored.get('compose_items') or [])[0]
    assert restored_item['category'] == 'download-main/web/auth'

    items_response = client.get('/vuln_catalog_items_data')
    assert items_response.status_code == 200
    items_payload = items_response.get_json() or {}
    assert (items_payload.get('items') or [])[0]['category'] == 'download-main/web/auth'


def test_vuln_catalog_import_reports_per_vulnerability_progress(monkeypatch):
    """Discovery should name each vulnerability and count it against the total.

    The import runs as one blocking POST, so this per-item reporting is the
    only thing the browser can show while a large catalog is validated.
    """
    client = app.test_client()
    _login(client)

    updates: list[dict] = []
    real_update = ingest.update_progress

    def capture(progress_id, **kwargs):
        updates.append({'progress_id': progress_id, **kwargs})
        return real_update(progress_id, **kwargs)

    monkeypatch.setattr(ingest, 'update_progress', capture)

    zip_bytes = _make_zip({
        f'pack/vuln-{index}/docker-compose.yml': 'services: {}\n'
        for index in range(5)
    })

    response = client.post(
        '/vuln_catalog_packs/upload',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
        data=MultiDict([
            ('zip_file', (io.BytesIO(zip_bytes), 'pack.zip')),
            ('import_progress_id', 'progressid12345'),
        ]),
        content_type='multipart/form-data',
    )
    assert response.status_code == 200

    discovery = [
        update for update in updates
        if update.get('step') == 'Discovering and validating vulnerabilities'
    ]
    assert [(u['current'], u['total']) for u in discovery] == [(1, 5), (2, 5), (3, 5), (4, 5), (5, 5)]
    assert [u['detail'] for u in discovery] == [f'pack/vuln-{index}' for index in range(5)]


def test_vuln_catalog_import_progress_endpoint_reports_snapshot_and_rejects_bad_id():
    client = app.test_client()
    _login(client)

    assert client.get('/api/vuln-catalog-import-progress/short').status_code == 400

    # An id nobody has reported against is 'waiting', not an error, so the
    # client can start polling before the upload reaches the server.
    pending = client.get('/api/vuln-catalog-import-progress/neverusedid123')
    assert pending.status_code == 200
    assert pending.get_json()['status'] == 'waiting'

    ingest.update_progress(
        'livesnapshotid123',
        step='Discovering and validating vulnerabilities',
        detail='pack/vuln-7',
        current=7,
        total=20,
    )
    payload = client.get('/api/vuln-catalog-import-progress/livesnapshotid123').get_json()
    assert payload['step'] == 'Discovering and validating vulnerabilities'
    assert payload['detail'] == 'pack/vuln-7'
    assert (payload['current'], payload['total'], payload['percent']) == (7, 20, 35)


def test_vuln_catalog_import_progress_requires_login():
    assert app.test_client().get('/api/vuln-catalog-import-progress/anonymousid123').status_code == 401


def test_import_validation_choice_overrides_environment_default(monkeypatch):
    """The Import dialog's answer wins over CORETG_CATALOG_ARCH_SCAN."""
    monkeypatch.setenv('CORETG_CATALOG_ARCH_SCAN', '1')
    ingest.set_active_architecture_scan(False)
    try:
        assert backend._vuln_catalog_architecture_scan_enabled() is False
    finally:
        ingest.set_active_architecture_scan(None)
    # Cleared override falls back to the environment.
    assert backend._vuln_catalog_architecture_scan_enabled() is True

    monkeypatch.setenv('CORETG_CATALOG_ARCH_SCAN', '0')
    ingest.set_active_architecture_scan(True)
    try:
        assert backend._vuln_catalog_architecture_scan_enabled() is True
    finally:
        ingest.set_active_architecture_scan(None)
    assert backend._vuln_catalog_architecture_scan_enabled() is False


def test_upload_route_applies_and_clears_validation_choice(monkeypatch):
    """The posted choice is active during install and reset afterwards."""
    client = app.test_client()
    _login(client)
    seen: dict = {}

    def fake_install(*, zip_file_path, label, origin):
        seen['during_install'] = ingest.active_architecture_scan()
        return {'id': 'choice-catalog'}

    monkeypatch.setattr(backend, '_install_vuln_catalog_zip_file', fake_install)

    for posted, expected in (('0', False), ('1', True)):
        seen.clear()
        response = client.post(
            '/vuln_catalog_packs/upload',
            headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
            data=MultiDict([
                ('zip_file', (io.BytesIO(b'PK\x03\x04demo'), 'catalog.zip')),
                ('validate_architectures', posted),
            ]),
            content_type='multipart/form-data',
        )
        assert response.status_code == 200
        assert seen['during_install'] is expected
        # Never leaks past the request onto a pooled worker thread.
        assert ingest.active_architecture_scan() is None


def test_upload_route_without_choice_keeps_configured_default(monkeypatch):
    """A POST that predates the dialog must not silently change behaviour."""
    client = app.test_client()
    _login(client)
    seen: dict = {}

    def fake_install(*, zip_file_path, label, origin):
        seen['during_install'] = ingest.active_architecture_scan()
        return {'id': 'default-catalog'}

    monkeypatch.setattr(backend, '_install_vuln_catalog_zip_file', fake_install)

    response = client.post(
        '/vuln_catalog_packs/upload',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
        data={'zip_file': (io.BytesIO(b'PK\x03\x04demo'), 'catalog.zip')},
        content_type='multipart/form-data',
    )
    assert response.status_code == 200
    assert seen['during_install'] is None


def _fake_remote_catalogs(monkeypatch, tmp_path, removed, local_ids, remote_ids):
    """Local catalogs vs. what the CORE VM still holds."""
    import stat as _stat

    catalog_root = tmp_path / 'outputs' / 'installed_vuln_catalogs'
    for cid in local_ids:
        (catalog_root / cid / 'content').mkdir(parents=True, exist_ok=True)

    class _Attr:
        def __init__(self, name):
            self.filename = name
            self.st_mode = _stat.S_IFDIR | 0o755

    remote_root = '/remote/repo/outputs/installed_vuln_catalogs'
    tree = {
        '/remote/repo': [_Attr('outputs')],
        remote_root: [_Attr(cid) for cid in remote_ids],
    }
    # Each remote catalog has content below it; the walk must stop at the
    # catalog directory rather than descending into per-vulnerability dirs.
    for cid in remote_ids:
        tree[f'{remote_root}/{cid}'] = [_Attr('content')]

    class _Sftp:
        def stat(self, path):
            if path not in tree:
                raise IOError(path)
            return object()

        def listdir_attr(self, path):
            if path not in tree:
                raise IOError(path)
            return tree[path]

        def close(self):
            pass

    class _Client:
        def open_sftp(self):
            return _Sftp()

        def close(self):
            pass

    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path))
    monkeypatch.setattr(backend, '_installed_vuln_catalogs_root', lambda: str(catalog_root))
    monkeypatch.setattr(backend, '_core_config_for_request', lambda **kw: {'ssh_host': 'core.example'})
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(backend, '_open_ssh_client', lambda cfg: _Client())
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda sftp: '/remote/repo')
    monkeypatch.setattr(backend, '_remote_remove_path', lambda client, path: removed.append(path))


def test_vuln_core_runtime_sync_removes_catalogs_absent_locally(tmp_path, monkeypatch):
    removed: list[str] = []
    _fake_remote_catalogs(
        monkeypatch, tmp_path, removed,
        local_ids=['05-27-26-keep'],
        remote_ids=['05-27-26-keep', '01-01-26-stale', '02-02-26-other-deployment'],
    )

    result = backend._reconcile_remote_vuln_catalog_runtime()

    assert result['ok'] is True
    assert result['checked'] == 3
    assert result['kept'] == 1
    assert sorted(result['removed']) == ['01-01-26-stale', '02-02-26-other-deployment']
    assert sorted(removed) == [
        '/remote/repo/outputs/installed_vuln_catalogs/01-01-26-stale',
        '/remote/repo/outputs/installed_vuln_catalogs/02-02-26-other-deployment',
    ]


def test_vuln_core_runtime_sync_dry_run_deletes_nothing(tmp_path, monkeypatch):
    removed: list[str] = []
    _fake_remote_catalogs(
        monkeypatch, tmp_path, removed,
        local_ids=['keep-me'], remote_ids=['keep-me', 'drop-me'],
    )

    result = backend._reconcile_remote_vuln_catalog_runtime(dry_run=True)

    assert result['ok'] is True
    assert result['dry_run'] is True
    assert result['removed'] == ['drop-me']
    assert removed == [], 'preview must not delete anything'


def test_vuln_core_runtime_sync_route_reports_counts(tmp_path, monkeypatch):
    removed: list[str] = []
    _fake_remote_catalogs(
        monkeypatch, tmp_path, removed,
        local_ids=['keep-me'], remote_ids=['keep-me', 'drop-me'],
    )
    client = app.test_client()
    _login(client)

    response = client.post('/api/vuln_catalog_packs/sync_core', json={'dry_run': True})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['ok'] is True
    assert (payload['checked'], payload['kept'], payload['removed_count']) == (2, 1, 1)
    assert removed == []


def test_vuln_core_runtime_sync_route_surfaces_unreachable_core_vm(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_reconcile_remote_vuln_catalog_runtime',
        lambda **kwargs: {'ok': False, 'error': 'CORE SSH configuration is required: no host'},
    )
    client = app.test_client()
    _login(client)

    response = client.post('/api/vuln_catalog_packs/sync_core', json={})
    assert response.status_code == 502
    assert 'CORE SSH configuration is required' in response.get_json()['error']
