import io
import json
import zipfile
from pathlib import Path

from webapp import app_backend as backend


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


def test_vuln_catalog_pack_upload_ajax_missing_file_returns_400(monkeypatch):
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
    assert resp.get_json() == {'ok': False, 'error': 'Missing zip_file'}


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
        'missing_required_file_count': 0,
    }
    assert captured['origin'] == 'upload'
    assert captured['label'] == 'danger_demo.zip'
    assert captured['exists_during_install'] is True
    assert not Path(captured['zip_file_path']).exists()


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
        'missing_required_file_count': 0,
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
