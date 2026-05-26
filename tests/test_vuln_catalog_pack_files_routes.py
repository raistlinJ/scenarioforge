import io
import zipfile
from pathlib import Path

from webapp import app_backend as backend


app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_vuln_catalog_pack_download_streams_zip(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    pack_zip = tmp_path / 'pack.zip'
    with zipfile.ZipFile(pack_zip, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('demo.txt', 'ok')

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_vuln_catalog_pack_zip_path', lambda catalog_id: str(pack_zip))

    resp = client.get('/vuln_catalog_packs/download/cat-1')

    assert resp.status_code == 200
    assert resp.data[:2] == b'PK'
    assert 'attachment; filename=vuln_catalog_cat-1.zip' in resp.headers.get('Content-Disposition', '')


def test_vuln_catalog_export_all_bundles_catalog_zips(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    pack_zip_one = tmp_path / 'cat-one.zip'
    pack_zip_two = tmp_path / 'cat-two.zip'
    with zipfile.ZipFile(pack_zip_one, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('one/docker-compose.yml', 'services: {}\n')
    with zipfile.ZipFile(pack_zip_two, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('two/docker-compose.yml', 'services: {}\n')

    paths = {'cat-1': str(pack_zip_one), 'cat-2': str(pack_zip_two)}
    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_load_vuln_catalogs_state', lambda: {
        'catalogs': [
            {'id': 'cat-1', 'label': 'alpha', 'origin': 'test', 'installed_at': 'now', 'compose_count': 1},
            {'id': 'cat-2', 'label': 'beta', 'origin': 'test', 'installed_at': 'now', 'compose_count': 1},
            {'id': 'missing', 'label': 'missing'},
        ]
    })
    monkeypatch.setattr(backend, '_vuln_catalog_pack_zip_path', lambda catalog_id: paths.get(catalog_id, str(tmp_path / 'missing.zip')))

    resp = client.get('/vuln_catalog_packs/export_all?download_token=test-token')

    assert resp.status_code == 200
    assert 'attachment; filename=vulnerability_catalog.zip' in resp.headers.get('Content-Disposition', '')
    assert 'coretg_catalog_download_token=test-token' in resp.headers.get('Set-Cookie', '')
    with zipfile.ZipFile(io.BytesIO(resp.data), 'r') as archive:
        names = set(archive.namelist())
        assert 'catalogs/cat-1-alpha.zip' in names
        assert 'catalogs/cat-2-beta.zip' in names
        assert 'catalogs/missing-missing.zip' not in names
        manifest = archive.read('catalogs.json').decode('utf-8')
    assert 'cat-1' in manifest
    assert 'cat-2' in manifest


def test_vuln_catalog_pack_browse_lists_entries_and_redirects_files(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    pack_dir = tmp_path / 'pack'
    nested = pack_dir / 'folder'
    nested.mkdir(parents=True)
    (pack_dir / 'root.txt').write_text('root', encoding='utf-8')
    (nested / 'child.txt').write_text('child', encoding='utf-8')

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_vuln_catalog_pack_content_dir', lambda catalog_id: str(pack_dir))
    monkeypatch.setattr(backend, '_safe_path_under', lambda base_dir, subpath: str(Path(base_dir) / subpath))

    browse_resp = client.get('/vuln_catalog_packs/browse/cat-1')
    assert browse_resp.status_code == 200
    page = browse_resp.get_data(as_text=True)
    assert 'folder' in page
    assert 'root.txt' in page

    redirect_resp = client.get('/vuln_catalog_packs/browse/cat-1/root.txt', follow_redirects=False)
    assert redirect_resp.status_code in (302, 308)
    assert '/vuln_catalog_packs/file/cat-1/root.txt' in redirect_resp.headers.get('Location', '')


def test_vuln_catalog_pack_readme_renders_plain_text(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    pack_dir = tmp_path / 'pack'
    pack_dir.mkdir(parents=True)
    readme = pack_dir / 'README.txt'
    readme.write_text('hello from readme', encoding='utf-8')

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_vuln_catalog_pack_content_dir', lambda catalog_id: str(pack_dir))
    monkeypatch.setattr(backend, '_safe_path_under', lambda base_dir, subpath: str(Path(base_dir) / subpath))

    resp = client.get('/vuln_catalog_packs/readme/cat-1/README.txt')

    assert resp.status_code == 200
    assert 'hello from readme' in resp.get_data(as_text=True)


def test_vuln_catalog_pack_item_files_returns_urls(monkeypatch, tmp_path):
    client = app.test_client()
    _login(client)

    pack_dir = tmp_path / 'pack'
    item_dir = pack_dir / 'items' / 'sample'
    item_dir.mkdir(parents=True)
    (item_dir / 'docker-compose.yml').write_text('services: {}\n', encoding='utf-8')
    (item_dir / 'README.md').write_text('# hi\n', encoding='utf-8')

    monkeypatch.setattr(backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(backend, '_load_vuln_catalogs_state', lambda: {'catalogs': [{'id': 'cat-1'}]})
    monkeypatch.setattr(backend, '_normalize_vuln_catalog_items', lambda entry: [{'id': 5, 'dir_rel': 'items/sample', 'rel_dir': 'items/sample'}])
    monkeypatch.setattr(backend, '_vuln_catalog_pack_content_dir', lambda catalog_id: str(pack_dir))
    monkeypatch.setattr(backend, '_safe_path_under', lambda base_dir, subpath: str(Path(base_dir) / subpath))

    resp = client.get('/vuln_catalog_packs/item_files/cat-1/5')

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload['ok'] is True
    names = {item['name'] for item in payload['files']}
    assert names == {'docker-compose.yml', 'README.md'}
    urls = {item['url'] for item in payload['files']}
    assert '/vuln_catalog_packs/file/cat-1/items/sample/docker-compose.yml' in urls