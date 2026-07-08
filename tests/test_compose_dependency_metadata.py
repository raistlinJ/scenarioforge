import io
import zipfile
from pathlib import Path

from scenarioforge.compose_dependencies import missing_dependency_paths, scan_compose_dependencies
from webapp.app_backend import app
import webapp.app_backend as app_backend


def _make_zip(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return buf.getvalue()


def _login(client) -> None:
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (200, 302)


def test_compose_dependency_scanner_reports_missing_env_and_bind(tmp_path: Path) -> None:
    compose_path = tmp_path / 'docker-compose.yml'
    compose_path.write_text(
        (
            'services:\n'
            '  web:\n'
            '    image: alpine:3.19\n'
            '    env_file:\n'
            '      - .env\n'
            '      - path: optional.env\n'
            '        required: false\n'
            '    volumes:\n'
            '      - ./.venv:/app/.venv\n'
            '      - named_data:/data\n'
            'volumes:\n'
            '  named_data: {}\n'
        ),
        encoding='utf-8',
    )

    summary = scan_compose_dependencies(compose_path)

    assert missing_dependency_paths(summary) == ['.env', '.venv']
    required = summary.get('requires') or []
    assert any(item.get('path') == 'optional.env' and item.get('required') is False for item in required)
    assert not any(item.get('path') == 'named_data' for item in required)


def test_vuln_catalog_import_tracks_missing_compose_support_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(app_backend, '_outputs_dir', lambda: str(tmp_path / 'outputs'))
    monkeypatch.setattr(app_backend, '_get_repo_root', lambda: str(tmp_path))

    zip_path = tmp_path / 'vuln-pack.zip'
    zip_path.write_bytes(
        _make_zip({
            'demo/docker-compose.yml': (
                'services:\n'
                '  web:\n'
                '    image: alpine:3.19\n'
                '    env_file:\n'
                '      - .env\n'
                '    volumes:\n'
                '      - ./.venv:/app/.venv\n'
            ),
        })
    )

    entry = app_backend._install_vuln_catalog_zip_file(
        zip_file_path=str(zip_path),
        label='vuln-pack.zip',
        origin='upload',
    )

    assert entry.get('missing_required_file_count') == 2
    item = (entry.get('compose_items') or [])[0]
    assert item.get('missing_required_files') == ['.env', '.venv']
    assert item.get('disabled') is True
    assert item.get('disabled_due_to_missing_files') is True

    client = app.test_client()
    _login(client)
    resp = client.get('/vuln_catalog_items_data')
    assert resp.status_code == 200
    data = resp.get_json() or {}
    api_item = (data.get('items') or [])[0]
    assert api_item.get('missing_required_file_count') == 2
    assert api_item.get('missing_required_files') == ['.env', '.venv']
    assert api_item.get('disabled') is True
    assert api_item.get('disabled_due_to_missing_files') is True


def test_vuln_catalog_dependency_status_updates_only_after_explicit_recheck(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(app_backend, '_outputs_dir', lambda: str(tmp_path / 'outputs'))
    monkeypatch.setattr(app_backend, '_get_repo_root', lambda: str(tmp_path))

    zip_path = tmp_path / 'vuln-pack.zip'
    zip_path.write_bytes(
        _make_zip({
            'demo/docker-compose.yml': (
                'services:\n'
                '  web:\n'
                '    image: alpine:3.19\n'
                '    env_file:\n'
                '      - .env\n'
            ),
        })
    )
    entry = app_backend._install_vuln_catalog_zip_file(
        zip_file_path=str(zip_path),
        label='vuln-pack.zip',
        origin='upload',
    )
    content_dir = Path(app_backend._vuln_catalog_pack_content_dir(str(entry.get('id'))))
    (content_dir / 'demo' / '.env').write_text('READY=1\n', encoding='utf-8')

    client = app.test_client()
    _login(client)

    cached_resp = client.get('/vuln_catalog_items_data')
    assert cached_resp.status_code == 200
    cached_item = ((cached_resp.get_json() or {}).get('items') or [])[0]
    assert cached_item.get('missing_required_files') == ['.env']
    assert cached_item.get('disabled') is True

    recheck_resp = client.post('/vuln_catalog_items/recheck_dependencies', json={})
    assert recheck_resp.status_code == 200
    assert (recheck_resp.get_json() or {}).get('missing_required_file_count') == 0

    refreshed_resp = client.get('/vuln_catalog_items_data')
    assert refreshed_resp.status_code == 200
    refreshed_item = ((refreshed_resp.get_json() or {}).get('items') or [])[0]
    assert refreshed_item.get('missing_required_files') == []
    assert refreshed_item.get('disabled') is False
    assert refreshed_item.get('disabled_due_to_missing_files') is False


def test_generator_pack_import_returns_missing_dependency_warning(tmp_path: Path, monkeypatch) -> None:
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))

    gen_id = 'pack_test_missing_dependency'
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: Pack Test Missing Dependency
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
inputs: []
artifacts:
  requires: []
  produces:
    - File(path)
injects: []
"""
    compose = """services:
  generator:
    image: python:3.11-slim
    env_file:
      - .env
    command: ["python", "-c", "print('ok')"]
"""
    zip_bytes = _make_zip({
        f'flag_generators/{gen_id}/manifest.yaml': manifest,
        f'flag_generators/{gen_id}/docker-compose.yml': compose,
        f'flag_generators/{gen_id}/generator.py': "print('hi')\n",
    })

    client = app.test_client()
    _login(client)
    resp = client.post(
        '/generator_packs/upload',
        data={'zip_file': (io.BytesIO(zip_bytes), 'pack.zip')},
        content_type='multipart/form-data',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
    )

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    warnings = payload.get('warnings') or []
    assert any(warning.get('dependency_path') == '.env' for warning in warnings if isinstance(warning, dict))

    data_resp = client.get('/flag_generators_data')
    assert data_resp.status_code == 200
    data = data_resp.get_json() or {}
    generators = [g for g in (data.get('generators') or []) if g.get('id') == gen_id]
    assert generators
    assert generators[0].get('missing_required_files') == ['.env']
    assert generators[0].get('_disabled') is True
    assert generators[0].get('_disabled_due_to_missing_files') is True


def test_generator_dependency_status_updates_only_after_explicit_recheck(tmp_path: Path, monkeypatch) -> None:
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))

    gen_id = 'pack_test_cached_dependency'
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: Pack Test Cached Dependency
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
inputs: []
artifacts:
  produces:
    - File(path)
injects: []
"""
    compose = """services:
  generator:
    image: python:3.11-slim
    env_file:
      - .env
    command: ["python", "-c", "print('ok')"]
"""
    zip_bytes = _make_zip({
        f'flag_generators/{gen_id}/manifest.yaml': manifest,
        f'flag_generators/{gen_id}/docker-compose.yml': compose,
        f'flag_generators/{gen_id}/generator.py': "print('hi')\n",
    })

    client = app.test_client()
    _login(client)
    upload_resp = client.post(
        '/generator_packs/upload',
        data={'zip_file': (io.BytesIO(zip_bytes), 'pack.zip')},
        content_type='multipart/form-data',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
    )
    assert upload_resp.status_code == 200

    state = app_backend._load_installed_generator_packs_state()
    installed_path = Path((state.get('packs') or [])[0]['installed'][0]['path'])
    (installed_path / '.env').write_text('READY=1\n', encoding='utf-8')

    cached_resp = client.get('/flag_generators_data')
    assert cached_resp.status_code == 200
    cached_generators = [g for g in ((cached_resp.get_json() or {}).get('generators') or []) if g.get('id') == gen_id]
    assert cached_generators
    assert cached_generators[0].get('missing_required_files') == ['.env']
    assert cached_generators[0].get('_disabled') is True

    recheck_resp = client.post('/api/generator_catalog/recheck_dependencies', json={'kind': 'flag-generator'})
    assert recheck_resp.status_code == 200
    assert (recheck_resp.get_json() or {}).get('missing_required_file_count') == 0

    refreshed_resp = client.get('/flag_generators_data')
    assert refreshed_resp.status_code == 200
    refreshed_generators = [g for g in ((refreshed_resp.get_json() or {}).get('generators') or []) if g.get('id') == gen_id]
    assert refreshed_generators
    assert refreshed_generators[0].get('missing_required_files') == []
    assert refreshed_generators[0].get('_disabled') is False
    assert refreshed_generators[0].get('_disabled_due_to_missing_files') is False


def test_scan_dockerfile_build_network_detects_network_ops(tmp_path):
    """A Dockerfile that installs packages / fetches at build time (like the
    phpmailer vulhub item) must be flagged; a plain FROM+COPY must not."""
    from scenarioforge.compose_dependencies import scan_dockerfile_build_network

    heavy = tmp_path / 'Dockerfile.heavy'
    heavy.write_text(
        "FROM vulhub/php:5.6-apache\n"
        "COPY www/* /var/www/html/\n"
        "RUN set -ex \\\n"
        "    && apt-get update \\\n"
        "    && apt-get install -y --no-install-recommends git \\\n"
        "    && curl -sSL https://getcomposer.org/installer | php \\\n"
        "    && php composer.phar install\n",
        encoding='utf-8',
    )
    assert scan_dockerfile_build_network(str(heavy)) == ['apt', 'composer', 'curl/wget']

    simple = tmp_path / 'Dockerfile.simple'
    simple.write_text("FROM python:3.11-slim\nWORKDIR /app\nCOPY generator.py /app/\nCMD [\"python\", \"generator.py\"]\n", encoding='utf-8')
    assert scan_dockerfile_build_network(str(simple)) == []


def test_scan_compose_dependencies_surfaces_build_network(tmp_path):
    from scenarioforge.compose_dependencies import scan_compose_dependencies

    (tmp_path / 'Dockerfile').write_text("FROM alpine\nRUN apk add --no-cache git && pip install requests\n", encoding='utf-8')
    compose = tmp_path / 'docker-compose.yml'
    compose.write_text("services:\n  web:\n    build: .\n", encoding='utf-8')

    summary = scan_compose_dependencies(str(compose))
    assert summary['requires_build_network'] is True
    assert 'web: apk' in summary['build_network_notes']
    assert 'web: pip install' in summary['build_network_notes']


def test_scan_compose_dependencies_no_build_network_for_pull_only(tmp_path):
    from scenarioforge.compose_dependencies import scan_compose_dependencies

    compose = tmp_path / 'docker-compose.yml'
    compose.write_text("services:\n  web:\n    image: nginx:1\n  db:\n    image: mysql:8\n", encoding='utf-8')

    summary = scan_compose_dependencies(str(compose))
    assert summary['requires_build_network'] is False
    assert summary['build_network_notes'] == []


def test_apply_dependency_auto_disable_tracks_reasons_independently():
    from scenarioforge.compose_dependencies import apply_dependency_auto_disable

    # Build-network item is auto-disabled, tracked by its own reason flag.
    item: dict = {}
    changed = apply_dependency_auto_disable(item, missing=False, needs_build_network=True)
    assert changed and item['disabled'] is True
    assert item['disabled_due_to_build_network'] is True
    assert item['disabled_due_to_missing_files'] is False

    # Clearing only the build-network reason re-enables (no other reason).
    apply_dependency_auto_disable(item, missing=False, needs_build_network=False)
    assert item['disabled'] is False

    # A manual disable (no reason flags) is preserved across a clean check.
    manual = {'disabled': True}
    apply_dependency_auto_disable(manual, missing=False, needs_build_network=False)
    assert manual['disabled'] is True

    # If both reasons apply, fixing files alone keeps it disabled for build-net.
    both = {}
    apply_dependency_auto_disable(both, missing=True, needs_build_network=True)
    assert both['disabled'] is True
    apply_dependency_auto_disable(both, missing=False, needs_build_network=True)
    assert both['disabled'] is True and both['disabled_due_to_build_network'] is True
