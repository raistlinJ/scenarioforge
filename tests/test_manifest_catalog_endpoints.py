import json
from pathlib import Path

from scenarioforge.generator_manifests import discover_generator_manifests
from webapp.app_backend import app
import webapp.app_backend as app_backend


def _write_flag_generator_manifest(path: Path, *, generator_id: str, name: str | None = None) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / 'manifest.yaml').write_text(
        f"""manifest_version: 1
id: {generator_id}
kind: flag-generator
name: {name or generator_id}
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
inputs: []
artifacts:
  produces:
    - Flag(flag_id)
""",
        encoding='utf-8',
    )


def test_manifest_discovery_allows_empty_catalog(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    repo_root.mkdir()
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(tmp_path / 'installed_generators'))

    for kind in ('flag-generator', 'flag-node-generator'):
        generators, plugins, errors = discover_generator_manifests(repo_root=repo_root, kind=kind)
        assert generators == []
        assert plugins == {}
        assert errors == []


def test_catalog_endpoints_allow_empty_installed_catalog(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    repo_root.mkdir()
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(tmp_path / 'installed_generators'))
    monkeypatch.setattr(app_backend, '_get_repo_root', lambda: str(repo_root))

    client = app.test_client()
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (200, 302)

    for endpoint in ('/flag_generators_data', '/flag_node_generators_data'):
        resp = client.get(endpoint)
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)
        assert data.get('errors') == [] or data.get('errors') is None
        assert data.get('generators') == []


def test_repo_root_does_not_ship_starter_generator_catalog():
    repo_root = Path(__file__).resolve().parents[1]
    assert not (repo_root / 'flag_generators').exists()
    assert not (repo_root / 'flag_node_generators').exists()


def test_manifest_discovery_can_exclude_disabled_installed_generators(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    repo_root.mkdir()
    installed_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(installed_root))

    source_id = 'disabled_shared_id'
    _write_flag_generator_manifest(repo_root / 'flag_generators' / source_id, generator_id=source_id, name='Repo Copy')

    installed_path = installed_root / 'flag_generators' / '000001'
    _write_flag_generator_manifest(installed_path, generator_id='000001', name='Installed Copy')
    (installed_path / '.coretg_pack.json').write_text(
        json.dumps({
            'pack_id': 'pack-1',
            'pack_label': 'Pack One',
            'generator_id': '000001',
            'source_generator_id': source_id,
        }),
        encoding='utf-8',
    )
    (installed_root / '_packs_state.json').write_text(
        json.dumps({
            'packs': [
                {
                    'id': 'pack-1',
                    'label': 'Pack One',
                    'installed': [
                        {
                            'id': '000001',
                            'kind': 'flag-generator',
                            'path': str(installed_path),
                            'disabled': True,
                        }
                    ],
                }
            ]
        }),
        encoding='utf-8',
    )

    visible, visible_plugins, visible_errors = discover_generator_manifests(
        repo_root=repo_root,
        kind='flag-generator',
        include_disabled=True,
    )
    assert visible_errors == []
    assert [generator.get('id') for generator in visible] == [source_id]
    assert visible[0].get('_disabled') is True
    assert source_id in visible_plugins

    enabled, enabled_plugins, enabled_errors = discover_generator_manifests(
        repo_root=repo_root,
        kind='flag-generator',
        include_disabled=False,
    )
    assert enabled_errors == []
    assert enabled == []
    assert enabled_plugins == {}


def test_manifest_discovery_rejects_ambiguous_installed_source_ids(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    repo_root.mkdir()
    installed_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(installed_root))

    for assigned_id in ('000001', '000002'):
        installed_path = installed_root / 'flag_generators' / assigned_id
        _write_flag_generator_manifest(installed_path, generator_id=assigned_id)
        (installed_path / '.coretg_pack.json').write_text(
            json.dumps({
                'pack_id': f'pack-{assigned_id}',
                'generator_id': assigned_id,
                'source_generator_id': 'shared_source_id',
            }),
            encoding='utf-8',
        )

    generators, plugins, errors = discover_generator_manifests(
        repo_root=repo_root,
        kind='flag-generator',
    )

    assert generators == []
    assert plugins == {}
    assert any('duplicate generator id: shared_source_id' in error.error for error in errors)
