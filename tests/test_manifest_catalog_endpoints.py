from pathlib import Path

from scenarioforge.generator_manifests import discover_generator_manifests
from webapp.app_backend import app
import webapp.app_backend as app_backend


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
