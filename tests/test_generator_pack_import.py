import io
import os
import zipfile

import pytest
from pathlib import Path

from webapp.app_backend import app
import webapp.app_backend as app_backend
from werkzeug.datastructures import MultiDict
from werkzeug.utils import secure_filename


def _make_zip(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, content in files.items():
            z.writestr(path, content)
    buf.seek(0)
    return buf.read()


def _minimal_generator_files(generator_id: str, *, kind: str = "flag-generator") -> dict[str, str]:
    catalog_dir = "flag_node_generators" if kind == "flag-node-generator" else "flag_generators"
    produced_artifact = "Flag(flag_id)" if kind == "flag-node-generator" else "File(path)"
    base = f"{catalog_dir}/{generator_id}"
    return {
        f"{base}/manifest.yaml": f"""manifest_version: 1
id: {generator_id}
kind: {kind}
name: {generator_id}
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
artifacts:
  produces: [{produced_artifact}]
""",
        f"{base}/docker-compose.yml": "services:\n  generator:\n    image: python:3.11-slim\n",
    }


def test_generator_pack_rolls_back_files_when_state_commit_fails(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))
    zip_path = tmp_path / "pack.zip"
    zip_path.write_bytes(_make_zip(_minimal_generator_files("transaction_test")))

    def fail_state_save(_state):
        raise OSError("state write failed")

    monkeypatch.setattr(app_backend, "_save_installed_generator_packs_state", fail_state_save)

    ok, note = app_backend._install_generator_pack(
        zip_path=str(zip_path),
        pack_label="transaction-test",
        pack_origin="upload",
    )

    assert ok is False
    assert "state write failed" in note
    assert not list(install_root.rglob("manifest.yaml"))
    assert not list(install_root.rglob(".coretg_pack.json"))
    assert not list(install_root.glob(".coretg-generator-stage-*"))


def test_generator_pack_rolls_back_first_item_when_second_publish_fails(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))
    zip_path = tmp_path / "two-generators.zip"
    pack_files = {
        **_minimal_generator_files("transaction_first"),
        **_minimal_generator_files("transaction_second", kind="flag-node-generator"),
    }
    zip_path.write_bytes(_make_zip(pack_files))

    real_replace = os.replace
    publish_calls = 0

    def fail_second_publish(source, destination):
        nonlocal publish_calls
        if ".coretg-generator-stage-" in str(source):
            publish_calls += 1
            if publish_calls == 2:
                raise OSError("second publish failed")
        return real_replace(source, destination)

    monkeypatch.setattr(app_backend.os, "replace", fail_second_publish)

    with pytest.raises(OSError, match="second publish failed"):
        app_backend._install_generator_pack_payload(
            zip_path=str(zip_path),
            pack_id="transaction-pack",
            safe_label="transaction-pack",
            pack_origin="upload",
            next_numeric=1,
        )

    assert publish_calls == 2
    assert not list(install_root.rglob("manifest.yaml"))
    assert not list(install_root.rglob(".coretg_pack.json"))
    assert not list(install_root.glob(".coretg-generator-stage-*"))
    assert not (install_root / "flag_generators").exists()
    assert not (install_root / "flag_node_generators").exists()


def test_generator_bundle_rolls_back_all_packs_when_state_commit_fails(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))
    first_pack = _make_zip(_minimal_generator_files("bundle_transaction_first"))
    second_pack = _make_zip(
        _minimal_generator_files("bundle_transaction_second", kind="flag-node-generator")
    )
    bundle_path = tmp_path / "bundle.zip"
    bundle_path.write_bytes(
        _make_zip({
            "packs/first.zip": first_pack,
            "packs/second.zip": second_pack,
        })
    )

    def fail_state_save(_state):
        raise OSError("bundle state write failed")

    monkeypatch.setattr(app_backend, "_save_installed_generator_packs_state", fail_state_save)

    ok, note = app_backend._install_generator_pack_or_bundle(
        zip_path=str(bundle_path),
        pack_label="transaction-bundle",
        pack_origin="upload",
    )

    assert ok is False
    assert "staged installs were rolled back" in note
    assert "bundle state write failed" in note
    assert not list(install_root.rglob("manifest.yaml"))
    assert not list(install_root.rglob(".coretg_pack.json"))
    assert not list(install_root.glob(".coretg-generator-stage-*"))


def test_generator_pack_zip_upload_installs_and_is_discoverable(tmp_path, monkeypatch):
    # Install into a temp directory so tests don't mutate the repo.
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_binary_embed_text"

    manifest = """manifest_version: 1
id: pack_test_binary_embed_text
kind: flag-generator
name: \"Pack Test: Binary Embed\"
description: \"Test pack generator\"
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

    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""

    generator_py = """def main():
    return 0
"""

    zip_bytes = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": generator_py,
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(zip_bytes), "pack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    # Should now appear in manifest-backed endpoint.
    data_resp = client.get("/flag_generators_data")
    assert data_resp.status_code == 200
    data = data_resp.get_json() or {}
    ids = {g.get("id") for g in (data.get("generators") or []) if isinstance(g, dict)}
    assert gen_id in ids

    # Ensure files were installed into the configured install root.
    assert (install_root / "flag_generators").exists()


def test_generator_pack_upload_rejects_duplicate_stable_generator_ids(tmp_path, monkeypatch):
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))

    manifest_one = """manifest_version: 1
id: first_numeric_id
kind: flag-node-generator
name: First
runtime: {type: docker-compose, compose_file: docker-compose.yml, service: generator}
artifacts: {produces: [Flag(flag_id)]}
"""
    manifest_two = manifest_one.replace('first_numeric_id', 'second_numeric_id').replace('name: First', 'name: Second')
    compose = """services:
  generator:
    image: python:3.11-slim
"""
    marker = '{"source_generator_id":"same_stable_id"}'
    zip_bytes = _make_zip({
        'flag_node_generators/one/manifest.yaml': manifest_one,
        'flag_node_generators/one/docker-compose.yml': compose,
        'flag_node_generators/one/.coretg_pack.json': marker,
        'flag_node_generators/two/manifest.yaml': manifest_two,
        'flag_node_generators/two/docker-compose.yml': compose,
        'flag_node_generators/two/.coretg_pack.json': marker,
    })

    client = app.test_client()
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (200, 302)
    response = client.post(
        '/generator_packs/upload',
        data={'zip_file': (io.BytesIO(zip_bytes), 'duplicate.zip')},
        content_type='multipart/form-data',
        headers={'X-Requested-With': 'XMLHttpRequest'},
    )

    assert response.status_code == 400
    assert 'duplicate stable generator id' in response.get_json()['error']
    assert not list(install_root.rglob('manifest.yaml'))


def test_generator_pack_zip_upload_xhr_returns_confirmation_payload(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_upload_xhr"
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: \"Pack Test: Upload XHR\"
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
    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""
    zip_bytes = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": "print('hi')\n",
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(zip_bytes), "pack-xhr.zip")},
        content_type="multipart/form-data",
        headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"},
    )

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get("ok") is True
    assert payload.get("confirmation_text") == f"Added to catalog as {gen_id}."
    assert payload.get("import_summary") == {
        "installed_generator_count": 1,
        "generator_kind_count": 1,
        "warning_count": 0,
    }
    assert payload.get("installed_as", {}).get("pack_label") == "pack-xhr"
    assert payload.get("installed_as", {}).get("grouped") == [
        {"kind": "flag-generator", "count": 1, "ids": [gen_id]}
    ]


def test_generator_repository_folder_upload_installs_recursively(tmp_path, monkeypatch):
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))

    gen_id = 'folder_repo_generator'
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: Folder Repository Generator
source_path: runtime/generator
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
artifacts:
  produces: [File(path)]
"""
    compose = """services:
  generator:
    image: python:3.11-slim
"""
    upload = MultiDict([
        ('repo_label', 'downloaded-generator-repo'),
        ('repo_paths', 'downloaded-generator-repo/catalog/generator/manifest.yaml'),
        ('repo_paths', 'downloaded-generator-repo/runtime/generator/docker-compose.yml'),
        ('repo_paths', 'downloaded-generator-repo/runtime/generator/generator.py'),
        ('repo_files', (io.BytesIO(manifest.encode()), 'manifest.yaml')),
        ('repo_files', (io.BytesIO(compose.encode()), 'docker-compose.yml')),
        ('repo_files', (io.BytesIO(b'print("ok")\n'), 'generator.py')),
    ])

    client = app.test_client()
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (200, 302)
    response = client.post(
        '/generator_packs/upload',
        data=upload,
        content_type='multipart/form-data',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
    )

    assert response.status_code == 200
    payload = response.get_json() or {}
    assert payload.get('confirmation_text') == f'Added to catalog as {gen_id}.'
    assert payload.get('import_summary', {}).get('installed_generator_count') == 1
    assert payload.get('installed_as', {}).get('pack_label') == 'downloaded-generator-repo'
    assert payload.get('installed_as', {}).get('origin') == 'folder-upload'
    installed_manifest = next(install_root.rglob('manifest.yaml'))
    assert (installed_manifest.parent / 'docker-compose.yml').is_file()
    assert (installed_manifest.parent / 'generator.py').is_file()


def test_generator_repository_zip_resolves_repo_root_source_path(tmp_path, monkeypatch):
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))

    gen_id = 'github_zip_generator'
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: GitHub ZIP Generator
source_path: runtime/generator
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
artifacts:
  produces: [File(path)]
"""
    compose = """services:
  generator:
    image: python:3.11-slim
"""
    zip_bytes = _make_zip({
        'generator-repo-main/catalog/generator/manifest.yaml': manifest,
        'generator-repo-main/runtime/generator/docker-compose.yml': compose,
        'generator-repo-main/runtime/generator/generator.py': 'print("ok")\n',
    })

    client = app.test_client()
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (200, 302)
    response = client.post(
        '/generator_packs/upload',
        data={'zip_file': (io.BytesIO(zip_bytes), 'generator-repo-main.zip')},
        content_type='multipart/form-data',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
    )

    assert response.status_code == 200
    assert response.get_json()['confirmation_text'] == f'Added to catalog as {gen_id}.'
    installed_manifest = next(install_root.rglob('manifest.yaml'))
    assert (installed_manifest.parent / 'docker-compose.yml').is_file()


def test_generator_repository_folder_upload_rejects_unsafe_relative_path(tmp_path, monkeypatch):
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))

    client = app.test_client()
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (200, 302)
    response = client.post(
        '/generator_packs/upload',
        data=MultiDict([
            ('repo_label', 'unsafe-repo'),
            ('repo_paths', 'unsafe-repo/../manifest.yaml'),
            ('repo_files', (io.BytesIO(b'manifest_version: 1\n'), 'manifest.yaml')),
        ]),
        content_type='multipart/form-data',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
    )

    assert response.status_code == 400
    assert 'unsafe path' in response.get_json()['error']
    assert not list(install_root.rglob('manifest.yaml'))


def test_generator_pack_import_url_xhr_returns_confirmation_payload(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_import_url_xhr"
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: \"Pack Test: Import URL XHR\"
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
    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""
    zip_bytes = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": "print('hi')\n",
        }
    )
    monkeypatch.setattr(app_backend, "_download_zip_from_url", lambda url: zip_bytes)

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/import_url",
        data={"zip_url": "https://example.com/packs/demo.zip"},
        headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"},
    )

    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get("ok") is True
    assert payload.get("confirmation_text") == f"Added to catalog as {gen_id}."
    assert payload.get("import_summary", {}).get("installed_generator_count") == 1
    assert payload.get("installed_as", {}).get("origin") == "url"
    assert payload.get("installed_as", {}).get("grouped") == [
        {"kind": "flag-generator", "count": 1, "ids": [gen_id]}
    ]


def test_generator_pack_uninstall_removes_generators(tmp_path, monkeypatch):
    # Uninstall removes the CORE runtime copy over SSH before touching local
    # files, and aborts if that fails. There is no CORE VM in a test run, so
    # without this the delete is refused and nothing is removed. These tests
    # are about local pack removal, so the remote step is stubbed as done.
    monkeypatch.setattr(
        app_backend, "_cleanup_remote_generator_pack",
        lambda pack: (True, "remote cleanup stubbed in tests"),
    )
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_uninstall"

    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: \"Pack Test: Uninstall\"
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

    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""

    zip_bytes = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": "print('hi')\n",
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(zip_bytes), "pack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    packs_state = app_backend._load_installed_generator_packs_state()
    packs = packs_state.get("packs") or []
    assert isinstance(packs, list) and packs
    pack_id = packs[-1].get("id")
    assert pack_id

    installed = packs[-1].get("installed") or []
    assert installed and isinstance(installed, list)
    installed_path = installed[0].get("path")
    assert installed_path and os.path.exists(installed_path)

    del_resp = client.post(f"/generator_packs/delete/{pack_id}", follow_redirects=False)
    assert del_resp.status_code in (302, 303)
    assert not os.path.exists(installed_path)

    data_resp = client.get("/flag_generators_data")
    assert data_resp.status_code == 200
    data = data_resp.get_json() or {}
    ids = {g.get("id") for g in (data.get("generators") or []) if isinstance(g, dict)}
    assert gen_id not in ids


def test_generator_pack_uninstall_ajax_returns_success_and_removes_pack(tmp_path, monkeypatch):
    install_root = tmp_path / 'installed_generators'
    installed_path = install_root / 'flag_generators' / 'p_demo__1'
    installed_path.mkdir(parents=True)
    state = {
        'packs': [{
            'id': 'pack-demo',
            'label': 'Demo Pack',
            'installed': [{'id': '1', 'kind': 'flag-generator', 'path': str(installed_path)}],
        }],
    }
    saved = {}
    monkeypatch.setattr(app_backend, '_installed_generators_root', lambda: str(install_root))
    monkeypatch.setattr(app_backend, '_load_installed_generator_packs_state', lambda: state)
    monkeypatch.setattr(app_backend, '_save_installed_generator_packs_state', lambda value: saved.update(value))
    monkeypatch.setattr(app_backend, '_cleanup_remote_generator_pack', lambda pack: (True, 'remote copy removed'))

    client = app.test_client()
    client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    response = client.post(
        '/generator_packs/delete/pack-demo',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['ok'] is True
    assert payload['pack_id'] == 'pack-demo'
    assert payload['removed'] == 1
    assert payload['remote_cleanup'] == 'remote copy removed'
    assert saved['packs'] == []
    assert not installed_path.exists()


def test_generator_pack_uninstall_ajax_explains_remote_cleanup_failure(tmp_path, monkeypatch):
    install_root = tmp_path / 'installed_generators'
    installed_path = install_root / 'flag_generators' / 'p_demo__1'
    installed_path.mkdir(parents=True)
    state = {
        'packs': [{
            'id': 'pack-demo',
            'label': 'Demo Pack',
            'installed': [{'id': '1', 'kind': 'flag-generator', 'path': str(installed_path)}],
        }],
    }
    monkeypatch.setattr(app_backend, '_installed_generators_root', lambda: str(install_root))
    monkeypatch.setattr(app_backend, '_load_installed_generator_packs_state', lambda: state)
    monkeypatch.setattr(
        app_backend,
        '_save_installed_generator_packs_state',
        lambda value: (_ for _ in ()).throw(AssertionError('state must not change')),
    )
    monkeypatch.setattr(app_backend, '_cleanup_remote_generator_pack', lambda pack: (False, 'CORE VM unavailable'))

    client = app.test_client()
    client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    response = client.post(
        '/generator_packs/delete/pack-demo',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
    )

    assert response.status_code == 409
    assert response.get_json() == {
        'ok': False,
        'message': 'Uninstall aborted: failed removing the CORE runtime copy: CORE VM unavailable',
        'pack_id': 'pack-demo',
        'stage': 'remote_cleanup',
    }
    assert installed_path.exists()


def test_delete_installed_generator_by_source_id_removes_imported_generator(tmp_path, monkeypatch):
        install_root = tmp_path / "installed_generators"
        monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

        gen_id = "pack_test_delete_by_source_id"
        manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: "Pack Test: Delete By Source ID"
runtime:
    type: docker-compose
    compose_file: docker-compose.yml
    service: generator
inputs: []
artifacts:
    requires: []
    produces:
        - Flag(flag_id)
injects: []
"""
        compose = """services:
    generator:
        image: python:3.11-slim
        command: ["python", "-c", "print('ok')"]
"""
        zip_bytes = _make_zip(
                {
                        f"flag_generators/{gen_id}/manifest.yaml": manifest,
                        f"flag_generators/{gen_id}/docker-compose.yml": compose,
                        f"flag_generators/{gen_id}/generator.py": "print('hi')\n",
                }
        )

        client = app.test_client()
        login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login_resp.status_code in (200, 302)

        upload_resp = client.post(
                "/generator_packs/upload",
                data={"zip_file": (io.BytesIO(zip_bytes), "pack.zip")},
                content_type="multipart/form-data",
                follow_redirects=False,
        )
        assert upload_resp.status_code in (302, 303)

        data_resp = client.get("/flag_generators_data")
        data = data_resp.get_json() or {}
        assert gen_id in {g.get("id") for g in (data.get("generators") or []) if isinstance(g, dict)}

        delete_resp = client.post("/api/flag_generators/delete", json={"generator_id": gen_id})
        assert delete_resp.status_code == 200

        data_resp = client.get("/flag_generators_data")
        data = data_resp.get_json() or {}
        assert gen_id not in {g.get("id") for g in (data.get("generators") or []) if isinstance(g, dict)}
        assert not any((install_root / "flag_generators").iterdir())


def test_generator_pack_download_zip_contains_manifest(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_download"
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: \"Pack Test: Download\"
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
    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""

    zip_bytes = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": "print('hi')\n",
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(zip_bytes), "pack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    packs_state = app_backend._load_installed_generator_packs_state()
    packs = packs_state.get("packs") or []
    assert packs and isinstance(packs, list)
    pack_id = packs[-1].get("id")
    assert pack_id

    dl = client.get(f"/generator_packs/download/{pack_id}")
    assert dl.status_code == 200
    assert dl.data[:2] == b"PK"

    z = zipfile.ZipFile(io.BytesIO(dl.data), "r")
    names = set(z.namelist())
    # Archive structure is normalized to flag_generators/<installed_dir>/manifest.yaml
    assert any(n.endswith("/manifest.yaml") and n.startswith("flag_generators/") for n in names)


def test_generator_pack_zip_upload_rejects_missing_manifest(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    zip_bytes = _make_zip(
        {
            "flag_generators/bad_one/docker-compose.yml": "version: '3.8'\nservices: {generator: {image: busybox}}\n",
            "flag_generators/bad_one/generator.py": "print('hi')\n",
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(zip_bytes), "badpack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    # No installed generators directory should be created beyond the root.
    # (The root is created, but no kind subdir should exist.)
    assert not (install_root / "flag_generators").exists()


def test_generator_pack_upload_rejects_vulnerability_catalog_bundle_with_clear_error(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    vuln_catalog_zip = _make_zip({"vuln-demo/docker-compose.yml": "services: {}\n"})
    bundle_zip = _make_zip(
        {
            "catalogs/vuln-demo.zip": vuln_catalog_zip,
            "catalogs.json": '{"catalogs":[{"archive":"catalogs/vuln-demo.zip","label":"Vuln Demo"}]}\n',
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(bundle_zip), "vulnerability_catalog.zip")},
        content_type="multipart/form-data",
        headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"},
    )

    assert resp.status_code == 400
    payload = resp.get_json() or {}
    assert "Vulnerability Catalog export" in payload.get("error", "")
    state = app_backend._load_installed_generator_packs_state()
    assert state.get("packs") in (None, [])


def test_generator_pack_export_all_is_zip_of_zips(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_export_all"
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: \"Pack Test: Export All\"
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
    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""

    zip_bytes = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": "print('hi')\n",
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(zip_bytes), "pack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    packs_state = app_backend._load_installed_generator_packs_state()
    packs = packs_state.get("packs") or []
    assert packs and isinstance(packs, list)
    pack = packs[-1]
    pack_id = pack.get("id")
    assert pack_id
    saved_note, _message = app_backend._set_generator_note_state(
        kind='flag-generator',
        generator_id=gen_id,
        note='',
        note_color='green',
    )
    assert saved_note is True
    label = secure_filename(str(pack.get("label") or "")).strip() or "pack"
    expected_inner = f"packs/{pack_id}-{label}.zip"

    all_dl = client.get("/generator_packs/export_all?download_token=test-token")
    assert all_dl.status_code == 200
    assert all_dl.data[:2] == b"PK"
    assert "coretg_catalog_download_token=test-token" in all_dl.headers.get("Set-Cookie", "")

    outer = zipfile.ZipFile(io.BytesIO(all_dl.data), "r")
    outer_names = set(outer.namelist())
    assert expected_inner in outer_names

    inner_bytes = outer.read(expected_inner)
    assert inner_bytes[:2] == b"PK"
    inner = zipfile.ZipFile(io.BytesIO(inner_bytes), "r")
    inner_names = set(inner.namelist())
    assert "pack.json" in inner_names
    assert any(n.endswith("/manifest.yaml") and n.startswith("flag_generators/") for n in inner_names)
    export_metadata = __import__('json').loads(inner.read('pack.json').decode('utf-8'))
    assert export_metadata['catalog_notes'] == [{
        'kind': 'flag-generator',
        'generator_id': str((pack.get('installed') or [{}])[0]['id']),
        'note': '',
        'note_color': 'green',
    }]


def test_generator_pack_export_all_without_installed_packs_is_empty_bundle(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    all_dl = client.get("/generator_packs/export_all")

    assert all_dl.status_code == 200
    outer = zipfile.ZipFile(io.BytesIO(all_dl.data), "r")
    assert set(outer.namelist()) == set()


def test_generator_import_and_export_preserve_original_categories(tmp_path, monkeypatch):
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))

    def manifest(generator_id: str, kind: str) -> str:
        return f"""manifest_version: 1
id: {generator_id}
kind: {kind}
name: {generator_id}
runtime: {{type: docker-compose, compose_file: docker-compose.yml, service: generator}}
artifacts: {{produces: [Flag(flag_id)]}}
"""

    compose = """services:
  generator:
    image: python:3.11-slim
"""
    archive = _make_zip({
        'download-main/flag_generators/encoding/text_demo/manifest.yaml': manifest('text_demo', 'flag-generator'),
        'download-main/flag_generators/encoding/text_demo/docker-compose.yml': compose,
        'download-main/flag_node_generators/network/http/http_demo/manifest.yaml': manifest('http_demo', 'flag-node-generator'),
        'download-main/flag_node_generators/network/http/http_demo/docker-compose.yml': compose,
    })

    client = app.test_client()
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (200, 302)
    response = client.post(
        '/generator_packs/upload',
        data={'zip_file': (io.BytesIO(archive), 'download-main.zip')},
        content_type='multipart/form-data',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
    )
    assert response.status_code == 200

    state = app_backend._load_installed_generator_packs_state()
    pack = (state.get('packs') or [])[0]
    installed = {app_backend._installed_generator_marker_source_id(item): item for item in pack['installed']}
    assert installed['text_demo']['category'] == 'encoding'
    assert installed['http_demo']['category'] == 'network/http'
    assert Path(installed['text_demo']['path']).parent == install_root / 'flag_generators' / 'encoding'
    assert Path(installed['http_demo']['path']).parent == install_root / 'flag_node_generators' / 'network' / 'http'

    generator_payload = client.get('/flag_generators_data').get_json() or {}
    generator_view = next(item for item in generator_payload.get('generators') or [] if item.get('id') == 'text_demo')
    assert generator_view['_category'] == 'encoding'
    assert generator_view['_source_name'] == 'encoding'
    node_payload = client.get('/flag_node_generators_data').get_json() or {}
    node_view = next(item for item in node_payload.get('generators') or [] if item.get('id') == 'http_demo')
    assert node_view['_category'] == 'network/http'
    assert node_view['_source_name'] == 'network/http'

    exported = app_backend._pack_to_zip_bytes(pack)
    with zipfile.ZipFile(io.BytesIO(exported), 'r') as exported_zip:
        names = set(exported_zip.namelist())
        metadata = __import__('json').loads(exported_zip.read('pack.json').decode('utf-8'))
    assert any(name.startswith('flag_generators/encoding/') and name.endswith('/manifest.yaml') for name in names)
    assert any(name.startswith('flag_node_generators/network/http/') and name.endswith('/manifest.yaml') for name in names)
    exported_categories = {item.get('category') for item in metadata.get('installed') or []}
    assert exported_categories == {'encoding', 'network/http'}


def test_repo_local_category_export_does_not_duplicate_category_directory(tmp_path, monkeypatch):
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(tmp_path / 'installed_generators'))
    category_dir = tmp_path / 'source' / 'flag_generators' / 'archives'
    generator_dir = category_dir / 'archive_demo'
    generator_dir.mkdir(parents=True)
    (generator_dir / 'manifest.yaml').write_text('manifest_version: 1\nid: archive_demo\n', encoding='utf-8')

    archive = app_backend._pack_to_zip_bytes({
        'id': 'repo-local:flag_generators:archives',
        'label': 'Archives',
        'repo_local': True,
        'installed': [{
            'id': 'archive_demo',
            'kind': 'flag-generator',
            'category': 'archives',
            'path': str(category_dir),
            'repo_local': True,
        }],
    })

    with zipfile.ZipFile(io.BytesIO(archive), 'r') as exported_zip:
        names = set(exported_zip.namelist())
    assert 'flag_generators/archives/archive_demo/manifest.yaml' in names
    assert not any(name.startswith('flag_generators/archives/archives/') for name in names)


def test_generator_pack_bundle_import_preserves_nested_pack_categories(tmp_path, monkeypatch):
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    source_path_manifest = """manifest_version: 1
id: source_path_archive_demo
kind: flag-generator
name: "Source Path Archive Demo"
source_path: flag_generators/archive/_runtime
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
inputs: []
artifacts:
  requires: []
  produces:
    - Flag(flag_id)
injects: []
"""
    simple_manifest = """manifest_version: 1
id: simple_http_demo
kind: flag-generator
name: "Simple HTTP Demo"
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
inputs: []
artifacts:
  requires: []
  produces:
    - Flag(flag_id)
injects: []
"""
    compose = """services:
  generator:
    image: python:3.11-slim
    command: ["python", "generator.py"]
"""
    source_pack = _make_zip(
        {
            "pack.json": __import__('json').dumps({
                'id': 'repo-local:flag_generators:archive',
                'label': 'Archive',
                'origin': 'flag_generators/archive',
                'catalog_notes': [{
                    'kind': 'flag-generator',
                    'generator_id': 'source_path_archive_demo',
                    'note': 'preserve this note',
                    'note_color': 'red',
                }],
            }) + '\n',
            "flag_generators/archive/_runtime/docker-compose.yml": compose,
            "flag_generators/archive/_runtime/generator.py": "print('archive')\n",
            "flag_generators/archive/source_path_archive_demo/manifest.yaml": source_path_manifest,
        }
    )
    simple_pack = _make_zip(
        {
            "pack.json": '{"id":"repo-local:flag_generators:http","label":"HTTP","origin":"flag_generators/http"}\n',
            "flag_generators/http/simple_http_demo/manifest.yaml": simple_manifest,
            "flag_generators/http/simple_http_demo/docker-compose.yml": compose,
            "flag_generators/http/simple_http_demo/generator.py": "print('http')\n",
        }
    )
    bundle_zip = _make_zip(
        {
            "packs/archive.zip": source_pack,
            "packs/http.zip": simple_pack,
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    resp = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(bundle_zip), "flag_catalog.zip")},
        content_type="multipart/form-data",
        headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"},
    )

    assert resp.status_code == 200
    state = app_backend._load_installed_generator_packs_state()
    packs = state.get("packs") or []
    labels = [pack.get("label") for pack in packs if isinstance(pack, dict)]
    assert labels == ["Archive", "HTTP"]
    assert all(pack.get("label") != "flag_catalog" for pack in packs if isinstance(pack, dict))

    archive_pack = next(pack for pack in packs if pack.get("label") == "Archive")
    archive_installed = archive_pack.get("installed") or []
    archive_path = archive_installed[0].get("path")
    assert archive_path
    assert (Path(archive_path) / "docker-compose.yml").is_file()
    assert (Path(archive_path) / "generator.py").is_file()
    installed_manifest = (Path(archive_path) / "manifest.yaml").read_text(encoding="utf-8")
    assert "source_path:" not in installed_manifest
    assert archive_installed[0]['note'] == 'preserve this note'
    assert archive_installed[0]['note_color'] == 'red'


def test_generator_pack_can_roundtrip_export_all_zip(tmp_path, monkeypatch):
    # Uninstall removes the CORE runtime copy over SSH before touching local
    # files, and aborts if that fails. There is no CORE VM in a test run, so
    # without this the delete is refused and nothing is removed. These tests
    # are about local pack removal, so the remote step is stubbed as done.
    monkeypatch.setattr(
        app_backend, "_cleanup_remote_generator_pack",
        lambda pack: (True, "remote cleanup stubbed in tests"),
    )
    install_root = tmp_path / "installed_generators"
    monkeypatch.setenv("CORETG_INSTALLED_GENERATORS_DIR", str(install_root))

    gen_id = "pack_test_roundtrip"
    manifest = f"""manifest_version: 1
id: {gen_id}
kind: flag-generator
name: \"Pack Test: Roundtrip\"
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
    compose = """version: '3.8'
services:
  generator:
    image: python:3.11-slim
    command: [\"python\", \"-c\", \"print('ok')\"]
"""

    pack_zip = _make_zip(
        {
            f"flag_generators/{gen_id}/manifest.yaml": manifest,
            f"flag_generators/{gen_id}/docker-compose.yml": compose,
            f"flag_generators/{gen_id}/generator.py": "print('hi')\n",
        }
    )

    client = app.test_client()
    login_resp = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
    assert login_resp.status_code in (200, 302)

    up = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(pack_zip), "pack.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert up.status_code in (302, 303)

    # Export bundle
    bundle = client.get("/generator_packs/export_all")
    assert bundle.status_code == 200
    assert bundle.data[:2] == b"PK"

    # Uninstall all currently installed packs (just one for this test)
    state = app_backend._load_installed_generator_packs_state()
    packs = state.get("packs") or []
    assert packs and isinstance(packs, list)
    for p in list(packs):
        pid = p.get("id")
        assert pid
        d = client.post(f"/generator_packs/delete/{pid}", follow_redirects=False)
        assert d.status_code in (302, 303)

    # Ensure generator no longer discoverable
    data_resp = client.get("/flag_generators_data")
    assert data_resp.status_code == 200
    data = data_resp.get_json() or {}
    ids = {g.get("id") for g in (data.get("generators") or []) if isinstance(g, dict)}
    assert gen_id not in ids

    # Re-import from the export-all zip bundle
    restore = client.post(
        "/generator_packs/upload",
        data={"zip_file": (io.BytesIO(bundle.data), "generator_packs.zip")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert restore.status_code in (302, 303)

    # Generator should be back
    data_resp2 = client.get("/flag_generators_data")
    assert data_resp2.status_code == 200
    data2 = data_resp2.get_json() or {}
    ids2 = {g.get("id") for g in (data2.get("generators") or []) if isinstance(g, dict)}
    assert gen_id in ids2


def _repo_generator_entries(label, kind_dir, category, gid, kind='flag-generator'):
    manifest = f"""manifest_version: 1
id: {gid}
kind: {kind}
name: {gid}
source_path: {gid}
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
artifacts:
  produces: [File(path)]
"""
    compose = "services:\n  generator:\n    image: nginx:alpine\n"
    base = f'{label}/{kind_dir}/{category}/{gid}'
    return [
        (f'{base}/manifest.yaml', manifest, 'manifest.yaml'),
        (f'{base}/docker-compose.yml', compose, 'docker-compose.yml'),
    ]


def _post_repo_folder(entries, label, client):
    items = [('repo_label', label)]
    for path, content, name in entries:
        items.append(('repo_paths', path))
        items.append(('repo_files', (io.BytesIO(content.encode()), name)))
    return client.post(
        '/generator_packs/upload',
        data=MultiDict(items),
        content_type='multipart/form-data',
        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
    )


@pytest.mark.parametrize('kind_dir', ['flag_generators', 'flag-generators', 'Flag Generators'])
def test_repository_categories_survive_however_the_kind_dir_is_spelled(kind_dir, tmp_path, monkeypatch):
    """A downloaded repo spells its kind directory however it likes. Failing to
    recognise it flattened every category into one undifferentiated pack."""
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))

    label = 'generators-repo'
    entries = []
    for category, gid in [('archives', 'arch_gen'), ('binary-generators', 'bin_gen')]:
        entries += _repo_generator_entries(label, kind_dir, category, gid)

    client = app.test_client()
    client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    resp = _post_repo_folder(entries, label, client)
    assert resp.status_code == 200, (resp.get_json() or {}).get('error')

    installed = sorted(
        str(p.relative_to(install_root).parent.parent) for p in install_root.rglob('manifest.yaml')
    )
    assert installed == ['flag_generators/archives', 'flag_generators/binary-generators']


def test_import_does_not_scan_image_architectures(tmp_path, monkeypatch):
    """Resolving an unpulled image costs a registry round trip per image, which
    turned an ~80-generator import into minutes of dead time in the request."""
    from scenarioforge.utils import image_architectures as ia

    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))
    ia.clear_image_architecture_cache()
    monkeypatch.setattr(
        ia, '_run',
        lambda *_a, **_k: pytest.fail('import must not shell out to docker to scan architectures'),
    )

    label = 'generators-repo'
    entries = _repo_generator_entries(label, 'flag-generators', 'archives', 'scan_gen')

    client = app.test_client()
    client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    resp = _post_repo_folder(entries, label, client)
    assert resp.status_code == 200, (resp.get_json() or {}).get('error')

    state = app_backend._load_installed_generator_packs_state()
    installed_items = [
        item
        for pack in (state.get('packs') or [])
        for item in (pack.get('installed') or [])
    ]
    assert installed_items
    assert all(item.get('architecture_source') == 'unscanned' for item in installed_items)
