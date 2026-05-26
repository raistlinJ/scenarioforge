import io
import os
import zipfile
from pathlib import Path

from webapp.app_backend import app
import webapp.app_backend as app_backend
from werkzeug.utils import secure_filename


def _make_zip(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, content in files.items():
            z.writestr(path, content)
    buf.seek(0)
    return buf.read()


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
    assert payload.get("installed_as", {}).get("pack_label") == "pack-xhr"
    assert payload.get("installed_as", {}).get("grouped") == [
        {"kind": "flag-generator", "count": 1, "ids": [gen_id]}
    ]


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
    assert payload.get("installed_as", {}).get("origin") == "url"
    assert payload.get("installed_as", {}).get("grouped") == [
        {"kind": "flag-generator", "count": 1, "ids": [gen_id]}
    ]


def test_generator_pack_uninstall_removes_generators(tmp_path, monkeypatch):
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
            "pack.json": '{"id":"repo-local:flag_generators:archive","label":"Archive","origin":"flag_generators/archive"}\n',
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


def test_generator_pack_can_roundtrip_export_all_zip(tmp_path, monkeypatch):
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
