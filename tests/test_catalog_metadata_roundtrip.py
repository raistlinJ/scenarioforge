"""Catalog exports must carry everything an import cannot work out for itself.

Architecture is the reason this matters most: an air-gapped CORE host has no
registry to ask, so without carrying the scanned values in the export it could
never tell an amd64-only item (which only runs there under emulation, where
heavy applications segfault mid-boot) from one nobody has scanned yet.

The operator's own curation has to survive the trip too -- an enable/disable
decision and a note are work that should not evaporate on reinstall.
"""

from __future__ import annotations

import io
import json
import os
import zipfile

import pytest
from flask import Flask

import webapp.app_backend as backend
import webapp.routes.vuln_catalog_pack_files as pack_files


COMPOSE_REL = "vulhub/app/docker-compose.yml"


def _export_zip(catalog: dict, source_zip: str) -> bytes:
    """Run the real export route against a stubbed catalog."""
    app = Flask(__name__)
    pack_files.register(
        app,
        require_builder_or_admin=lambda: None,
        vuln_catalog_pack_zip_path=lambda _cid: source_zip,
        vuln_catalog_pack_content_dir=lambda _cid: "/tmp/unused",
        safe_path_under=lambda a, b: os.path.join(a, b),
        load_vuln_catalogs_state=lambda: {"catalogs": [catalog]},
        normalize_vuln_catalog_items=backend._normalize_vuln_catalog_items,
        os_module=os,
    )
    with app.test_client() as client:
        response = client.get(f"/vuln_catalog_packs/download/{catalog['id']}")
        assert response.status_code == 200, response.status_code
        return response.data


@pytest.fixture
def source_zip(tmp_path):
    path = tmp_path / "catalog.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(COMPOSE_REL, "services:\n  web:\n    image: nginx:1\n")
    return str(path)


@pytest.fixture
def curated_catalog():
    return {
        "id": "c1",
        "compose_items": [{
            "id": 1,
            "name": "app",
            "compose_rel": COMPOSE_REL,
            "category": "web/proxy",
            "note": "hand-checked",
            "note_color": "green",
            "architectures": ["amd64"],
            "architecture_source": "registry",
            "architecture_unresolved": ["some/other:img"],
            "disabled": True,
            "disabled_by_operator": True,
            "disabled_by_catalog": False,
            "persistent": True,
            "validated_ok": True,
            "validated_incomplete": False,
            "validated_at": "2026-08-12T00:00:00Z",
            "validation_source": "scenarioforge-dataset@7373958",
            "disabled_reason": "operator chose to retain but disable this recipe",
        }],
    }


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #

def test_export_carries_architecture_and_curation(curated_catalog, source_zip):
    data = _export_zip(curated_catalog, source_zip)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        doc = json.loads(z.read(".scenarioforge/catalog_items.json"))
    entry = doc["items"][0]
    assert entry["compose_rel"] == COMPOSE_REL
    assert entry["architectures"] == ["amd64"]
    assert entry["architecture_source"] == "registry"
    assert entry["architecture_unresolved"] == ["some/other:img"]
    assert entry["disabled"] is True
    assert entry["disabled_by_operator"] is True
    assert entry["disabled_by_catalog"] is False
    assert entry["persistent"] is True
    assert entry["validated_ok"] is True
    assert entry["validated_incomplete"] is False
    assert entry["validated_at"] == "2026-08-12T00:00:00Z"
    assert entry["validation_source"] == "scenarioforge-dataset@7373958"
    assert entry["disabled_reason"] == "operator chose to retain but disable this recipe"


def test_export_still_carries_notes_and_layout(curated_catalog, source_zip):
    # The pre-existing metadata files must not regress.
    data = _export_zip(curated_catalog, source_zip)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        notes = json.loads(z.read(".scenarioforge/catalog_notes.json"))["notes"]
        layout = json.loads(z.read(".scenarioforge/catalog_layout.json"))["items"]
    assert notes[0]["note"] == "hand-checked"
    assert notes[0]["note_color"] == "green"
    assert layout[0]["category"] == "web/proxy"


def test_export_keeps_the_original_catalog_content(curated_catalog, source_zip):
    data = _export_zip(curated_catalog, source_zip)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert COMPOSE_REL in z.namelist(), "the catalog's own content must be untouched"


def test_export_is_idempotent_and_does_not_nest_metadata(curated_catalog, tmp_path, source_zip):
    # Exporting an already-exported ZIP must replace its metadata, not stack
    # duplicate copies of it.
    first = _export_zip(curated_catalog, source_zip)
    again_path = tmp_path / "again.zip"
    again_path.write_bytes(first)
    second = _export_zip(curated_catalog, str(again_path))
    with zipfile.ZipFile(io.BytesIO(second)) as z:
        names = z.namelist()
    assert names.count(".scenarioforge/catalog_items.json") == 1
    assert names.count(".scenarioforge/catalog_notes.json") == 1


def test_export_omits_entries_that_say_nothing(source_zip):
    bare = {"id": "c1", "compose_items": [
        {"id": 1, "name": "app", "compose_rel": COMPOSE_REL},
    ]}
    data = _export_zip(bare, source_zip)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        doc = json.loads(z.read(".scenarioforge/catalog_items.json"))
    # `disabled` normalizes to False for every item, which is still a real
    # statement; what must not appear is architecture data nobody has.
    for entry in doc["items"]:
        assert "architectures" not in entry


# --------------------------------------------------------------------------- #
# Import
# --------------------------------------------------------------------------- #

def _install(tmp_path, monkeypatch, *, items_metadata, arch_scan="0"):
    zip_path = tmp_path / "import.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr(COMPOSE_REL, "services:\n  web:\n    image: nginx:1\n")
        if items_metadata is not None:
            z.writestr(".scenarioforge/catalog_items.json",
                       json.dumps({"version": 1, "items": items_metadata}))
    monkeypatch.setattr(backend, "_outputs_dir", lambda: str(tmp_path / "outputs"))
    # Off by default here so a restored value is provably the imported one
    # rather than a fresh scan of this machine.
    monkeypatch.setenv("CORETG_CATALOG_ARCH_SCAN", arch_scan)
    backend._install_vuln_catalog_zip_file_single(
        zip_file_path=str(zip_path), label="roundtrip.zip", origin="test")
    state = backend._load_vuln_catalogs_state()
    return backend._normalize_vuln_catalog_items(state["catalogs"][-1])[0]


def test_import_restores_architecture_without_rescanning(tmp_path, monkeypatch):
    # The air-gapped case: no registry reachable, and the scan disabled outright.
    item = _install(tmp_path, monkeypatch, items_metadata=[{
        "compose_rel": COMPOSE_REL,
        "architectures": ["amd64"],
        "architecture_source": "registry",
        "architecture_unresolved": ["some/other:img"],
    }])
    assert item["architectures"] == ["amd64"]
    assert item["architecture_source"] == "registry"
    assert item["architecture_unresolved"] == ["some/other:img"]


def test_import_restores_operator_disable(tmp_path, monkeypatch):
    item = _install(tmp_path, monkeypatch, items_metadata=[{
        "compose_rel": COMPOSE_REL, "disabled": True, "disabled_by_operator": True,
    }])
    assert item["disabled"] is True
    assert item["disabled_by_operator"] is True


def test_import_applies_validation_defaults_and_item_exceptions(tmp_path, monkeypatch):
    item = _install(tmp_path, monkeypatch, items_metadata=[], arch_scan="0")
    assert item.get("validated_ok") is None

    zip_path = tmp_path / "defaults.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr(COMPOSE_REL, "services:\n  web:\n    image: nginx:1\n")
        z.writestr(
            ".scenarioforge/catalog_items.json",
            json.dumps({
                "version": 1,
                "defaults": {
                    "validated_ok": True,
                    "validated_incomplete": False,
                    "validation_source": "dataset-and-paper",
                },
                "items": [{
                    "compose_rel": COMPOSE_REL,
                    "disabled": True,
                    "disabled_by_catalog": True,
                    "validated_ok": None,
                    "disabled_reason": "not in the validated research catalog",
                }],
            }),
        )
    monkeypatch.setattr(backend, "_outputs_dir", lambda: str(tmp_path / "default-outputs"))
    monkeypatch.setenv("CORETG_CATALOG_ARCH_SCAN", "0")
    backend._install_vuln_catalog_zip_file_single(
        zip_file_path=str(zip_path), label="defaults.zip", origin="test"
    )
    state = backend._load_vuln_catalogs_state()
    restored = backend._normalize_vuln_catalog_items(state["catalogs"][-1])[0]
    assert restored["disabled"] is True
    assert restored["disabled_by_catalog"] is True
    assert restored["validated_ok"] is None
    assert restored["validated_incomplete"] is False
    assert restored["validation_source"] == "dataset-and-paper"
    assert restored["disabled_reason"] == "not in the validated research catalog"


def test_import_pins_new_items_persistent_by_default(tmp_path, monkeypatch):
    # `persistent` is what keeps a cached image alive through Clear Cache and
    # the cleanup routines. Importing a catalog and then pulling its images is
    # one workflow, so the pin comes with the import rather than needing a
    # second pass over every item.
    item = _install(tmp_path, monkeypatch, items_metadata=None)
    assert item["persistent"] is True


def test_import_keeps_an_exported_item_unpinned(tmp_path, monkeypatch):
    # The default must not overrule curation carried by an export: an item
    # deliberately left unpinned elsewhere stays unpinned on reinstall.
    item = _install(tmp_path, monkeypatch, items_metadata=[{
        "compose_rel": COMPOSE_REL, "persistent": False,
    }])
    assert item["persistent"] is False


def test_import_restores_persistent_pin(tmp_path, monkeypatch):
    item = _install(tmp_path, monkeypatch, items_metadata=[{
        "compose_rel": COMPOSE_REL, "persistent": True,
    }])
    assert item["persistent"] is True


def test_an_imported_enable_cannot_override_this_hosts_own_finding(tmp_path, monkeypatch):
    # A catalog curated elsewhere cannot vouch for files or a build network on
    # THIS host, so a local auto-disable must still win. Otherwise an import
    # could re-enable an item that genuinely cannot run here.
    zip_path = tmp_path / "import.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        # `pip install` in the Dockerfile => needs build-time internet.
        z.writestr(COMPOSE_REL, "services:\n  web:\n    build: .\n")
        z.writestr("vulhub/app/Dockerfile", "FROM python:3.11\nRUN pip install django\n")
        z.writestr(".scenarioforge/catalog_items.json", json.dumps({"version": 1, "items": [
            {"compose_rel": COMPOSE_REL, "disabled": False, "disabled_by_operator": False}]}))
    monkeypatch.setattr(backend, "_outputs_dir", lambda: str(tmp_path / "outputs"))
    monkeypatch.setenv("CORETG_CATALOG_ARCH_SCAN", "0")
    backend._install_vuln_catalog_zip_file_single(
        zip_file_path=str(zip_path), label="x.zip", origin="test")
    state = backend._load_vuln_catalogs_state()
    item = backend._normalize_vuln_catalog_items(state["catalogs"][-1])[0]
    assert item["requires_build_network"] is True
    assert item["disabled"] is True, "a local finding must not be overridden by an imported enable"


def test_import_without_the_metadata_file_still_works(tmp_path, monkeypatch):
    # Catalogs exported before this metadata existed must keep importing.
    item = _install(tmp_path, monkeypatch, items_metadata=None)
    assert item["name"]
    assert item["architectures"] == []
    assert item["architecture_source"] == "unscanned"


def test_malformed_item_metadata_is_rejected_clearly(tmp_path, monkeypatch):
    zip_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr(COMPOSE_REL, "services:\n  web:\n    image: nginx:1\n")
        z.writestr(".scenarioforge/catalog_items.json", "{ not json")
    monkeypatch.setattr(backend, "_outputs_dir", lambda: str(tmp_path / "outputs"))
    with pytest.raises(ValueError, match="catalog item metadata"):
        backend._install_vuln_catalog_zip_file_single(
            zip_file_path=str(zip_path), label="bad.zip", origin="test")


def test_import_ignores_path_traversal_in_item_metadata(tmp_path, monkeypatch):
    item = _install(tmp_path, monkeypatch, items_metadata=[
        {"compose_rel": "../../escape/docker-compose.yml", "architectures": ["amd64"]},
        {"compose_rel": COMPOSE_REL, "architectures": ["arm64"]},
    ])
    # The traversal entry must not have been applied to anything.
    assert item["architectures"] == ["arm64"]


# --------------------------------------------------------------------------- #
# Full circle
# --------------------------------------------------------------------------- #

def test_export_then_import_preserves_everything(tmp_path, monkeypatch, curated_catalog, source_zip):
    exported = _export_zip(curated_catalog, source_zip)
    round_trip = tmp_path / "roundtrip.zip"
    round_trip.write_bytes(exported)

    monkeypatch.setattr(backend, "_outputs_dir", lambda: str(tmp_path / "outputs"))
    monkeypatch.setenv("CORETG_CATALOG_ARCH_SCAN", "0")
    backend._install_vuln_catalog_zip_file_single(
        zip_file_path=str(round_trip), label="roundtrip.zip", origin="test")

    state = backend._load_vuln_catalogs_state()
    item = backend._normalize_vuln_catalog_items(state["catalogs"][-1])[0]
    assert item["architectures"] == ["amd64"]
    assert item["architecture_source"] == "registry"
    assert item["architecture_unresolved"] == ["some/other:img"]
    assert item["disabled"] is True
    assert item["disabled_by_operator"] is True
    assert item["disabled_by_catalog"] is False
    assert item["persistent"] is True
    assert item["validated_ok"] is True
    assert item["validated_incomplete"] is False
    assert item["validated_at"] == "2026-08-12T00:00:00Z"
    assert item["validation_source"] == "scenarioforge-dataset@7373958"
    assert item["disabled_reason"] == "operator chose to retain but disable this recipe"
    assert item["note"] == "hand-checked"
    assert item["note_color"] == "green"
    assert item["category"] == "web/proxy"
