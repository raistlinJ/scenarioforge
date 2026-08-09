"""End-to-end: import a multi-scenario bundle, delete one, and refresh.

Regression coverage for a reported bug: after importing a scenario file and
deleting one of its scenarios, refreshing the page brought it back. The
scenario list itself (payload['scenarios'], what the sidebar renders from) was
always pruned correctly; what survived was `result_path` -- still pointing at
the original imported file, which delete never rewrites -- so the "Live XML
preview" pane read the deleted scenario's markup straight back off disk.
"""

import io

from webapp.app_backend import app
from webapp import app_backend as backend


TWO_SCENARIO_XML = b"""<?xml version="1.0"?>
<Scenarios>
<Scenario name="ImportedProj"><ScenarioEditor>
<Section name="Node Information" total_nodes="3"><Item type="PC" count="3"/></Section>
</ScenarioEditor></Scenario>
<Scenario name="KeepMe"><ScenarioEditor>
<Section name="Node Information" total_nodes="2"><Item type="PC" count="2"/></Section>
</ScenarioEditor></Scenario>
</Scenarios>"""


def test_deleted_scenario_does_not_reappear_in_the_xml_preview_after_refresh(tmp_path, monkeypatch):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    monkeypatch.setitem(app.config, "UPLOAD_FOLDER", str(uploads))
    monkeypatch.setattr(backend, "_outputs_dir", lambda: str(outputs))
    monkeypatch.setattr(backend, "_load_run_history", lambda: [])

    with app.test_client() as client:
        login = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login.status_code in (302, 303)

        imported = client.post(
            "/load_xml",
            data={
                "scenarios_xml": (io.BytesIO(TWO_SCENARIO_XML), "imported.xml"),
                "import_progress_id": "p1",
            },
            content_type="multipart/form-data",
        )
        assert imported.status_code == 200
        assert b"ImportedProj" in imported.data

        deleted = client.post("/delete_scenarios", json={"names": ["ImportedProj"]})
        assert deleted.status_code == 200
        assert deleted.get_json()["ok"] is True

        refreshed = client.get("/")
        assert refreshed.status_code == 200
        html = refreshed.data.decode("utf-8", "ignore")
        assert "ImportedProj" not in html, (
            "deleted scenario's XML resurfaced after refresh -- result_path "
            "still names the un-rewritten source file"
        )
        assert "KeepMe" in html


def test_a_single_remaining_scenario_survives_the_same_delete(tmp_path, monkeypatch):
    # The fix must not disturb the ordinary case: one scenario deleted, one
    # kept, and the kept one's own content should still render.
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    monkeypatch.setitem(app.config, "UPLOAD_FOLDER", str(uploads))
    monkeypatch.setattr(backend, "_outputs_dir", lambda: str(outputs))
    monkeypatch.setattr(backend, "_load_run_history", lambda: [])

    with app.test_client() as client:
        client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        client.post(
            "/load_xml",
            data={
                "scenarios_xml": (io.BytesIO(TWO_SCENARIO_XML), "imported.xml"),
                "import_progress_id": "p2",
            },
            content_type="multipart/form-data",
        )
        client.post("/delete_scenarios", json={"names": ["ImportedProj"]})
        refreshed = client.get("/")
        html = refreshed.data.decode("utf-8", "ignore")
        assert 'name="KeepMe"' in html or "KeepMe" in html
