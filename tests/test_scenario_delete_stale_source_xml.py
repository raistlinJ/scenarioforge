"""Deleting a scenario must not leave a stale combined XML as its source.

An imported bundle's XML file backs every scenario it contains. Deleting one of
those scenarios prunes it from the editor snapshot's `scenarios` list (what the
sidebar and the JSON payload render from) but never touches -- and never
should, it lives outside outputs/ -- the file the snapshot's `result_path` and
`project_key_hint` still name. On the next page load, `_index()` reads that
file's raw bytes straight into the "Live XML preview" pane whenever
`result_path` is set, and reuses it as the XML source for Download/Generate,
bypassing the correctly-pruned scenario list entirely. The deleted scenario
therefore came back after a refresh, in the one place delete never looked.
"""

import json

from webapp import app_backend as backend


def _write_snapshot(path, snap):
    path.write_text(json.dumps(snap), encoding="utf-8")


def _xml(*names):
    scenarios = "".join(
        f'<Scenario name="{n}"><ScenarioEditor>'
        f'<Section name="Node Information" total_nodes="1"/>'
        f"</ScenarioEditor></Scenario>"
        for n in names
    )
    return f"<Scenarios>{scenarios}</Scenarios>"


def test_result_path_is_cleared_when_its_file_still_names_the_deleted_scenario(tmp_path, monkeypatch):
    snap_dir = tmp_path / "editor_snapshots"
    snap_dir.mkdir()
    monkeypatch.setattr(backend, "_editor_state_snapshot_dir", lambda: str(snap_dir))

    source_xml = tmp_path / "imported.xml"
    source_xml.write_text(_xml("ImportedProj", "KeepMe"), encoding="utf-8")

    snap_path = snap_dir / "user.json"
    _write_snapshot(snap_path, {
        "scenarios": [{"name": "ImportedProj"}, {"name": "KeepMe"}],
        "result_path": str(source_xml),
        "project_key_hint": str(source_xml),
    })

    result = backend._remove_scenarios_from_all_editor_snapshots(["ImportedProj"])
    assert result["snapshot_scenarios_removed"] == 1

    saved = json.loads(snap_path.read_text(encoding="utf-8"))
    assert [s["name"] for s in saved["scenarios"]] == ["KeepMe"]
    # The whole point: a reload must not be able to read the deleted scenario
    # back out of a source file delete never rewrote.
    assert saved["result_path"] is None
    assert saved["project_key_hint"] is None
    # The uploaded bundle itself is never touched -- it is not ours to rewrite,
    # and other snapshots or a re-import may still need it intact.
    assert "ImportedProj" in source_xml.read_text(encoding="utf-8")


def test_result_path_survives_when_its_file_no_longer_names_the_deleted_scenario(tmp_path, monkeypatch):
    # A snapshot whose source file was already re-saved without the deleted
    # scenario (the normal post-delete autosave) must not be reset needlessly.
    snap_dir = tmp_path / "editor_snapshots"
    snap_dir.mkdir()
    monkeypatch.setattr(backend, "_editor_state_snapshot_dir", lambda: str(snap_dir))

    source_xml = tmp_path / "resaved.xml"
    source_xml.write_text(_xml("KeepMe"), encoding="utf-8")

    snap_path = snap_dir / "user.json"
    _write_snapshot(snap_path, {
        "scenarios": [{"name": "KeepMe"}],
        "result_path": str(source_xml),
        "project_key_hint": str(source_xml),
    })

    result = backend._remove_scenarios_from_all_editor_snapshots(["ImportedProj"])
    assert result["snapshot_scenarios_removed"] == 0

    saved = json.loads(snap_path.read_text(encoding="utf-8"))
    assert saved["result_path"] == str(source_xml)
    assert saved["project_key_hint"] == str(source_xml)


def test_unrelated_snapshot_is_also_cleared_when_it_shares_the_stale_source(tmp_path, monkeypatch):
    # A snapshot whose own `scenarios` list never named the deleted scenario
    # (e.g. it only tracks one of several scenarios an import produced) can
    # still point result_path at the same combined file.
    snap_dir = tmp_path / "editor_snapshots"
    snap_dir.mkdir()
    monkeypatch.setattr(backend, "_editor_state_snapshot_dir", lambda: str(snap_dir))

    source_xml = tmp_path / "imported.xml"
    source_xml.write_text(_xml("ImportedProj", "KeepMe"), encoding="utf-8")

    snap_path = snap_dir / "other-user.json"
    _write_snapshot(snap_path, {
        "scenarios": [{"name": "KeepMe"}],
        "result_path": str(source_xml),
        "project_key_hint": str(source_xml),
    })

    result = backend._remove_scenarios_from_all_editor_snapshots(["ImportedProj"])
    assert result["snapshot_scenarios_removed"] == 0

    saved = json.loads(snap_path.read_text(encoding="utf-8"))
    assert saved["result_path"] is None
    assert saved["project_key_hint"] is None


def test_missing_source_file_does_not_raise(tmp_path, monkeypatch):
    snap_dir = tmp_path / "editor_snapshots"
    snap_dir.mkdir()
    monkeypatch.setattr(backend, "_editor_state_snapshot_dir", lambda: str(snap_dir))

    snap_path = snap_dir / "user.json"
    _write_snapshot(snap_path, {
        "scenarios": [{"name": "ImportedProj"}, {"name": "KeepMe"}],
        "result_path": str(tmp_path / "gone.xml"),
        "project_key_hint": str(tmp_path / "gone.xml"),
    })

    result = backend._remove_scenarios_from_all_editor_snapshots(["ImportedProj"])
    assert result["snapshot_scenarios_removed"] == 1
    saved = json.loads(snap_path.read_text(encoding="utf-8"))
    # A source that no longer exists cannot resurrect anything, so it is left
    # as-is rather than guessed at.
    assert saved["result_path"] == str(tmp_path / "gone.xml")


def test_helper_matches_by_normalized_name_and_by_match_key(tmp_path):
    source_xml = tmp_path / "imported.xml"
    source_xml.write_text(_xml("Imported Proj", "KeepMe"), encoding="utf-8")
    snap = {"result_path": str(source_xml)}
    remove_norms = {backend._normalize_scenario_label("Imported Proj")}
    remove_match = {backend._scenario_match_key("Imported Proj")}
    assert backend._snapshot_source_still_names_a_removed_scenario(snap, remove_norms, remove_match)
    assert not backend._snapshot_source_still_names_a_removed_scenario(snap, {"nope"}, {"nope"})
