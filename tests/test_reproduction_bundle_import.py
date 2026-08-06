import hashlib
import json
import xml.etree.ElementTree as ET
import zipfile

import pytest

from webapp.reproduction_bundle import import_scenario_file


def _bundle(tmp_path, *, artifact_bytes=b"FLAG-123\n"):
    source_path = "/tmp/vulns/flag_generators_runs/demo"
    root = ET.Element("Scenarios")
    scenario = ET.SubElement(root, "Scenario", {"name": "portable-demo"})
    sequencing = ET.SubElement(scenario, "FlagSequencing")
    state = ET.SubElement(sequencing, "FlowState")
    state.text = json.dumps(
        {
            "scenario": "portable-demo",
            "chain": [{"id": "7"}],
            "flag_assignments": [
                {
                    "id": "demo-generator",
                    "node_id": "7",
                    "artifacts_dir": source_path,
                    "outputs_manifest": f"{source_path}/outputs.json",
                    "resolved_outputs": {"Flag(flag_id)": "FLAG-123"},
                }
            ],
        }
    )
    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    manifest = {
        "format": "scenarioforge-reproduction",
        "version": 1,
        "fidelity": "portable-artifacts",
        "flow": {"scenario": "portable-demo"},
        "scenario": {
            "path": "scenario.xml",
            "sha256": hashlib.sha256(xml_bytes).hexdigest(),
        },
        "artifact_sources": [
            {
                "source_path": source_path,
                "archive_path": "artifacts/001",
                "bundled": True,
                "files": [
                    {
                        "path": "flag.txt",
                        "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                        "size": len(artifact_bytes),
                        "mode": 0o600,
                    }
                ],
            }
        ],
    }
    bundle = tmp_path / "portable.scenarioforge.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("scenario.xml", xml_bytes)
        archive.writestr("artifacts/001/flag.txt", artifact_bytes)
        archive.writestr("scenarioforge-reproduction.json", json.dumps(manifest))
    return bundle, source_path


def test_import_auto_detects_bundle_restores_artifacts_and_rewrites_xml(tmp_path):
    bundle, source_path = _bundle(tmp_path)
    upload_root = tmp_path / "uploads"

    imported = import_scenario_file(str(bundle), str(upload_root))

    assert imported.kind == "reproduction-bundle"
    assert imported.fidelity == "portable-artifacts"
    assert imported.bundled_artifact_sources == 1
    root = ET.parse(imported.xml_path).getroot()
    flow = json.loads(root.find(".//FlowState").text)
    restored_dir = flow["reproduction_artifact_sources"][0]["restored_path"]
    assert restored_dir.startswith(str(upload_root.resolve()))
    assert open(f"{restored_dir}/flag.txt", "rb").read() == b"FLAG-123\n"
    assert flow["reproduction_artifact_sources"][0]["target_path"] == source_path
    assert flow["flag_assignments"][0]["artifacts_dir"] == source_path
    assert flow["flag_assignments"][0]["outputs_manifest"] == f"{source_path}/outputs.json"


def test_import_auto_detects_plain_xml_regardless_of_extension(tmp_path):
    source = tmp_path / "scenario.data"
    source.write_text('<Scenarios><Scenario name="demo" /></Scenarios>', encoding="utf-8")

    imported = import_scenario_file(str(source), str(tmp_path / "uploads"))

    assert imported.kind == "xml"
    assert imported.xml_path == str(source.resolve())


def test_import_rejects_bundle_path_traversal(tmp_path):
    bundle, _ = _bundle(tmp_path)
    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(unsafe, "w") as target:
        for info in source.infolist():
            target.writestr(info.filename, source.read(info.filename))
        target.writestr("../escape.txt", b"nope")

    with pytest.raises(ValueError, match="unsafe bundle member"):
        import_scenario_file(str(unsafe), str(tmp_path / "uploads"))
