from pathlib import Path


def test_flow_flag_record_from_host_metadata_flag_node_generator(tmp_path: Path):
    from scenarioforge.builders.topology import _flow_flag_record_from_host_metadata

    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    compose_path = run_dir / "docker-compose.yml"
    compose_path.write_text("services:\n  node:\n    image: alpine:3.19\n", encoding="utf-8")

    hdata = {
        "metadata": {
            "flow_flag": {
                "type": "flag-node-generator",
                "generator_id": "nfs_sensitive_file",
                "generator_name": "Sample: NFS Sensitive File",
                "run_dir": str(run_dir),
                "inject_files": ["workspace"],
                "inject_source_dir": str(run_dir),
                "outputs_manifest": str(run_dir / "outputs.json"),
                "inject_candidate_paths": ["/home/ir/evidence"],
            }
        }
    }
    rec = _flow_flag_record_from_host_metadata(hdata)
    assert isinstance(rec, dict)
    assert rec.get("Type") == "docker-compose"
    assert rec.get("Path") == str(compose_path)
    assert rec.get("InjectFiles") == ["workspace"]
    assert rec.get("InjectSourceDir") == str(run_dir)
    assert rec.get("OutputsManifest") == str(run_dir / "outputs.json")
    assert rec.get("RunDir") == str(run_dir)
    assert rec.get("InjectCandidatePaths") == ["/home/ir/evidence"]


def test_flow_flag_record_from_host_metadata_preserves_all_manifest_injects(tmp_path: Path):
    from scenarioforge.builders.topology import _flow_flag_record_from_host_metadata

    specs: list[tuple[str, list[str], list[str]]] = [
        ("imported_node_with_workspace", ["workspace"], ["/home/ir/evidence"]),
        ("imported_node_with_multiple_injects", ["workspace", "secrets"], ["/opt/challenge", "/var/tmp/drop"]),
    ]

    for generator_id, injects, candidates in specs:
        run_dir = tmp_path / generator_id
        run_dir.mkdir(parents=True, exist_ok=True)
        compose_path = run_dir / "docker-compose.yml"
        compose_path.write_text("services:\n  node:\n    image: alpine:3.19\n", encoding="utf-8")
        outputs_manifest = run_dir / "outputs.json"
        outputs_manifest.write_text('{"outputs": {}}\n', encoding="utf-8")

        hdata = {
            "metadata": {
                "flow_flag": {
                    "type": "flag-node-generator",
                    "generator_id": generator_id,
                    "generator_name": generator_id,
                    "run_dir": str(run_dir),
                    "inject_files": injects,
                    "inject_source_dir": str(run_dir),
                    "outputs_manifest": str(outputs_manifest),
                    "inject_candidate_paths": candidates,
                }
            }
        }

        rec = _flow_flag_record_from_host_metadata(hdata)
        assert isinstance(rec, dict), generator_id
        assert rec.get("Type") == "docker-compose", generator_id
        assert rec.get("Path") == str(compose_path), generator_id
        assert rec.get("InjectFiles") == injects, generator_id
        assert rec.get("InjectSourceDir") == str(run_dir), generator_id
        assert rec.get("OutputsManifest") == str(outputs_manifest), generator_id
        assert rec.get("RunDir") == str(run_dir), generator_id
        assert rec.get("InjectCandidatePaths") == candidates, generator_id
