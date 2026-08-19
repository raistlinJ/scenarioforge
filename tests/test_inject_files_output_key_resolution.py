import json
from pathlib import Path

import pytest

from scripts import run_flag_generator as rfg


def test_inject_files_can_reference_output_artifact_key(tmp_path: Path):
    out_dir = tmp_path
    (out_dir / "artifacts").mkdir(parents=True, exist_ok=True)

    # Simulate a generator output file.
    (out_dir / "artifacts" / "challenge").write_text("bin", encoding="utf-8")

    (out_dir / "outputs.json").write_text(
        json.dumps({"outputs": {"File(path)": "artifacts/challenge"}}),
        encoding="utf-8",
    )

    expanded = rfg.expand_inject_files_from_outputs(out_dir, ["File(path)"])
    assert expanded == ["artifacts/challenge"]

    injected_dir = rfg._stage_injected_dir(out_dir, expanded)
    assert injected_dir is not None
    assert (injected_dir / "challenge").exists()


def test_absolute_output_dir_paths_fail_instead_of_dropping_the_inject(tmp_path: Path):
    out_dir = tmp_path
    (out_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    (out_dir / "artifacts" / "challenge").write_text("bin", encoding="utf-8")
    (out_dir / "outputs.json").write_text(
        json.dumps({"outputs": {"File(path)": "/outputs/artifacts/challenge"}}),
        encoding="utf-8",
    )

    # Expansion drops the entry, so nothing downstream can notice the artifact is missing.
    assert rfg.expand_inject_files_from_outputs(out_dir, ["File(path)"]) == []

    with pytest.raises(ValueError) as excinfo:
        rfg._validate_inject_output_paths(out_dir, ["File(path)"])
    assert "relative to /outputs" in str(excinfo.value)
    assert "File(path)=/outputs/artifacts/challenge" in str(excinfo.value)


def test_absolute_run_output_dir_paths_are_rejected_too(tmp_path: Path):
    out_dir = tmp_path
    (out_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    (out_dir / "artifacts" / "challenge").write_text("bin", encoding="utf-8")
    (out_dir / "outputs.json").write_text(
        json.dumps({"outputs": {"File(path)": str(out_dir.resolve() / "artifacts" / "challenge")}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        rfg._validate_inject_output_paths(out_dir, ["File(path)"])


def test_relative_and_metadata_absolute_outputs_pass_inject_path_validation(tmp_path: Path):
    out_dir = tmp_path
    (out_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    (out_dir / "artifacts" / "challenge").write_text("bin", encoding="utf-8")
    (out_dir / "outputs.json").write_text(
        json.dumps({"outputs": {
            "File(path)": "artifacts/challenge",
            # Absolute metadata values that are not injectable files stay allowed.
            "Directory(host, path)": "/exports",
        }}),
        encoding="utf-8",
    )

    rfg._validate_inject_output_paths(out_dir, ["File(path)"])
    rfg._validate_inject_output_paths(out_dir, ["Directory(host, path)"])
    rfg._validate_inject_output_paths(out_dir, ["File(path) -> /opt/drop"])
