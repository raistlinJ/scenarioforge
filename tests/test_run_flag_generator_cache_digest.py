from pathlib import Path

import pytest

from scripts import run_flag_generator as rfg


def _write_manifest(path: Path, *, generator_id: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "manifest.yaml").write_text(
        f"""
manifest_version: 1
id: {generator_id}
kind: flag-generator
name: {generator_id}
runtime: {{type: docker-compose, compose_file: docker-compose.yml, service: generator}}
artifacts:
  produces: [Flag(flag_id)]
""".strip(),
        encoding="utf-8",
    )


def test_find_generator_suppresses_unrelated_manifest_warnings_on_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_manifest(tmp_path / "flag_generators" / "dupe_a", generator_id="dupe")
    _write_manifest(tmp_path / "flag_generators" / "dupe_b", generator_id="dupe")
    _write_manifest(tmp_path / "flag_generators" / "target", generator_id="target")

    gen, manifest_path = rfg.find_generator(tmp_path, "flag-generator", "target")

    assert gen["id"] == "target"
    assert manifest_path.name == "manifest.yaml"
    assert capsys.readouterr().out == ""


def test_find_generator_prints_manifest_warning_details_on_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_manifest(tmp_path / "flag_generators" / "dupe_a", generator_id="dupe")
    _write_manifest(tmp_path / "flag_generators" / "dupe_b", generator_id="dupe")

    with pytest.raises(SystemExit):
        rfg.find_generator(tmp_path, "flag-generator", "missing")

    stdout = capsys.readouterr().out
    assert "[manifest] warnings while looking up missing:" in stdout
    assert "[manifest] warning:" in stdout
    assert "duplicate generator id: dupe" in stdout
    assert "[manifest] warnings: 1" not in stdout


def test_source_cache_digest_tracks_generator_source_and_ignores_transient_compose(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM python:3.11-slim\nCOPY generator.py /app/generator.py\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("services:\n  generator:\n    build: .\n", encoding="utf-8")
    generator_path = tmp_path / "generator.py"
    generator_path.write_text("print('old')\n", encoding="utf-8")

    initial = rfg._source_cache_digest(tmp_path)
    (tmp_path / "docker-compose.hostnet.123.yml").write_text("transient\n", encoding="utf-8")
    assert rfg._source_cache_digest(tmp_path) == initial

    generator_path.write_text("print('new')\n", encoding="utf-8")
    assert rfg._source_cache_digest(tmp_path) != initial