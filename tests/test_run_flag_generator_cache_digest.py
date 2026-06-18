from pathlib import Path
import subprocess
import sys

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


def _write_python_generator(path: Path, *, flag_value: str) -> None:
    (path / "generator.py").write_text(
        f"""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--config')
parser.add_argument('--out-dir')
args = parser.parse_args()
out_dir = Path(args.out_dir)
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'outputs.json').write_text(json.dumps({{'outputs': {{'Flag(flag_id)': '{flag_value}'}}}}) + '\\n', encoding='utf-8')
""".strip()
        + "\n",
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


def test_compose_failure_uses_direct_python_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    source_dir = tmp_path / "flag_generators" / "fallback_gen"
    _write_manifest(source_dir, generator_id="fallback_gen")
    (source_dir / "docker-compose.yml").write_text("services:\n  generator:\n    image: python:3.11-slim\n", encoding="utf-8")
    _write_python_generator(source_dir, flag_value="FLAG{fallback}")

    def _fail_compose(**_kwargs):
        raise subprocess.CalledProcessError(1, ["docker", "compose", "run"], output="docker failed", stderr="pull failed")

    monkeypatch.setattr(rfg, "run_compose", _fail_compose)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_flag_generator.py",
            "--kind",
            "flag-generator",
            "--generator-id",
            "fallback_gen",
            "--out-dir",
            str(tmp_path / "run-out"),
            "--config",
            '{"seed":"s"}',
            "--repo-root",
            str(tmp_path),
        ],
    )

    assert rfg.main() == 0
    stdout = capsys.readouterr().out
    assert "docker compose generator failed; trying direct Python fallback" in stdout
    assert "direct-python-fallback" in stdout
    assert (tmp_path / "run-out" / "outputs.json").is_file()


def test_direct_python_first_skips_compose_when_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    source_dir = tmp_path / "flag_generators" / "direct_first_gen"
    _write_manifest(source_dir, generator_id="direct_first_gen")
    (source_dir / "docker-compose.yml").write_text("services:\n  generator:\n    image: python:3.11-slim\n", encoding="utf-8")
    _write_python_generator(source_dir, flag_value="FLAG{direct-first}")

    def _unexpected_compose(**_kwargs):
        raise AssertionError("compose should not run when direct Python succeeds first")

    monkeypatch.setenv("CORETG_RUN_FLAG_GENERATOR_PY_FIRST", "1")
    monkeypatch.setattr(rfg, "run_compose", _unexpected_compose)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_flag_generator.py",
            "--kind",
            "flag-generator",
            "--generator-id",
            "direct_first_gen",
            "--out-dir",
            str(tmp_path / "run-out"),
            "--config",
            '{"seed":"s"}',
            "--repo-root",
            str(tmp_path),
        ],
    )

    assert rfg.main() == 0
    stdout = capsys.readouterr().out
    assert "direct-python-first" in stdout
    assert (tmp_path / "run-out" / "outputs.json").is_file()


def test_compose_system_exit_uses_direct_python_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    source_dir = tmp_path / "flag_generators" / "timeout_gen"
    _write_manifest(source_dir, generator_id="timeout_gen")
    (source_dir / "docker-compose.yml").write_text("services:\n  generator:\n    image: python:3.11-slim\n", encoding="utf-8")
    _write_python_generator(source_dir, flag_value="FLAG{timeout-fallback}")

    def _timeout_compose(**_kwargs):
        raise SystemExit("docker command timed out after 180s")

    monkeypatch.setattr(rfg, "run_compose", _timeout_compose)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_flag_generator.py",
            "--kind",
            "flag-generator",
            "--generator-id",
            "timeout_gen",
            "--out-dir",
            str(tmp_path / "run-out"),
            "--config",
            '{"seed":"s"}',
            "--repo-root",
            str(tmp_path),
        ],
    )

    assert rfg.main() == 0
    stdout = capsys.readouterr().out
    assert "docker compose generator exited before completion; trying direct Python fallback" in stdout
    assert (tmp_path / "run-out" / "outputs.json").is_file()


def test_cli_main_reports_command_failure_without_traceback(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def _fail_main():
        raise subprocess.CalledProcessError(72, ["docker", "compose", "run"], output="compose stdout", stderr="compose stderr")

    monkeypatch.setattr(rfg, "main", _fail_main)

    assert rfg.cli_main() == 72
    captured = capsys.readouterr()
    assert "[cmd] failed rc=72" in captured.err
    assert "compose stderr" in captured.err
    assert "compose stdout" in captured.err
    assert "Traceback" not in captured.err
