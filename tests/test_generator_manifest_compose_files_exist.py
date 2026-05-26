from __future__ import annotations

from pathlib import Path

import pytest


yaml = pytest.importorskip("yaml")


def _manifest_paths(repo_root: Path) -> list[Path]:
    manifests: list[Path] = []
    for base in ("flag_generators", "flag_node_generators"):
        root = repo_root / base
        if not root.exists():
            continue
        manifests.extend(root.rglob("manifest.yaml"))
        manifests.extend(root.rglob("manifest.yml"))
    return sorted(set(manifests))


def test_compose_required_generator_manifests_have_compose_files() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    missing: list[str] = []

    for manifest_path in _manifest_paths(repo_root):
        doc = yaml.safe_load(manifest_path.read_text("utf-8", errors="ignore"))
        if not isinstance(doc, dict):
            continue
        kind = str(doc.get("kind") or "").strip().lower()
        runtime = doc.get("runtime") if isinstance(doc.get("runtime"), dict) else {}
        runtime_type = str(runtime.get("type") or "docker-compose").strip().lower()
        compose_required = runtime_type in {"docker-compose", "compose"} or kind == "flag-node-generator"
        if not compose_required:
            continue

        source_path = str(
            doc.get("source_path")
            or (doc.get("source", {}).get("path") if isinstance(doc.get("source"), dict) else "")
            or ""
        ).strip()
        source_base = (repo_root / source_path).resolve() if source_path else manifest_path.parent.resolve()
        compose_name = str(runtime.get("compose_file") or runtime.get("file") or "docker-compose.yml").strip() or "docker-compose.yml"
        compose_path = (source_base / compose_name).resolve()
        if not compose_path.exists():
            missing.append(f"{manifest_path.relative_to(repo_root)} -> {compose_path.relative_to(repo_root) if compose_path.is_relative_to(repo_root) else compose_path}")

    assert not missing, "Missing compose files for compose-required manifests:\n" + "\n".join(sorted(missing))
