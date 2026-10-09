"""Producer identity without importing the orchestrator or exposing environment files."""

from pathlib import Path
import hashlib
import subprocess
import sys
from importlib.metadata import version, PackageNotFoundError


def identity():
    root = Path(__file__).resolve().parents[2]
    digest = hashlib.sha256()
    for folder in (root / "scenarioforge", root / "webapp"):
        for path in sorted([*folder.rglob("*.py"), *folder.rglob("*.js")]):
            if (
                not path.is_file()
                or path.is_symlink()
                or not path.resolve().is_relative_to(root)
            ):
                continue
            digest.update(str(path.relative_to(root)).encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    revision = None
    dirty = None
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            ).stdout.strip()
        )
    except (OSError, subprocess.SubprocessError):
        pass
    packages = {}
    for name in ("Flask", "paramiko", "grpcio", "PyYAML"):
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            packages[name] = None
    return dict(
        python=sys.version,
        dependencies=packages,
        name="scenarioforge",
        git_revision=revision,
        dirty_checkout=dirty,
        source_sha256=digest.hexdigest(),
    )
