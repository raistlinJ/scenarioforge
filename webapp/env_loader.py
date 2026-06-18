from __future__ import annotations

import ast
import os
import re

from pathlib import Path
from typing import Iterable


_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _env_file_candidates(base_dir: Path | None = None, explicit_path: str | None = None) -> list[Path]:
    repo_root = (base_dir or Path(__file__).resolve().parent.parent).resolve()
    candidates: list[Path] = []
    explicit = str(explicit_path or os.environ.get("CORETG_ENV_FILE") or "").strip()
    if explicit:
        candidates.append(Path(explicit).expanduser())
    candidates.append(repo_root / ".scenarioforge.env")
    candidates.append(repo_root / ".scenarioforge.env.example")

    deduped: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(resolved)
    return deduped


def _parse_env_value(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in {'"', "'"} and value[-1] == value[0]:
        try:
            parsed = ast.literal_eval(value)
        except Exception:
            parsed = value[1:-1]
        return str(parsed)
    comment_index = value.find(" #")
    if comment_index >= 0:
        value = value[:comment_index].rstrip()
    return value


def load_env_file(path: str | Path, *, override: bool = False) -> list[str]:
    env_path = Path(path).expanduser().resolve(strict=False)
    if not env_path.is_file():
        return []

    loaded_keys: list[str] = []
    try:
        lines = env_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        if not _ENV_KEY_RE.match(key):
            continue
        parsed_value = _parse_env_value(value)
        if override or key not in os.environ:
            os.environ[key] = parsed_value
        loaded_keys.append(key)
    return loaded_keys


def load_runtime_env_files(
    *,
    base_dir: Path | None = None,
    explicit_path: str | None = None,
    override: bool = False,
    include_example: bool = False,
) -> list[Path]:
    loaded: list[Path] = []
    candidates = _env_file_candidates(base_dir=base_dir, explicit_path=explicit_path)
    if not include_example:
        candidates = [candidate for candidate in candidates if candidate.name != ".scenarioforge.env.example"]
    for candidate in candidates:
        if load_env_file(candidate, override=override):
            loaded.append(candidate)
    return loaded


__all__: Iterable[str] = [
    "load_env_file",
    "load_runtime_env_files",
]