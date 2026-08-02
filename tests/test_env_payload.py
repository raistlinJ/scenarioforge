"""Serialized payloads must never be handed over as an oversized env var.

Linux caps a single argv/envp string at MAX_ARG_STRLEN (32 pages = 128 KiB).
Past it, every execve from that environment fails with E2BIG -- and because the
command never runs it produces no output, so the failure is blamed on whatever
ran next. `CORETG_FLOW_ASSIGNMENTS_JSON` hit 143,712 bytes at 17 challenges and
cost four wrong diagnoses.

The ratchet at the bottom is the point: this must not come back through a new
call site.
"""

from __future__ import annotations

import ast
import json
import pathlib
import re

import pytest

from scenarioforge.utils.env_payload import (
    MAX_ARG_STRLEN,
    MAX_ENV_VALUE_BYTES,
    read_env_payload,
    set_env_payload,
    sidecar_var_name,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_ceiling_leaves_headroom_under_the_kernel_limit():
    assert MAX_ENV_VALUE_BYTES < MAX_ARG_STRLEN


@pytest.mark.parametrize(
    ('name', 'expected'),
    [
        ('CORETG_FLOW_ASSIGNMENTS_JSON', 'CORETG_FLOW_ASSIGNMENTS_PATH'),
        ('CORETG_INJECT_FILES_JSON', 'CORETG_INJECT_FILES_PATH'),
        ('SOMETHING_ELSE', 'SOMETHING_ELSE_PATH'),
    ],
)
def test_sidecar_var_name(name, expected):
    assert sidecar_var_name(name) == expected


def test_small_payload_travels_in_the_environment(tmp_path):
    env = {}
    assert set_env_payload(env, 'X_JSON', '{"a": 1}', sidecar_dir=str(tmp_path)) == ''
    assert env['X_JSON'] == '{"a": 1}'
    assert 'X_PATH' not in env


def test_large_payload_spills_to_a_file(tmp_path):
    env = {}
    blob = json.dumps(['x' * 1000] * 200)  # comfortably over the ceiling
    assert len(blob) > MAX_ENV_VALUE_BYTES

    path = set_env_payload(env, 'X_JSON', blob, sidecar_dir=str(tmp_path))

    assert 'X_JSON' not in env, 'an oversized value breaks every later execve'
    assert env['X_PATH'] == path
    assert pathlib.Path(path).read_text(encoding='utf-8') == blob


def test_no_value_written_can_exceed_the_kernel_limit(tmp_path):
    for size in (1, 1000, MAX_ENV_VALUE_BYTES - 1, MAX_ENV_VALUE_BYTES + 1, 500_000):
        env = {}
        set_env_payload(env, 'X_JSON', 'y' * size, sidecar_dir=str(tmp_path))
        for value in env.values():
            assert len(str(value).encode('utf-8')) < MAX_ARG_STRLEN


def test_switching_to_a_sidecar_clears_the_stale_value(tmp_path):
    env = {'X_JSON': 'small'}
    set_env_payload(env, 'X_JSON', 'z' * (MAX_ENV_VALUE_BYTES + 1), sidecar_dir=str(tmp_path))
    assert 'X_JSON' not in env


def test_switching_back_clears_the_stale_sidecar(tmp_path):
    env = {}
    set_env_payload(env, 'X_JSON', 'z' * (MAX_ENV_VALUE_BYTES + 1), sidecar_dir=str(tmp_path))
    set_env_payload(env, 'X_JSON', 'small', sidecar_dir=str(tmp_path))
    assert env['X_JSON'] == 'small'
    assert 'X_PATH' not in env


def test_payload_is_dropped_rather_than_breaking_execve(tmp_path, monkeypatch):
    """If no sidecar can be written, losing one payload beats breaking them all."""
    monkeypatch.setattr('scenarioforge.utils.env_payload._write_sidecar', lambda *a, **k: '')
    env = {}
    set_env_payload(env, 'X_JSON', 'z' * (MAX_ENV_VALUE_BYTES + 1), sidecar_dir=str(tmp_path))
    assert env == {}


@pytest.mark.parametrize('size', [10, MAX_ENV_VALUE_BYTES + 1])
def test_round_trip_through_either_form(tmp_path, size):
    env = {}
    blob = json.dumps(['v' * 10] * (size // 12 + 1))
    set_env_payload(env, 'X_JSON', blob, sidecar_dir=str(tmp_path))
    assert read_env_payload('X_JSON', env) == blob


def test_read_returns_empty_when_nothing_is_set():
    assert read_env_payload('X_JSON', {}) == ''


def test_read_survives_a_missing_sidecar(tmp_path):
    env = {'X_PATH': str(tmp_path / 'gone.json')}
    assert read_env_payload('X_JSON', env) == ''


# --- ratchet -----------------------------------------------------------------

# json.dumps straight into an environment mapping is the shape that caused the
# outage. Anything matching has to go through set_env_payload instead.
_RAW_ASSIGNMENT = re.compile(r'(?:os\.environ|env)\s*\[[^\]]+\]\s*=\s*json\.dumps')

_SEARCH_DIRS = ('webapp', 'scenarioforge', 'scripts')


def _python_files():
    for directory in _SEARCH_DIRS:
        for path in (REPO_ROOT / directory).rglob('*.py'):
            if '__pycache__' in path.parts:
                continue
            yield path


def test_no_module_assigns_json_dumps_straight_into_an_environment():
    offenders = []
    for path in _python_files():
        text = path.read_text(encoding='utf-8', errors='ignore')
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _RAW_ASSIGNMENT.search(line):
                offenders.append(f'{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}')
    assert not offenders, (
        'serialized payloads must go through scenarioforge.utils.env_payload.set_env_payload, '
        'which spills to a file before the value can break execve:\n  ' + '\n  '.join(offenders)
    )


def test_env_payload_module_has_no_heavy_imports():
    """It is imported on the remote path, where little else is guaranteed."""
    tree = ast.parse((REPO_ROOT / 'scenarioforge' / 'utils' / 'env_payload.py').read_text(encoding='utf-8'))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split('.')[0])
    assert imported <= {'__future__', 'logging', 'os', 'tempfile', 'typing'}
