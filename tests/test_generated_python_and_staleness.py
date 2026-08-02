"""Two gaps that let a broken generator survive repeated executes.

A generator emitted `"directory_traversal": true` into a Python file. That is
valid *syntax* -- `true` is just a name -- so it failed only at import, and the
symptom appeared four layers away: container crash-loop, CORE unable to read its
PID, session stuck in `configuration`, run reported successful.

Fixing the generator then changed nothing, because artifacts were regenerated
only when *missing*. The previous output was still on disk, so it was reused and
the fix silently never applied until the directory was deleted by hand.
"""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _runner():
    spec = importlib.util.spec_from_file_location(
        'flag_generator_runner', REPO_ROOT / 'scripts' / 'run_flag_generator.py'
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _check(files: dict[str, str]):
    module = _runner()
    out = pathlib.Path(tempfile.mkdtemp())
    for name, body in files.items():
        (out / name).write_text(body, encoding='utf-8')
    module._validate_generated_python_compiles(out)


def test_json_literal_in_python_is_rejected():
    """The exact failure observed: json.dumps output pasted into a .py."""
    with pytest.raises(SystemExit) as excinfo:
        _check({'app.py': 'CONFIG = {\n  "directory_traversal": true,\n}\n'})
    message = str(excinfo.value)
    assert 'true' in message and 'True' in message
    assert 'app.py line 2' in message


def test_all_three_json_literals_are_caught():
    with pytest.raises(SystemExit) as excinfo:
        _check({'a.py': 'X = {"a": null, "b": false}\n'})
    assert 'null' in str(excinfo.value) or 'false' in str(excinfo.value)


def test_a_real_syntax_error_is_still_caught():
    with pytest.raises(SystemExit):
        _check({'a.py': 'def f(:\n'})


def test_the_corrected_generator_output_passes():
    """Parsing the JSON at runtime is the fix; it must not be flagged."""
    _check({'app.py': 'import json\nCONFIG = json.loads(r"""{"x": true}""")\n'})


def test_a_bound_name_is_not_a_json_literal():
    """`true` as an actual variable is odd but legal, and not this bug."""
    _check({'a.py': 'true = 1\nprint(true)\n'})
    _check({'b.py': 'from x import null\nprint(null)\n'})
    _check({'c.py': 'def f(false):\n    return false\n'})


def test_non_python_files_are_ignored():
    _check({'notes.txt': 'true false null\n', 'a.py': 'X = True\n'})


class _Stat:
    def __init__(self, mtime):
        self.st_mtime = mtime


class _Sftp:
    def __init__(self, mtimes):
        self.mtimes = mtimes

    def stat(self, path):
        for key, value in self.mtimes.items():
            if path.endswith(key):
                return _Stat(value)
        raise FileNotFoundError(path)


@pytest.fixture
def backend(monkeypatch):
    from webapp import app_backend

    monkeypatch.setattr(
        app_backend, '_installed_generator_repo_relpath',
        lambda _gid: 'outputs/installed_generators/flag_node_generators/p_x__71',
    )
    monkeypatch.setattr(
        app_backend, '_remote_flow_assignment_expected_paths',
        lambda _a: ['/tmp/vulns/flag_node_generators_runs/s/04_x/outputs.json'],
    )
    return app_backend


def test_output_older_than_its_generator_is_stale(backend):
    """The case that made the generator fix a no-op."""
    sftp = _Sftp({'p_x__71/generator.py': 2000.0, '04_x/outputs.json': 1000.0})
    reason = backend._flow_assignment_artifacts_are_stale(
        sftp, {'id': '71'}, remote_repo='/tmp/scenarioforge'
    )
    assert reason and 'newer than its output' in reason


def test_output_newer_than_its_generator_is_fresh(backend):
    sftp = _Sftp({'p_x__71/generator.py': 1000.0, '04_x/outputs.json': 2000.0})
    assert backend._flow_assignment_artifacts_are_stale(
        sftp, {'id': '71'}, remote_repo='/tmp/scenarioforge'
    ) == ''


def test_an_unresolvable_comparison_does_not_force_regeneration(backend):
    """Unknown must not mean stale, or every run regenerates everything."""
    assert backend._flow_assignment_artifacts_are_stale(
        _Sftp({}), {'id': '71'}, remote_repo='/tmp/scenarioforge'
    ) == ''


def test_regeneration_triggers_on_stale_not_only_missing():
    """The gate itself must consult staleness, not merely define a helper for it."""
    source = (REPO_ROOT / 'webapp' / 'app_backend.py').read_text(encoding='utf-8', errors='ignore')

    marker = 'missing_before = _flow_assignment_missing_remote_paths(sftp, assignment)'
    assert marker in source, 'regeneration gate moved'
    gate = source[source.index(marker):source.index(marker) + 900]

    assert '_flow_assignment_artifacts_are_stale(' in gate, (
        'the gate skips assignments whose artifacts merely exist, however stale'
    )
    assert 'remote_repo=remote_repo' in gate
    assert 'flow.artifacts.regenerate stale' in gate
