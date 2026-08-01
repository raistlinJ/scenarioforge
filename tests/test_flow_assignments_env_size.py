"""Flow assignments must not be handed over as an oversized env var.

Linux caps a single argv/envp string at MAX_ARG_STRLEN (32 pages = 128 KiB).
`CORETG_FLOW_ASSIGNMENTS_JSON` carried the whole assignment set, which reached
143,712 bytes at 17 challenges. Past the cap *every* later execve fails with
E2BIG -- so docker, compose and everything else died with:

    [OSError] [Errno 7] Argument list too long: 'sudo'

and, because the command never ran, produced no output to explain itself. That
surfaced as a bare `rc=1` blamed on whichever command happened to be next: a
failed pull, an image reported absent while present, a compose v2 probe that
"failed" and fell back to a docker-compose binary that was not installed.

The payload has to travel out of band once it gets big.
"""

from __future__ import annotations

import json

import pytest

from scenarioforge import cli
from scenarioforge.builders import topology as topo

MAX_ARG_STRLEN = 128 * 1024

ENV_JSON = 'CORETG_FLOW_ASSIGNMENTS_JSON'
ENV_PATH = 'CORETG_FLOW_ASSIGNMENTS_PATH'


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.delenv(ENV_JSON, raising=False)
    monkeypatch.delenv(ENV_PATH, raising=False)
    monkeypatch.setattr(topo, '_FLOW_ASSIGNMENTS_CACHE', None, raising=False)
    yield
    monkeypatch.setattr(topo, '_FLOW_ASSIGNMENTS_CACHE', None, raising=False)


def _assignments(count, filler=0):
    return [
        {
            'node_id': f'docker-{i}',
            'id': f'gen_{i}',
            'hint': 'x' * filler,
            'config_overrides': {'Checksum(sha256)': f'value_{i}'},
        }
        for i in range(count)
    ]


def _export(monkeypatch, assigns, tmp_path):
    monkeypatch.setattr(cli, '_flow_state_from_xml', lambda *a, **k: {'flag_assignments': assigns})
    monkeypatch.setattr(
        cli, '_write_flow_assignments_sidecar',
        lambda blob: _write(tmp_path / 'flow_assignments.json', blob),
    )
    cli._export_flow_assignments_to_env('ignored.xml', None)


def _write(path, blob):
    path.write_text(blob, encoding='utf-8')
    return str(path)


def test_small_payload_still_travels_in_the_environment(monkeypatch, tmp_path):
    import os
    assigns = _assignments(3)
    _export(monkeypatch, assigns, tmp_path)

    assert json.loads(os.environ[ENV_JSON]) == assigns
    assert ENV_PATH not in os.environ, 'no sidecar needed for a small set'


def test_oversized_payload_leaves_the_environment(monkeypatch, tmp_path):
    import os
    assigns = _assignments(17, filler=9000)  # ~150 KB, as at 17 challenges
    assert len(json.dumps(assigns)) > MAX_ARG_STRLEN, 'fixture must exceed the kernel cap'

    _export(monkeypatch, assigns, tmp_path)

    assert ENV_JSON not in os.environ, 'an oversized value breaks every later execve'
    assert json.loads(open(os.environ[ENV_PATH], encoding='utf-8').read()) == assigns


def test_no_exported_value_can_exceed_the_kernel_cap(monkeypatch, tmp_path):
    """The property that actually matters, whatever the threshold."""
    import os
    for count, filler in ((1, 0), (17, 9000), (60, 4000)):
        monkeypatch.delenv(ENV_JSON, raising=False)
        _export(monkeypatch, _assignments(count, filler), tmp_path)
        value = os.environ.get(ENV_JSON) or ''
        assert len(value.encode('utf-8')) < MAX_ARG_STRLEN, f'{count} assignments exceeded the cap'


def test_consumer_reads_the_sidecar(monkeypatch, tmp_path):
    import os
    assigns = _assignments(17, filler=9000)
    _export(monkeypatch, assigns, tmp_path)
    assert ENV_PATH in os.environ

    assert topo._flow_assignments_from_env() == assigns


def test_consumer_still_prefers_the_env_var(monkeypatch, tmp_path):
    import os
    assigns = _assignments(2)
    _export(monkeypatch, assigns, tmp_path)
    assert ENV_JSON in os.environ

    assert topo._flow_assignments_from_env() == assigns


def test_consumer_survives_a_missing_sidecar(monkeypatch, tmp_path):
    monkeypatch.setenv(ENV_PATH, str(tmp_path / 'does-not-exist.json'))
    assert topo._flow_assignments_from_env() == []
