"""A transient pull failure must not abort a run whose images are already local.

Execute forces CORETG_DOCKER_STRICT_PULL=1, so any non-zero `docker compose
pull` aborted the whole scenario -- including a Docker Hub rate limit or a
momentary registry blip on a node whose images were already on disk:

    RuntimeError: docker compose pull failed (node=flaggenslot-1 rc=1)

with nothing after it, because compose had written no output to act on.

A pull is a prefetch, not the run. It only blocks images the host lacks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scenarioforge.builders import topology as topo

COMPOSE = (
    'services:\n'
    '  node:\n'
    '    build:\n'
    '      context: /tmp/vulns/mail-smtp-open-relay-queue/.\n'
    '      dockerfile: Dockerfile\n'
    '  inject_copy:\n'
    '    image: alpine:3.19\n'
    '  flaggenslot-1:\n'
    '    build:\n'
    '      context: /tmp/vulns/mail-smtp-open-relay-queue/.\n'
    '      dockerfile: Dockerfile\n'
    '    container_name: flaggenslot-1\n'
)


class _Proc:
    def __init__(self, returncode, stdout=''):
        self.returncode = returncode
        self.stdout = stdout


@pytest.fixture
def compose_file(tmp_path):
    path = tmp_path / 'docker-compose-flaggenslot-1.yml'
    path.write_text(COMPOSE, encoding='utf-8')
    return path


def _install(monkeypatch, handler):
    monkeypatch.setattr(topo, '_docker_compose_cmd', lambda: ['docker', 'compose'])
    monkeypatch.setattr(topo, '_docker_cmd', lambda: ['docker'])
    monkeypatch.setattr(topo.subprocess, 'run', handler)
    monkeypatch.setenv('CORETG_DOCKER_STRICT_PULL', '1')


def _preflight(compose_path, node_name='flaggenslot-1'):
    topo._PREFLIGHTED_DOCKER_NODE_COMPOSES.discard(str(Path(compose_path).resolve()))
    topo._docker_compose_preflight(str(compose_path), node_name=node_name)


def _runner(calls, *, pull_rc, pull_out='', inspect_rc=0):
    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        calls.append(argv)
        if 'pull' in argv:
            return _Proc(pull_rc() if callable(pull_rc) else pull_rc, pull_out)
        if argv[:3] == ['docker', 'image', 'inspect']:
            return _Proc(inspect_rc, '')
        if argv[:2] == ['docker', 'inspect']:
            # Preflight polls for a non-zero PID; without one it waits out the
            # full budget and then fails for an unrelated reason.
            return _Proc(0, '123 running')
        return _Proc(0, '')
    return fake_run


def _pull_calls(calls):
    return [c for c in calls if 'pull' in c]


def test_pull_is_retried_once_before_giving_up(compose_file, monkeypatch):
    calls = []
    attempts = {'n': 0}

    def pull_rc():
        attempts['n'] += 1
        return 1 if attempts['n'] == 1 else 0

    _install(monkeypatch, _runner(calls, pull_rc=pull_rc))
    _preflight(compose_file)

    assert len(_pull_calls(calls)) == 2, 'a transient failure should be retried once'


def test_persistent_failure_tolerated_when_images_are_local(compose_file, monkeypatch):
    calls = []
    _install(monkeypatch, _runner(calls, pull_rc=1, inspect_rc=0))

    _preflight(compose_file)  # must not raise

    inspects = [c for c in calls if c[:3] == ['docker', 'image', 'inspect']]
    assert inspects, 'local presence should be checked before aborting'
    assert 'alpine:3.19' in inspects[0]


def test_aborts_when_the_image_is_genuinely_absent(compose_file, monkeypatch):
    calls = []
    _install(monkeypatch, _runner(calls, pull_rc=1, pull_out='toomanyrequests', inspect_rc=1))

    with pytest.raises(RuntimeError) as excinfo:
        _preflight(compose_file)

    message = str(excinfo.value)
    assert 'docker compose pull failed' in message
    assert 'flaggenslot-1' in message
    assert 'alpine:3.19' in message, 'the unavailable image must be named'
    assert 'toomanyrequests' in message


def test_empty_pull_output_still_explains_itself(compose_file, monkeypatch):
    """The original error was a bare rc=1 with nothing to act on."""
    calls = []
    _install(monkeypatch, _runner(calls, pull_rc=1, pull_out='', inspect_rc=1))

    with pytest.raises(RuntimeError) as excinfo:
        _preflight(compose_file)

    message = str(excinfo.value)
    assert 'no output' in message
    assert str(compose_file) in message, 'the compose path locates the problem'


def test_buildable_services_are_never_pulled(compose_file, monkeypatch):
    calls = []
    _install(monkeypatch, _runner(calls, pull_rc=0))
    _preflight(compose_file)

    for call in _pull_calls(calls):
        assert 'node' not in call
        assert 'flaggenslot-1' not in call
        assert 'inject_copy' in call
