"""A preflight failure must say why, not just rc=1.

`_run` collapsed every exception -- a timeout, a missing binary -- to (1, ''),
which is indistinguishable from a command that ran and returned 1. Every caller
then produced a bare rc=1 with nothing after it:

    RuntimeError: docker compose inject helper failed (... helper=inject_copy rc=1)

Three separate execute failures in a row were debugged blind because of this.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scenarioforge.builders import topology as topo

COMPOSE = (
    'services:\n'
    '  docker-1:\n'
    '    image: alpine:3.20\n'
    '    container_name: docker-1\n'
    '  inject_copy:\n'
    '    image: alpine:3.20\n'
)


class _Proc:
    def __init__(self, returncode, stdout=''):
        self.returncode = returncode
        self.stdout = stdout


@pytest.fixture
def compose_file(tmp_path):
    path = tmp_path / 'docker-compose.yml'
    path.write_text(COMPOSE, encoding='utf-8')
    return path


def _preflight(compose_path, node_name='docker-1'):
    topo._PREFLIGHTED_DOCKER_NODE_COMPOSES.discard(str(Path(compose_path).resolve()))
    topo._docker_compose_preflight(str(compose_path), node_name=node_name)


def _install(monkeypatch, handler):
    monkeypatch.setattr(topo, '_docker_compose_cmd', lambda: ['docker', 'compose'])
    monkeypatch.setattr(topo, '_docker_cmd', lambda: ['docker'])
    monkeypatch.setattr(topo.subprocess, 'run', handler)
    monkeypatch.setenv('CORETG_DOCKER_STRICT_PULL', '1')


def _is_helper_start(argv):
    return 'up' in argv and 'inject_copy' in argv and '--no-start' not in argv


def test_helper_timeout_is_named_in_the_error(compose_file, monkeypatch):
    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        if _is_helper_start(argv):
            raise subprocess.TimeoutExpired(cmd='docker', timeout=300)
        if argv[:2] == ['docker', 'inspect']:
            return _Proc(0, '123 running')
        return _Proc(0, '')

    _install(monkeypatch, fake_run)
    with pytest.raises(RuntimeError) as excinfo:
        _preflight(compose_file)

    message = str(excinfo.value)
    assert 'inject helper failed' in message
    assert 'timeout' in message.lower(), 'a killed command must not read as a container exit'


def test_missing_binary_is_named_in_the_error(compose_file, monkeypatch):
    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        if _is_helper_start(argv):
            raise FileNotFoundError(2, 'No such file or directory', 'docker')
        if argv[:2] == ['docker', 'inspect']:
            return _Proc(0, '123 running')
        return _Proc(0, '')

    _install(monkeypatch, fake_run)
    with pytest.raises(RuntimeError) as excinfo:
        _preflight(compose_file)

    assert 'not found' in str(excinfo.value).lower()


def test_helper_container_logs_are_captured(compose_file, monkeypatch):
    """The container's output is the only thing that says why the copy failed."""
    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        if _is_helper_start(argv):
            return _Proc(1, 'inject_copy-1 exited with code 1')
        if 'ps' in argv and '-q' in argv:
            return _Proc(0, 'deadbeefcafe')
        if argv[:2] == ['docker', 'logs']:
            return _Proc(0, "cp: can't stat '/src/service': No such file or directory")
        if argv[:2] == ['docker', 'inspect']:
            return _Proc(0, '1 exited')
        return _Proc(0, '')

    _install(monkeypatch, fake_run)
    with pytest.raises(RuntimeError) as excinfo:
        _preflight(compose_file)

    message = str(excinfo.value)
    assert "can't stat '/src/service'" in message, 'the cause must reach the operator'
    assert 'inject_copy logs' in message


def test_empty_reason_still_explains_itself(compose_file, monkeypatch):
    """The exact shape of the reported failure: rc=1 and nothing else."""
    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        if _is_helper_start(argv):
            return _Proc(1, '')
        if 'ps' in argv and '-q' in argv:
            return _Proc(0, '')  # no container left to inspect
        if argv[:2] == ['docker', 'inspect']:
            return _Proc(0, '123 running')
        return _Proc(0, '')

    _install(monkeypatch, fake_run)
    with pytest.raises(RuntimeError) as excinfo:
        _preflight(compose_file)

    message = str(excinfo.value)
    assert 'rc=1)' not in message.strip().splitlines()[-1], 'must not stop at the rc line'
    assert 'never ran' in message
