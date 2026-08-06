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
import yaml

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


def _runner(calls, *, pull_rc, pull_out='', inspect_rc=0, inspect_out=None):
    if inspect_out is None:
        inspect_out = '' if inspect_rc == 0 else 'Error: No such image: alpine:3.19'

    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        calls.append(argv)
        if 'pull' in argv:
            return _Proc(pull_rc() if callable(pull_rc) else pull_rc, pull_out)
        if argv[:3] == ['docker', 'image', 'inspect']:
            return _Proc(inspect_rc, inspect_out)
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

    # inspect_rc=1: the image is absent, so a pull is actually attempted. With a
    # cached image the pull is skipped and there is nothing to retry.
    _install(monkeypatch, _runner(calls, pull_rc=pull_rc, inspect_rc=1))
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


def test_unverifiable_image_is_not_reported_as_missing(compose_file, monkeypatch):
    """A daemon/sudo error is not evidence the image is absent.

    Blaming a present image for a sudo failure sent the reader after the wrong
    problem entirely.
    """
    calls = []
    _install(monkeypatch, _runner(
        calls,
        pull_rc=1,
        inspect_rc=1,
        inspect_out='permission denied while trying to connect to the Docker daemon socket',
    ))

    _preflight(compose_file)  # indeterminate -> must not abort on a false claim


def test_no_pull_at_all_when_every_image_is_cached(compose_file, monkeypatch):
    """A fully cached scenario must not need the registry.

    The pull contacted the network even when nothing needed fetching, which
    made an otherwise offline-capable run depend on the internet.
    """
    calls = []
    _install(monkeypatch, _runner(calls, pull_rc=0, inspect_rc=0))
    _preflight(compose_file)

    assert _pull_calls(calls) == [], 'a cached run must issue no pull'
    inspects = [c for c in calls if c[:3] == ['docker', 'image', 'inspect']]
    assert any('alpine:3.19' in c for c in inspects), 'presence must be confirmed first'


def test_mixed_cache_pulls_only_the_missing_base_service(tmp_path, monkeypatch):
    """One cold base must not refresh every cached base on the same node."""
    compose_path = tmp_path / 'docker-compose-docker-4.yml'
    compose_path.write_text(
        'services:\n'
        '  cached_db:\n'
        '    image: postgres:16-alpine\n'
        '  cold_app:\n'
        '    image: example/app:1.0\n'
        '  cached_helper:\n'
        '    image: alpine:3.19\n',
        encoding='utf-8',
    )
    calls = []

    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        calls.append(argv)
        if argv[:3] == ['docker', 'image', 'inspect']:
            image = argv[-1]
            if image == 'example/app:1.0':
                return _Proc(1, f'Error: No such image: {image}')
            return _Proc(0, 'sha256:cached')
        if argv[:2] == ['docker', 'inspect']:
            return _Proc(0, '123 running')
        return _Proc(0, '')

    _install(monkeypatch, fake_run)
    topo.IMAGES_REQUIRED_THIS_RUN.clear()
    try:
        _preflight(compose_path, node_name='docker-4')

        pulls = _pull_calls(calls)
        assert len(pulls) == 1
        assert pulls[0][-1] == 'cold_app'
        assert 'cached_db' not in pulls[0]
        assert 'cached_helper' not in pulls[0]
        assert topo.IMAGES_REQUIRED_THIS_RUN == {
            'postgres:16-alpine', 'example/app:1.0', 'alpine:3.19',
        }
    finally:
        topo.IMAGES_REQUIRED_THIS_RUN.clear()


def test_arm64_manifest_mismatch_pins_failed_dependency_to_amd64(tmp_path, monkeypatch):
    compose_path = tmp_path / 'docker-compose-docker-12.yml'
    compose_path.write_text(
        'services:\n'
        '  mysql:\n'
        '    image: mysql:5.5\n'
        '  docker-12:\n'
        '    build: .\n'
        '    image: local-node:latest\n',
        encoding='utf-8',
    )
    calls = []
    pull_attempts = {'n': 0}

    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        calls.append(argv)
        if 'pull' in argv:
            pull_attempts['n'] += 1
            if pull_attempts['n'] == 1:
                return _Proc(
                    1,
                    'Image mysql:5.5 Error no matching manifest for linux/arm64/v8 '
                    'in the manifest list entries',
                )
            return _Proc(0, 'Image mysql:5.5 Pulled')
        if argv[:3] == ['docker', 'image', 'inspect']:
            return _Proc(1, 'Error: No such image')
        if argv[:2] == ['docker', 'inspect']:
            return _Proc(0, '123 running')
        return _Proc(0, '')

    _install(monkeypatch, fake_run)
    _preflight(compose_path, node_name='docker-12')

    compose = yaml.safe_load(compose_path.read_text(encoding='utf-8'))
    assert compose['services']['mysql']['platform'] == 'linux/amd64'
    assert 'platform' not in compose['services']['docker-12']
    assert len(_pull_calls(calls)) == 2


def test_pull_still_happens_when_an_image_is_absent(compose_file, monkeypatch):
    calls = []
    _install(monkeypatch, _runner(calls, pull_rc=0, inspect_rc=1))
    _preflight(compose_file)

    assert _pull_calls(calls), 'a cold cache must still fetch'


def test_pull_happens_when_presence_cannot_be_confirmed(compose_file, monkeypatch):
    """Skipping requires certainty, not merely the absence of bad news."""
    calls = []
    _install(monkeypatch, _runner(
        calls, pull_rc=0, inspect_rc=1,
        inspect_out='permission denied while trying to connect to the Docker daemon socket',
    ))
    _preflight(compose_file)

    assert _pull_calls(calls), 'an unverifiable cache must not suppress the pull'


def test_buildable_services_are_never_pulled(compose_file, monkeypatch):
    calls = []
    _install(monkeypatch, _runner(calls, pull_rc=0))
    _preflight(compose_file)

    for call in _pull_calls(calls):
        assert 'node' not in call
        assert 'flaggenslot-1' not in call
        assert 'inject_copy' in call
