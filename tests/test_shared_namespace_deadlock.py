"""A node whose app needs a sidecar that needs the node cannot start either.

Collapsing a multi-service vuln into one network namespace inverts the
dependency: sidecars get `network_mode: service:<node>`, so they can only start
while the node is *running*. `zabbix/CVE-2017-2824`'s server exits in 226 ms
because MySQL is not listening, goes to `restarting`, and Docker then refuses
the sidecars outright:

    cannot join network namespace of container: ... is restarting

MySQL never starts, so the server can never succeed. Measured upstream, the
image is fine: given a MySQL that is already listening, the same server stays
`Up (healthy)`. Vulhub's own recipes that survive this repair are the ones that
retry by hand -- rocketchat wraps `node main.js` in a 30-attempt loop.

Measured both ways it can fail. zabbix exits instantly and flaps, so Docker
refuses the sidecars outright and nothing starts. apisix retries
`http://etcd:2379` twice, gets connection refused, and exits before etcd is up
-- no Docker error at all, just a node that is gone
(dataset-catalog-coverage-005). One condition covers both: a node holding a
namespace other containers need has to keep PID 1 alive, so the wrap is applied
to any such node rather than waiting for a failure signature.
"""

from __future__ import annotations

import os
import tempfile

import pytest
import yaml

from scenarioforge.builders.topology import (
    _compose_namespace_join_refused,
    _wrap_node_command_with_retry,
)

DOCKER_REFUSAL = (
    'Container docker-13conf-mysql-1  Starting\n'
    'Error response from daemon: cannot join network namespace of container: '
    'Container 9d731aeafb50 is restarting, wait until the container is running'
)


def _compose(tmp_path: str, service: dict) -> str:
    path = os.path.join(tmp_path, 'docker-compose.yml')
    with open(path, 'w', encoding='utf-8') as fh:
        yaml.safe_dump({'services': {'docker-13': service}}, fh, sort_keys=False)
    return path


@pytest.fixture
def tmpdir_path():
    return tempfile.mkdtemp(prefix='nsdeadlock_')


# --------------------------------------------------------------------------- #
# Recognising the deadlock
# --------------------------------------------------------------------------- #

def test_the_docker_refusal_is_recognised() -> None:
    assert _compose_namespace_join_refused(DOCKER_REFUSAL) is True


def test_an_unrelated_sidecar_failure_is_not_mistaken_for_it() -> None:
    """Any other sidecar failure must keep its existing handling."""
    assert _compose_namespace_join_refused(
        'Error response from daemon: pull access denied for someimage'
    ) is False
    assert _compose_namespace_join_refused('') is False
    assert _compose_namespace_join_refused(None) is False


# --------------------------------------------------------------------------- #
# The rewrite
# --------------------------------------------------------------------------- #

def test_the_app_keeps_its_own_argv(tmpdir_path) -> None:
    path = _compose(tmpdir_path, {
        'image': 'x:iproute2',
        'entrypoint': ['/usr/local/coretg/bin/coretg-app-user-exec', '/docker-entrypoint.sh'],
        'command': ['server'],
    })
    assert _wrap_node_command_with_retry(path, 'docker-13') is True
    svc = yaml.safe_load(open(path, encoding='utf-8').read())['services']['docker-13']
    assert svc['entrypoint'][:2] == ['sh', '-c']
    script = svc['entrypoint'][2]
    # The shim must still be what runs the app, in the same order.
    assert '/usr/local/coretg/bin/coretg-app-user-exec /docker-entrypoint.sh server' in script
    # `command` is folded into the script; leaving it would append it twice.
    assert 'command' not in svc


def test_a_broken_app_still_gives_up(tmpdir_path) -> None:
    """The container must not be held open forever, or PID-0 becomes silent."""
    path = _compose(tmpdir_path, {'image': 'x', 'command': ['server']})
    _wrap_node_command_with_retry(path, 'docker-13')
    script = yaml.safe_load(open(path, encoding='utf-8').read())['services']['docker-13']['entrypoint'][2]
    assert 'exit 1' in script, script
    assert '-ge 30' in script, script


def test_a_successful_app_exit_is_still_a_successful_exit(tmpdir_path) -> None:
    path = _compose(tmpdir_path, {'image': 'x', 'command': ['server']})
    _wrap_node_command_with_retry(path, 'docker-13')
    script = yaml.safe_load(open(path, encoding='utf-8').read())['services']['docker-13']['entrypoint'][2]
    assert '&& exit 0' in script, script


def test_arguments_needing_quoting_survive(tmpdir_path) -> None:
    path = _compose(tmpdir_path, {
        'image': 'x',
        'command': ['sh', '-c', 'echo "a b"; run --flag=1'],
    })
    _wrap_node_command_with_retry(path, 'docker-13')
    script = yaml.safe_load(open(path, encoding='utf-8').read())['services']['docker-13']['entrypoint'][2]
    assert "'echo \"a b\"; run --flag=1'" in script, script


def test_wrapping_twice_is_refused(tmpdir_path) -> None:
    path = _compose(tmpdir_path, {'image': 'x', 'command': ['server']})
    assert _wrap_node_command_with_retry(path, 'docker-13') is True
    assert _wrap_node_command_with_retry(path, 'docker-13') is False


def test_a_service_with_no_startup_is_left_alone(tmpdir_path) -> None:
    # Nothing to re-execute; the app-user shim declines these too.
    path = _compose(tmpdir_path, {'image': 'x'})
    assert _wrap_node_command_with_retry(path, 'docker-13') is False


def test_a_missing_service_is_left_alone(tmpdir_path) -> None:
    path = _compose(tmpdir_path, {'image': 'x', 'command': ['server']})
    assert _wrap_node_command_with_retry(path, 'nope') is False


# --------------------------------------------------------------------------- #
# Applied to any node that holds a namespace for others
# --------------------------------------------------------------------------- #

def test_preflight_wraps_a_node_that_has_namespace_sharing_sidecars() -> None:
    """The condition is "others share my namespace", not a failure signature.

    apisix produced no Docker error at all -- it just exited after two refused
    connections to an etcd that could not have been up yet -- so a reactive
    trigger keyed on the deadlock message never fired for it.
    """
    import inspect

    from scenarioforge.builders import topology

    src = inspect.getsource(topology._docker_compose_preflight)
    wrap_at = src.index('_wrap_node_command_with_retry(compose_path, str(target_service))')
    up_at = src.index("up_services = [str(target_service)]")
    # Wrapped before the node is started, or the first start races unwrapped.
    assert wrap_at < up_at, 'the wrap must be applied before the node is started'
    assert '_compose_shared_namespace_services(compose_path, str(target_service))' in src


def test_a_single_service_node_is_not_wrapped(tmpdir_path) -> None:
    """Nothing shares its namespace, so its app owning PID 1 is correct."""
    path = _compose(tmpdir_path, {'image': 'nginx', 'command': ['nginx']})
    # The helper itself still wraps on request; the guard is the caller's
    # sidecar check, asserted above. This pins that a lone service has no
    # sidecars to find.
    from scenarioforge.builders.topology import _compose_shared_namespace_services

    assert _compose_shared_namespace_services(path, 'docker-13') == []
