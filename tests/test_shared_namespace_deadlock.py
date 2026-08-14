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
import shutil
import subprocess
import tempfile

import pytest
import yaml

from scenarioforge.builders.topology import (
    _compose_namespace_join_refused,
    _finalize_shared_namespace_supervisor,
    _inspect_compose_service_image_config,
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
    # The shim must still be what runs the app, in the same order. It stays as
    # argv rather than being interpolated into shell source.
    assert svc['command'] == [
        '/usr/local/coretg/bin/coretg-app-user-exec',
        '/docker-entrypoint.sh',
        'server',
    ]
    assert '"$$@" &' in script
    assert svc['restart'] == 'no'
    assert svc['labels']['coretg.stable_node_supervisor'] == '1'


def test_a_broken_app_still_gives_up(tmpdir_path) -> None:
    """The container must not be held open forever, or PID-0 becomes silent."""
    path = _compose(tmpdir_path, {'image': 'x', 'command': ['server']})
    _wrap_node_command_with_retry(path, 'docker-13')
    script = yaml.safe_load(open(path, encoding='utf-8').read())['services']['docker-13']['entrypoint'][2]
    assert 'exhausted retries' in script, script
    assert '-ge 30' in script, script


def test_a_successful_app_exit_is_still_a_successful_exit(tmpdir_path) -> None:
    path = _compose(tmpdir_path, {'image': 'x', 'command': ['server']})
    _wrap_node_command_with_retry(path, 'docker-13')
    script = yaml.safe_load(open(path, encoding='utf-8').read())['services']['docker-13']['entrypoint'][2]
    assert 'exit 0' in script, script


def test_arguments_needing_quoting_survive(tmpdir_path) -> None:
    path = _compose(tmpdir_path, {
        'image': 'x',
        'command': ['sh', '-c', 'echo "a b"; run --flag=1'],
    })
    _wrap_node_command_with_retry(path, 'docker-13')
    svc = yaml.safe_load(open(path, encoding='utf-8').read())['services']['docker-13']
    assert svc['command'] == ['sh', '-c', 'echo "a b"; run --flag=1']


def test_wrapping_twice_is_refused(tmpdir_path) -> None:
    path = _compose(tmpdir_path, {'image': 'x', 'command': ['server']})
    assert _wrap_node_command_with_retry(path, 'docker-13') is True
    assert _wrap_node_command_with_retry(path, 'docker-13') is False


def test_supervisor_shell_variables_survive_compose_interpolation(tmpdir_path) -> None:
    """Compose must hand retry state to the container shell, not expand it."""
    path = _compose(tmpdir_path, {'image': 'x', 'command': ['server']})
    _wrap_node_command_with_retry(path, 'docker-13')
    script = yaml.safe_load(open(path, encoding='utf-8').read())['services']['docker-13']['entrypoint'][2]
    for variable in ('attempt', 'child', 'rc'):
        assert f'$${variable}' in script, script
        assert f'${variable}' not in script.replace(f'$${variable}', ''), script
    assert '$$((' in script, script


def test_docker_compose_accepts_the_supervisor_without_variable_warnings(tmpdir_path) -> None:
    docker = shutil.which('docker')
    if not docker:
        pytest.skip('docker CLI is unavailable')
    path = _compose(tmpdir_path, {'image': 'alpine:3.19', 'command': ['sleep', 'infinity']})
    _wrap_node_command_with_retry(path, 'docker-13')
    proc = subprocess.run(
        [docker, 'compose', '-f', path, 'config'],
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = f'{proc.stdout}\n{proc.stderr}'
    assert proc.returncode == 0, output
    assert 'variable is not set' not in output.lower(), output


def test_wrapper_images_use_the_injected_busybox_shell(tmpdir_path) -> None:
    path = _compose(tmpdir_path, {
        'image': 'coretg/example:iproute2',
        'command': ['server'],
    })
    _wrap_node_command_with_retry(path, 'docker-13')
    entrypoint = yaml.safe_load(open(path, encoding='utf-8').read())['services']['docker-13']['entrypoint']
    assert entrypoint[:3] == ['/usr/local/coretg/bin/busybox', 'sh', '-c']
    assert entrypoint[4] == 'coretg-stable-node-supervisor'


def test_image_default_startup_is_preserved_for_build_only_nodes(tmpdir_path, monkeypatch) -> None:
    """Django-style build services omit startup from Compose and inherit it."""
    path = os.path.join(tmpdir_path, 'docker-compose.yml')
    with open(path, 'w', encoding='utf-8') as fh:
        yaml.safe_dump({
            'services': {
                'docker-13': {'build': {'context': '.'}, 'restart': 'on-failure:3'},
                'db': {'image': 'oracle', 'network_mode': 'service:docker-13'},
            },
        }, fh, sort_keys=False)
    monkeypatch.setattr(
        'scenarioforge.builders.topology._inspect_compose_service_image_config',
        lambda *_a, **_k: {
            'Entrypoint': ['/docker-entrypoint.sh'],
            'Cmd': ['python', 'manage.py', 'runserver', '0.0.0.0:8000'],
        },
    )
    assert _finalize_shared_namespace_supervisor(path, 'docker-13') is True
    node = yaml.safe_load(open(path, encoding='utf-8').read())['services']['docker-13']
    script = node['entrypoint'][2]
    assert node['command'] == [
        '/docker-entrypoint.sh', 'python', 'manage.py', 'runserver', '0.0.0.0:8000',
    ]
    assert node['restart'] == 'no'


def test_app_user_shim_is_restored_before_supervisor_argv_is_captured(tmpdir_path, monkeypatch) -> None:
    path = os.path.join(tmpdir_path, 'docker-compose.yml')
    with open(path, 'w', encoding='utf-8') as fh:
        yaml.safe_dump({
            'services': {
                'docker-13': {'image': 'coretg/example:iproute2', 'command': ['server']},
                'db': {'image': 'db', 'network_mode': 'service:docker-13'},
            },
        }, fh, sort_keys=False)
    calls = []

    def restore_user(*_args, **_kwargs):
        calls.append('restore-user')

    def inspect_image(*_args, **_kwargs):
        calls.append('inspect-startup')
        return {'Entrypoint': [], 'Cmd': []}

    monkeypatch.setattr('scenarioforge.builders.topology._apply_wrapper_app_user_entrypoints', restore_user)
    monkeypatch.setattr('scenarioforge.builders.topology._inspect_compose_service_image_config', inspect_image)
    assert _finalize_shared_namespace_supervisor(path, 'docker-13', docker_cmd=['docker']) is True
    assert calls == ['restore-user', 'inspect-startup']


def test_build_only_image_config_uses_the_compose_project_tag(tmpdir_path) -> None:
    path = _compose(tmpdir_path, {'build': {'context': '.'}})
    calls = []

    def fake_run(args, timeout):
        calls.append(list(args))
        if 'docker-13conf-docker-13' in args:
            return 0, '{"Entrypoint":["/start"],"Cmd":["serve"]}'
        return 1, 'not found'

    config = _inspect_compose_service_image_config(
        path,
        'docker-13',
        node_name='docker-13',
        docker_cmd=['docker'],
        run=fake_run,
    )
    assert config == {'Entrypoint': ['/start'], 'Cmd': ['serve']}
    assert any('docker-13conf-docker-13' in call for call in calls)


def test_finalizer_does_not_touch_a_single_service_node(tmpdir_path) -> None:
    path = _compose(tmpdir_path, {
        'image': 'nginx',
        'command': ['nginx', '-g', 'daemon off;'],
        'restart': 'on-failure:3',
    })
    before = open(path, encoding='utf-8').read()
    assert _finalize_shared_namespace_supervisor(path, 'docker-13') is False
    assert open(path, encoding='utf-8').read() == before


def test_finalizer_can_be_disabled_without_touching_compose(tmpdir_path, monkeypatch) -> None:
    path = os.path.join(tmpdir_path, 'docker-compose.yml')
    with open(path, 'w', encoding='utf-8') as fh:
        yaml.safe_dump({
            'services': {
                'docker-13': {'image': 'app', 'command': ['server']},
                'db': {'image': 'db', 'network_mode': 'service:docker-13'},
            },
        }, fh, sort_keys=False)
    before = open(path, encoding='utf-8').read()
    monkeypatch.setenv('CORETG_STABLE_NODE_SUPERVISOR', '0')
    assert _finalize_shared_namespace_supervisor(path, 'docker-13') is False
    assert open(path, encoding='utf-8').read() == before


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
    wrap_at = src.index('_finalize_shared_namespace_supervisor(')
    up_at = src.index("up_services = [str(target_service)]")
    # Wrapped before the node is started, or the first start races unwrapped.
    assert wrap_at < up_at, 'the wrap must be applied before the node is started'
    assert 'docker_cmd=docker_cmd' in src


def test_a_single_service_node_is_not_wrapped(tmpdir_path) -> None:
    """Nothing shares its namespace, so its app owning PID 1 is correct."""
    path = _compose(tmpdir_path, {'image': 'nginx', 'command': ['nginx']})
    # The helper itself still wraps on request; the guard is the caller's
    # sidecar check, asserted above. This pins that a lone service has no
    # sidecars to find.
    from scenarioforge.builders.topology import _compose_shared_namespace_services

    assert _compose_shared_namespace_services(path, 'docker-13') == []
