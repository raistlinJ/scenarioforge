"""Namespace-sharing sidecars have to be started for the real run too.

Collapsing a multi-service vuln onto one network namespace gives its sidecars
`network_mode: service:<node>`, which makes them depend on the node.
`docker compose up -d <node>` starts a service's *dependencies*, and this
dependency runs the other way -- so CORE brings the node up alone. Preflight
compensates with an explicit sidecar start, but preflight tears its containers
down again before CORE begins, and nothing repeated it afterwards.

dataset-catalog-coverage-005: preflight started and removed
`docker-13conf-etcd-1`, nothing started it again, `apisix` ran with no etcd and
exited. The start-recovery restart revived it but invalidated CORE's veth/netns,
so the session never left "configuration" and the run failed as
"CORE never finished instantiating router-1, router-2, router-3".
"""

from __future__ import annotations

import os
import tempfile

import pytest
import yaml

from scenarioforge import cli


class _Proc:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def staged(monkeypatch):
    """A compose tree on disk plus a recorder for the docker commands run."""
    root = tempfile.mkdtemp(prefix='sidecars_')
    calls: list[list[str]] = []

    def _compose_for(node: str, services: dict) -> str:
        path = os.path.join(root, node, 'docker-compose.yml')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as fh:
            yaml.safe_dump({'services': services}, fh, sort_keys=False)
        return path

    monkeypatch.setattr(
        cli, '_docker_node_compose_path',
        lambda name: os.path.join(root, name, 'docker-compose.yml'), raising=False,
    )
    from scenarioforge.builders import topology
    monkeypatch.setattr(
        topology, '_docker_node_compose_path',
        lambda name, out_base='/tmp/vulns': os.path.join(root, name, 'docker-compose.yml'),
    )

    def _fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return _Proc(0)

    monkeypatch.setattr(cli, '_run_docker_cmd', _fake_run)
    return _compose_for, calls


def test_the_sidecars_of_a_multi_service_node_are_started(staged) -> None:
    compose_for, calls = staged
    compose_for('docker-13', {
        'docker-13': {'image': 'apisix'},
        'etcd': {'image': 'etcd', 'network_mode': 'service:docker-13'},
    })
    started = cli._start_namespace_sharing_sidecars(['docker-13'])
    assert started and started[0]['services'] == ['etcd']
    assert any('etcd' in call and 'up' in call for call in calls), calls


def test_a_single_service_node_runs_no_extra_command(staged) -> None:
    compose_for, calls = staged
    compose_for('docker-11', {'docker-11': {'image': 'nginx'}})
    assert cli._start_namespace_sharing_sidecars(['docker-11']) == []
    assert calls == []


def test_a_node_with_no_compose_is_skipped(staged) -> None:
    _compose_for, calls = staged
    assert cli._start_namespace_sharing_sidecars(['docker-99']) == []
    assert calls == []


def test_every_sidecar_of_a_node_is_started_in_one_command(staged) -> None:
    compose_for, calls = staged
    compose_for('docker-12', {
        'docker-12': {'image': 'apisix'},
        'etcd': {'image': 'etcd', 'network_mode': 'service:docker-12'},
        'dashboard': {'image': 'dash', 'network_mode': 'service:docker-12'},
    })
    started = cli._start_namespace_sharing_sidecars(['docker-12'])
    assert sorted(started[0]['services']) == ['dashboard', 'etcd']
    ups = [c for c in calls if 'up' in c]
    assert len(ups) == 1, ups
    assert 'etcd' in ups[0] and 'dashboard' in ups[0]
    # Images are already built by preflight; rebuilding here would be wasted work.
    assert '--no-build' in ups[0]
    # And never the node: see test_it_never_restarts_the_node_core_is_running.
    assert '--no-deps' in ups[0]


def test_a_failed_start_is_reported_and_does_not_raise(staged, monkeypatch) -> None:
    compose_for, _calls = staged
    compose_for('docker-13', {
        'docker-13': {'image': 'apisix'},
        'etcd': {'image': 'etcd', 'network_mode': 'service:docker-13'},
    })
    monkeypatch.setattr(cli, '_run_docker_cmd', lambda *a, **k: _Proc(1, 'boom'))
    started = cli._start_namespace_sharing_sidecars(['docker-13'])
    assert started[0]['rc'] == 1


def test_it_runs_before_the_wait_not_after() -> None:
    """Waiting first would only watch a sidecar-less node fail."""
    import inspect

    src = inspect.getsource(cli._ensure_docker_nodes_running)
    start_at = src.index('_start_namespace_sharing_sidecars(names)')
    wait_at = src.index('_wait_for_docker_running(names')
    assert start_at < wait_at, src


def test_the_command_uses_the_project_name_core_daemon_uses(staged) -> None:
    """core-daemon derives the project from the `<node>conf` directory it runs in.

    Without `-p` the project comes from the compose file's own directory, so the
    sidecar looks for `service:<node>` in a project holding no such container and
    fails having touched nothing. Preflight forces the same name for the same
    reason. Seen as "Failed starting namespace-sharing sidecar(s) ... rc=1".
    """
    compose_for, calls = staged
    compose_for('docker-13', {
        'docker-13': {'image': 'apisix'},
        'etcd': {'image': 'etcd', 'network_mode': 'service:docker-13'},
    })
    cli._start_namespace_sharing_sidecars(['docker-13'])
    up = next(c for c in calls if 'up' in c)
    assert '-p' in up, up
    assert up[up.index('-p') + 1] == 'docker-13conf', up


def test_a_failure_reports_compose_stderr(staged, monkeypatch) -> None:
    """stdout alone said "1 Creating" and named no cause."""
    compose_for, _calls = staged
    compose_for('docker-13', {
        'docker-13': {'image': 'apisix'},
        'etcd': {'image': 'etcd', 'network_mode': 'service:docker-13'},
    })
    seen: dict = {}

    def _fail(*_a, **_k):
        return _Proc(1, stdout='1 Creating', stderr='no such service: docker-13')

    monkeypatch.setattr(cli, '_run_docker_cmd', _fail)
    monkeypatch.setattr(cli.logging, 'warning', lambda msg, *a: seen.setdefault('msg', msg % a))
    cli._start_namespace_sharing_sidecars(['docker-13'])
    assert 'no such service' in seen.get('msg', ''), seen


def test_it_never_restarts_the_node_core_is_running(staged) -> None:
    """`--no-deps`, or compose takes the node down with the sidecars.

    Each sidecar declares `depends_on: [<node>]`. Without `--no-deps` compose
    recreates and restarts the node CORE is already running, destroying the veth
    and network namespace CORE built and stranding every sidecar sharing it.
    Measured on dataset-catalog-coverage-005: compose logged "Container
    docker-12 Starting / Started", the sidecars failed with "runc create failed:
    can't get final child's PID from pipe: EOF", and both nodes ended up exited.
    """
    compose_for, calls = staged
    compose_for('docker-12', {
        'docker-12': {'image': 'apisix'},
        'etcd': {'image': 'etcd', 'network_mode': 'service:docker-12',
                 'depends_on': ['docker-12']},
    })
    cli._start_namespace_sharing_sidecars(['docker-12'])
    up = next(c for c in calls if 'up' in c)
    assert '--no-deps' in up, up
    # The node is never named on the command line either.
    assert 'docker-12' not in up[up.index('up'):], up
