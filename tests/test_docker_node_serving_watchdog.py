"""A container can be `running` while the service inside it is wedged.

Measured on the CORE VM: Nexus 3.21.1 lost a race bootstrapping its OrientDB
databases, logged "Failed to start nexus", began shutting down and then
deadlocked in OSGi teardown. The JVM sat at ~50% CPU and never exited, so
Docker reported the container `running` with `RestartCount=0` and nothing ever
served on 8081. `restart: on-failure` only fires when a container *exits*, so
nothing recovered it and the run failed several minutes later with a bare
"execute FAIL" naming no node.

The checks here pin the two properties that keep the detector from doing harm:
it only judges a node on a definite answer, and it separates "slow" from
"wedged".
"""

from types import SimpleNamespace

import pytest

from scenarioforge import cli


# Real /proc/net/tcp from a container: 0x1F91 == 8081 listening, plus an
# established connection that must not be mistaken for one.
PROC_NET_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 00000000:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0
   1: 0100007F:9C40 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0
"""


def test_listening_ports_are_parsed_from_proc():
    assert _ports(PROC_NET_TCP) == {8081}


def test_established_sockets_are_not_reported_as_listening():
    established = "  sl  local_address rem_address   st\n   1: 0100007F:9C40 0100007F:C350 01\n"
    assert _ports(established) == set()


def _ports(text):
    return cli._parse_proc_net_tcp_listening_ports(text)


def test_garbage_input_yields_no_ports_rather_than_raising():
    for text in ('', 'not a table', '   0: nocolon 0A\n'):
        assert _ports(text) == set()


def _serving_env(monkeypatch, *, listening, log_markers):
    """Drive the wait loop with scripted docker responses."""
    calls = {'restarted': []}
    marker_state = {'i': 0}

    def _docker(cmd, **_kwargs):
        joined = ' '.join(cmd)
        if 'ExposedPorts' in joined:
            return SimpleNamespace(returncode=0, stdout='{"8081/tcp":{}}')
        if 'logs' in cmd:
            markers = log_markers
            idx = min(marker_state['i'], len(markers) - 1)
            marker_state['i'] += 1
            return SimpleNamespace(returncode=0, stdout=markers[idx])
        if 'exec' in cmd:
            if listening is None:
                return SimpleNamespace(returncode=1, stdout='')
            return SimpleNamespace(returncode=0, stdout=listening)
        return SimpleNamespace(returncode=0, stdout='')

    monkeypatch.setattr(cli, '_run_docker_cmd', _docker)
    monkeypatch.setattr(cli.time, 'sleep', lambda *_a, **_k: None)
    monkeypatch.setattr(
        cli, '_restart_not_running_docker_nodes',
        lambda names, **_k: calls['restarted'].append(list(names)) or [{'ok': True}],
    )
    return calls


def test_node_serving_its_exposed_port_is_left_alone(monkeypatch):
    _serving_env(monkeypatch, listening=PROC_NET_TCP, log_markers=['x'])

    result = cli._wait_for_docker_nodes_serving(['docker-9'], timeout_s=5.0, quiet_s=0.0)

    assert result['served'] == ['docker-9']
    assert result['not_serving'] == []


# 0x138D == 5005, the JVM debug port, opened long before the application is up.
PROC_NET_TCP_DEBUG_PORT_ONLY = """\
  sl  local_address rem_address   st
   0: 00000000:138D 00000000:0000 0A
"""


def test_a_port_opened_early_does_not_certify_the_service(monkeypatch):
    """Captured from the wedged container: 5005 listening, 8081 dead.

    A stalled JVM keeps whatever it bound before it stalled, so accepting any
    single exposed port would have declared the hung node healthy.
    """
    def _docker(cmd, **_kwargs):
        joined = ' '.join(cmd)
        if 'ExposedPorts' in joined:
            return SimpleNamespace(returncode=0, stdout='{"8081/tcp":{},"5005/tcp":{}}')
        if 'logs' in cmd:
            return SimpleNamespace(returncode=0, stdout='frozen')
        return SimpleNamespace(returncode=0, stdout=PROC_NET_TCP_DEBUG_PORT_ONLY)

    monkeypatch.setattr(cli, '_run_docker_cmd', _docker)
    monkeypatch.setattr(cli.time, 'sleep', lambda *_a, **_k: None)

    result = cli._wait_for_docker_nodes_serving(['docker-9'], timeout_s=0.05, quiet_s=0.0)

    assert result['served'] == []
    assert result['hung'] == ['docker-9']


def test_unreadable_container_is_skipped_not_condemned(monkeypatch):
    """`docker exec` failing means unknown, which must never mean unhealthy.

    Distroless and shell-less images cannot be probed at all; judging them on a
    failed exec would restart perfectly healthy nodes.
    """
    _serving_env(monkeypatch, listening=None, log_markers=['x'])

    result = cli._wait_for_docker_nodes_serving(['docker-9'], timeout_s=5.0, quiet_s=0.0)

    assert result['skipped'] == ['docker-9']
    assert result['not_serving'] == []
    assert result['hung'] == []


def test_node_exposing_no_port_is_never_waited_on(monkeypatch):
    """Traffic-only and shell-only nodes have no readiness to assert."""
    def _docker(cmd, **_kwargs):
        if 'ExposedPorts' in ' '.join(cmd):
            return SimpleNamespace(returncode=0, stdout='null')
        raise AssertionError('must not probe a node with no exposed port')

    monkeypatch.setattr(cli, '_run_docker_cmd', _docker)

    result = cli._wait_for_docker_nodes_serving(['docker-7'], timeout_s=5.0, quiet_s=0.0)

    assert result['skipped'] == ['docker-7']
    assert result['not_serving'] == []


def test_still_logging_counts_as_slow_not_hung(monkeypatch):
    """A booting service must be waited out, not torn down.

    Nexus takes 93-138s to start, so treating "not yet listening" as failure
    would kill it mid-boot every time.
    """
    _serving_env(
        monkeypatch,
        listening="  sl  local_address rem_address   st\n",  # nothing listening
        log_markers=['line-1', 'line-2', 'line-3', 'line-4', 'line-5'],
    )

    result = cli._wait_for_docker_nodes_serving(['docker-9'], timeout_s=0.05, quiet_s=30.0)

    assert result['not_serving'] == ['docker-9']
    assert result['hung'] == []


def test_silent_and_not_listening_is_reported_as_hung(monkeypatch):
    _serving_env(
        monkeypatch,
        listening="  sl  local_address rem_address   st\n",
        log_markers=['frozen'],  # same marker every poll
    )

    result = cli._wait_for_docker_nodes_serving(['docker-9'], timeout_s=0.05, quiet_s=0.0)

    assert result['hung'] == ['docker-9']


def test_hung_node_is_reported_but_not_restarted_by_default(monkeypatch):
    """Recreating the container discards the veth CORE attached to it.

    The service would come back healthy but off the topology, so recovery is
    the operator's call and detection is what ships on by default.
    """
    calls = _serving_env(
        monkeypatch,
        listening="  sl  local_address rem_address   st\n",
        log_markers=['frozen'],
    )
    monkeypatch.delenv('CORETG_DOCKER_RESTART_HUNG_SERVICE', raising=False)
    monkeypatch.setenv('CORETG_DOCKER_SERVING_QUIET_S', '0')

    cli._ensure_docker_nodes_serving(['docker-9'], serving_wait_s=0.05)

    assert calls['restarted'] == []


def test_restart_happens_only_when_explicitly_enabled(monkeypatch):
    calls = _serving_env(
        monkeypatch,
        listening="  sl  local_address rem_address   st\n",
        log_markers=['frozen'],
    )
    monkeypatch.setenv('CORETG_DOCKER_RESTART_HUNG_SERVICE', '1')
    monkeypatch.setenv('CORETG_DOCKER_SERVING_QUIET_S', '0')

    cli._ensure_docker_nodes_serving(['docker-9'], serving_wait_s=0.05)

    assert calls['restarted'] == [['docker-9']]


@pytest.mark.parametrize('wait_s', [0.0, -1.0])
def test_zero_wait_disables_the_check_entirely(monkeypatch, wait_s):
    def _docker(*_a, **_k):
        raise AssertionError('no docker calls when disabled')

    monkeypatch.setattr(cli, '_run_docker_cmd', _docker)

    assert cli._ensure_docker_nodes_serving(['docker-9'], serving_wait_s=wait_s)['not_serving'] == []
