"""A session stuck in `configuration` is not a deployed scenario.

CORE leaving a session in `configuration` means it never instantiated the
topology. Compose has still started the containers -- ScenarioForge brings those
up itself -- so the run looked healthy and reported success while every node sat
with nothing but loopback: no interface, no address, no reachable service.

`network_mode: none` is deliberate; CORE is what later moves a veth into the
namespace. So "containers running" and "scenario deployed" are different claims,
and only the second one matters.
"""

from __future__ import annotations

import subprocess

import pytest

from scenarioforge import cli


def _tolerate(**kwargs):
    defaults = dict(
        session_state='configuration',
        docker_names=['docker-13'],
        docker_runtime={'not_running': []},
        unwired_nodes=[],
    )
    defaults.update(kwargs)
    return cli._should_tolerate_configuration_state_for_docker(
        defaults.pop('session_state'),
        defaults.pop('docker_names'),
        defaults.pop('docker_runtime'),
        **defaults,
    )


def test_configuration_is_accepted_only_when_nodes_are_wired():
    assert _tolerate() is True


def test_configuration_is_rejected_when_a_node_has_no_interface():
    """The false success this exists to stop."""
    assert _tolerate(unwired_nodes=['docker-13']) is False


def test_existing_guards_still_apply():
    assert _tolerate(docker_runtime={'not_running': ['docker-13']}) is False
    assert _tolerate(mismatches=[{'name': 'docker-13'}]) is False
    assert _tolerate(docker_names=[]) is False
    assert _tolerate(session_state='runtime') is False


class _Docker:
    def __init__(self, addrs_by_node, rc=0):
        self.addrs = addrs_by_node
        self.rc = rc

    def __call__(self, argv, **kwargs):
        node = argv[2]
        return subprocess.CompletedProcess(argv, self.rc, stdout=self.addrs.get(node, ''), stderr='')


@pytest.fixture
def docker(monkeypatch):
    def _install(addrs, rc=0):
        import shutil
        monkeypatch.setattr(shutil, 'which', lambda _n: '/usr/bin/docker')
        monkeypatch.setattr(subprocess, 'run', _Docker(addrs, rc))
    return _install


def test_a_node_with_only_loopback_is_reported_unwired(docker):
    """`ip -o -4 addr` filtered of lo returns nothing for an unwired node."""
    docker({'docker-13': '', 'docker-14': 'eth0\n'})
    assert cli._docker_nodes_without_core_interfaces(['docker-13', 'docker-14']) == ['docker-13']


def test_a_wired_node_is_not_reported(docker):
    docker({'docker-13': 'eth0\n'})
    assert cli._docker_nodes_without_core_interfaces(['docker-13']) == []


def test_an_uninspectable_node_is_not_called_unwired(docker):
    """This decides whether to fail a run, so unknown must not mean broken."""
    docker({'docker-13': ''}, rc=1)
    assert cli._docker_nodes_without_core_interfaces(['docker-13']) == []


def test_the_failure_says_what_is_actually_wrong():
    """"stayed in configuration" alone does not tell an operator anything."""
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / 'scenarioforge' / 'cli.py').read_text(
        encoding='utf-8', errors='ignore'
    )
    assert 'never instantiated the' in source
    assert 'containers are running but the scenario is not deployed' in source
