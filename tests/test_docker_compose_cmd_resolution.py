"""Never select a compose binary the host does not have.

`_docker_compose_cmd` probes `docker compose version` and fell back to the v1
`docker-compose` on any non-zero result. But the probe also fails on a sudo
hiccup or a timeout under load, and v1 is not installed on a modern CORE VM, so
the fallback chose a binary that cannot exist. Every later command then died as
"command not found" -- producing no output, which is why the failure surfaced as
a bare rc=1:

    docker compose pull failed (node=flaggenslot-1 rc=1)
    command: sudo -S -p  docker-compose -p flaggenslot-1conf ... pull inject_copy

A failed probe is not proof that the v2 plugin is absent.
"""

from __future__ import annotations

import subprocess

import pytest

from scenarioforge.builders import topology as topo


class _Proc:
    def __init__(self, returncode):
        self.returncode = returncode


@pytest.fixture(autouse=True)
def _no_sudo(monkeypatch):
    monkeypatch.delenv('CORETG_DOCKER_USE_SUDO', raising=False)
    monkeypatch.delenv('CORETG_DOCKER_SUDO_PASSWORD', raising=False)


def _probe(monkeypatch, *, rc=0, exc=None):
    def fake_run(args, **kwargs):
        if exc is not None:
            raise exc
        return _Proc(rc)
    monkeypatch.setattr(topo.subprocess, 'run', fake_run)


def _which(monkeypatch, *, v1_installed):
    monkeypatch.setattr(
        topo.shutil, 'which',
        lambda name: '/usr/bin/docker-compose' if (name == 'docker-compose' and v1_installed) else None,
    )


def test_uses_v2_when_probe_succeeds(monkeypatch):
    _probe(monkeypatch, rc=0)
    _which(monkeypatch, v1_installed=False)
    assert topo._docker_compose_cmd() == ['docker', 'compose']


def test_failed_probe_still_uses_v2_when_v1_is_not_installed(monkeypatch):
    """The regression: v1 was chosen on a host that never had it."""
    _probe(monkeypatch, rc=1)
    _which(monkeypatch, v1_installed=False)
    assert topo._docker_compose_cmd() == ['docker', 'compose']


def test_probe_timeout_still_uses_v2_when_v1_is_not_installed(monkeypatch):
    _probe(monkeypatch, exc=subprocess.TimeoutExpired(cmd='docker', timeout=10))
    _which(monkeypatch, v1_installed=False)
    assert topo._docker_compose_cmd() == ['docker', 'compose']


def test_falls_back_to_v1_only_when_it_actually_exists(monkeypatch):
    _probe(monkeypatch, rc=1)
    _which(monkeypatch, v1_installed=True)
    assert topo._docker_compose_cmd() == ['docker-compose']


def test_sudo_prefix_is_preserved_on_the_fallback_path(monkeypatch):
    monkeypatch.setenv('CORETG_DOCKER_USE_SUDO', '1')
    monkeypatch.setenv('CORETG_DOCKER_SUDO_PASSWORD', 'secret')
    monkeypatch.setattr(topo, '_DOCKER_SUDO_PASSWORD_CACHE', None, raising=False)
    _probe(monkeypatch, rc=1)
    _which(monkeypatch, v1_installed=False)
    assert topo._docker_compose_cmd() == ['sudo', '-S', '-p', '', 'docker', 'compose']
