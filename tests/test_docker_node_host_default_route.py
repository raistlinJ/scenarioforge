"""Host-side default-route installation for docker nodes.

The in-node DockerDefaultRoute service can only work when the container has
`ip`, NET_ADMIN, a shell, and the service assigned. Images like vulhub/kibana
ship no iproute2 and cannot install it (CentOS 7 mirrors are gone, and inside a
CORE topology there is no route out yet anyway), and a container started from an
unprepared compose file runs as a non-root user with no NET_ADMIN. The host has
all of it, so the route is installed via nsenter into the container's netns.
"""

import subprocess

import pytest

from scenarioforge.builders import topology


@pytest.mark.parametrize(
    "cidr,expected",
    [
        ("10.0.33.2/24", "10.0.33.1"),
        ("10.0.33.1/24", "10.0.33.2"),  # node holds the first host address
        ("10.0.33.2/16", "10.0.0.1"),  # not a /24
        ("192.168.194.5/24", "192.168.194.1"),
        ("172.28.151.2/30", "172.28.151.1"),
        ("10.0.0.1/31", None),  # too narrow to derive
        ("10.0.0.5/32", None),
        ("not-an-ip", None),
        ("", None),
    ],
)
def test_derive_gateway(cidr, expected):
    assert topology._derive_gateway(cidr) == expected


class _Host:
    """Fake host: one container, scripted addresses and route state."""

    def __init__(self, *, pid="650", addrs=None, has_default=False, replace_rc=0, add_rc=0):
        self.pid = pid
        self.addrs = addrs if addrs is not None else [
            "2: eth1    inet 10.0.33.2/24 brd 10.0.33.255 scope global eth1"
        ]
        self.has_default = has_default
        self.replace_rc = replace_rc
        self.add_rc = add_rc
        self.calls = []

    def run(self, args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        call = [str(a) for a in args]
        self.calls.append(call)

        def done(rc, out=""):
            return subprocess.CompletedProcess(args, rc, stdout=out)

        if "inspect" in call:
            return done(0, self.pid + "\n")
        if call[-3:] == ["route", "show", "default"]:
            return done(0, "default via 10.0.33.1 dev eth1\n" if self.has_default else "")
        if "addr" in call and "show" in call:
            return done(0, "\n".join(self.addrs))
        if "replace" in call:
            return done(self.replace_rc, "" if self.replace_rc == 0 else "RTNETLINK answers: Network unreachable")
        if "add" in call and "route" in call:
            return done(self.add_rc, "" if self.add_rc == 0 else "RTNETLINK answers: File exists")
        return done(0)

    def route_cmds(self):
        return [c for c in self.calls if "route" in c and ("replace" in c or "add" in c)]


@pytest.fixture(autouse=True)
def _no_sudo(monkeypatch):
    monkeypatch.delenv("CORETG_DOCKER_USE_SUDO", raising=False)
    monkeypatch.delenv("CORETG_DEFAULT_GW", raising=False)
    monkeypatch.setattr(topology, "_docker_sudo_password", lambda: None)


def test_sets_default_route_via_nsenter(monkeypatch):
    host = _Host()
    monkeypatch.setattr(topology.subprocess, "run", host.run)

    results = topology._ensure_docker_node_default_routes(["docker-2"])

    assert "set default via 10.0.33.1 dev eth1" in results["docker-2"]
    cmd = host.route_cmds()[0]
    # Must enter the container's network namespace by pid, not exec inside it:
    # the container may have no `ip`, no NET_ADMIN, and no root user.
    assert cmd[:4] == ["nsenter", "-t", "650", "-n"]
    assert "docker" not in cmd and "exec" not in cmd
    assert cmd[-8:] == ["ip", "route", "replace", "default", "via", "10.0.33.1", "dev", "eth1"]


def test_noop_when_default_route_already_present(monkeypatch):
    host = _Host(has_default=True)
    monkeypatch.setattr(topology.subprocess, "run", host.run)

    results = topology._ensure_docker_node_default_routes(["docker-2"])

    assert results["docker-2"] == "already set"
    assert host.route_cmds() == []


def test_skips_container_with_no_pid(monkeypatch):
    host = _Host(pid="0")
    monkeypatch.setattr(topology.subprocess, "run", host.run)

    results = topology._ensure_docker_node_default_routes(["docker-2"])

    assert "no container pid" in results["docker-2"]
    assert host.route_cmds() == []


def test_prefers_core_interface_over_docker_bridge(monkeypatch):
    host = _Host(addrs=[
        "1: eth0    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0",
        "2: eth1    inet 10.0.33.2/24 brd 10.0.33.255 scope global eth1",
    ])
    monkeypatch.setattr(topology.subprocess, "run", host.run)

    results = topology._ensure_docker_node_default_routes(["docker-2"])

    assert "10.0.33.1" in results["docker-2"] and "eth1" in results["docker-2"]


def test_falls_back_to_eth0_when_it_is_the_only_interface(monkeypatch):
    """A CORE-attached interface is often eth0 under network_mode: none."""
    host = _Host(addrs=["1: eth0    inet 10.0.33.2/24 brd 10.0.33.255 scope global eth0"])
    monkeypatch.setattr(topology.subprocess, "run", host.run)

    results = topology._ensure_docker_node_default_routes(["docker-2"])

    assert "set default via 10.0.33.1 dev eth0" in results["docker-2"]


def test_ignores_loopback(monkeypatch):
    host = _Host(addrs=["1: lo    inet 127.0.0.1/8 scope global lo"])
    monkeypatch.setattr(topology.subprocess, "run", host.run)

    results = topology._ensure_docker_node_default_routes(["docker-2"])

    assert "no global IPv4 address" in results["docker-2"]


def test_falls_back_to_route_add_when_replace_fails(monkeypatch):
    host = _Host(replace_rc=2, add_rc=0)
    monkeypatch.setattr(topology.subprocess, "run", host.run)

    results = topology._ensure_docker_node_default_routes(["docker-2"])

    assert "set default via" in results["docker-2"]
    verbs = [c for c in host.route_cmds()]
    assert any("replace" in c for c in verbs) and any("add" in c for c in verbs)


def test_reports_failure_with_the_real_error(monkeypatch):
    host = _Host(replace_rc=2, add_rc=2)
    monkeypatch.setattr(topology.subprocess, "run", host.run)

    results = topology._ensure_docker_node_default_routes(["docker-2"])

    assert results["docker-2"].startswith("failed")
    assert "RTNETLINK" in results["docker-2"]


def test_explicit_gateway_override(monkeypatch):
    monkeypatch.setenv("CORETG_DEFAULT_GW", "10.0.33.254")
    host = _Host()
    monkeypatch.setattr(topology.subprocess, "run", host.run)

    results = topology._ensure_docker_node_default_routes(["docker-2"])

    assert "10.0.33.254" in results["docker-2"]


def test_handles_multiple_nodes_independently(monkeypatch):
    host = _Host()
    monkeypatch.setattr(topology.subprocess, "run", host.run)

    results = topology._ensure_docker_node_default_routes(["docker-1", "docker-2", ""])

    assert set(results) == {"docker-1", "docker-2"}


def test_empty_input_is_a_noop(monkeypatch):
    host = _Host()
    monkeypatch.setattr(topology.subprocess, "run", host.run)
    assert topology._ensure_docker_node_default_routes([]) == {}
    assert host.calls == []


def test_uses_sudo_prefix_when_configured(monkeypatch):
    monkeypatch.setenv("CORETG_DOCKER_USE_SUDO", "1")
    host = _Host()
    monkeypatch.setattr(topology.subprocess, "run", host.run)

    topology._ensure_docker_node_default_routes(["docker-2"])

    assert host.route_cmds()[0][0] == "sudo"
