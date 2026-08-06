"""Services CORE co-locates cannot own per-container network options.

CORE runs a Docker node's stack in a single network namespace: it rewrites each
secondary service to ``network_mode: service:<node>`` and leaves the node-named
service on ``none``, whose namespace it manages. Docker refuses to create a
container that both joins another's namespace and asks for its own hostname,
ports, DNS and so on:

    service:node:1 Error response from daemon: conflicting options:
    hostname and the container type network mode

Nothing starts, every node reports "not running", and the cause appears only in
the core-daemon journal -- so the scenario looks deployed and is not.
"""

from __future__ import annotations

import pytest

from scenarioforge.utils import vuln_process


def _stack():
    return {
        'services': {
            'node': {
                'image': 'svc:1', 'hostname': 'smb-78a653',
                'expose': ['1445'], 'ports': ['1445:445'],
                'dns': ['1.1.1.1'], 'mac_address': '02:42:ac:11:00:02',
                'network_mode': 'none',
            },
            'inject_copy': {'image': 'alpine:3.19', 'network_mode': 'none'},
            'docker-13': {
                'image': 'svc:1', 'hostname': 'smb-78a653',
                'expose': ['1445'], 'network_mode': 'none',
            },
        }
    }


def test_secondary_services_lose_every_conflicting_option():
    out = vuln_process._strip_network_conflicts_from_secondary_services(_stack(), 'docker-13')
    node = out['services']['node']

    for key in vuln_process.CONTAINER_NETWORK_MODE_CONFLICTING_KEYS:
        assert key not in node, f'{key} would make Docker refuse the container'
    # Everything unrelated to networking is untouched.
    assert node['image'] == 'svc:1'
    assert node['network_mode'] == 'none'


def test_the_node_named_service_keeps_its_networking():
    """CORE does not rewrite that one, and it owns the namespace the rest join."""
    out = vuln_process._strip_network_conflicts_from_secondary_services(_stack(), 'docker-13')
    primary = out['services']['docker-13']

    assert primary['hostname'] == 'smb-78a653'
    # Its own exposed port survives; the secondaries' intent is merged in
    # alongside it rather than lost.
    assert '1445' in [str(p) for p in primary['expose']]


def test_primary_service_gets_a_stable_self_resolving_hostname():
    obj = {
        'services': {
            'inject_copy': {'image': 'alpine:3.19'},
            'docker-17': {
                'image': 'metabase:0.40.4',
                'network_mode': 'none',
                'extra_hosts': ['inject_copy:127.0.0.1'],
            },
        },
    }

    out = vuln_process._ensure_primary_service_hostname(obj, 'docker-17')
    primary = out['services']['docker-17']

    assert primary['hostname'] == 'docker-17'
    assert primary['extra_hosts'] == [
        'inject_copy:127.0.0.1',
        'docker-17:127.0.0.1',
    ]


def test_primary_service_preserves_explicit_hostname_and_mapping():
    obj = {
        'services': {
            'node': {
                'hostname': 'metabase-lab',
                'extra_hosts': {'metabase-lab': '127.0.1.1'},
            },
        },
    }

    out = vuln_process._ensure_primary_service_hostname(obj, 'node')

    assert out['services']['node']['hostname'] == 'metabase-lab'
    assert out['services']['node']['extra_hosts'] == {'metabase-lab': '127.0.1.1'}


def test_hostname_and_port_exposing_are_both_covered():
    """The two conflicts observed in the field, in that order."""
    keys = vuln_process.CONTAINER_NETWORK_MODE_CONFLICTING_KEYS
    assert 'hostname' in keys
    assert 'expose' in keys and 'ports' in keys


def test_strip_tolerates_junk():
    strip = vuln_process._strip_network_conflicts_from_secondary_services
    assert strip(None, 'docker-13') is None
    assert strip({}, 'docker-13') == {}
    assert strip({'services': 'nope'}, 'docker-13') == {'services': 'nope'}
    # An unnamed primary must not cause every service to be stripped blindly.
    out = strip({'services': {'a': {'hostname': 'h'}}}, '')
    assert 'hostname' not in out['services']['a']


def test_strip_runs_after_the_node_alias_exists():
    """It has to know which service is the node-named one to spare it."""
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / 'scenarioforge' / 'utils' / 'vuln_process.py').read_text(
        encoding='utf-8', errors='ignore'
    ).splitlines()
    alias = [i for i, l in enumerate(source) if '_ensure_service_named_as_node(obj, node_name' in l]
    strip = [i for i, l in enumerate(source) if '_strip_network_conflicts_from_secondary_services(obj, node_name)' in l]
    assert alias and strip, 'compose post-processing wiring changed'
    assert min(strip) > min(alias), 'the strip must follow the node alias step'


def test_self_resolving_hostname_is_applied_after_the_node_alias_exists():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / 'scenarioforge' / 'utils' / 'vuln_process.py').read_text(
        encoding='utf-8', errors='ignore'
    ).splitlines()
    alias = [i for i, line in enumerate(source) if '_ensure_service_named_as_node(obj, node_name' in line]
    hostname = [i for i, line in enumerate(source) if '_ensure_primary_service_hostname(obj, node_name)' in line]

    assert alias and hostname, 'compose post-processing wiring changed'
    assert min(hostname) > min(alias), 'the primary service does not exist before the alias step'


def test_port_intent_moves_to_the_node_service_rather_than_vanishing():
    """Reporting reads exposed ports from the compose file.

    Dropping them would quietly lose that, so they move to the service whose
    namespace every other one joins -- which is where they are reachable anyway.
    """
    obj = {
        'services': {
            'app': {'image': 'a', 'expose': ['80'], 'ports': ['8080:80'], 'network_mode': 'none'},
            'host-1': {'image': 'b', 'network_mode': 'none'},
        }
    }
    out = vuln_process._strip_network_conflicts_from_secondary_services(obj, 'host-1')

    assert 'expose' not in out['services']['app']
    assert 'ports' not in out['services']['app']
    # Published mapping collapses to the container-side port.
    assert out['services']['host-1']['expose'] == ['80']


def test_moved_ports_do_not_duplicate_what_the_node_already_exposes():
    obj = {
        'services': {
            'app': {'expose': ['80'], 'network_mode': 'none'},
            'host-1': {'expose': ['80', '443'], 'network_mode': 'none'},
        }
    }
    out = vuln_process._strip_network_conflicts_from_secondary_services(obj, 'host-1')
    assert out['services']['host-1']['expose'] == ['80', '443']
