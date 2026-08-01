"""Aliasing a service to the node name must not leave a twin behind.

CORE runs `docker compose up -d <node_name>`, so the compose file needs a
service under that exact key. The alias was a deepcopy that kept the original,
which built the identical image twice and created a container that is never
started:

    preflight build service=node          image=flaggenslot-1conf-node
    preflight build service=flaggenslot-1 image=flaggenslot-1conf-flaggenslot-1

Both from the same context. The copy is redundant -- but only when nothing else
names it, since a multi-service vuln wires itself together through that name.
"""

from __future__ import annotations

import pytest

from scenarioforge.utils import vuln_process


def _referenced(services, name):
    return vuln_process._compose_service_is_referenced(services, name)


def test_unreferenced_service_is_not_referenced():
    services = {'web': {'image': 'a'}, 'docker-1': {'image': 'a'}}
    assert _referenced(services, 'web') is False


@pytest.mark.parametrize(
    'sibling',
    [
        {'depends_on': ['web']},
        {'depends_on': {'web': {'condition': 'service_started'}}},
        {'network_mode': 'service:web'},
        {'ipc': 'service:web'},
        {'pid': 'service:web'},
        {'links': ['web']},
        {'links': ['web:upstream']},
        {'volumes_from': ['web']},
        {'volumes_from': ['web:ro']},
        {'extends': {'service': 'web'}},
    ],
    ids=lambda s: next(iter(s)) + '-' + str(next(iter(s.values())))[:24],
)
def test_every_wiring_form_counts_as_a_reference(sibling):
    services = {'web': {'image': 'a'}, 'db': dict({'image': 'b'}, **sibling)}
    assert _referenced(services, 'web') is True


def test_a_service_does_not_reference_itself():
    services = {'web': {'image': 'a', 'depends_on': ['web']}}
    assert _referenced(services, 'web') is False


def test_similar_names_are_not_confused():
    services = {'web': {'image': 'a'}, 'db': {'image': 'b', 'depends_on': ['website']}}
    assert _referenced(services, 'web') is False


def test_service_prefix_in_another_namespace_is_not_a_match():
    services = {'web': {'image': 'a'}, 'db': {'image': 'b', 'network_mode': 'service:webserver'}}
    assert _referenced(services, 'web') is False


def test_container_network_mode_is_not_a_service_reference():
    services = {'web': {'image': 'a'}, 'db': {'image': 'b', 'network_mode': 'container:web'}}
    assert _referenced(services, 'web') is False
