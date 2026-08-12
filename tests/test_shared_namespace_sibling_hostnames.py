"""Sibling service names must resolve once a stack shares one namespace.

The repair collapses a multi-service vuln onto the node's network namespace and
maps each sidecar's name to 127.0.0.1 in the node's `extra_hosts`, so recipe
config addressing a sidecar by name keeps working. Two gaps in that:

1. The node service is renamed to the node's name, so its *recipe* name
   disappears. `zabbix/CVE-2017-2824`'s `agent` and `web` carry
   `ZBX_SRV_HOST=server`, and `_compose_service_is_referenced` does not inspect
   environment values, so `server` is dropped without an alias.
2. Sidecars get no mapping at all, and cannot: Docker refuses `extra_hosts`
   alongside a shared namespace -- measured directly, `docker run --network
   container:X --add-host mysql:127.0.0.1` fails with "conflicting options:
   custom host-to-IP mapping and the network mode". Their references have to be
   rewritten in the environment instead.
"""

from __future__ import annotations

from scenarioforge.utils.vuln_process import (
    _compose_source_service,
    _record_compose_source_service,
    _rewrite_env_hostnames_to_loopback,
)


# --------------------------------------------------------------------------- #
# Remembering the recipe's own name for the renamed node service
# --------------------------------------------------------------------------- #

def test_the_source_name_round_trips_through_dict_labels() -> None:
    svc: dict = {'labels': {'existing': 'kept'}}
    _record_compose_source_service(svc, 'server')
    assert _compose_source_service(svc) == 'server'
    assert svc['labels']['existing'] == 'kept'


def test_the_source_name_round_trips_through_list_labels() -> None:
    svc: dict = {'labels': ['traefik.enable=false']}
    _record_compose_source_service(svc, 'server')
    assert _compose_source_service(svc) == 'server'
    assert 'traefik.enable=false' in svc['labels']


def test_recording_twice_does_not_duplicate_a_list_label() -> None:
    svc: dict = {'labels': []}
    _record_compose_source_service(svc, 'server')
    _record_compose_source_service(svc, 'server')
    assert len([x for x in svc['labels'] if 'source_service' in x]) == 1


def test_a_service_with_no_labels_gains_them() -> None:
    svc: dict = {}
    _record_compose_source_service(svc, 'server')
    assert _compose_source_service(svc) == 'server'


def test_no_record_means_no_name() -> None:
    assert _compose_source_service({}) == ''
    assert _compose_source_service({'labels': ['a=b']}) == ''
    assert _compose_source_service(None) == ''


# --------------------------------------------------------------------------- #
# Pointing sidecar environment at loopback
# --------------------------------------------------------------------------- #

def test_the_zabbix_sidecar_environment_is_rewritten() -> None:
    svc = {'environment': [
        'ZBX_SRV_HOST=server',
        'ZBX_SRV_HOST_ACT=server',
        'DATABASE_HOST=mysql',
        'DATABASE_PORT=3306',
        'DATABASE_USER=root',
    ]}
    changed = _rewrite_env_hostnames_to_loopback(svc, {'server', 'mysql', 'web', 'agent'})
    assert sorted(changed) == ['DATABASE_HOST', 'ZBX_SRV_HOST', 'ZBX_SRV_HOST_ACT']
    assert 'ZBX_SRV_HOST=127.0.0.1' in svc['environment']
    assert 'DATABASE_HOST=127.0.0.1' in svc['environment']
    # Untouched values stay exactly as they were.
    assert 'DATABASE_PORT=3306' in svc['environment']
    assert 'DATABASE_USER=root' in svc['environment']


def test_mapping_style_environment_is_rewritten_too() -> None:
    svc = {'environment': {'DATABASE_HOST': 'mysql', 'DATABASE_PORT': 3306}}
    changed = _rewrite_env_hostnames_to_loopback(svc, {'mysql'})
    assert changed == ['DATABASE_HOST']
    assert svc['environment']['DATABASE_HOST'] == '127.0.0.1'
    assert svc['environment']['DATABASE_PORT'] == 3306


def test_a_url_that_merely_contains_the_name_is_left_alone() -> None:
    """Whole-value matches only; rewriting inside a URL risks mangling it."""
    svc = {'environment': ['DSN=mysql://root@mysql:3306/zabbix']}
    assert _rewrite_env_hostnames_to_loopback(svc, {'mysql'}) == []
    assert svc['environment'] == ['DSN=mysql://root@mysql:3306/zabbix']


def test_names_that_are_not_siblings_are_left_alone() -> None:
    svc = {'environment': ['UPSTREAM=example.com', 'DATABASE_HOST=mysql']}
    changed = _rewrite_env_hostnames_to_loopback(svc, {'mysql'})
    assert changed == ['DATABASE_HOST']
    assert 'UPSTREAM=example.com' in svc['environment']


def test_a_service_without_environment_is_untouched() -> None:
    svc: dict = {'image': 'mysql:5'}
    assert _rewrite_env_hostnames_to_loopback(svc, {'mysql'}) == []
    assert svc == {'image': 'mysql:5'}
    assert _rewrite_env_hostnames_to_loopback(None, {'mysql'}) == []
    assert _rewrite_env_hostnames_to_loopback({'environment': ['A=b']}, set()) == []
