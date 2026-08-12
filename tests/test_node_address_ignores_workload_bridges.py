"""A node's address must be the one CORE gave it, not one it made itself.

`_node_cidrs` takes the first global IPv4 the node reports. A workload that runs
its own Docker daemon has two: the address CORE assigned to eth0, and the
172.17.0.1/16 its docker0 bridge carries. docker0 enumerated first, so
`docker/unauthorized-rce` was identified by its private bridge and every probe
of it came back "packets dropped (no-route) and no segmentation rule covers
this path" -- nothing on the CORE network can reach 172.17.0.1
(dataset-catalog-coverage-013).

CORE names the interfaces it assigns eth0..ethN, so excluding Docker's and
libvirt's bridge names cannot hide one.
"""

from __future__ import annotations

from webapp.artifact_checks import ports_probe_script


def _generated():
    return ports_probe_script()


def _is_own_bridge():
    """Pull the helper out of the generated script and make it callable."""
    lines = _generated().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith('def _is_own_bridge'))
    namespace: dict = {}
    exec(compile("\n".join(lines[start:start + 3]), '<helper>', 'exec'), namespace)
    return namespace['_is_own_bridge']


def test_the_generated_probe_script_is_valid_python() -> None:
    compile(_generated(), '<ports_probe>', 'exec')


def test_dockers_own_bridges_are_excluded() -> None:
    is_own = _is_own_bridge()
    for name in ('docker0', 'docker1', 'br-1a2b3c4d', 'virbr0'):
        assert is_own(name) is True, name


def test_core_assigned_interfaces_are_kept() -> None:
    is_own = _is_own_bridge()
    for name in ('eth0', 'eth1', 'eth10', 'ens3', 'lo'):
        assert is_own(name) is False, name


def test_a_trailing_colon_from_ip_output_is_tolerated() -> None:
    # `ip -o link show` prints "2: eth0:" style fields; the name may carry one.
    assert _is_own_bridge()('eth0:') is False
    assert _is_own_bridge()('docker0:') is True


def test_the_awk_filter_reaches_both_address_queries() -> None:
    """The fallback query (no `scope global`) needs the same filter.

    It exists for addresses carrying another scope, and a workload bridge would
    otherwise walk straight back in through it.
    """
    script = _generated()
    assert script.count('skip_if') >= 3, 'filter should be defined once and used by both queries'
    assert "ip -4 -o addr show scope global" in script
    assert "ip -4 -o addr show 2>/dev/null" in script


def test_the_nsenter_fallback_filters_too() -> None:
    """Reading the namespace from the CORE VM must not reintroduce the bridge."""
    assert '_is_own_bridge(line.split()[1])' in _generated()
