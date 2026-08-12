"""A Flow pivot edge must point at something a participant can reach.

The runtime check probes the target's port. When neither the edge nor the
target's offerings declare one it reports `no-target-port` and fails the run --
"the target exposes no port for this pivot ... the participant has no service
to reach".

Two of the 306 catalog vulns publish no port at all: `imagemagick/CVE-2020-29599`
and `openssl/CVE-2022-0778`, both "run a tool against a crafted file" bugs with
no service. A node carrying one of those plus a file-based flag generator has
nothing listening, so declaring a pivot to it asserts a path that cannot exist.
Seen as dataset-catalog-coverage-030's `docker-10 -> docker-8`.

The distinction that matters is "known to publish nothing" versus "no ports
found". A node whose offerings were never recorded yields an empty port list
too, and the runtime check reaches those services by probing live listeners --
skipping on an empty list alone dropped every pivot edge in the suite.
"""

from __future__ import annotations

import pytest

from webapp import app_backend as ab

PORTLESS = 'imagemagick/CVE-2020-29599'
LISTENING = 'influxdb/CVE-2019-20933'


@pytest.fixture
def pivot_edge(monkeypatch):
    """Drive one source->target pivot rule and report what survives."""
    def _run(target_node_extra: dict, *, target_ports=None, ports_by_offering=None):
        table = ports_by_offering if ports_by_offering is not None else {LISTENING: [8086]}

        def _ports_for_offering(name):
            if name not in table:
                raise KeyError(name)  # an offering we cannot resolve
            return list(table[name])

        monkeypatch.setattr(ab, '_flow_ports_for_offering', _ports_for_offering)
        rule = {'name': 'Pivot', 'target_node': 'docker-8', 'pivot_nodes': ['docker-10']}
        if target_ports is not None:
            rule['target_ports'] = target_ports
        monkeypatch.setattr(
            ab, '_flow_pivot_context_sources', lambda _ctx, _preview: [{'rules': [rule]}]
        )
        chain = [
            {'id': '1', 'name': 'docker-10', 'ip4': '10.0.0.10'},
            {'id': '2', 'name': 'docker-8', 'ip4': '10.0.0.8', **target_node_extra},
        ]
        rules = ab._flow_pivot_rules_for_chain({}, chain, pivot_context={})
        return [r for r in (rules or []) if r.get('target_name') == 'docker-8']

    return _run


def test_a_target_whose_only_offering_is_portless_gets_no_edge(pivot_edge) -> None:
    assert pivot_edge({'vulnerabilities': [PORTLESS]}, ports_by_offering={PORTLESS: []}) == []


def test_a_target_with_one_listening_offering_keeps_its_edge(pivot_edge) -> None:
    edges = pivot_edge({'vulnerabilities': [LISTENING]})
    assert len(edges) == 1, edges
    assert edges[0]['inferred_target_ports'] == ['8086']


def test_a_portless_vuln_beside_a_listening_one_keeps_its_edge(pivot_edge) -> None:
    """The node is reachable; only the one vuln is serviceless."""
    edges = pivot_edge(
        {'vulnerabilities': [PORTLESS, LISTENING]},
        ports_by_offering={PORTLESS: [], LISTENING: [8086]},
    )
    assert len(edges) == 1, edges


def test_a_target_with_no_recorded_offerings_keeps_its_edge(pivot_edge) -> None:
    """Unknown is not the same as none.

    Skipping whenever no port could be derived removed every pivot edge, since
    plenty of nodes never record their offerings and are reached by probing
    live listeners instead.
    """
    assert len(pivot_edge({})) == 1


def test_an_unresolvable_offering_keeps_its_edge(pivot_edge) -> None:
    edges = pivot_edge({'vulnerabilities': ['some/unknown-entry']}, ports_by_offering={})
    assert len(edges) == 1, edges


def test_an_explicitly_declared_target_port_keeps_its_edge(pivot_edge) -> None:
    edges = pivot_edge(
        {'vulnerabilities': [PORTLESS]},
        target_ports=['9200'],
        ports_by_offering={PORTLESS: []},
    )
    assert len(edges) == 1, edges
    assert edges[0]['target_ports'] == ['9200']


def test_the_rule_keys_off_ports_not_a_vulnerability_blocklist(pivot_edge) -> None:
    # A future catalog entry with this shape is covered without anyone adding
    # its name, and these vulns keep their edge wherever the node does listen.
    assert pivot_edge({'vulnerabilities': ['brand/new-portless']},
                      ports_by_offering={'brand/new-portless': []}) == []
