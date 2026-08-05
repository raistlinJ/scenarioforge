"""Node Information challenge slots: VulnerabilitySlot and FlagGenSlot.

A plain Docker host is the catch-all challenge target and may take either a
vulnerability or a flag-node-generator. A challenge slot reserves Docker-backed
capacity for exactly one of those kinds. Slots are consumed before the planner
adds additive Docker hosts, and slots left over stay in the topology as empty
Docker-backed hosts.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from scenarioforge.planning.docker_capacity import ensure_role_counts_docker_capacity
from scenarioforge.planning.node_plan import (
    ALLOWED_HOST_ROLES,
    FLAG_GEN_SLOT_ROLE,
    HOST_ROLE_DISPLAY_ORDER,
    VULNERABILITY_SLOT_ROLE,
    _normalize_role_name,
    challenge_slot_kind,
    is_docker_backed_role,
)
from webapp.app_backend import app


# ---------------------------------------------------------------------------
# Role vocabulary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'raw,expected',
    [
        ('VulnerabilitySlot', VULNERABILITY_SLOT_ROLE),
        ('vulnerability-slot', VULNERABILITY_SLOT_ROLE),
        ('Vulnerability Slot', VULNERABILITY_SLOT_ROLE),
        ('vuln_slot', VULNERABILITY_SLOT_ROLE),
        ('FlagGenSlot', FLAG_GEN_SLOT_ROLE),
        ('flag-gen-slot', FLAG_GEN_SLOT_ROLE),
        ('Flag Gen Slot', FLAG_GEN_SLOT_ROLE),
        ('Docker', 'Docker'),
    ],
)
def test_slot_role_spellings_normalize(raw: str, expected: str) -> None:
    """Unknown roles fall back to PC, so a missed alias silently drops a slot."""
    assert _normalize_role_name(raw) == expected


def test_unknown_role_still_falls_back_to_pc() -> None:
    assert _normalize_role_name('NotARole') == 'PC'


def test_slots_are_docker_backed_but_carry_a_kind() -> None:
    assert is_docker_backed_role(VULNERABILITY_SLOT_ROLE)
    assert is_docker_backed_role(FLAG_GEN_SLOT_ROLE)
    assert is_docker_backed_role('Docker')
    assert not is_docker_backed_role('PC')

    assert challenge_slot_kind(VULNERABILITY_SLOT_ROLE) == 'vulnerability'
    assert challenge_slot_kind(FLAG_GEN_SLOT_ROLE) == 'flag-node-generator'
    # A plain Docker host is unrestricted, so it reports no slot kind.
    assert challenge_slot_kind('Docker') == ''


def test_display_order_matches_allowed_roles() -> None:
    assert set(HOST_ROLE_DISPLAY_ORDER) == ALLOWED_HOST_ROLES
    assert len(HOST_ROLE_DISPLAY_ORDER) == len(ALLOWED_HOST_ROLES)


# ---------------------------------------------------------------------------
# Capacity repair
# ---------------------------------------------------------------------------


def test_declared_cards_still_add_their_own_docker_hosts() -> None:
    """Slots are extra capacity; they must not cancel out declared card rows.

    5 FlagGenSlot rows plus 5 declared generators is 10 challenge hosts, not 5.
    """
    counts, repair = ensure_role_counts_docker_capacity({FLAG_GEN_SLOT_ROLE: 5}, 0, 5)
    assert repair['added_docker_hosts'] == 5
    assert counts['Docker'] == 5
    assert counts[FLAG_GEN_SLOT_ROLE] == 5
    assert repair['challenge_capacity'] == 10


def test_vulnerability_slots_do_not_absorb_declared_vulnerabilities() -> None:
    counts, repair = ensure_role_counts_docker_capacity({VULNERABILITY_SLOT_ROLE: 5}, 3, 0)
    assert counts['Docker'] == 3
    assert counts[VULNERABILITY_SLOT_ROLE] == 5
    assert repair['challenge_capacity'] == 8


def test_no_slots_declared_keeps_legacy_additive_behaviour() -> None:
    counts, repair = ensure_role_counts_docker_capacity({'Docker': 2}, 3, 1)
    assert repair['added_docker_hosts'] == 4
    assert counts['Docker'] == 6


def test_slots_alone_are_capacity_with_no_declared_cards() -> None:
    counts, repair = ensure_role_counts_docker_capacity({FLAG_GEN_SLOT_ROLE: 4}, 0, 0)
    assert counts[FLAG_GEN_SLOT_ROLE] == 4
    assert repair['added_docker_hosts'] == 0
    assert repair['challenge_capacity'] == 4


def test_explicit_docker_rows_are_never_consumed_either() -> None:
    counts, _ = ensure_role_counts_docker_capacity(
        {'Docker': 1, VULNERABILITY_SLOT_ROLE: 2, FLAG_GEN_SLOT_ROLE: 2}, 1, 1
    )
    assert counts['Docker'] == 3
    assert counts[VULNERABILITY_SLOT_ROLE] == 2
    assert counts[FLAG_GEN_SLOT_ROLE] == 2


# ---------------------------------------------------------------------------
# Flow placement eligibility
# ---------------------------------------------------------------------------


def _node(role: str, **extra):
    node = {'id': 'n1', 'name': 'n1', 'role': role, 'type': role}
    node.update(extra)
    return node


def test_flow_treats_slots_as_docker_backed() -> None:
    from webapp import app_backend as backend

    assert backend._flow_node_is_docker_role(_node(VULNERABILITY_SLOT_ROLE))
    assert backend._flow_node_is_docker_role(_node(FLAG_GEN_SLOT_ROLE))
    assert not backend._flow_node_is_docker_role(_node('PC'))


def test_flow_slot_eligibility_is_restricted_to_its_own_kind() -> None:
    from webapp import app_backend as backend

    vuln_slot = _node(VULNERABILITY_SLOT_ROLE)
    flag_slot = _node(FLAG_GEN_SLOT_ROLE)
    docker = _node('Docker')

    assert backend._flow_node_accepts_challenge_kind(vuln_slot, 'vulnerability')
    assert not backend._flow_node_accepts_challenge_kind(vuln_slot, 'flag-node-generator')

    assert backend._flow_node_accepts_challenge_kind(flag_slot, 'flag-node-generator')
    assert not backend._flow_node_accepts_challenge_kind(flag_slot, 'vulnerability')

    # A plain Docker host stays the catch-all.
    assert backend._flow_node_accepts_challenge_kind(docker, 'vulnerability')
    assert backend._flow_node_accepts_challenge_kind(docker, 'flag-node-generator')

    # Non-container hosts host no challenges at all.
    assert not backend._flow_node_accepts_challenge_kind(_node('PC'), 'vulnerability')


def test_flow_reads_slot_kind_from_preview_metadata() -> None:
    """Preview hosts carry the kind in metadata rather than in the role string."""
    from webapp import app_backend as backend

    node = {'id': 'n1', 'type': 'docker', 'metadata': {'challenge_slot_kind': 'vulnerability'}}
    assert backend._flow_node_challenge_slot_kind(node) == 'vulnerability'
    assert not backend._flow_node_accepts_challenge_kind(node, 'flag-node-generator')


# ---------------------------------------------------------------------------
# End-to-end through the planner
# ---------------------------------------------------------------------------


def _preview_for(node_rows: str, vuln_count: int = 2):
    xml = f"""<Scenarios><Scenario name='slots'><ScenarioEditor>
<section name='Node Information'>{node_rows}</section>
<section name='Routing' density='0.0'></section>
<section name='Services' density='0.0'></section>
<section name='Vulnerabilities' density='0.0'>
  <item selected='Specific' v_metric='Count' v_count='{vuln_count}' v_name='VulnA' v_path='https://example.com/x'/>
</section>
<section name='Segmentation' density='0.0'></section>
<section name='Traffic' density='0.0'></section>
</ScenarioEditor></Scenario></Scenarios>"""
    app.config['TESTING'] = True
    client = app.test_client()
    client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, 'slots.xml')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(xml)
        resp = client.post('/api/plan/preview_full', json={'xml_path': path, 'scenario': 'slots'})
        assert resp.status_code == 200
        payload = resp.get_json() or {}
        assert payload.get('ok'), payload
        return payload['full_preview']


def test_vulnerability_slots_materialize_empty_for_sequencing() -> None:
    """A slot is capacity, not a placement.

    It stays empty at plan time so it does not become a mandatory challenge --
    chain expansion pulls in every vulnerability-carrying host. Flag-sequencing
    draws a vulnerability only for the slots the chain actually reaches; see
    tests/test_vulnerability_slot_lazy_fill.py.
    """
    preview = _preview_for(
        "<item selected='VulnerabilitySlot' v_metric='Count' v_count='3'/>", vuln_count=2
    )
    hosts = list(preview['hosts'])
    slots = [h for h in hosts if h['role'] == VULNERABILITY_SLOT_ROLE]
    assert len(slots) == 3
    assert not any(h.get('vulnerabilities') for h in slots), slots
    # The two declared rows keep their own additive Docker hosts.
    assert preview['role_counts'].get('Docker') == 2
    assert len(hosts) == 5


def test_slot_rows_add_capacity_on_top_of_declared_cards() -> None:
    """Slots are additive: 2 slots plus 2 declared vulnerabilities is 4 hosts."""
    with_slots = _preview_for(
        "<item selected='VulnerabilitySlot' v_metric='Count' v_count='2'/>", vuln_count=2
    )
    without_slots = _preview_for('', vuln_count=2)
    assert len(without_slots['hosts']) == 2
    assert len(with_slots['hosts']) == 4
    assert with_slots['role_counts'].get('Docker') == 2
    assert with_slots['role_counts'].get(VULNERABILITY_SLOT_ROLE) == 2


def test_flag_gen_slot_does_not_receive_vulnerabilities() -> None:
    preview = _preview_for(
        "<item selected='FlagGenSlot' v_metric='Count' v_count='3'/>", vuln_count=2
    )
    for host in preview['hosts']:
        if host['role'] == FLAG_GEN_SLOT_ROLE:
            assert not host.get('vulnerabilities'), host
    # The vulnerabilities had to go somewhere: additive Docker hosts.
    assert preview['role_counts'].get('Docker') == 2


def test_slot_hosts_carry_their_kind_into_the_preview() -> None:
    preview = _preview_for(
        "<item selected='VulnerabilitySlot' v_metric='Count' v_count='1'/>"
        "<item selected='FlagGenSlot' v_metric='Count' v_count='1'/>",
        vuln_count=1,
    )
    by_role = {h['role']: h for h in preview['hosts']}
    assert (by_role[VULNERABILITY_SLOT_ROLE].get('metadata') or {}).get('challenge_slot_kind') == 'vulnerability'
    assert (by_role[FLAG_GEN_SLOT_ROLE].get('metadata') or {}).get('challenge_slot_kind') == 'flag-node-generator'


# ---------------------------------------------------------------------------
# Secondary role normalizer (Web UI / AI coverage counting)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'raw,expected',
    [
        ('VulnerabilitySlot', VULNERABILITY_SLOT_ROLE),
        ('vulnerability-slot', VULNERABILITY_SLOT_ROLE),
        ('vuln slot', VULNERABILITY_SLOT_ROLE),
        ('FlagGenSlot', FLAG_GEN_SLOT_ROLE),
        ('flag gen slot', FLAG_GEN_SLOT_ROLE),
        ('Docker', 'Docker'),
        ('bogus', ''),
    ],
)
def test_node_information_role_normalizer_knows_slots(raw: str, expected: str) -> None:
    """app_backend keeps its own alias table; a gap here silently counts zero slots."""
    from webapp import app_backend as backend

    assert backend._normalize_node_information_role(raw) == expected


def test_slot_rows_count_as_container_capacity() -> None:
    """A scenario declaring only slots still has Docker-backed hosts."""
    from webapp.routes import ai_provider

    payload = {
        'sections': {
            'Node Information': {
                'items': [
                    {'selected': 'VulnerabilitySlot', 'v_count': 3},
                    {'selected': 'FlagGenSlot', 'v_count': 2},
                    {'selected': 'PC', 'v_count': 4},
                ]
            }
        }
    }
    assert ai_provider._count_docker_rows(payload) == 5
    assert ai_provider._count_node_role_rows(payload, VULNERABILITY_SLOT_ROLE) == 3
    assert ai_provider._count_node_role_rows(payload, FLAG_GEN_SLOT_ROLE) == 2


# --------------------------------------------------------------------------- #
# Pivot-access providers are additive, never challenge capacity
# --------------------------------------------------------------------------- #

def _provider_host(**extra):
    """A host as `_materialise_pivot_providers` leaves it in the plan."""
    host = {
        'node_id': 26,
        'name': 'pivot-10-0-171-0',
        'role': 'Docker',
        'ip4': '10.0.171.5/24',
        'metadata': {
            'pivot_access_provider': {
                'subnet': '10.0.171.0/24',
                'image': 'lscr.io/linuxserver/openssh-server:latest',
                'port': 2222, 'protocol': 'tcp', 'kind': 'ssh', 'label': 'SSH',
                'consumes_slot': False,
            },
        },
    }
    host.update(extra)
    return host


def test_a_pivot_provider_never_accepts_a_challenge():
    """The regression: Flow placed generators on added provider nodes.

    A provider is a plain Docker host with no slot kind, so it looked like free
    capacity. An *added* provider runs the SSH provider image, which has no
    generator staging and no `/flow_injects`, so the run failed the injects
    check with `MISSING_DIR:/flow_injects` on two nodes that could never have
    held them. The planner already records `consumes_slot: false`.
    """
    from webapp import app_backend as ab

    provider = _provider_host()
    assert ab._flow_node_is_pivot_access_provider(provider) is True
    for kind in ('flag-node-generator', 'vulnerability'):
        assert ab._flow_node_accepts_challenge_kind(provider, kind) is False, kind
    assert ab._flow_node_allows_flag_node_generator(provider) is False


def test_excluding_providers_does_not_touch_real_capacity():
    from webapp import app_backend as ab

    plain = {'node_id': 6, 'name': 'docker-1', 'role': 'Docker'}
    slot = {'node_id': 11, 'name': 'flaggenslot-6', 'role': 'FlagGenSlot'}
    assert ab._flow_node_is_pivot_access_provider(plain) is False
    assert ab._flow_node_accepts_challenge_kind(plain, 'flag-node-generator') is True
    assert ab._flow_node_accepts_challenge_kind(slot, 'flag-node-generator') is True


def test_a_host_without_the_marker_is_not_mistaken_for_a_provider():
    # Name alone must not be the signal: an author may legitimately name a host
    # "pivot-something". Only the planner's metadata marker counts.
    from webapp import app_backend as ab

    lookalike = {'node_id': 30, 'name': 'pivot-10-0-171-0', 'role': 'Docker', 'metadata': {}}
    assert ab._flow_node_is_pivot_access_provider(lookalike) is False
    assert ab._flow_node_accepts_challenge_kind(lookalike, 'flag-node-generator') is True


def test_the_marker_survives_into_the_topology_graph():
    """The chain picker works on graph nodes, not on plan hosts.

    `_build_topology_graph_from_preview_plan` copies a fixed set of host keys
    and flattens them onto the graph node. `pivot_access_provider` was in that
    copy list but read from the host's *top level*, while the planner writes it
    under `metadata` -- so the graph node arrived looking like an ordinary free
    Docker host and Flow kept chaining providers even after the eligibility gate
    learned to reject them.
    """
    from webapp import app_backend as ab

    preview = {
        'hosts': [
            {'node_id': 6, 'name': 'docker-1', 'role': 'Docker', 'ip4': '10.0.0.6/24'},
            {'node_id': 26, 'name': 'pivot-10-0-88-0', 'role': 'Docker', 'ip4': '10.0.88.5/24',
             'metadata': {'pivot_access_provider': {
                 'subnet': '10.0.88.0/24', 'kind': 'ssh', 'port': 2222,
                 'consumes_slot': False}}},
        ],
    }
    nodes, _links, adj = ab._build_topology_graph_from_preview_plan(preview)
    by_name = {str(n.get('name')): n for n in nodes}

    provider = by_name['pivot-10-0-88-0']
    assert 'pivot_access_provider' in provider, 'the marker must reach the graph node'
    assert ab._flow_node_is_pivot_access_provider(provider) is True
    assert ab._flow_node_accepts_challenge_kind(provider, 'flag-node-generator') is False

    plain = by_name['docker-1']
    assert ab._flow_node_is_pivot_access_provider(plain) is False
    assert ab._flow_node_accepts_challenge_kind(plain, 'flag-node-generator') is True

    # And the picker that actually builds the chain skips it.
    picked = ab._pick_flow_nonvulnerability_docker_nodes(nodes, adj, length=2)
    assert [str(p.get('name')) for p in picked] == ['docker-1']


def test_provider_detection_accepts_both_host_shapes():
    """A plan host nests the marker; a graph node flattens it."""
    from webapp import app_backend as ab

    nested = {'node_id': 26, 'role': 'Docker',
              'metadata': {'pivot_access_provider': {'kind': 'ssh'}}}
    flattened = {'id': '26', 'type': 'docker', 'pivot_access_provider': {'kind': 'ssh'}}
    assert ab._flow_node_is_pivot_access_provider(nested) is True
    assert ab._flow_node_is_pivot_access_provider(flattened) is True
    # A truthy non-dict must not be mistaken for the marker.
    assert ab._flow_node_is_pivot_access_provider({'pivot_access_provider': 'yes'}) is False
