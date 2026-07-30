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


def test_declared_slots_absorb_demand_instead_of_adding_docker() -> None:
    counts, repair = ensure_role_counts_docker_capacity({'Docker': 1, VULNERABILITY_SLOT_ROLE: 3}, 3, 0)
    assert repair['added_docker_hosts'] == 0
    # The user's explicit Docker row is never consumed by challenge demand.
    assert counts['Docker'] == 1
    assert counts[VULNERABILITY_SLOT_ROLE] == 3


def test_demand_beyond_slots_spills_onto_docker() -> None:
    counts, repair = ensure_role_counts_docker_capacity({'Docker': 1, VULNERABILITY_SLOT_ROLE: 2}, 3, 0)
    assert repair['added_docker_hosts'] == 1
    assert counts['Docker'] == 2


def test_no_slots_declared_keeps_legacy_additive_behaviour() -> None:
    counts, repair = ensure_role_counts_docker_capacity({'Docker': 2}, 3, 1)
    assert repair['added_docker_hosts'] == 4
    assert counts['Docker'] == 6


def test_unused_slots_are_kept_as_empty_hosts() -> None:
    counts, repair = ensure_role_counts_docker_capacity({VULNERABILITY_SLOT_ROLE: 4}, 1, 0)
    assert counts[VULNERABILITY_SLOT_ROLE] == 4
    assert repair['unused_vulnerability_slots'] == 3
    assert repair['added_docker_hosts'] == 0


def test_a_slot_never_absorbs_the_other_challenge_kind() -> None:
    """FlagGenSlot capacity must not soak up vulnerability demand."""
    counts, repair = ensure_role_counts_docker_capacity({FLAG_GEN_SLOT_ROLE: 3}, 2, 0)
    assert repair['added_docker_hosts'] == 2
    assert counts['Docker'] == 2
    assert counts[FLAG_GEN_SLOT_ROLE] == 3


def test_each_kind_draws_from_its_own_slot_pool() -> None:
    counts, repair = ensure_role_counts_docker_capacity(
        {VULNERABILITY_SLOT_ROLE: 2, FLAG_GEN_SLOT_ROLE: 2}, 3, 1
    )
    assert repair['used_vulnerability_slots'] == 2
    assert repair['used_flag_gen_slots'] == 1
    # Only the one unabsorbed vulnerability becomes an additive Docker host.
    assert repair['added_docker_hosts'] == 1
    assert counts['Docker'] == 1


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


def test_vulnerabilities_prefer_declared_slots_over_docker_hosts() -> None:
    preview = _preview_for(
        "<item selected='Docker' v_metric='Count' v_count='1'/>"
        "<item selected='VulnerabilitySlot' v_metric='Count' v_count='3'/>",
        vuln_count=2,
    )
    hosts = {int(h['node_id']): h for h in preview['hosts']}
    bearing = [h for h in hosts.values() if h.get('vulnerabilities')]
    assert len(bearing) == 2
    # Every vulnerability landed on a slot; the declared Docker host stays free.
    assert all(h['role'] == VULNERABILITY_SLOT_ROLE for h in bearing)
    assert preview['role_counts'].get('Docker') == 1
    # The leftover slot is still materialized, just empty.
    assert sum(1 for h in hosts.values() if h['role'] == VULNERABILITY_SLOT_ROLE) == 3


def test_slots_are_not_double_counted_against_additive_hosts() -> None:
    """Declaring exactly enough slots yields the same host count as declaring none.

    The slots replace the additive Docker hosts rather than stacking on top of
    them, which is what keeps a slot from silently growing the topology.
    """
    with_slots = _preview_for(
        "<item selected='VulnerabilitySlot' v_metric='Count' v_count='2'/>", vuln_count=2
    )
    without_slots = _preview_for('', vuln_count=2)
    assert len(with_slots['hosts']) == len(without_slots['hosts']) == 2
    # Without slots the demand materializes as additive Docker hosts instead.
    assert without_slots['role_counts'].get('Docker') == 2
    assert with_slots['role_counts'].get('Docker') is None
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
