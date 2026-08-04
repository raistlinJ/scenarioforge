"""An added pivot provider becomes a real node.

The planner can decide a walled-off subnet needs a provider that does not exist
yet. These cover what happens next: the node is allocated into the topology
plan, addressed inside that subnet, hung off its switch, pinned to an SSH image,
and given the allow rules that were impossible while it had no address.

The invariants that keep it honest are covered too -- it is additive (never a
challenge slot, never part of the author's plan counts), it is Docker-backed,
and re-planning over a topology that already has one reuses it instead of
stacking up a second provider per preview.
"""

import ipaddress

import pytest

from scenarioforge.planning.full_preview import (
    PreviewNode, _materialise_pivot_providers, build_full_preview,
)
from scenarioforge.planning.preview_validation import validate_full_preview
from scenarioforge.utils.pivot_access import (
    ENTRY_SSH, PIVOT_PROVIDER_METADATA_KEY, PIVOT_SSH_IMAGE, PIVOT_SSH_PORT,
    PivotAccessPlan, PivotEntry, PivotProvider, is_pivot_provider_host,
    plan_pivot_access, provisioned_entry_points,
)
from scenarioforge.types import NodeInfo


WALLED_OFF = '172.21.240.0/24'
OUTSIDE = '10.0.140.0/24'


def _plan(subnet=WALLED_OFF, router_ids=(1, 2)):
    return PivotAccessPlan(
        providers=[PivotProvider(
            subnet=subnet,
            node_id=None,
            node_name='pivot-172-21-240-0',
            entry=PivotEntry(kind=ENTRY_SSH, port=PIVOT_SSH_PORT, protocol='tcp',
                             label='SSH', provisioned=True),
            blocked_from=[OUTSIDE],
            added=True,
            role='Docker',
            image=PIVOT_SSH_IMAGE,
        )],
        router_ids=list(router_ids),
    )


def _topology(subnet=WALLED_OFF):
    """One router, one switch, one host inside the subnet that gets walled off."""
    routers = [PreviewNode(node_id=1, name='router-1', role='Router', kind='router',
                           ip4='172.21.240.1/24')]
    switches = [PreviewNode(node_id=8, name='sw-8', role='Switch', kind='switch')]
    hosts = [PreviewNode(node_id=4, name='vulnslot-1', role='VulnerabilitySlot',
                         kind='host', ip4='172.21.240.2/24')]
    detail = {
        'switch_id': 8, 'router_id': 1,
        'rsw_subnet': subnet, 'lan_subnet': subnet,
        'router_ip': '172.21.240.1/24', 'switch_ip': None,
        'hosts': [4], 'host_if_ips': {4: '172.21.240.2/24'},
    }
    return {
        'plan_kwargs': dict(
            host_nodes=hosts,
            host_map={h.node_id: h for h in hosts},
            host_router_map={4: 1},
            switches_detail=[detail],
            switch_nodes=switches,
            router_nodes=routers,
            assigned_ips={'172.21.240.1', '172.21.240.2'},
        ),
        'hosts': hosts,
        'detail': detail,
    }


def _materialise(plan=None, topo=None):
    topo = topo or _topology()
    plan = plan if plan is not None else _plan()
    created = _materialise_pivot_providers(plan, **topo['plan_kwargs'])
    return plan, topo, created


# --------------------------------------------------------------------------- #
# The node itself
# --------------------------------------------------------------------------- #

def test_an_added_provider_becomes_a_docker_host_in_the_plan():
    plan, topo, created = _materialise()
    assert len(created) == 1
    node = created[0]
    # Docker-backed, never a vnode: a CORE vnode shares the CORE VM filesystem,
    # so SSH on one is a host escape rather than a pivot.
    assert node.role == 'Docker'
    assert node.kind == 'host'
    assert node in topo['plan_kwargs']['host_nodes']


def test_the_provider_is_addressed_inside_the_subnet_it_opens():
    plan, _topo, created = _materialise()
    address = ipaddress.ip_interface(created[0].ip4)
    assert address.ip in ipaddress.ip_network(WALLED_OFF)
    assert plan.providers[0].address == str(address.ip)


def test_the_provider_does_not_take_an_address_already_in_use():
    _plan_out, topo, created = _materialise()
    taken = {'172.21.240.1', '172.21.240.2'}
    assert created[0].ip4.split('/')[0] not in taken


def test_the_provider_is_linked_to_the_subnets_switch_and_router():
    _plan_out, topo, created = _materialise()
    node_id = created[0].node_id
    detail = topo['detail']
    assert node_id in detail['hosts']
    assert detail['host_if_ips'][node_id] == created[0].ip4
    # Same router as the rest of the subnet, so it is reachable over the same path.
    assert topo['plan_kwargs']['host_router_map'][node_id] == detail['router_id']


def test_the_provider_carries_the_image_it_must_boot():
    _plan_out, _topo, created = _materialise()
    marker = created[0].metadata[PIVOT_PROVIDER_METADATA_KEY]
    assert marker['image'] == PIVOT_SSH_IMAGE
    assert marker['subnet'] == WALLED_OFF
    assert marker['port'] == PIVOT_SSH_PORT


def test_the_port_follows_the_image_not_the_ssh_default():
    # The default provider image is a rootless sshd on 2222. Opening 22 would
    # look right in the plan and refuse every connection in the lab.
    assert PIVOT_SSH_PORT != 22
    _plan_out, _topo, created = _materialise()
    assert created[0].metadata[PIVOT_PROVIDER_METADATA_KEY]['port'] == PIVOT_SSH_PORT


def test_the_node_id_is_above_every_existing_node():
    # Challenge slots are numbered positionally over the sorted host list, so an
    # id in the middle would shift every later host's slot.
    _plan_out, topo, created = _materialise()
    existing = [4, 1, 8]
    assert created[0].node_id > max(existing)


# --------------------------------------------------------------------------- #
# The rules that make it reachable
# --------------------------------------------------------------------------- #

def test_rules_are_written_once_the_provider_has_an_address():
    plan, _topo, created = _materialise()
    assert plan.allow_rules, 'a materialised provider must be opened up'
    dst = {r['rule']['dst'] for r in plan.allow_rules}
    assert dst == {created[0].ip4.split('/')[0]}


def test_forward_allows_reach_every_router_not_just_the_enforcing_one():
    # Segmentation leaves every router with -P FORWARD DROP, so a packet has to
    # survive each hop.
    plan, _topo, _created = _materialise(plan=_plan(router_ids=(1, 2, 3)))
    forward = [r for r in plan.allow_rules if r['rule']['chain'] == 'FORWARD']
    assert {r['node_id'] for r in forward} == {1, 2, 3}


def test_the_provider_gets_its_own_input_allow():
    plan, _topo, created = _materialise()
    inputs = [r for r in plan.allow_rules if r['rule']['chain'] == 'INPUT']
    assert [r['node_id'] for r in inputs] == [created[0].node_id]


def test_rules_open_the_providers_port_to_any_source():
    # Not just the subnets the block took access away from: the participant is
    # in none of them, and locking them out of the entrance defeats the point.
    from scenarioforge.utils.pivot_access import ANY_SOURCE

    plan, _topo, _created = _materialise()
    for entry in plan.allow_rules:
        assert entry['rule']['port'] == PIVOT_SSH_PORT
        assert entry['rule']['src'] == ANY_SOURCE
        assert entry['rule']['reason'] == 'pivot-access'


# --------------------------------------------------------------------------- #
# The participant has to be able to reach the entrance
# --------------------------------------------------------------------------- #

HITL_SUBNET = '10.254.200.0/24'


def _plan_with_participant(rules, hosts, **kwargs):
    return plan_pivot_access(
        rules, hosts, router_ids=[1],
        entry_points={4: [PivotEntry(kind='vulnerability', port=8080)]},
        participant_subnets=[HITL_SUBNET], **kwargs,
    )


def _subnet_block_rules():
    # The shape that used to lock the participant out: the subnet is walled off
    # from one other subnet, so the allow was scoped to that subnet alone.
    return [{'node_id': 1, 'service': 'Segmentation', 'rule': {
        'type': 'subnet_block', 'node': 1, 'src': OUTSIDE, 'dst': WALLED_OFF,
        'chain': 'FORWARD', 'default_deny': True}}]


def _inside_hosts():
    return [NodeInfo(node_id=4, ip4='172.21.240.6/24', role='Docker')]


def test_the_participant_can_reach_a_provider_behind_a_subnet_block():
    plan = _plan_with_participant(_subnet_block_rules(), _inside_hosts())
    assert plan.providers
    assert plan.allow_rules
    # Opening only OUTSIDE would leave the participant, who is on neither side
    # of that rule, unable to reach the one node built to let them in.
    for entry in plan.allow_rules:
        assert entry['rule']['src'] == '0.0.0.0/0'


def test_the_participant_network_is_named_on_the_provider():
    plan = _plan_with_participant(_subnet_block_rules(), _inside_hosts())
    assert HITL_SUBNET in plan.providers[0].blocked_from
    # The rule that closed the subnet is still named, since it explains why a
    # provider was needed at all.
    assert OUTSIDE in plan.providers[0].blocked_from


def test_the_participant_is_recorded_as_a_network_never_an_address():
    # A participant who re-addresses inside their own subnet is still the same
    # participant; a single address would be defeated by a new DHCP lease.
    plan = plan_pivot_access(
        _subnet_block_rules(), _inside_hosts(), router_ids=[1],
        entry_points={4: [PivotEntry(kind='vulnerability', port=8080)]},
        participant_subnets=['10.254.200.3', '10.254.200.0/24'],
    )
    recorded = [s for s in plan.providers[0].blocked_from if s.startswith('10.254.200.')]
    assert recorded == ['10.254.200.0/24']


def test_a_participant_already_inside_the_subnet_is_not_added():
    # They need no way in; they are already there.
    plan = plan_pivot_access(
        _subnet_block_rules(), _inside_hosts(), router_ids=[1],
        entry_points={4: [PivotEntry(kind='vulnerability', port=8080)]},
        participant_subnets=[WALLED_OFF],
    )
    assert WALLED_OFF not in plan.providers[0].blocked_from


def test_no_participant_subnets_leaves_the_report_unchanged():
    plan = plan_pivot_access(
        _subnet_block_rules(), _inside_hosts(), router_ids=[1],
        entry_points={4: [PivotEntry(kind='vulnerability', port=8080)]},
    )
    assert plan.providers[0].blocked_from == [OUTSIDE]


# --------------------------------------------------------------------------- #
# It stays additive
# --------------------------------------------------------------------------- #

def test_no_challenge_slot_is_consumed():
    _plan_out, topo, created = _materialise()
    slots = [h for h in topo['plan_kwargs']['host_nodes'] if 'Slot' in h.role]
    # The pre-existing slot is untouched and the provider is not one.
    assert [h.node_id for h in slots] == [4]
    assert created[0].metadata[PIVOT_PROVIDER_METADATA_KEY]['consumes_slot'] is False


def test_the_provider_is_recognisable_as_additive():
    _plan_out, _topo, created = _materialise()
    assert is_pivot_provider_host(created[0])
    assert is_pivot_provider_host({'node_id': 1, 'metadata': {}}) is False
    assert is_pivot_provider_host({'node_id': 1}) is False


def test_plan_parity_ignores_the_provider():
    # Execute compares the saved preview against one rebuilt from the XML, and
    # the XML says nothing about a node this feature decided to add.
    from scenarioforge.cli import _plan_summary_from_full_preview

    plain = {'hosts': [{'node_id': 1, 'role': 'Docker'}, {'node_id': 2, 'role': 'PC'}]}
    with_provider = {'hosts': plain['hosts'] + [{
        'node_id': 3, 'role': 'Docker',
        'metadata': {PIVOT_PROVIDER_METADATA_KEY: {'subnet': WALLED_OFF}},
    }]}
    assert (_plan_summary_from_full_preview(with_provider)['hosts_total']
            == _plan_summary_from_full_preview(plain)['hosts_total'])


# --------------------------------------------------------------------------- #
# Re-planning over a topology that already has one
# --------------------------------------------------------------------------- #

def test_replanning_reuses_the_provider_instead_of_adding_another():
    plan, topo, created = _materialise()
    hosts = [NodeInfo(node_id=h.node_id, ip4=h.ip4, role=h.role)
             for h in topo['plan_kwargs']['host_nodes']]
    rules = [{'node_id': 1, 'service': 'Segmentation', 'rule': {
        'type': 'subnet_block', 'src': OUTSIDE, 'dst': WALLED_OFF}}]

    again = plan_pivot_access(
        rules, hosts, routers=[NodeInfo(node_id=1, ip4='172.21.240.1/24', role='Router')],
        entry_points=provisioned_entry_points(topo['plan_kwargs']['host_nodes']),
        node_names={h.node_id: h.name for h in topo['plan_kwargs']['host_nodes']},
    )
    assert len(again.providers) == 1
    provider = again.providers[0]
    assert provider.node_id == created[0].node_id
    # Still reported as added: the node exists only because of this feature, and
    # calling it reused would credit the scenario with a node it never asked for.
    assert provider.added is True
    assert provider.reused is False
    assert provider.entry.port == PIVOT_SSH_PORT
    assert again.allow_rules


def test_provisioned_entry_points_reads_preview_payloads_and_objects():
    _plan_out, topo, created = _materialise()
    as_objects = provisioned_entry_points(topo['plan_kwargs']['host_nodes'])
    as_dicts = provisioned_entry_points([vars(h) for h in topo['plan_kwargs']['host_nodes']])
    assert list(as_objects) == list(as_dicts) == [created[0].node_id]
    assert as_objects[created[0].node_id][0].provisioned is True


# --------------------------------------------------------------------------- #
# When it cannot be placed
# --------------------------------------------------------------------------- #

def test_a_subnet_with_no_switch_is_reported_not_silently_dropped():
    plan, _topo, created = _materialise(plan=_plan(subnet='192.0.2.0/24'))
    assert created == []
    assert plan.providers[0].node_id is None
    assert plan.unresolved and 'switch' in plan.unresolved[0]['reason']


def test_a_full_subnet_is_reported_not_silently_dropped():
    topo = _topology()
    net = ipaddress.ip_network(WALLED_OFF)
    topo['plan_kwargs']['assigned_ips'] = {str(ip) for ip in net.hosts()}
    plan, _topo, created = _materialise(topo=topo)
    assert created == []
    assert plan.unresolved and 'address' in plan.unresolved[0]['reason']


def test_nothing_happens_without_an_added_provider():
    plan = PivotAccessPlan(providers=[PivotProvider(
        subnet=WALLED_OFF, node_id=4, node_name='docker-1',
        entry=PivotEntry(kind='vulnerability', port=8080), reused=True,
    )])
    _plan_out, topo, created = _materialise(plan=plan)
    assert created == []
    assert len(topo['plan_kwargs']['host_nodes']) == 1


# --------------------------------------------------------------------------- #
# End to end through the preview
# --------------------------------------------------------------------------- #

def _preview_with_pivot(**overrides):
    kwargs = dict(
        role_counts={'PC': 3, 'Docker': 2}, routers_planned=3, services_plan={},
        vulnerabilities_plan={}, r2r_policy=None,
        r2s_policy={'mode': 'Exact', 'target_per_router': 1},
        routing_items=None, routing_plan={}, segmentation_density=1.0,
        segmentation_items=[{'selected': 'Firewall', 'factor': 1.0}],
        traffic_plan=None, seed=101, ip4_prefix='10.10.0.0/16',
        segmentation_accessible_by_pivot=True,
    )
    kwargs.update(overrides)
    return build_full_preview(**kwargs)


def test_the_preview_leaves_no_provider_without_a_node():
    full = _preview_with_pivot()
    access = (full['segmentation_preview'] or {}).get('pivot_access') or {}
    if not access.get('providers'):
        pytest.skip('this seed walled nothing off')
    host_ids = {h['node_id'] for h in full['hosts']}
    for provider in access['providers']:
        assert provider['node_id'] in host_ids, provider
        assert provider['address']


def test_the_materialised_preview_is_still_valid():
    full = _preview_with_pivot()
    assert validate_full_preview(full) == []


def test_the_provider_appears_in_the_payload_the_builder_reads():
    full = _preview_with_pivot()
    access = (full['segmentation_preview'] or {}).get('pivot_access') or {}
    if not access.get('added_node_count'):
        pytest.skip('this seed walled nothing off')
    providers = [h for h in full['hosts'] if is_pivot_provider_host(h)]
    assert len(providers) == access['added_node_count']
    for host in providers:
        assert host['role'] == 'Docker'
        assert host['node_id'] in full['host_router_map']
        assert host['ip4']


# --------------------------------------------------------------------------- #
# What the builder runs on the node
# --------------------------------------------------------------------------- #

def _provider_hdata(node_id=12, image=PIVOT_SSH_IMAGE, port=PIVOT_SSH_PORT):
    return {
        'node_id': node_id, 'name': 'pivot-172-21-240-0', 'role': 'Docker',
        'ip4': '172.21.240.3/24',
        'metadata': {PIVOT_PROVIDER_METADATA_KEY: {
            'subnet': WALLED_OFF, 'image': image, 'port': port,
            'protocol': 'tcp', 'kind': ENTRY_SSH, 'label': 'SSH',
            'consumes_slot': False,
        }},
    }


def test_the_compose_entry_is_pinned_to_the_providers_image(tmp_path):
    from scenarioforge.builders import topology

    record = topology._pivot_access_record_from_host_metadata(
        _provider_hdata(image='example.invalid/openssh:pinned'),
        'pivot-172-21-240-0', out_base=str(tmp_path),
    )
    assert record is not None
    text = open(record['Path'], encoding='utf-8').read()
    # The plan's image, so a site mirroring its own gets what the offline image
    # preparation actually made available locally.
    assert 'example.invalid/openssh:pinned' in text
    # Not the standard template, which serves nothing to pivot through.
    assert 'standard-ubuntu-docker-core' not in text
    assert record['compose_ports'][0]['port'] == PIVOT_SSH_PORT


def test_the_compose_entry_exposes_the_port_the_rules_open(tmp_path):
    from scenarioforge.builders import topology

    path = topology._write_pivot_access_compose(
        'pivot-172-21-240-0', PIVOT_SSH_IMAGE, PIVOT_SSH_PORT, out_base=str(tmp_path))
    record = {'Type': 'docker-compose', 'Name': 'pivot-access-test', 'Path': path}
    from scenarioforge.utils.vuln_process import extract_compose_ports
    ports = {entry['port'] for entry in extract_compose_ports(record, out_base=str(tmp_path))}
    assert ports == {PIVOT_SSH_PORT}


def test_an_ordinary_host_gets_no_provider_record():
    from scenarioforge.builders import topology

    assert topology._pivot_access_record_from_host_metadata(
        {'node_id': 4, 'role': 'Docker', 'metadata': {}}, 'docker-1') is None
    assert topology._pivot_access_record_from_host_metadata({'node_id': 4}, 'docker-1') is None


def test_the_provider_record_wins_over_the_standard_template():
    import inspect
    from scenarioforge.builders import topology

    src = inspect.getsource(topology._try_build_segmented_topology_from_preview)
    assert '_pivot_access_record_from_host_metadata' in src
    # Checked before the standard record, or the node would boot an image with
    # no sshd and the subnet would stay unreachable.
    assert (src.index('_pivot_access_record_from_host_metadata')
            < src.index('_standard_docker_compose_record()'))


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #

def test_the_image_is_prepared_before_the_topology_is_built():
    # CORE starts a Docker node the moment it is added, so the image has to be
    # local by then -- segmentation reporting it afterwards is far too late.
    import inspect
    from scenarioforge import cli

    src = inspect.getsource(cli.main) if hasattr(cli, 'main') else ''
    if '_ensure_pivot_provider_images' not in src:
        src = open(cli.__file__, encoding='utf-8').read()
    assert (src.index('_ensure_pivot_provider_images')
            < src.index('PHASE: Building topology'))


def test_execute_time_discovery_calls_a_provider_ssh_not_a_vulnerability(tmp_path):
    from scenarioforge.builders import topology
    from scenarioforge.cli import _seg_pivot_entry_points

    class _Node:
        def __init__(self, name):
            self.name = name

    class _Session:
        def get_node(self, node_id):
            return _Node({12: 'pivot-172-21-240-0'}.get(node_id) or f'node-{node_id}')

    hosts = [NodeInfo(node_id=12, ip4='172.21.240.3/24', role='Docker')]
    record = topology._pivot_access_record_from_host_metadata(
        _provider_hdata(), 'pivot-172-21-240-0', out_base=str(tmp_path))
    entries = _seg_pivot_entry_points({'pivot-172-21-240-0': record}, hosts, _Session())
    assert [e.kind for e in entries[12]] == [ENTRY_SSH]
    assert entries[12][0].provisioned is True


def test_discovery_does_not_depend_on_the_live_session():
    # `core.api.grpc.wrappers.Session` has no `get_node` on the CORE builds this
    # runs against. A live run showed every name lookup coming back empty, so the
    # provider went unrecognised and execute re-added one per subnet. The plan
    # answers for its own nodes instead.
    from scenarioforge.cli import _seg_pivot_entry_points

    class _SessionWithoutGetNode:
        pass

    provider = _provider_hdata(node_id=12)
    for session in (None, _SessionWithoutGetNode()):
        entries = _seg_pivot_entry_points({}, [], session, preview_hosts=[provider])
        assert [e.kind for e in entries[12]] == [ENTRY_SSH]
        assert entries[12][0].port == PIVOT_SSH_PORT


def test_provider_names_come_from_the_plan_when_the_session_cannot_answer():
    from scenarioforge.cli import _preview_host_names

    names = _preview_host_names([
        {'node_id': 4, 'name': 'pc-1'},
        _provider_hdata(node_id=12),
        {'node_id': 7},
    ])
    assert names == {4: 'pc-1', 12: 'pivot-172-21-240-0'}


def test_the_provider_is_left_out_of_the_challenge_slot_range():
    from scenarioforge.cli import _pivot_provider_hosts

    preview = {'hosts': [
        {'node_id': 4, 'role': 'VulnerabilitySlot'},
        {'node_id': 5, 'role': 'Docker'},
        _provider_hdata(node_id=12),
    ]}
    assert [h['node_id'] for h in _pivot_provider_hosts(preview)] == [12]


# --------------------------------------------------------------------------- #
# Nested pivots: detected and reported, deliberately not enforced
# --------------------------------------------------------------------------- #

def _chained_blocks():
    """B is walled off only from A, and A is itself walled off from everything.

    Reads as an author asking for two steps: get into A, then through it to B.
    """
    return [
        {'node_id': 1, 'service': 'Segmentation', 'rule': {
            'type': 'protect_internal', 'node': 1, 'subnet': '10.0.10.0/24'}},
        {'node_id': 1, 'service': 'Segmentation', 'rule': {
            'type': 'subnet_block', 'node': 1, 'src': '10.0.10.0/24', 'dst': '10.0.20.0/24'}},
    ]


def test_a_pivot_behind_a_pivot_is_detected():
    from scenarioforge.utils.pivot_access import nested_pivot_candidates, walled_off_details

    candidates = nested_pivot_candidates(walled_off_details(_chained_blocks()))
    assert [c['subnet'] for c in candidates] == ['10.0.20.0/24']
    assert candidates[0]['reached_through'] == ['10.0.10.0/24']


def test_a_subnet_with_a_direct_way_in_is_not_nested():
    from scenarioforge.utils.pivot_access import nested_pivot_candidates, walled_off_details

    rules = _chained_blocks() + [
        # Also blocked from a subnet that is not itself walled off, so there is
        # a way in that crosses no other boundary.
        {'node_id': 1, 'service': 'Segmentation', 'rule': {
            'type': 'subnet_block', 'node': 1, 'src': '10.0.99.0/24', 'dst': '10.0.20.0/24'}},
    ]
    assert nested_pivot_candidates(walled_off_details(rules)) == []


def test_a_subnet_blocked_from_everything_is_not_nested():
    from scenarioforge.utils.pivot_access import nested_pivot_candidates, walled_off_details

    rules = [{'node_id': 1, 'service': 'Segmentation', 'rule': {
        'type': 'protect_internal', 'node': 1, 'subnet': '10.0.10.0/24'}}]
    assert nested_pivot_candidates(walled_off_details(rules)) == []


def test_nesting_is_reported_on_the_plan_and_not_enforced():
    from scenarioforge.utils.pivot_access import NESTED_PIVOTS_SUPPORTED, ANY_SOURCE

    hosts = [NodeInfo(node_id=4, ip4='10.0.10.5/24', role='Docker'),
             NodeInfo(node_id=5, ip4='10.0.20.5/24', role='Docker')]
    plan = plan_pivot_access(
        _chained_blocks(), hosts, router_ids=[1],
        entry_points={4: [PivotEntry(kind='vulnerability', port=8080)],
                      5: [PivotEntry(kind='vulnerability', port=9090)]},
    )
    assert NESTED_PIVOTS_SUPPORTED is False
    payload = plan.as_dict()
    assert payload['nested_supported'] is False
    assert [c['subnet'] for c in payload['nested_candidates']] == ['10.0.20.0/24']
    # Flattened: the inner provider is reachable without crossing the outer one.
    assert plan.allow_rules
    assert {e['rule']['src'] for e in plan.allow_rules} == {ANY_SOURCE}


# --------------------------------------------------------------------------- #
# What the CLI reports about pivot access
# --------------------------------------------------------------------------- #

def _access_payload(**overrides):
    payload = {
        'providers': [{
            'subnet': WALLED_OFF, 'node_id': 14, 'node_name': 'pivot-172-21-240-0',
            'address': '172.21.240.4', 'added': True, 'reused': False,
            'image': PIVOT_SSH_IMAGE, 'blocked_from': [OUTSIDE, HITL_SUBNET],
            'entry': {'kind': 'ssh', 'port': PIVOT_SSH_PORT, 'protocol': 'tcp'},
        }],
        'unresolved': [], 'nested_supported': False, 'nested_candidates': [],
    }
    payload.update(overrides)
    return payload


def test_the_cli_summarises_pivot_access_from_a_preview():
    from scenarioforge.cli import _pivot_access_summary

    summary = _pivot_access_summary({'segmentation_preview': {'pivot_access': _access_payload()}})
    assert summary['provider_count'] == 1
    assert summary['added_node_count'] == 1
    provider = summary['providers'][0]
    assert provider['node'] == 'pivot-172-21-240-0'
    assert provider['entry'] == f'ssh:{PIVOT_SSH_PORT}'
    assert provider['address'] == '172.21.240.4'
    # Who the entrance was opened for, which is not who the block shut out.
    assert HITL_SUBNET in provider['opened_for']


def test_the_cli_summarises_pivot_access_from_a_runtime_summary():
    from scenarioforge.cli import _pivot_access_summary

    # Execute holds the segmentation summary, not a preview.
    summary = _pivot_access_summary({'rules': [], 'pivot_access': _access_payload()})
    assert summary['provider_count'] == 1


def test_the_cli_reports_a_subnet_with_no_way_in():
    from scenarioforge.cli import _pivot_access_summary

    payload = _access_payload(providers=[], unresolved=[
        {'subnet': '10.9.9.0/24', 'reason': 'no switch serves this subnet'},
    ])
    summary = _pivot_access_summary({'pivot_access': payload})
    assert summary['unresolved'][0]['subnet'] == '10.9.9.0/24'


def test_the_cli_reports_nested_candidates_and_that_they_are_not_enforced():
    from scenarioforge.cli import _pivot_access_summary

    payload = _access_payload(nested_candidates=[{'subnet': '10.0.20.0/24',
                                                  'reached_through': ['10.0.10.0/24']}])
    summary = _pivot_access_summary({'pivot_access': payload})
    assert summary['nested_supported'] is False
    assert summary['nested_candidates'][0]['subnet'] == '10.0.20.0/24'


def test_the_cli_summary_is_absent_when_pivot_access_is_off():
    from scenarioforge.cli import _pivot_access_summary

    assert _pivot_access_summary({'segmentation_preview': {}}) is None
    assert _pivot_access_summary({}) is None
    assert _pivot_access_summary(None) is None


def test_the_topo_phase_reports_pivot_access():
    import inspect
    from scenarioforge import cli

    src = inspect.getsource(cli)
    assert "'pivot_access': _pivot_access_summary(preview_full)" in src


def test_a_phase_result_survives_an_unwritable_plan_output(tmp_path, capsys):
    # In VM mode the run is delegated to the CORE VM, so --plan-output names a
    # directory from the machine the command was typed on. Letting that raise
    # reported a topology that built correctly as a failed phase.
    from scenarioforge.cli import _emit_phase_json

    unwritable = tmp_path / 'no-such-device' / 'x'
    unwritable.mkdir(parents=True)
    unwritable.chmod(0o500)
    try:
        _emit_phase_json({'ok': True, 'phase': 'topo'}, output_path=str(unwritable / 'out.json'))
    finally:
        unwritable.chmod(0o700)
    captured = capsys.readouterr()
    assert '"phase": "topo"' in captured.out          # the result still lands on stdout
    assert 'could not write --plan-output' in captured.err


def test_a_plan_output_directory_is_created_when_missing(tmp_path, capsys):
    from scenarioforge.cli import _emit_phase_json

    target = tmp_path / 'nested' / 'deeper' / 'out.json'
    _emit_phase_json({'ok': True, 'phase': 'topo'}, output_path=str(target))
    assert target.is_file()
    assert '"phase": "topo"' in target.read_text(encoding='utf-8')
    assert 'could not write' not in capsys.readouterr().err
