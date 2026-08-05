"""A rule's recorded effect matches the rule actually written.

`segmentation_summary.json` records the planner's intent, and its fields change
meaning with the chain: a `subnet_block` on INPUT emits `-s SRC -j DROP`, which
never matches the `dst` the rule records, and a `protect_internal` on INPUT
emits `! -s NET -j DROP` on a node that need not be in NET. Consumers that
re-derived "what does this block" from those fields disagreed with each other
and with the firewall.

`rule_effect` states it once, from the planner's variables. `effect_from_iptables`
reads it back out of the emitted command. The two are computed from different
things on purpose, so comparing them across everything the planner can produce
catches an effect that does not describe the rule that was written -- which is
the exact fault this model exists to prevent.
"""

import random

import pytest

from scenarioforge.types import NodeInfo, SegmentationInfo
from scenarioforge.utils.segmentation import (
    EFFECT_NODE, EFFECT_TRANSIT, effect_from_iptables,
    plan_and_apply_segmentation, rule_effect,
)


class _Session:
    def get_node(self, node_id):
        return None


def _plan(tmp_path, seed, *, include_hosts):
    """A planned policy. Seeds are swept by the callers to cover rule shapes."""
    routers = [NodeInfo(node_id=i, ip4=f'10.0.{i}.1/24', role='Router') for i in (1, 2, 3)]
    hosts = [
        NodeInfo(node_id=10 + i, ip4=f'10.0.{(i % 3) + 1}.{2 + i // 3}/24', role='PC')
        for i in range(9)
    ]
    random.seed(seed)
    summary = plan_and_apply_segmentation(
        _Session(), routers, hosts, 1.0,
        [SegmentationInfo(name='Firewall', factor=1.0, abs_count=4),
         SegmentationInfo(name='NAT', factor=1.0, abs_count=1)],
        out_dir=str(tmp_path / f'seed-{seed}-{include_hosts}'),
        include_hosts=include_hosts,
    )
    node_ips = {n.node_id: n.ip4.split('/')[0] for n in routers + hosts}
    return summary, node_ips


def _planned_rules(tmp_path, *, include_hosts):
    """Every rule across a sweep of seeds, so all rule shapes get covered."""
    out = []
    for seed in range(40):
        summary, node_ips = _plan(tmp_path, seed, include_hosts=include_hosts)
        for entry in summary['rules']:
            out.append((entry, node_ips))
    assert out, 'the sweep produced no rules to check'
    return out


def _blocking_commands(entry):
    spec = entry['rule'].get('script_spec') or {}
    return [c for c in (spec.get('commands') or []) if 'DROP' in c]


# --------------------------------------------------------------------------- #
# The property: recorded effect == the rule that was written
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('include_hosts', [False, True])
def test_every_recorded_effect_describes_the_command_written(tmp_path, include_hosts):
    checked = 0
    for entry, node_ips in _planned_rules(tmp_path, include_hosts=include_hosts):
        rule = entry['rule']
        effect = rule.get('effect')
        assert isinstance(effect, dict), rule
        commands = _blocking_commands(entry)
        if not commands:
            # NAT, CUSTOM and `none` deny no path of their own.
            assert effect['blocks'] is False, rule
            continue
        assert len(commands) == 1, commands
        node_ip = node_ips.get(effect['enforced_by'], '')
        observed = effect_from_iptables(commands[0], node_ip=node_ip)
        assert observed is not None, commands
        for key in ('scope', 'blocks', 'protects', 'blocks_from', 'invert_source'):
            assert effect[key] == observed[key], (
                f'{key}: recorded {effect[key]!r} but the rule written was '
                f'{commands[0]!r}'
            )
        checked += 1
    assert checked, 'no blocking rules were produced to check'


@pytest.mark.parametrize('include_hosts', [False, True])
def test_a_host_enforced_rule_is_scoped_to_the_node_that_runs_it(tmp_path, include_hosts):
    seen_node_scope = False
    for entry, node_ips in _planned_rules(tmp_path, include_hosts=include_hosts):
        effect = entry['rule']['effect']
        if effect['scope'] != EFFECT_NODE or not effect['blocks']:
            continue
        seen_node_scope = True
        # It shields the node it sits on, never some subnet elsewhere.
        assert effect['protects'] == node_ips.get(effect['enforced_by'])
    if include_hosts:
        assert seen_node_scope, 'include_hosts should produce host-enforced rules'


def test_router_enforced_rules_are_transit_scoped(tmp_path):
    for entry, _ips in _planned_rules(tmp_path, include_hosts=False):
        assert entry['rule']['effect']['scope'] == EFFECT_TRANSIT


# --------------------------------------------------------------------------- #
# The two halves, read directly
# --------------------------------------------------------------------------- #

class _Node:
    def __init__(self, node_id, ip4):
        self.node_id = node_id
        self.ip4 = ip4


def test_a_transit_subnet_block_shields_the_destination_subnet():
    rule = {'type': 'subnet_block', 'node': 1, 'src': '10.0.2.0/24', 'dst': '10.0.1.0/24'}
    effect = rule_effect(rule, chain='FORWARD', node=_Node(1, '10.0.1.1/24'))
    assert effect == {
        'scope': EFFECT_TRANSIT, 'enforced_by': 1, 'blocks': True,
        'protects': '10.0.1.0/24', 'blocks_from': '10.0.2.0/24',
        'invert_source': False, 'default_deny_chain': 'FORWARD',
    }


def test_a_node_subnet_block_shields_only_the_node():
    # The emitted rule is `-A INPUT -s SRC -j DROP`, which never matches on dst,
    # so recording the planner's dst here would describe a rule nobody wrote.
    rule = {'type': 'subnet_block', 'node': 12, 'src': '10.0.2.0/24', 'dst': '10.0.1.0/24'}
    effect = rule_effect(rule, chain='INPUT', node=_Node(12, '10.0.1.5/24'))
    assert effect['scope'] == EFFECT_NODE
    assert effect['protects'] == '10.0.1.5'


def test_a_transit_protect_internal_shields_its_subnet_from_everything_else():
    rule = {'type': 'protect_internal', 'node': 1, 'subnet': '10.0.1.0/24'}
    effect = rule_effect(rule, chain='FORWARD', node=_Node(1, '10.0.1.1/24'))
    assert effect['protects'] == '10.0.1.0/24'
    assert effect['blocks_from'] == '10.0.1.0/24'
    assert effect['invert_source'] is True


def test_a_node_protect_internal_shields_the_node_not_the_named_subnet():
    # This is the case that placed a pivot provider in the wrong subnet: the
    # rule names 192.168.67.0/24 while sitting on a host in another subnet
    # entirely, and only that host is protected.
    rule = {'type': 'protect_internal', 'node': 6, 'subnet': '192.168.67.0/24'}
    effect = rule_effect(rule, chain='INPUT', node=_Node(6, '192.168.12.2/24'))
    assert effect['scope'] == EFFECT_NODE
    assert effect['protects'] == '192.168.12.2'
    assert effect['blocks_from'] == '192.168.67.0/24'
    assert effect['invert_source'] is True


def test_the_parser_reads_each_shape_the_planner_emits():
    cases = [
        ('iptables -A FORWARD -s 10.0.2.0/24 -d 10.0.1.0/24 -j DROP',
         {'scope': EFFECT_TRANSIT, 'protects': '10.0.1.0/24',
          'blocks_from': '10.0.2.0/24', 'invert_source': False}),
        ('iptables -A INPUT -s 10.0.2.0/24 -j DROP',
         {'scope': EFFECT_NODE, 'protects': '10.0.1.5',
          'blocks_from': '10.0.2.0/24', 'invert_source': False}),
        ('iptables -A FORWARD ! -s 10.0.1.0/24 -d 10.0.1.0/24 -j DROP',
         {'scope': EFFECT_TRANSIT, 'protects': '10.0.1.0/24',
          'blocks_from': '10.0.1.0/24', 'invert_source': True}),
        ('iptables -A INPUT ! -s 10.0.1.0/24 -j DROP',
         {'scope': EFFECT_NODE, 'protects': '10.0.1.5',
          'blocks_from': '10.0.1.0/24', 'invert_source': True}),
        ('iptables -A FORWARD -s 10.0.1.4 -d 10.0.2.7 -j DROP',
         {'scope': EFFECT_TRANSIT, 'protects': '10.0.2.7',
          'blocks_from': '10.0.1.4', 'invert_source': False}),
    ]
    for command, expected in cases:
        observed = effect_from_iptables(command, node_ip='10.0.1.5/24')
        assert observed is not None, command
        for key, value in expected.items():
            assert observed[key] == value, (command, key, observed[key])


def test_the_parser_ignores_commands_that_deny_nothing():
    assert effect_from_iptables('iptables -A INPUT -p tcp --dport 22 -j ACCEPT') is None
    assert effect_from_iptables('iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -j MASQUERADE') is None
    assert effect_from_iptables('') is None


# --------------------------------------------------------------------------- #
# What pivot access now reads
# --------------------------------------------------------------------------- #

def _entry(node_id, rule):
    return {'node_id': node_id, 'service': 'Segmentation', 'rule': rule}


def test_a_transit_block_still_walls_its_subnet_off():
    from scenarioforge.utils.pivot_access import walled_off_details

    rule = {'type': 'subnet_block', 'node': 1, 'src': '10.0.2.0/24', 'dst': '10.0.1.0/24'}
    rule['effect'] = rule_effect(rule, chain='FORWARD', node=_Node(1, '10.0.1.1/24'))
    details = walled_off_details([_entry(1, rule)])
    assert list(details) == ['10.0.1.0/24']
    assert details['10.0.1.0/24']['sources'] == ['10.0.2.0/24']
    assert details['10.0.1.0/24']['enforced_by'] == [1]


def test_a_host_enforced_block_walls_nothing_off():
    # The live bug: this rule shields one host on node 6, but was read as
    # walling off 192.168.67.0/24 -- so a provider node was built and addressed
    # in a subnet nothing was protecting.
    from scenarioforge.utils.pivot_access import walled_off_details

    rule = {'type': 'protect_internal', 'node': 6, 'subnet': '192.168.67.0/24'}
    rule['effect'] = rule_effect(rule, chain='INPUT', node=_Node(6, '192.168.12.2/24'))
    assert walled_off_details([_entry(6, rule)]) == {}


def test_a_host_enforced_subnet_block_walls_nothing_off():
    from scenarioforge.utils.pivot_access import walled_off_details

    rule = {'type': 'subnet_block', 'node': 12, 'src': '10.0.2.0/24', 'dst': '10.0.1.0/24'}
    rule['effect'] = rule_effect(rule, chain='INPUT', node=_Node(12, '10.0.1.5/24'))
    assert walled_off_details([_entry(12, rule)]) == {}


def test_a_transit_host_block_walls_nothing_off():
    # Unchanged behaviour, but now for a stated reason rather than a type name:
    # a /32 holds only the blocked host, so the pivot would be an allow straight
    # back into what the rule exists to block.
    from scenarioforge.utils.pivot_access import walled_off_details

    rule = {'type': 'host_block', 'node': 1, 'src': '10.0.2.7', 'dst': '10.0.1.4'}
    rule['effect'] = rule_effect(rule, chain='FORWARD', node=_Node(1, '10.0.1.1/24'))
    assert walled_off_details([_entry(1, rule)]) == {}


def test_a_plan_without_effects_still_reads(tmp_path):
    # Plans saved before rules carried an effect keep working, via the emitted
    # command and then the old fields.
    from scenarioforge.utils.pivot_access import walled_off_details

    rule = {'type': 'subnet_block', 'node': 1, 'src': '10.0.2.0/24', 'dst': '10.0.1.0/24',
            'script_spec': {'kind': 'firewall', 'chain': 'FORWARD',
                            'commands': ['iptables -A FORWARD -s 10.0.2.0/24 -d 10.0.1.0/24 -j DROP']}}
    assert list(walled_off_details([_entry(1, rule)])) == ['10.0.1.0/24']

    bare = {'type': 'subnet_block', 'node': 1, 'src': '10.0.2.0/24', 'dst': '10.0.1.0/24'}
    assert list(walled_off_details([_entry(1, bare)])) == ['10.0.1.0/24']


# --------------------------------------------------------------------------- #
# What the traffic allow generator now sees
# --------------------------------------------------------------------------- #

def _flow_allowed(rules, *, src, dst, recv_node_id, hosts=None):
    from scenarioforge.utils.segmentation import _flow_allowed_by_summary

    hosts = hosts or [
        NodeInfo(node_id=5, ip4='192.168.60.2/24', role='PC'),
        NodeInfo(node_id=9, ip4='10.0.7.9/24', role='PC'),
    ]
    return _flow_allowed_by_summary(rules, hosts, src, dst, 'tcp', 5001, recv_node_id)


def test_a_host_enforced_block_is_no_longer_missed():
    # The old reading required the destination to sit inside the subnet the rule
    # names. A host-enforced protect_internal names a subnet the node is not in,
    # so the flow was judged fine, no allow was written, and the traffic
    # silently never flowed.
    rule = {'type': 'protect_internal', 'node': 5, 'subnet': '172.21.240.0/24', 'chain': 'INPUT'}
    rule['effect'] = rule_effect(rule, chain='INPUT', node=_Node(5, '192.168.60.2/24'))
    rules = [_entry(5, rule)]
    assert _flow_allowed(rules, src='10.0.7.9', dst='192.168.60.2', recv_node_id=5) is False


def test_a_host_enforced_block_does_not_touch_a_flow_to_another_host():
    rule = {'type': 'protect_internal', 'node': 5, 'subnet': '172.21.240.0/24', 'chain': 'INPUT'}
    rule['effect'] = rule_effect(rule, chain='INPUT', node=_Node(5, '192.168.60.2/24'))
    rules = [_entry(5, rule)]
    assert _flow_allowed(rules, src='192.168.60.2', dst='10.0.7.9', recv_node_id=9) is True


def test_a_source_inside_the_protected_network_is_still_let_through():
    rule = {'type': 'protect_internal', 'node': 5, 'subnet': '10.0.7.0/24', 'chain': 'INPUT'}
    rule['effect'] = rule_effect(rule, chain='INPUT', node=_Node(5, '192.168.60.2/24'))
    rules = [_entry(5, rule)]
    # 10.0.7.9 is inside the network the rule accepts from.
    assert _flow_allowed(rules, src='10.0.7.9', dst='192.168.60.2', recv_node_id=5) is True


def test_a_transit_block_still_demands_a_forward_allow():
    rule = {'type': 'subnet_block', 'node': 1, 'src': '10.0.7.0/24', 'dst': '192.168.60.0/24'}
    rule['effect'] = rule_effect(rule, chain='FORWARD', node=_Node(1, '192.168.60.1/24'))
    rules = [_entry(1, rule)]
    assert _flow_allowed(rules, src='10.0.7.9', dst='192.168.60.2', recv_node_id=5) is False


def test_an_unrelated_block_leaves_the_flow_alone():
    rule = {'type': 'subnet_block', 'node': 1, 'src': '172.16.0.0/24', 'dst': '172.31.0.0/24'}
    rule['effect'] = rule_effect(rule, chain='FORWARD', node=_Node(1, '172.31.0.1/24'))
    rules = [_entry(1, rule)]
    assert _flow_allowed(rules, src='10.0.7.9', dst='192.168.60.2', recv_node_id=5) is True


def test_providers_are_only_planned_for_transit_blocks(tmp_path):
    # End to end: a policy of host-enforced rules asks for no provider at all.
    from scenarioforge.types import NodeInfo as _NI
    from scenarioforge.utils.pivot_access import plan_pivot_access

    summary, node_ips = _plan(tmp_path, 3, include_hosts=True)
    node_scoped = [e for e in summary['rules']
                   if e['rule'].get('effect', {}).get('scope') == EFFECT_NODE
                   and e['rule']['effect'].get('blocks')]
    if not node_scoped:
        pytest.skip('this seed placed no host-enforced blocks')
    hosts = [_NI(node_id=nid, ip4=f'{ip}/24', role='PC') for nid, ip in node_ips.items()]
    plan = plan_pivot_access(node_scoped, hosts)
    assert plan.providers == []
