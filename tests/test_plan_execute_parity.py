"""The scenario that runs is the scenario the plan showed.

Segmentation and traffic are both drawn from the global `random` module, so
running either planner a second time produces different answers than the plan
did -- a live run had the preview walling off three subnets and the same
scenario walling off two others. Since the plan is what the author reviews, what
Flow builds its chain against, and what pivot access places provider nodes for,
execute enforces the plan's decisions rather than making new ones.

These cover both directions: that a replay reproduces the plan exactly, and that
re-planning does not, so the guarantee is not accidentally satisfied by a lucky
seed.
"""

import hashlib
import os
import random

import pytest

from scenarioforge.cli import _planned_segmentation_rules, _planned_traffic_flows
from scenarioforge.types import NodeInfo, SegmentationInfo, TrafficInfo
from scenarioforge.utils.segmentation import (
    plan_and_apply_segmentation, segmentation_script_text, write_segmentation_script,
)
from scenarioforge.utils.traffic import generate_traffic_scripts


class _Session:
    """Enough session for the planner; node services are not under test here."""

    def get_node(self, node_id):
        return None


def _routers():
    return [NodeInfo(node_id=i, ip4=f'10.0.{i}.1/24', role='Router') for i in (1, 2, 3)]


def _hosts():
    return [
        NodeInfo(node_id=10 + i, ip4=f'10.0.{(i % 3) + 1}.{2 + i // 3}/24', role='PC')
        for i in range(9)
    ]


def _items():
    return [
        SegmentationInfo(name='Firewall', factor=1.0, abs_count=3),
        SegmentationInfo(name='NAT', factor=1.0, abs_count=1),
    ]


def _policy(summary):
    """What the policy actually is, independent of naming or ordering."""
    return sorted(
        (
            entry['node_id'],
            entry['rule'].get('type'),
            entry['rule'].get('src'),
            entry['rule'].get('dst') or entry['rule'].get('subnet'),
        )
        for entry in summary['rules']
    )


def _script_hashes(out_dir):
    return {
        name: hashlib.sha256(open(os.path.join(out_dir, name), 'rb').read()).hexdigest()
        for name in sorted(os.listdir(out_dir)) if name.endswith('.py')
    }


def _plan_segmentation(out_dir, seed, planned_rules=None):
    random.seed(seed)
    return plan_and_apply_segmentation(
        _Session(), _routers(), _hosts(), 1.0, _items(),
        out_dir=str(out_dir), include_hosts=True, planned_rules=planned_rules,
    )


# --------------------------------------------------------------------------- #
# Segmentation
# --------------------------------------------------------------------------- #

def test_replanning_does_not_reproduce_the_plan(tmp_path):
    # The premise. If this ever starts passing, the planner became deterministic
    # and the replay below is belt-and-braces rather than the whole guarantee.
    plan = _plan_segmentation(tmp_path / 'a', 99)
    again = _plan_segmentation(tmp_path / 'b', 12345)
    assert _policy(again) != _policy(plan)


def test_replaying_the_plan_reproduces_its_policy_exactly(tmp_path):
    plan = _plan_segmentation(tmp_path / 'a', 99)
    # A deliberately different RNG state, which is the realistic case: execute
    # has built a whole topology by the time segmentation runs.
    replay = _plan_segmentation(tmp_path / 'c', 777, planned_rules=plan['rules'])
    assert _policy(replay) == _policy(plan)


def test_replaying_the_plan_reproduces_its_scripts_byte_for_byte(tmp_path):
    plan = _plan_segmentation(tmp_path / 'a', 99)
    _plan_segmentation(tmp_path / 'c', 777, planned_rules=plan['rules'])
    assert _script_hashes(tmp_path / 'c') == _script_hashes(tmp_path / 'a')


def test_every_planned_rule_carries_its_own_enforcement(tmp_path):
    # Replay writes each rule's script from this spec, so a rule without one is
    # a rule that cannot be enforced as planned.
    plan = _plan_segmentation(tmp_path / 'a', 99)
    assert plan['rules']
    for entry in plan['rules']:
        spec = entry['rule'].get('script_spec')
        assert isinstance(spec, dict), entry
        assert segmentation_script_text(spec)


def test_a_replayed_rule_lands_in_this_runs_output_directory(tmp_path):
    # The plan's script paths come from whichever machine previewed; the run may
    # be on a different host entirely.
    plan = _plan_segmentation(tmp_path / 'a', 99)
    for entry in plan['rules']:
        entry['script'] = '/somewhere/else/' + os.path.basename(entry['script'])
    replay = _plan_segmentation(tmp_path / 'c', 777, planned_rules=plan['rules'])
    for entry in replay['rules']:
        assert entry['script'].startswith(str(tmp_path / 'c'))
        assert os.path.isfile(entry['script'])


def test_a_rule_without_a_script_is_refused_rather_than_half_applied(tmp_path):
    # A plan saved before rules carried their scripts. Recording it as applied
    # would have the summary claim a policy the scenario does not have.
    plan = _plan_segmentation(tmp_path / 'a', 99)
    stripped = []
    for entry in plan['rules']:
        clone = dict(entry)
        clone['rule'] = {k: v for k, v in entry['rule'].items() if k != 'script_spec'}
        stripped.append(clone)
    replay = _plan_segmentation(tmp_path / 'c', 777, planned_rules=stripped)
    assert replay['rules'] == []


def test_replay_is_skipped_when_the_plan_has_no_rules(tmp_path):
    # Nothing to replay must mean "plan normally", not "no segmentation at all".
    planned = _plan_segmentation(tmp_path / 'a', 99, planned_rules=[])
    assert planned['rules']


# --------------------------------------------------------------------------- #
# Which rules execute is willing to take from a plan
# --------------------------------------------------------------------------- #

def test_execute_reads_the_plans_rules():
    rules = [{'node_id': 1, 'service': 'Segmentation',
              'rule': {'type': 'subnet_block', 'src': 'a', 'dst': 'b',
                       'script_spec': {'kind': 'firewall', 'chain': 'FORWARD'}}}]
    preview = {'segmentation_preview': {'rules': rules}}
    assert _planned_segmentation_rules(preview) == rules


def test_execute_ignores_a_plan_whose_rules_carry_no_script():
    preview = {'segmentation_preview': {'rules': [
        {'node_id': 1, 'service': 'Segmentation', 'rule': {'type': 'subnet_block'}},
    ]}}
    assert _planned_segmentation_rules(preview) == []


def test_execute_tolerates_a_plan_without_segmentation():
    assert _planned_segmentation_rules({}) == []
    assert _planned_segmentation_rules(None) == []
    assert _planned_segmentation_rules({'segmentation_preview': {}}) == []


# --------------------------------------------------------------------------- #
# Traffic
# --------------------------------------------------------------------------- #

def _traffic_items():
    return [TrafficInfo(kind='TCP', factor=1.0, pattern='continuous', rate_kbps=128.0, abs_count=2),
            TrafficInfo(kind='UDP', factor=0.5, pattern='poisson', rate_kbps=64.0, abs_count=0)]


def _flows(out_dir, seed, planned_flows=None):
    random.seed(seed)
    generate_traffic_scripts(_hosts(), 0.6, _traffic_items(), out_dir=str(out_dir),
                             planned_flows=planned_flows)
    import json
    with open(os.path.join(str(out_dir), 'traffic_summary.json'), encoding='utf-8') as fh:
        return json.load(fh)['flows']


def _flow_shape(flows):
    return sorted((f['src_id'], f['dst_id'], f['protocol'], f['dst_port']) for f in flows)


def test_regenerating_traffic_does_not_reproduce_the_plans_flows(tmp_path):
    planned = _flows(tmp_path / 'a', 5)
    again = _flows(tmp_path / 'b', 4242)
    assert _flow_shape(again) != _flow_shape(planned)


def test_replaying_traffic_reproduces_the_plans_flows(tmp_path):
    planned = _flows(tmp_path / 'a', 5)
    replay = _flows(tmp_path / 'c', 4242, planned_flows=planned)
    assert _flow_shape(replay) == _flow_shape(planned)


def test_replayed_traffic_writes_the_same_per_node_configs(tmp_path):
    planned = _flows(tmp_path / 'a', 5)
    _flows(tmp_path / 'c', 4242, planned_flows=planned)
    names = lambda d: sorted(n for n in os.listdir(str(d)) if n.startswith('traffic_') and n.endswith('.json'))
    assert names(tmp_path / 'c') == names(tmp_path / 'a')


def test_execute_refuses_a_truncated_flow_list():
    # Replaying part of the plan would build a scenario with less traffic than
    # planned, which is worse than generating afresh and saying so.
    preview = {'traffic_scripts_preview': {
        'preview_flows': [{'src_id': 1, 'dst_id': 2}],
        'preview_flows_total': 900,
        'preview_flows_truncated': True,
    }}
    assert _planned_traffic_flows(preview) == []


def test_execute_reads_a_complete_flow_list():
    flows = [{'src_id': 1, 'dst_id': 2, 'protocol': 'TCP', 'dst_port': 5001}]
    preview = {'traffic_scripts_preview': {
        'preview_flows': flows, 'preview_flows_total': 1, 'preview_flows_truncated': False,
    }}
    assert _planned_traffic_flows(preview) == flows


def test_execute_tolerates_a_plan_without_traffic():
    assert _planned_traffic_flows({}) == []
    assert _planned_traffic_flows({'traffic_scripts_preview': {'preview_flows': []}}) == []
