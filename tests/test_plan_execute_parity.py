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


# --------------------------------------------------------------------------- #
# Settings that shape the policy are plan-time inputs
# --------------------------------------------------------------------------- #

SEGMENTATION_XML = """<?xml version='1.0' encoding='utf-8'?>
<Scenarios><Scenario name="S"><ScenarioEditor>
  <section name="Segmentation" density="0.5" {attrs}>
    <item selected="Firewall" factor="1.000" v_metric="Count" v_count="1" />
  </section>
</ScenarioEditor></Scenario></Scenarios>
"""


def _xml(tmp_path, attrs=''):
    path = tmp_path / 'scenario.xml'
    path.write_text(SEGMENTATION_XML.format(attrs=attrs), encoding='utf-8')
    return str(path)


class _Args:
    """A CLI namespace where nothing was passed."""

    scenario = 'S'
    nat_mode = None
    seg_include_hosts = None
    seg_accessible_by_pivot = None
    dnat_prob = None
    allow_src_subnet_prob = None
    allow_dst_subnet_prob = None

    def __init__(self, xml, **overrides):
        self.xml = xml
        for key, value in overrides.items():
            setattr(self, key, value)


def test_a_scenario_without_settings_gets_the_documented_defaults(tmp_path):
    from scenarioforge.cli import _seg_settings
    from scenarioforge.parsers.segmentation import SEGMENTATION_SETTING_DEFAULTS

    assert _seg_settings(_Args(_xml(tmp_path))) == SEGMENTATION_SETTING_DEFAULTS


def test_settings_travel_with_the_scenario(tmp_path):
    from scenarioforge.cli import _seg_settings

    path = _xml(tmp_path, 'nat_mode="MASQUERADE" include_hosts="true" dnat_probability="0.25"')
    settings = _seg_settings(_Args(path))
    assert settings['nat_mode'] == 'MASQUERADE'
    assert settings['include_hosts'] is True
    assert settings['dnat_probability'] == 0.25


def test_a_flag_that_was_passed_overrides_the_scenario(tmp_path):
    from scenarioforge.cli import _seg_settings

    path = _xml(tmp_path, 'nat_mode="MASQUERADE"')
    assert _seg_settings(_Args(path, nat_mode='SNAT'))['nat_mode'] == 'SNAT'


def test_a_flag_that_was_not_passed_leaves_the_scenario_alone(tmp_path):
    # The flags default to None so this stays distinguishable from passing the
    # value that happens to be the default.
    from scenarioforge.cli import _seg_settings

    path = _xml(tmp_path, 'nat_mode="MASQUERADE" allow_src_subnet_prob="0.9"')
    settings = _seg_settings(_Args(path))
    assert settings['nat_mode'] == 'MASQUERADE'
    assert settings['allow_src_subnet_prob'] == 0.9


def test_an_absent_switch_never_turns_a_scenario_setting_off(tmp_path):
    # A store_true flag only ever turns something on; not passing it is not an
    # instruction to override a scenario that turns it on.
    from scenarioforge.cli import _seg_settings

    path = _xml(tmp_path, 'include_hosts="true" accessible_by_pivot="true"')
    settings = _seg_settings(_Args(path, seg_include_hosts=False, seg_accessible_by_pivot=False))
    assert settings['include_hosts'] is True
    assert settings['accessible_by_pivot'] is True


def test_the_plan_records_the_settings_it_was_built_with(tmp_path):
    from scenarioforge.planning.full_preview import build_full_preview

    full = build_full_preview(
        role_counts={'PC': 4}, routers_planned=2, services_plan={}, vulnerabilities_plan={},
        r2r_policy=None, r2s_policy={'mode': 'Exact', 'target_per_router': 1},
        routing_items=None, routing_plan={}, segmentation_density=0.8,
        segmentation_items=[{'selected': 'Firewall', 'factor': 1.0}],
        traffic_plan=None, seed=7, ip4_prefix='10.10.0.0/16',
        segmentation_settings={'nat_mode': 'MASQUERADE', 'dnat_probability': 0.5},
    )
    settings = full['segmentation_preview']['settings']
    assert settings['nat_mode'] == 'MASQUERADE'
    assert settings['dnat_probability'] == 0.5


def test_execute_reads_the_settings_from_the_plan():
    from scenarioforge.cli import _plan_segmentation_settings

    plan = {'segmentation_preview': {'settings': {'nat_mode': 'MASQUERADE'}}}
    settings = _plan_segmentation_settings(plan)
    assert settings['nat_mode'] == 'MASQUERADE'
    # Filled out, so callers never have to decide what a missing key means.
    assert settings['allow_src_subnet_prob'] == 0.3


def test_a_setting_that_arrives_too_late_is_reported(tmp_path):
    # Silently ignoring it would let someone pass --nat-mode MASQUERADE and get
    # SNAT with no indication of why.
    from scenarioforge.cli import _segmentation_settings_conflicts

    conflicts = _segmentation_settings_conflicts(
        {'nat_mode': 'SNAT', 'dnat_probability': 0.0},
        {'nat_mode': 'MASQUERADE', 'dnat_probability': 0.0},
    )
    assert len(conflicts) == 1
    assert 'nat_mode' in conflicts[0] and 'MASQUERADE' in conflicts[0]


def test_matching_settings_are_not_reported_as_a_conflict():
    from scenarioforge.cli import _segmentation_settings_conflicts

    settings = {'nat_mode': 'SNAT', 'allow_src_subnet_prob': 0.3, 'include_hosts': False}
    assert _segmentation_settings_conflicts(settings, dict(settings)) == []


# --------------------------------------------------------------------------- #
# Per-flow decisions are the flow's, not the moment's
# --------------------------------------------------------------------------- #

def test_a_flows_draw_is_the_same_every_time_it_is_asked():
    from scenarioforge.utils.segmentation import flow_draw

    flow = {'src_id': 4, 'dst_id': 9, 'protocol': 'TCP', 'dst_port': 5009}
    random.seed(1)
    first = flow_draw(flow, 'dnat')
    random.seed(999)
    assert flow_draw(dict(flow), 'dnat') == first


def test_different_flows_and_different_questions_draw_independently():
    from scenarioforge.utils.segmentation import flow_draw

    a = {'src_id': 4, 'dst_id': 9, 'protocol': 'TCP', 'dst_port': 5009}
    b = {'src_id': 7, 'dst_id': 8, 'protocol': 'TCP', 'dst_port': 5008}
    assert flow_draw(a, 'dnat') != flow_draw(b, 'dnat')
    assert flow_draw(a, 'dnat') != flow_draw(a, 'allow-src')


def test_a_draw_stays_inside_the_unit_interval():
    from scenarioforge.utils.segmentation import flow_draw

    for port in range(5000, 5050):
        value = flow_draw({'src_id': 1, 'dst_id': 2, 'protocol': 'TCP', 'dst_port': port}, 'x')
        assert 0.0 <= value < 1.0
