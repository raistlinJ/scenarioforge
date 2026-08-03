"""The pivot classification reaches the chain rows.

`pivot_grants` is what the Flow chain rows and the guides read to draw the star.
These cover the path that populates it: preview topology + preview segmentation
rules -> pivot access plan -> classification -> stamped assignment.
"""

from webapp import app_backend as ab


def _preview(*, enabled=True, rules=None, hosts=None, routers=None):
    return {
        'hosts': hosts if hosts is not None else [
            {'node_id': 6, 'name': 'docker-21', 'role': 'Docker', 'ip4': '172.21.240.6/24'},
            {'node_id': 7, 'name': 'flaggenslot-1', 'role': 'FlagGenSlot', 'ip4': '172.21.240.2/24'},
            {'node_id': 9, 'name': 'docker-23', 'role': 'Docker', 'ip4': '10.0.140.6/24'},
        ],
        'routers': routers if routers is not None else [
            {'node_id': 1, 'name': 'router-1', 'role': 'Router', 'ip4': '172.21.240.1/24'},
        ],
        'segmentation_preview': {
            'accessible_by_pivot': enabled,
            'rules': rules if rules is not None else [{
                'node_id': 1, 'service': 'Segmentation',
                'rule': {'type': 'subnet_block', 'src': '10.0.140.0/24',
                         'dst': '172.21.240.0/24', 'default_deny': True},
            }],
        },
    }


def _chain(provides=('CodeExecution(host)',)):
    return [{'id': 'docker-21', 'name': 'docker-21', 'provides': list(provides)}]


def _assignments():
    return [{'node_id': 'docker-21', 'name': 'docker-21'}]


# --------------------------------------------------------------------------- #
# The happy path: an RCE step earns the star
# --------------------------------------------------------------------------- #

def test_rce_step_is_stamped_with_the_subnet_it_opens():
    out = ab._flow_stamp_pivot_grants(_assignments(), _chain(), _preview())
    assert out[0]['pivot_grants'] == ['172.21.240.0/24']


def test_the_full_classification_rides_along_for_explanations():
    out = ab._flow_stamp_pivot_grants(_assignments(), _chain(), _preview())
    decisions = out[0]['pivot_decisions']
    assert decisions and decisions[0]['disposition'] == 'absorbed'
    assert decisions[0]['provider_node'] == 'docker-21'
    assert decisions[0]['reason']


def test_a_step_without_code_execution_gets_no_star():
    # Its pivot is its own step, so this row must stay unmarked.
    out = ab._flow_stamp_pivot_grants(
        _assignments(), _chain(provides=['Credential(user, password)']), _preview())
    assert 'pivot_grants' not in out[0]
    assert out[0]['pivot_decisions'][0]['disposition'] == 'own_step'


# --------------------------------------------------------------------------- #
# It stays out of the way when it should
# --------------------------------------------------------------------------- #

def test_toggle_off_stamps_nothing():
    out = ab._flow_stamp_pivot_grants(_assignments(), _chain(), _preview(enabled=False))
    assert 'pivot_grants' not in out[0]
    assert 'pivot_decisions' not in out[0]


def test_no_segmentation_rules_stamps_nothing():
    out = ab._flow_stamp_pivot_grants(_assignments(), _chain(), _preview(rules=[]))
    assert 'pivot_grants' not in out[0]


def test_nothing_walled_off_stamps_nothing():
    rules = [{'node_id': 1, 'rule': {'type': 'nat', 'internal': '10.0.0.0/24'}}]
    out = ab._flow_stamp_pivot_grants(_assignments(), _chain(), _preview(rules=rules))
    assert 'pivot_grants' not in out[0]


def test_empty_inputs_are_returned_untouched():
    assert ab._flow_stamp_pivot_grants([], _chain(), _preview()) == []
    assert ab._flow_stamp_pivot_grants(None, _chain(), _preview()) is None


def test_non_dict_assignments_survive():
    out = ab._flow_stamp_pivot_grants(['junk', {'node_id': 'docker-21'}], _chain(), _preview())
    assert out[0] == 'junk'


def test_a_broken_preview_does_not_break_sequencing():
    for bad in (None, {}, {'hosts': 'nope'}, {'segmentation_preview': {'rules': 'nope'}}):
        assert ab._flow_stamp_pivot_grants(_assignments(), _chain(), bad) == _assignments()


# --------------------------------------------------------------------------- #
# Matching the provider to the right row
# --------------------------------------------------------------------------- #

def test_only_the_provider_row_is_stamped():
    assignments = [
        {'node_id': 'flaggenslot-1', 'name': 'flaggenslot-1'},
        {'node_id': 'docker-21', 'name': 'docker-21'},
    ]
    chain = [
        {'id': 'flaggenslot-1', 'name': 'flaggenslot-1', 'provides': ['Flag(flag_id)']},
        {'id': 'docker-21', 'name': 'docker-21', 'provides': ['Shell(host)']},
    ]
    out = ab._flow_stamp_pivot_grants(assignments, chain, _preview())
    assert 'pivot_grants' not in out[0]
    assert out[1]['pivot_grants'] == ['172.21.240.0/24']


def test_row_is_matched_by_position_when_the_assignment_lacks_a_name():
    out = ab._flow_stamp_pivot_grants([{}], _chain(), _preview())
    assert out[0]['pivot_grants'] == ['172.21.240.0/24']


# --------------------------------------------------------------------------- #
# The toggle's journey from XML to preview
# --------------------------------------------------------------------------- #

def test_preview_helpers_read_the_toggle():
    assert ab._flow_pivot_access_enabled(_preview()) is True
    assert ab._flow_pivot_access_enabled(_preview(enabled=False)) is False
    assert ab._flow_pivot_access_enabled({}) is False
    assert ab._flow_pivot_access_enabled(None) is False


def test_preview_nodeinfo_splits_hosts_from_routers():
    hosts, routers, names = ab._flow_preview_nodeinfo(_preview())
    assert [h.node_id for h in hosts] == [6, 7, 9]
    assert [r.node_id for r in routers] == [1]
    assert names[6] == 'docker-21' and names[1] == 'router-1'


def test_preview_nodeinfo_skips_entries_without_an_address():
    preview = _preview(hosts=[{'node_id': 6, 'name': 'x', 'role': 'Docker'}])
    hosts, _routers, _names = ab._flow_preview_nodeinfo(preview)
    assert hosts == []


def test_builder_carries_the_toggle_into_the_preview():
    import inspect
    from scenarioforge.planning.full_preview import build_full_preview
    sig = inspect.signature(build_full_preview)
    assert sig.parameters['segmentation_accessible_by_pivot'].default is False


def test_orchestrator_reads_the_toggle_from_the_scenario(tmp_path):
    from scenarioforge.parsers.segmentation import parse_segmentation_accessible_by_pivot
    path = tmp_path / 's.xml'
    path.write_text(
        '<Scenarios><Scenario name="S1">'
        '<section name="Segmentation" density="0.5" accessible_by_pivot="true"/>'
        '</Scenario></Scenarios>', encoding='utf-8')
    assert parse_segmentation_accessible_by_pivot(str(path), 'S1') is True
    # And the orchestrator puts it on the plan, which is how it reaches preview.
    import pathlib
    orch = pathlib.Path('scenarioforge/planning/orchestrator.py').read_text(encoding='utf-8')
    assert "seg_breakdown['accessible_by_pivot']" in orch
