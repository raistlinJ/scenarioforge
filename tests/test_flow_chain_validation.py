

# --------------------------------------------------------------------------- #
# An input Flow supplies is not a chain dependency
# --------------------------------------------------------------------------- #

def _supply_when_first_chain():
    """Two steps where the second declares a Flow-supplied credential.

    Taken from a real scenario: a DNS generator followed by a cache generator
    whose `Credential(user, password)` is marked `flow_supply_when_first`. The
    credential resolved to a real value with nothing upstream producing it,
    because Flow supplied it -- and then the page reported the chain invalid on
    refresh.
    """
    chain = [{'id': '26', 'name': '26'}, {'id': '27', 'name': '27'}]
    assignments = [
        {
            'node_id': '26', 'id': '138', 'flag_generator': 'DNS',
            'inputs': ['Knowledge(ip)', 'node_name', 'seed'],
            'outputs': ['Flag(flag_id)', 'FlagFile(path)'],
            'input_fields_required': ['node_name', 'seed'],
            'input_defs': [
                {'name': 'seed', 'type': 'string', 'required': True},
                {'name': 'node_name', 'type': 'string', 'required': True},
            ],
        },
        {
            'node_id': '27', 'id': '127', 'flag_generator': 'Cache',
            'inputs': ['Credential(user, password)', 'Knowledge(ip)', 'node_name', 'seed'],
            'outputs': ['Credential(user, password)', 'Flag(flag_id)'],
            'input_fields_required': ['Credential(user, password)', 'node_name', 'seed'],
            'input_defs': [
                {'name': 'seed', 'type': 'string', 'required': True},
                {'name': 'node_name', 'type': 'string', 'required': True},
                {'name': 'Credential(user, password)', 'type': 'string',
                 'required': True, 'sensitive': True, 'flow_supply_when_first': True},
            ],
        },
    ]
    return chain, assignments


def test_a_flow_supplied_input_is_not_reported_as_an_unmet_dependency():
    from webapp import app_backend as ab

    chain, assignments = _supply_when_first_chain()
    ok, errors = ab._flow_validate_chain_order_by_requires_produces(
        chain, assignments, scenario_label='S')
    assert ok is True, errors
    assert errors == []


def test_a_genuinely_unproduced_requirement_is_still_reported():
    # The relaxation is exactly the supply marker, nothing wider: a required
    # input nothing produces and Flow does not supply is still a broken order.
    from webapp import app_backend as ab

    chain, assignments = _supply_when_first_chain()
    assignments[1]['inputs'] = list(assignments[1]['inputs']) + ['Nonexistent(thing)']
    ok, errors = ab._flow_validate_chain_order_by_requires_produces(
        chain, assignments, scenario_label='S')
    assert ok is False
    assert any('Nonexistent(thing)' in str(e) for e in errors)


def test_the_supply_marker_is_read_off_an_assignment_not_only_a_manifest():
    # A generator definition carries its input dicts under `inputs`; an
    # assignment carries plain fact names there and the dicts under
    # `input_defs`. Preferring `inputs` outright found nothing on an assignment
    # -- every entry is a string and was skipped -- so a Flow-supplied input
    # read as an unmet dependency whenever the caller held an assignment.
    from webapp import app_backend as ab

    assignment = {
        'node_id': '27',
        'inputs': ['Credential(user, password)', 'node_name', 'seed'],
        'input_defs': [
            {'name': 'seed', 'required': True},
            {'name': 'Credential(user, password)', 'required': True,
             'flow_supply_when_first': True},
        ],
    }
    assert ab._flow_first_step_chain_supplied_input_names(assignment) == [
        'Credential(user, password)'
    ]


def test_the_marker_is_still_read_off_a_generator_manifest():
    # The manifest shape must keep working: it is what the sequencer reads.
    from webapp import app_backend as ab

    manifest = {
        'id': '127',
        'inputs': [
            {'name': 'seed', 'required': True},
            {'name': 'Credential(user, password)', 'required': True,
             'flow_supply_when_first': True},
        ],
    }
    assert ab._flow_first_step_chain_supplied_input_names(manifest) == [
        'Credential(user, password)'
    ]


def test_the_validator_and_the_sequencer_read_the_marker_the_same_way():
    # They disagreed because each re-derived it; the validator now uses the
    # sequencer's own helper so a new spelling of the marker cannot split them.
    import inspect
    from webapp import app_backend as ab

    src = inspect.getsource(ab._flow_validate_chain_order_by_requires_produces)
    assert '_flow_first_step_chain_supplied_input_names' in src
