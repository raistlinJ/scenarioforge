

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



def _plugin_contracts(assignments):
    """Self-contained plugin contracts for the steps under test.

    The validator looks each generator id up in the *installed* catalog and
    bails with "unknown plugin" before checking anything else. These
    assignments carry real ids (138, 127), so on a developer machine with those
    packs installed the lookup succeeded and the test measured what it meant to
    -- and on a clean CI runner it failed, having never run the check at all.

    `requires`/`produces` are the only fields the validator reads off a
    contract, and fact-shaped entries are the only ones that participate in
    ordering, so deriving them from the assignment keeps the test about the
    thing it is named for.
    """
    return {
        str(a['id']): {
            'requires': [x for x in a.get('inputs', []) if '(' in str(x)],
            'produces': [x for x in a.get('outputs', []) if '(' in str(x)],
        }
        for a in assignments
    }


def test_a_flow_supplied_input_is_not_reported_as_an_unmet_dependency():
    from webapp import app_backend as ab

    chain, assignments = _supply_when_first_chain()
    ok, errors = ab._flow_validate_chain_order_by_requires_produces(
        chain, assignments, scenario_label='S',
        plugins_by_id_override=_plugin_contracts(assignments))
    assert ok is True, errors
    assert errors == []


def test_a_genuinely_unproduced_requirement_is_still_reported():
    # The relaxation is exactly the supply marker, nothing wider: a required
    # input nothing produces and Flow does not supply is still a broken order.
    from webapp import app_backend as ab

    chain, assignments = _supply_when_first_chain()
    assignments[1]['inputs'] = list(assignments[1]['inputs']) + ['Nonexistent(thing)']
    ok, errors = ab._flow_validate_chain_order_by_requires_produces(
        chain, assignments, scenario_label='S',
        plugins_by_id_override=_plugin_contracts(assignments))
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


# --------------------------------------------------------------------------- #
# The same two shapes, wherever per-input metadata is read
# --------------------------------------------------------------------------- #

def _assignment_with_typed_supply():
    return {
        'node_id': '27', 'id': '127',
        'inputs': ['Credential(user, password)', 'retry_budget', 'node_name'],
        'input_defs': [
            {'name': 'node_name', 'type': 'string', 'required': True},
            {'name': 'Credential(user, password)', 'type': 'string', 'required': True,
             'flow_supply_when_first': True},
            {'name': 'retry_budget', 'type': 'integer', 'required': True,
             'flow_supply_when_first': True},
        ],
    }


def test_input_metadata_is_found_in_either_shape():
    from webapp import app_backend as ab

    manifest = {'inputs': [{'name': 'a', 'type': 'integer'}]}
    assignment = {'inputs': ['a'], 'input_defs': [{'name': 'a', 'type': 'integer'}]}
    assert ab._flow_input_defs_with_metadata(manifest) == [{'name': 'a', 'type': 'integer'}]
    assert ab._flow_input_defs_with_metadata(assignment) == [{'name': 'a', 'type': 'integer'}]
    # Strings carry no metadata, so a list of them is not the definitions list.
    assert ab._flow_input_defs_with_metadata({'inputs': ['a', 'b']}) == []
    assert ab._flow_input_defs_with_metadata(None) == []


def test_a_supplied_value_keeps_the_type_its_input_declares():
    # With no manifest the metadata has to come off the assignment. Reading the
    # wrong key left it empty, every supplied value was typed as a string, and a
    # numeric input reached the generator as text.
    from webapp import app_backend as ab

    out = ab._flow_apply_first_step_chain_supplied_inputs(
        _assignment_with_typed_supply(), None, scenario_label='S', position=0)
    values = out.get('chain_supplied_input_values') or {}
    assert isinstance(values.get('retry_budget'), int)
    assert isinstance(values.get('Credential(user, password)'), str)
    assert ':' in values['Credential(user, password)']


def test_a_manifest_still_wins_over_the_assignment_for_metadata():
    from webapp import app_backend as ab

    manifest = {
        'id': '127',
        'inputs': [
            {'name': 'retry_budget', 'type': 'string', 'required': True,
             'flow_supply_when_first': True},
        ],
    }
    out = ab._flow_apply_first_step_chain_supplied_inputs(
        _assignment_with_typed_supply(), manifest, scenario_label='S', position=0)
    values = out.get('chain_supplied_input_values') or {}
    # The manifest says string, so the supplied value is a string even though
    # the assignment's own copy says integer.
    assert isinstance(values.get('retry_budget'), str)
