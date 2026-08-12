"""`flow_supply_when_first` must only exempt the opening chain step.

Flow hands a marked input to the chain's first step and to no other, so the
exemption the chain validator grants for those inputs has to be tied to
position 0. Applied everywhere, it let a chain validate whose later step
depended on an artifact nothing in the chain produced -- observed with
`dep_ssh_key_bastion` placed second while requiring `SSHPrivateKey(path)`.
Nothing emitted one, the chain reported flow_valid=True, and the generator
then rejected its own config at run time with
"[validation error] SSHPrivateKey(path) is required", wrote no outputs.json,
and the run died two layers later claiming "Challenges and Flow Data not
found on CORE VM".
"""

from webapp import app_backend


def _plugin(pid, requires, produces, supply_when_first=(), optional_supply_when_first=()):
    return {
        'id': pid,
        'requires': list(requires),
        'produces': [{'artifact': p} for p in produces],
        'input_defs': (
            [{'name': n, 'required': True, 'flow_supply_when_first': True}
             for n in supply_when_first]
            + [{'name': n, 'required': False, 'flow_supply_when_first': True}
               for n in optional_supply_when_first]
        ),
    }


def _chain(plugins):
    nodes = [{'id': str(i), 'name': f'docker-{i}'} for i, _ in enumerate(plugins, 1)]
    assignments = []
    for i, p in enumerate(plugins, 1):
        assignments.append({
            'node_id': str(i),
            'id': p['id'],
            'input_defs': p.get('input_defs') or [],
            # Real assignments carry these, and whether a step is a branch start
            # -- which decides whether Flow supplies it anything -- is read off
            # them. Omitting them made every step look dependency-free, so every
            # step looked like a branch start.
            'requires': list(p['requires']),
            'outputs': [entry['artifact'] for entry in p['produces']],
            'input_fields_optional': [
                str(d['name']) for d in (p.get('input_defs') or [])
                if d.get('required') is False
            ],
        })
    return nodes, assignments


def _validate(plugins):
    nodes, assignments = _chain(plugins)
    return app_backend._flow_validate_chain_order_by_requires_produces(
        nodes,
        assignments,
        scenario_label='TestScenario',
        plugins_by_id_override={p['id']: p for p in plugins},
    )


def test_supply_when_first_is_honored_for_the_opening_step():
    # At position 0 Flow really does supply the value, so the requirement is
    # not a chain dependency and the chain must validate.
    ok, errors = _validate([
        _plugin('opener', ['SSHPrivateKey(path)'], ['Flag(flag_id)'],
                supply_when_first=['SSHPrivateKey(path)']),
    ])
    assert ok, errors


def test_supply_when_first_does_not_exempt_a_later_step_that_cannot_self_supply():
    # The regression: same generator, same marker, but second in the chain and
    # not producing the fact itself. Nothing before it produces
    # SSHPrivateKey(path), so this must be rejected rather than deferred to a
    # run-time crash.
    ok, errors = _validate([
        _plugin('first', [], ['File(path)']),
        _plugin('dep_ssh_key_bastion', ['SSHPrivateKey(path)'], ['Flag(flag_id)'],
                supply_when_first=['SSHPrivateKey(path)']),
    ])
    assert not ok
    assert any('SSHPrivateKey(path)' in e for e in errors), errors


def test_producing_the_fact_does_not_exempt_a_step_wired_into_the_chain():
    """dataset-segmented-firewall-pivot_run02: the same bug, one fact later.

    A later step used to keep the exemption whenever it also produced the
    marked fact, on the theory that such a generator mints the credential and
    then gates its own service behind it. `ssh_password_finance_terminal` --
    the generator that carve-out was written for -- does not mint it: its
    generator.py parses `Credential(user, password)` out of the run config,
    raises "Credential(user, password) is required" when it is absent, and
    re-exports the value it was handed.

    Producing the fact is still what makes Flow's invented value usable, but it
    is worth nothing unless Flow actually supplies one, and supply only happens
    at a branch start. Here the step takes `Pivot(docker-1)` from step 1, which
    is exactly what stops it being a branch start -- so it got no credential,
    and died at run time the same way `dep_ssh_key_bastion` did.
    """
    ok, errors = _validate([
        _plugin('git_http_bare_repo', [], ['Pivot(docker-1)', 'File(path)']),
        _plugin('ssh_password_finance_terminal',
                ['Credential(user, password)', 'Pivot(docker-1)'],
                ['Credential(user, password)', 'Flag(flag_id)'],
                supply_when_first=['Credential(user, password)']),
    ])
    assert not ok
    assert any('Credential(user, password)' in e for e in errors), errors


def test_an_optional_marked_input_is_free_anywhere_in_the_chain():
    """How a generator that really can mint its own value says so.

    Eleven catalog manifests -- the SMB, mail, database and cache variants
    whose generator does `if parsed_credential: ... elif needs_credential:
    <mint>` -- used to declare `Credential(user, password)` as
    `required: true`. That is what the stricter check above now rejects
    mid-chain, and for those generators it would be rejecting a chain that
    works. `required: false` is the accurate declaration: the input drops out
    of the dependency question entirely, at any position, while
    `flow_supply_when_first` still hands the step a value (and hints it) where
    it does open a branch.
    """
    ok, errors = _validate([
        _plugin('git_http_bare_repo', [], ['Pivot(docker-1)', 'File(path)']),
        _plugin('database_oracle_wallet_note',
                ['Credential(user, password)', 'Pivot(docker-1)'],
                ['Credential(user, password)', 'Flag(flag_id)'],
                optional_supply_when_first=['Credential(user, password)']),
    ])
    assert ok, errors

    # The marker is read off `flow_supply_when_first` alone, so making the
    # input optional must not quietly switch supply off.
    from webapp import app_backend as ab
    assert ab._flow_first_step_chain_supplied_input_names({
        'inputs': [{'name': 'Credential(user, password)', 'required': False,
                    'flow_supply_when_first': True}],
    }) == ['Credential(user, password)']


def test_a_self_producing_branch_head_keeps_the_exemption():
    # The legitimate later-step case: nothing this step needs came from an
    # earlier one, so it is a branch start and Flow does supply the credential
    # -- and because the step produces the fact, it creates the account with
    # the supplied value rather than needing a real upstream artifact.
    ok, errors = _validate([
        _plugin('opener', [], ['File(path)']),
        _plugin('ssh_password_finance_terminal',
                ['Credential(user, password)'],
                ['Credential(user, password)', 'Flag(flag_id)'],
                supply_when_first=['Credential(user, password)']),
    ])
    assert ok, errors


def test_a_later_step_is_fine_when_an_earlier_step_produces_the_artifact():
    # The exemption is not what makes a well-formed chain valid -- a real
    # producer upstream is -- so this must still pass.
    ok, errors = _validate([
        _plugin('keymaker', [], ['SSHPrivateKey(path)']),
        _plugin('dep_ssh_key_bastion', ['SSHPrivateKey(path)'], ['Flag(flag_id)'],
                supply_when_first=['SSHPrivateKey(path)']),
    ])
    assert ok, errors


# --------------------------------------------------------------------------- #
# The order Flow actually ships, not just the verdict on one
# --------------------------------------------------------------------------- #

def test_the_dag_moves_a_producer_ahead_of_a_marked_consumer(monkeypatch):
    """dataset-segmented-firewall-pivot_run02, reduced to its three moving parts.

    The DAG asks the validator whether a candidate order is acceptable, so a
    validator that waived `Credential(user, password)` for the self-producing
    consumer let the DAG keep it at sequence 2 with both real producers behind
    it. Flow reported flow_valid=True, the generator wrote no outputs.json, and
    execute then failed re-running it with "Challenges and Flow Data not found
    on CORE VM". Asserting the repaired order, not just the verdict, is what
    ties this file to the run that motivated it.
    """
    from webapp import app_backend as ab

    pivot = 'Pivot(docker-1)'
    credential = 'Credential(user, password)'
    plugins = [
        _plugin('git_http_bare_repo', [], [pivot, 'File(path)']),
        _plugin('ssh_password_finance_terminal',
                [credential, pivot], [credential, 'Flag(flag_id)'],
                supply_when_first=[credential]),
        _plugin('text_support_ticket_dump', [pivot], [credential, 'Flag(flag_id)']),
    ]
    nodes, assignments = _chain(plugins)
    monkeypatch.setattr(ab, '_flow_enabled_generator_defs_by_id', lambda: {})
    contracts = {p['id']: p for p in plugins}

    ordered_nodes, ordered_assignments, _debug = ab._flow_reorder_chain_by_generator_dag(
        nodes,
        assignments,
        scenario_label='TestScenario',
        plugins_by_id_override=contracts,
    )
    order = [str(a.get('id') or '') for a in ordered_assignments]
    assert order.index('text_support_ticket_dump') < order.index('ssh_password_finance_terminal'), order

    ok, errors = ab._flow_validate_chain_order_by_requires_produces(
        ordered_nodes,
        ordered_assignments,
        scenario_label='TestScenario',
        plugins_by_id_override=contracts,
    )
    assert ok, errors


# --------------------------------------------------------------------------- #
# Selection must ask the same question supply does
# --------------------------------------------------------------------------- #

def test_selection_rejects_a_marked_consumer_that_depends_on_the_chain():
    """A marked input is only free where Flow will actually supply it.

    Supply happens at a branch start, and a step is only a branch start when
    none of its other requirements came from an earlier step. Selection used to
    waive marked inputs everywhere, so it placed `dep_ssh_key_bastion` -- which
    needs a marked `SSHPrivateKey(path)` *and* a `Pivot(...)` an earlier step
    produces -- at a position where supply was then skipped. Nothing else
    produces the key, and the generator refused its own config at run time.
    """
    from webapp import app_backend as ab

    # Mirrors the real shape: the marked fact is not self-produced, and another
    # requirement is satisfied only by an earlier step's output.
    gen = {
        'id': 'dep_ssh_key_bastion',
        'requires': ['Pivot(docker-15)', 'SSHPrivateKey(path)'],
        'produces': [{'artifact': 'Flag(flag_id)'}],
        'input_defs': [
            {'name': 'SSHPrivateKey(path)', 'required': True,
             'flow_supply_when_first': True},
        ],
    }
    names = ab._flow_first_step_chain_supplied_input_names(gen)
    assert names == ['SSHPrivateKey(path)'], names

    # A step whose only unmet requirement is the marked one *is* a branch start
    # and stays selectable; the guard is specifically about depending on the
    # chain so far. Both shapes are exercised end-to-end through the solver in
    # tests/test_flow_staged_topology_expansion.py, which covers the parallel
    # branch case this must not regress.


def test_selection_and_validation_agree_about_a_self_producing_consumer(monkeypatch):
    """Whatever selection picks, the chain it hands back has to validate.

    Selection and the chain validator both decide when a marked input counts
    as satisfied, and the two drifting apart is what let a starved
    `ssh_password_finance_terminal` through. They read the marker differently
    on purpose -- selection may keep the exemption for a self-produced fact
    because its own supply step then always fabricates a value, which the
    validator has no way to assume -- so the invariant worth pinning is the
    agreement itself, not either rule.

    Asserting a specific pick would just record today's shuffle; asserting
    agreement fails whenever a change to either side reintroduces the split.
    """
    from webapp import app_backend as ab

    credential = 'Credential(user, password)'
    node_gens = [
        {
            'id': 'pivot_source', 'name': 'PivotSource', 'language': 'python',
            '_source_name': 'test',
            'inputs': [], 'outputs': [{'name': 'Shell(host)'}],
            'hint_levels': {'low': ['Next: {{NEXT_NODE_ID}}']},
        },
        {
            # Requires the credential *and* a fact only step 1 produces, so it
            # can never be a branch start at position 2.
            'id': 'ssh_password_finance_terminal', 'name': 'SelfProducer',
            'language': 'python', '_source_name': 'test',
            'inputs': [
                {'name': credential, 'required': True, 'flow_supply_when_first': True},
                {'name': 'Shell(host)', 'required': True},
            ],
            'outputs': [{'name': credential}, {'name': 'Flag(flag_id)'}],
            'hint_levels': {'low': ['Next: {{NEXT_NODE_ID}}']},
        },
        {
            'id': 'plain_follower', 'name': 'PlainFollower', 'language': 'python',
            '_source_name': 'test',
            'inputs': [{'name': 'Shell(host)', 'required': True}],
            'outputs': [{'name': 'Flag(flag_id)'}],
            'hint_levels': {'low': ['Next: {{NEXT_NODE_ID}}']},
        },
    ]
    contracts = {
        'pivot_source': {'requires': [], 'produces': [{'artifact': 'Shell(host)'}]},
        'ssh_password_finance_terminal': {
            'requires': [credential, 'Shell(host)'],
            'produces': [{'artifact': credential}, {'artifact': 'Flag(flag_id)'}],
        },
        'plain_follower': {
            'requires': ['Shell(host)'], 'produces': [{'artifact': 'Flag(flag_id)'}],
        },
    }
    monkeypatch.setattr(ab, '_flag_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(ab, '_flag_node_generators_from_enabled_sources', lambda: (node_gens, []))
    monkeypatch.setattr(ab, '_flow_enabled_plugin_contracts_by_id', lambda: contracts)
    monkeypatch.setattr(ab, '_flow_enabled_generator_defs_by_id',
                        lambda: {g['id']: g for g in node_gens})

    preview = {'seed': 0, 'hosts': [
        {'node_id': 'h1', 'name': 'docker-1', 'role': 'Docker', 'vulnerabilities': []},
        {'node_id': 'h2', 'name': 'docker-2', 'role': 'Docker', 'vulnerabilities': []},
    ]}
    chain_nodes = [
        {'id': 'h1', 'name': 'docker-1', 'type': 'docker', 'is_vuln': False},
        {'id': 'h2', 'name': 'docker-2', 'type': 'docker', 'is_vuln': False},
    ]

    assignments = ab._flow_compute_flag_assignments(preview, chain_nodes, 'TestScenario')
    assert len(assignments) == 2, assignments

    ok, errors = ab._flow_validate_chain_order_by_requires_produces(
        chain_nodes, assignments, scenario_label='TestScenario',
        plugins_by_id_override=contracts,
    )
    assert ok, ([a.get('id') for a in assignments], errors)
