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


def _plugin(pid, requires, produces, supply_when_first=()):
    return {
        'id': pid,
        'requires': list(requires),
        'produces': [{'artifact': p} for p in produces],
        'input_defs': [
            {'name': n, 'required': True, 'flow_supply_when_first': True}
            for n in supply_when_first
        ],
    }


def _chain(plugins):
    nodes = [{'id': str(i), 'name': f'docker-{i}'} for i, _ in enumerate(plugins, 1)]
    assignments = []
    for i, p in enumerate(plugins, 1):
        assignments.append({
            'node_id': str(i),
            'id': p['id'],
            'input_defs': p.get('input_defs') or [],
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


def test_supply_when_first_does_not_exempt_a_later_step():
    # The regression: same generator, same marker, but second in the chain.
    # Nothing before it produces SSHPrivateKey(path), so this must be rejected
    # rather than deferred to a run-time crash.
    ok, errors = _validate([
        _plugin('first', [], ['File(path)']),
        _plugin('dep_ssh_key_bastion', ['SSHPrivateKey(path)'], ['Flag(flag_id)'],
                supply_when_first=['SSHPrivateKey(path)']),
    ])
    assert not ok
    assert any('SSHPrivateKey(path)' in e for e in errors), errors


def test_a_later_step_is_fine_when_an_earlier_step_produces_the_artifact():
    # The exemption is not what makes a well-formed chain valid -- a real
    # producer upstream is -- so this must still pass.
    ok, errors = _validate([
        _plugin('keymaker', [], ['SSHPrivateKey(path)']),
        _plugin('dep_ssh_key_bastion', ['SSHPrivateKey(path)'], ['Flag(flag_id)'],
                supply_when_first=['SSHPrivateKey(path)']),
    ])
    assert ok, errors
