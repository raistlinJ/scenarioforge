"""A supplied first-step input must survive the DAG reorder pass.

`flow_supply_when_first` is recorded only on a generator *definition*, whose
`inputs` are descriptor dicts. An assignment lists `inputs` as bare fact names,
so it can never reveal the flag. The DAG reorder passed each assignment as its
own definition, so the flag went unseen and the pass cleared a value the
assignment step had correctly supplied -- the generator then ran without it:

    [inputs] required and not supplied: ['Checksum(sha256)']

The assignment step got the gate right; this pass silently undid it.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from webapp import app_backend as backend

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

GEN_ID = 'dep_checksum_evidence_gate'
SUPPLIED_FACT = 'Checksum(sha256)'

GEN_DEF = {
    'id': GEN_ID,
    'inputs': [
        {'name': 'seed', 'type': 'string', 'required': True},
        {'name': 'node_name', 'type': 'string', 'required': True},
        {'name': SUPPLIED_FACT, 'type': 'string', 'required': True, 'flow_supply_when_first': True},
    ],
}


def _assignment():
    """An assignment as _flow_compute_flag_assignments emits it, already supplied."""
    return {
        'node_id': 'docker-11',
        'id': GEN_ID,
        'inputs': [SUPPLIED_FACT, 'node_name', 'seed'],
        'config_overrides': {SUPPLIED_FACT: 'value_abc123'},
        'resolved_inputs': {SUPPLIED_FACT: 'value_abc123'},
        'chain_supplied_input_values': {SUPPLIED_FACT: 'value_abc123'},
        'chain_supplied_inputs': [SUPPLIED_FACT],
    }


def _apply(gen_def, *, supply_on_start=True, assignment=None):
    return backend._flow_apply_first_step_chain_supplied_inputs(
        assignment if assignment is not None else _assignment(),
        gen_def,
        scenario_label='Scenario1',
        position=5,
        supply_on_start=supply_on_start,
    )


def test_assignment_cannot_reveal_supply_flag():
    """Why a real definition is required: bare fact names carry no flag."""
    assert backend._flow_first_step_chain_supplied_input_names(GEN_DEF) == [SUPPLIED_FACT]
    assert backend._flow_first_step_chain_supplied_input_names(_assignment()) == []


def test_supply_definition_resolves_by_id():
    assert backend._flow_supply_definition_for(_assignment(), {GEN_ID: GEN_DEF}) is GEN_DEF


@pytest.mark.parametrize(
    'registry',
    [None, {}, {'some-other-generator': GEN_DEF}],
    ids=['no-registry', 'empty-registry', 'id-absent'],
)
def test_supply_definition_returns_none_when_unresolvable(registry):
    assert backend._flow_supply_definition_for(_assignment(), registry) is None


def test_dag_pass_preserves_supplied_value_with_real_definition():
    out = _apply(GEN_DEF)
    assert out.get('config_overrides') == {SUPPLIED_FACT: 'value_abc123'}
    assert out.get('chain_supplied_input_values') == {SUPPLIED_FACT: 'value_abc123'}


def test_unresolvable_definition_preserves_rather_than_clears():
    """Invisible flags are not evidence the step needs no supply."""
    out = _apply(None)
    assert out.get('chain_supplied_input_values') == {SUPPLIED_FACT: 'value_abc123'}
    assert out.get('config_overrides') == {SUPPLIED_FACT: 'value_abc123'}


def test_non_start_still_clears():
    """A step that consumes a real upstream value must not keep a stand-in."""
    out = _apply(GEN_DEF, supply_on_start=False)
    assert not out.get('chain_supplied_input_values')


def test_clears_when_definition_declares_no_supply_and_nothing_supplied():
    plain_def = {'id': GEN_ID, 'inputs': [{'name': 'seed', 'type': 'string', 'required': True}]}
    assignment = _assignment()
    assignment.pop('chain_supplied_input_values')
    assignment.pop('config_overrides')
    out = _apply(plain_def, assignment=assignment)
    assert not out.get('chain_supplied_input_values')


def test_dag_reorder_never_passes_an_assignment_as_its_own_definition():
    """Source ratchet: the defect was one identifier, easy to reintroduce."""
    source = (REPO_ROOT / 'webapp' / 'app_backend.py').read_text()
    tree = ast.parse(source)

    reorder = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == '_flow_reorder_chain_by_generator_dag'
    )

    calls = [
        node for node in ast.walk(reorder)
        if isinstance(node, ast.Call)
        and (getattr(node.func, 'attr', None) or getattr(node.func, 'id', None))
        == '_flow_apply_first_step_chain_supplied_inputs'
    ]
    assert calls, 'expected the DAG reorder to apply first-step supplied inputs'

    for call in calls:
        args = [ast.unparse(arg) for arg in call.args]
        assert len(args) >= 2, f'line {call.lineno}: no generator definition passed'
        assert args[0] != args[1], (
            f'line {call.lineno}: assignment passed as its own generator definition; '
            'the supply flag would be invisible and the supplied value cleared'
        )
        assert {kw.arg for kw in call.keywords} >= {'supply_on_start'}, (
            f'line {call.lineno}: supply_on_start omitted, so only position 0 is '
            'treated as a branch start'
        )
