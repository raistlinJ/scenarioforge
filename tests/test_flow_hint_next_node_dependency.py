"""Hints must not claim an ordering the dependency graph does not impose.

Most manifests phrase their low hint as "<do the thing> before moving to
{{NEXT_NODE_NAME}}", which assumes a linear chain. `{{NEXT_NODE_NAME}}` was
rendered from the *positional* next step, so on a parallel stage it named an
unrelated sibling -- telling participants a gate exists where none does, while
the flow diagram showed the two nodes as independent.
"""

from __future__ import annotations

import pytest

from webapp import app_backend


@pytest.mark.parametrize(
    'template,expected',
    [
        ('Inspect the vendor intake dropbox before moving to {{NEXT_NODE_NAME}}.',
         'Inspect the vendor intake dropbox.'),
        ('Enumerate the exposed Redis-style keys before moving to {{NEXT_NODE_NAME}}.',
         'Enumerate the exposed Redis-style keys.'),
        ('Use the deploy repo credentials before moving to {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}.',
         'Use the deploy repo credentials.'),
        # No next-node reference at all: left completely alone.
        ('Inspect the SMTP bounce spool for the delivery diagnostic.',
         'Inspect the SMTP bounce spool for the delivery diagnostic.'),
    ],
)
def test_strip_removes_only_the_pointer_clause(template: str, expected: str) -> None:
    assert app_backend._flow_strip_next_node_references(template) == expected


def test_a_hint_that_is_only_a_pointer_strips_to_nothing() -> None:
    """The scaffolding's form has no instruction underneath it.

    Callers must supply a fallback rather than render an empty hint.
    """
    assert app_backend._flow_strip_next_node_references('Target: {{NEXT_NODE_IP}}') == ''
    assert app_backend._flow_strip_next_node_references('Next: {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}') == ''


def _assignment(node_id: str, produces: list[str], requires: list[str]):
    return {'node_id': node_id, 'produces': produces, 'requires': requires}


def test_dependent_successor_is_the_step_that_consumes_the_output() -> None:
    chain = [
        _assignment('1', ['Endpoint(path)'], []),
        _assignment('2', [], ['Endpoint(path)']),
    ]
    assert app_backend._flow_dependent_successor_id(chain, 0) == '2'


def test_no_dependent_successor_on_a_parallel_stage() -> None:
    """Neither consumes the other's output, so neither gates the other."""
    chain = [
        _assignment('1', ['File(path)'], []),
        _assignment('2', ['File(path)'], []),
    ]
    assert app_backend._flow_dependent_successor_id(chain, 0) == ''
    assert app_backend._flow_dependent_successor_id(chain, 1) == ''


def test_an_earlier_consumer_does_not_count_as_a_successor() -> None:
    """Only later steps can be gated by this one."""
    chain = [
        _assignment('1', [], ['Endpoint(path)']),
        _assignment('2', ['Endpoint(path)'], []),
    ]
    assert app_backend._flow_dependent_successor_id(chain, 1) == ''


def test_last_step_has_no_successor() -> None:
    chain = [_assignment('1', ['File(path)'], [])]
    assert app_backend._flow_dependent_successor_id(chain, 0) == ''
