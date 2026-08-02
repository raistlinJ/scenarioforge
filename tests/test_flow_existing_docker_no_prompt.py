"""Using already-declared Docker capacity must not interrupt Generate.

Declared slots and spare Docker hosts exist precisely so flag sequencing can
draw on them, and that stage changes nothing in the Topology specification.
Asking for confirmation made every Generate that used a slot stop on a modal.

Adding *new* Docker nodes is a different matter: it rewrites the specification
and the XML, so it still confirms.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FLOW_TEMPLATE_PATH = REPO_ROOT / 'webapp' / 'templates' / 'flow.html'


@pytest.fixture(scope='module')
def expansion_block() -> str:
    """The block that decides whether a chain-expansion stage proceeds."""
    source = FLOW_TEMPLATE_PATH.read_text(encoding='utf-8')
    start = source.find('let wantsExpansion')
    assert start != -1, 'chain-expansion approval block not found'
    end = source.find('acceptedChainExpansionStages.add(stage)', start)
    assert end != -1, 'end of the approval block not found'
    return source[start:end]


def test_existing_docker_stage_does_not_prompt(expansion_block: str) -> None:
    existing = expansion_block.split('} else {')[0]
    assert "stage === 'existing_docker'" in existing
    assert 'confirmFlowAction' not in existing, (
        'using capacity already declared in Topology must not stop on a modal'
    )


def test_existing_docker_stage_is_still_reported(expansion_block: str) -> None:
    """Silent is not the same as invisible -- it belongs in the log."""
    existing = expansion_block.split('} else {')[0]
    assert 'appendLoadingLog' in existing


def test_adding_docker_nodes_still_confirms(expansion_block: str) -> None:
    branch = expansion_block.split('} else {', 1)[1]
    assert 'confirmFlowAction' in branch
    assert 'Add Docker Nodes to Topology?' in branch


def test_the_removed_prompt_is_gone_entirely() -> None:
    source = FLOW_TEMPLATE_PATH.read_text(encoding='utf-8')
    assert 'Use Existing Docker Nodes' not in source


def test_cancelling_the_remaining_prompt_still_aborts(expansion_block: str) -> None:
    """Auto-approving one stage must not make the other unstoppable."""
    source = FLOW_TEMPLATE_PATH.read_text(encoding='utf-8')
    tail = source[source.find('let wantsExpansion'):]
    cancel = re.search(r'if \(!wantsExpansion\)\s*\{([^}]*)\}', tail)
    assert cancel is not None, 'the cancel path must survive'
    assert 'Generate cancelled' in cancel.group(1)
