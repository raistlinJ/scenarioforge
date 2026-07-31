"""A start hint says where to begin, and nothing else.

The Initial Facts panel used to append the generator id, its catalog display
name, the assignment type, and the vulnerability name to each start hint:

    Start: docker-2 @ 10.103.160.3; generator: git_deploy_key_repo |
    Git: Deploy Key Repository; type: flag-node-generator

All of that describes how the challenge is built, so it hands over the answer
before anyone has looked at the host. Only the node and its address remain.

Two separate places build these hints -- the primary start hint and the
branch-start hints for later sequences -- so the detail can come back in one
without the other.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FLOW_TEMPLATE_PATH = REPO_ROOT / 'webapp' / 'templates' / 'flow.html'


def _flow_text() -> str:
    return FLOW_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')


def test_start_hints_are_node_and_address_only() -> None:
    text = _flow_text()

    assert 'initHints = [`Start: ${firstName}${suffix}`];' in text, (
        'the primary start hint must carry only the node name and address'
    )
    assert 'const text = `${prefix} start: ${nodeName}${suffix}`;' in text, (
        'branch-start hints must carry only the node name and address'
    )


def test_no_start_hint_appends_generator_or_type_detail() -> None:
    text = _flow_text()

    for fragment in ("'generator: '", "'type: '", "'target: '"):
        assert fragment not in text, (
            f'{fragment} is back in a Flow hint; start hints must not name the '
            'generator, the assignment type, or the vulnerability'
        )


def test_start_hint_templates_carry_no_detail_suffix() -> None:
    """The removed form appended `; ` + a joined detail list."""
    text = _flow_text()

    offenders = [
        line.strip()
        for line in text.splitlines()
        if 'start: ' in line and re.search(r"details\.length|firstHintDetails", line)
    ]
    assert not offenders, offenders


def test_technique_source_is_facilitator_only() -> None:
    """The guides' Critical Access table names the generator that built a step.

    That is the same disclosure start hints omit, so it belongs to facilitators.
    Both guide builders carry their own copy of the row.
    """
    reports_path = REPO_ROOT / 'webapp' / 'templates' / 'reports.html'
    for path in (FLOW_TEMPLATE_PATH, reports_path):
        text = path.read_text(encoding='utf-8', errors='ignore')
        rows = [line for line in text.splitlines() if 'Technique Source' in line]
        assert rows, f'{path.name} no longer renders a Technique Source row'
        for row in rows:
            assert 'facilitatorMode' in row, (
                f'{path.name} shows Technique Source to participants: {row.strip()}'
            )
