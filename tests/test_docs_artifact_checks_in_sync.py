"""The Feature Deep Dive's check list must track CHECK_ORDER.

It described seven checks for a while after two more were added, which is how
the pivot-check confusion went undocumented.
"""

import re

from webapp import artifact_checks as ac

_DOC = open('docs/FEATURE_DEEP_DIVE.md', encoding='utf-8').read()


def _artifact_section() -> str:
    start = _DOC.index('## Artifact checks')
    return _DOC[start:_DOC.index('## Generator packs', start)]


def test_doc_numbers_every_registered_check():
    numbered = re.findall(r'^(\d+)\. ', _artifact_section(), re.M)
    assert numbered == [str(i) for i in range(1, len(ac.CHECK_ORDER) + 1)]


def test_doc_distinguishes_the_two_pivot_checks():
    section = _artifact_section()
    assert 'The two "pivot" checks are unrelated features' in section
    # The distinction that actually resolves the confusion.
    assert 'earned' in section and 'granted' in section
