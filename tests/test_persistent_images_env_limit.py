"""An oversized pin list is dropped, and says so usefully.

The pinned image list rides on the remote command line. Linux caps a single
argv/environment string at MAX_ARG_STRLEN, and exceeding it makes *every*
command on that host fail with E2BIG -- silently, because the command never runs
and so prints nothing. Dropping the list costs one run's pin protection; passing
it costs the run.

This is the one path where the operator's `persistent` marking stops working, so
the warning has to explain itself rather than report a byte count.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from scenarioforge.utils.env_payload import MAX_ARG_STRLEN, MAX_ENV_VALUE_BYTES
from webapp import app_backend as backend

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(scope='module')
def warning() -> str:
    return backend._persistent_images_skipped_warning(
        count=3412, size_bytes=72104, limit=MAX_ENV_VALUE_BYTES,
    )


def test_states_plainly_that_pins_were_not_applied(warning: str) -> None:
    assert 'NOT applied' in warning


def test_reports_the_actual_size_and_the_ceiling(warning: str) -> None:
    assert '3,412 images' in warning
    assert '72,104 bytes' in warning
    assert f'{MAX_ENV_VALUE_BYTES:,}' in warning


def test_names_the_underlying_cause(warning: str) -> None:
    """Without this the reader cannot tell why a size limit exists at all."""
    assert f'{MAX_ARG_STRLEN:,}' in warning
    assert 'Argument list too long' in warning


def test_states_the_consequence_and_its_bound(warning: str) -> None:
    assert 'pulled again' in warning
    assert 'run itself is unaffected' in warning


def test_offers_at_least_three_ways_to_fix_it(warning: str) -> None:
    suggestions = [ln for ln in warning.splitlines() if ln.strip().startswith('- ')]
    assert len(suggestions) >= 3, f'expected actionable suggestions, got {suggestions}'
    assert any('unpin' in s for s in suggestions)


def test_mentions_the_escape_hatch(warning: str) -> None:
    """A large set is legitimate; say that the ceiling is removable."""
    assert 'as a file' in warning


def test_the_limit_leaves_headroom_under_the_kernel_cap() -> None:
    assert MAX_ENV_VALUE_BYTES < MAX_ARG_STRLEN


def test_warning_fires_only_past_the_ceiling() -> None:
    """Source check: the skip branch is the one that warns."""
    source = (REPO_ROOT / 'webapp' / 'app_backend.py').read_text(encoding='utf-8')
    start = source.find('CORETG_PERSISTENT_IMAGES_JSON=')
    assert start != -1, 'the pin list is no longer published to the remote run'
    block = source[start - 600:start + 900]

    assert '<= MAX_ENV_VALUE_BYTES' in block, 'the value must be size-checked before use'
    assert '_persistent_images_skipped_warning(' in block, 'the oversized path must explain itself'


def test_message_has_no_unformatted_placeholders(warning: str) -> None:
    assert not re.search(r'%[sd]|\{[a-z_]+\}', warning)
