"""Tests for the CI test ratchet.

The ratchet decides whether CI passes, so a parsing slip here silently disables
the gate (or blocks every PR). The first version matched any line starting with
ERROR, which picked up captured logging such as
``ERROR    root:cli.py:5733 Saved PlanPreview does not match ...`` and reported
two phantom regressions.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from check_test_ratchet import _FAILED_RE, main, read_baseline, write_baseline  # noqa: E402


def _parse(line: str) -> str | None:
    m = _FAILED_RE.match(line.strip())
    return m.group(1) if m else None


@pytest.mark.parametrize(
    'line,expected',
    [
        ('FAILED tests/test_foo.py::test_bar - AssertionError: boom', 'tests/test_foo.py::test_bar'),
        ('FAILED tests/test_foo.py::test_bar', 'tests/test_foo.py::test_bar'),
        ('FAILED tests/test_a.py::TestClass::test_method', 'tests/test_a.py::TestClass::test_method'),
        ('ERROR tests/test_collect_boom.py', 'tests/test_collect_boom.py'),
    ],
)
def test_parses_pytest_summary_lines(line: str, expected: str) -> None:
    assert _parse(line) == expected


@pytest.mark.parametrize(
    'line',
    [
        # Captured logging echoed into the same stream.
        'ERROR    root:cli.py:5733 Saved PlanPreview does not match the current XML',
        'ERROR    root:cli.py:5737 PlanPreview mismatch: hosts_total flow=1 xml=0',
        'ERROR    webapp.app_backend:app.py:12 something went wrong',
        # Ordinary progress/summary noise.
        '34 failed, 1721 passed, 5 skipped in 172.43s',
        'FAILED',
        '',
    ],
)
def test_ignores_non_node_id_lines(line: str) -> None:
    assert _parse(line) is None


def test_baseline_roundtrip(tmp_path, monkeypatch) -> None:
    import check_test_ratchet as mod

    target = tmp_path / 'known_failures.txt'
    monkeypatch.setattr(mod, 'BASELINE', target)

    ids = {'tests/test_a.py::test_one', 'tests/test_b.py::test_two'}
    mod.write_baseline(ids, total=len(ids))
    assert mod.read_baseline() == ids

    text = target.read_text(encoding='utf-8')
    assert text.startswith('#'), 'baseline should carry an explanatory header'
    assert 'Recorded count: 2' in text
    # Sorted for a stable diff when the set changes.
    body = [l for l in text.splitlines() if l and not l.startswith('#')]
    assert body == sorted(body)


def test_missing_baseline_is_an_error(tmp_path, monkeypatch) -> None:
    """Without a baseline the gate must fail rather than silently pass."""
    import check_test_ratchet as mod

    monkeypatch.setattr(mod, 'BASELINE', tmp_path / 'absent.txt')
    monkeypatch.setattr(mod, 'run_pytest', lambda extra: (set(), 0))
    assert main([]) == 1


def test_empty_baseline_means_green_not_missing(tmp_path, monkeypatch) -> None:
    """A fully green suite records an empty baseline; that must still pass.

    The first version treated an empty set as "no baseline recorded" and exited 1,
    so clearing the last known failure would have failed CI on a green suite.
    """
    import check_test_ratchet as mod

    target = tmp_path / 'known_failures.txt'
    monkeypatch.setattr(mod, 'BASELINE', target)
    mod.write_baseline(set(), total=0)
    assert target.is_file()
    assert mod.read_baseline() == set()

    monkeypatch.setattr(mod, 'run_pytest', lambda extra: (set(), 0))
    assert main([]) == 0

    # A failure against an empty baseline is still a regression.
    monkeypatch.setattr(mod, 'run_pytest', lambda extra: ({'tests/test_x.py::test_y'}, 1))
    assert main([]) == 1


def test_new_failure_fails_and_fixed_failure_passes(tmp_path, monkeypatch) -> None:
    import check_test_ratchet as mod

    target = tmp_path / 'known_failures.txt'
    monkeypatch.setattr(mod, 'BASELINE', target)
    mod.write_baseline({'tests/test_a.py::test_known'}, total=1)

    # Same set -> pass.
    monkeypatch.setattr(mod, 'run_pytest', lambda extra: ({'tests/test_a.py::test_known'}, 1))
    assert main([]) == 0

    # A baseline entry now passing -> still pass (ratchet may shrink).
    monkeypatch.setattr(mod, 'run_pytest', lambda extra: (set(), 0))
    assert main([]) == 0

    # An unlisted failure -> fail.
    monkeypatch.setattr(
        mod, 'run_pytest',
        lambda extra: ({'tests/test_a.py::test_known', 'tests/test_b.py::test_new'}, 1),
    )
    assert main([]) == 1
