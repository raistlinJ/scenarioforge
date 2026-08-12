"""A failed remote flow regeneration must leave its reason in the log.

The exception raised on this path carries a fixed message
(`FLOW_REMOTE_ARTIFACTS_MISSING_MESSAGE`), which callers compare by equality,
so the reason cannot travel with it. The log line is the only record.

Measured on dataset-segmented-firewall-pivot_run02: a regeneration exited 1 and
the payload was summarized at 600 characters, which the JSON envelope alone
consumed -- the generator's output was cut mid-word ("Container fg_...
Creatin") and the cause could not be recovered from the log at all. The run
reported "Challenges and Flow Data not found on CORE VM. Please re-run Flow
Generator...", which describes absent data rather than a failed attempt, and
names a remedy that does not fix it: what worked was deleting the assignment
directories so generation took the normal path instead of the repair path.
"""

import re

from webapp import app_backend as ab

_SRC = open(ab.__file__, encoding='utf-8').read()
_FN = _SRC[_SRC.index('def _regenerate_missing_remote_flow_artifacts_for_plan'):]
_FN = _FN[:_FN.index('def _ensure_remote_traffic_agent')]


def test_regenerate_failure_detail_is_not_truncated_to_the_envelope():
    limits = [int(m) for m in re.findall(r'limit=(\d+)', _FN)]
    assert limits, 'no summarize limit found on the regenerate failure path'
    assert min(limits) >= 4000, (
        f'limit {min(limits)} is too small to carry the generator output; '
        'at 600 the JSON envelope alone consumed it'
    )


def test_the_raw_fallback_keeps_as_much_as_the_summary():
    """The except-branch slice must not silently reimpose the old cap."""
    slices = [int(m) for m in re.findall(r"str\(result or ''\)\[:(\d+)\]", _FN)]
    assert slices and min(slices) >= 4000


def test_exception_message_stays_exactly_the_shared_constant():
    """`_fail_run` compares this by equality; appending detail would break it.

    This is why the detail has to go to the log rather than into the error.
    """
    assert 'raise RuntimeError(FLOW_REMOTE_ARTIFACTS_MISSING_MESSAGE)' in _FN
    assert "str(exc).strip() == FLOW_REMOTE_ARTIFACTS_MISSING_MESSAGE" in _SRC


def test_failure_detail_is_written_to_the_log():
    assert 'flow.artifacts.regenerate failed details' in _FN
