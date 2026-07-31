"""Execute must report *how* a run ended, not just that it ended.

The log stream's `end` event only says the run finished; the return code lives
on /run_status/<id>. `pollRunStatus` reads it and routes to the success or
failure summary -- but nothing ever called it, so a finished run restored the
buttons, logged "Async run ended", and left the operator to work out the outcome
themselves.

The poll now runs alongside the stream, so the outcome is still detected if the
stream drops before its `end` event ever arrives.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
INDEX_TEMPLATE_PATH = REPO_ROOT / 'webapp' / 'templates' / 'index.html'

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not available')


def _index_text() -> str:
    return INDEX_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')


def _extract(pattern: str) -> str:
    match = re.search(pattern, _index_text(), re.S)
    assert match, f'could not extract {pattern!r} from index.html'
    return match.group(0)


_HARNESS_TEMPLATE = r"""
const executeProgressState = { summaryShown: false, runStatusPollActive: false, validationSummary: null };
const state = {}; const calls = [];
function persistEditorState(){}
function shouldUpdateValidationSummary(){ return false; }
function logExecuteValidationSummary(){}
function refreshExecuteSummaryIfVisible(){}
function queueExecuteSummaryRedirect(){ calls.push('redirect'); }
function transitionExecuteProgressToSummary(ok, runId){ calls.push(ok ? 'SUCCESS' : 'FAILURE'); }
const document = { getElementById: () => null };
const url_for_reports = '/reports';

let polls = 0;
globalThis.fetch = async (url) => {
  polls += 1;
  const done = polls >= __DONE_AFTER__;
  return {
    ok: true,
    json: async () => ({ done, returncode: done ? __RC__ : null }),
  };
};

(async () => {
  ensureRunStatusPoll('run-1');
  // Second call must not start a competing chain.
  ensureRunStatusPoll('run-1');
  await new Promise(r => setTimeout(r, 3500));
  console.log(JSON.stringify({ calls, polls, active: executeProgressState.runStatusPollActive }));
  process.exit(0);
})();
"""


def _run(done_after: int, returncode: int) -> dict:
    js = (
        _extract(r'    function ensureRunStatusPoll\(runId\) \{.*?\n    \}\n')
        + _extract(r'    async function pollRunStatus\(runId\) \{.*?\n    \}\n')
        + _HARNESS_TEMPLATE.replace('__DONE_AFTER__', str(done_after)).replace('__RC__', str(returncode))
    )
    # The extracted function references a Jinja url_for for the redirect target.
    js = re.sub(r'\{\{.*?\}\}', 'url_for_reports', js, flags=re.S)
    with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as handle:
        handle.write(js)
        path = handle.name
    try:
        proc = subprocess.run(['node', path], capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, proc.stderr[:800]
        return json.loads(proc.stdout.strip().splitlines()[-1])
    finally:
        Path(path).unlink(missing_ok=True)


def test_a_successful_run_is_reported_as_success():
    result = _run(done_after=1, returncode=0)
    assert 'SUCCESS' in result['calls'], result


def test_a_failed_run_is_reported_as_failure():
    """The case the old flow could not express at all."""
    result = _run(done_after=1, returncode=1)
    assert 'FAILURE' in result['calls'], result
    assert 'SUCCESS' not in result['calls'], result


def test_polling_continues_until_the_run_is_done():
    result = _run(done_after=3, returncode=0)
    assert result['polls'] >= 3, result
    assert 'SUCCESS' in result['calls'], result


def test_the_poll_chain_is_not_duplicated():
    """`ensureRunStatusPoll` is called from both stream start and stream end."""
    result = _run(done_after=3, returncode=0)
    # One chain at ~1s per tick over 3.5s; two chains would roughly double this.
    assert result['polls'] <= 5, result
    assert result['active'] is False, result


def test_stream_start_and_end_both_arm_the_poll():
    text = _index_text()
    assert text.count('ensureRunStatusPoll(runId)') >= 2, (
        'the poll must be armed when the stream starts and nudged when it ends'
    )
