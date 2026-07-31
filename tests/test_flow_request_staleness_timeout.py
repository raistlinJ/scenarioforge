"""Long Flow requests are budgeted on silence, not on total duration.

`fetchWithTransientRetry` aborted at a fixed deadline measured from the request
start. How long a sequence or resolve legitimately takes scales with chain
length, so one number cannot serve both jobs: set it low and real work is cut
off, set it high and a stalled request sits behind a countdown that is still
ticking down, telling the operator nothing.

These endpoints already stream phase lines to /api/flag-sequencing/flow_progress
while they run, so the browser can distinguish the two. The budget now applies to
the gap between those lines.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FLOW_TEMPLATE_PATH = REPO_ROOT / 'webapp' / 'templates' / 'flow.html'

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not available')

_HARNESS = r"""
function isTransientFetchError(){ return false; }
function sleepForFetchRetry(){ return Promise.resolve(); }
function appendLoadingLog(){}
function describeFetchError(e){ return String(e); }
globalThis.fetch = function (url, init) {
  return new Promise((_res, rej) => {
    const sig = init && init.signal;
    if (sig) sig.addEventListener('abort', () => {
      const e = new Error('aborted'); e.name = 'AbortError'; rej(e);
    });
  });
};
(async () => {
  const out = {};
  let t0 = Date.now();
  try {
    await fetchWithTransientRetry('/x', {}, { timeoutMs: 800 });
  } catch (e) {
    out.fixed = { ms: Date.now() - t0, stall: !!e.isStall };
  }
  const act = createFlowActivitySignal();
  const keep = setInterval(() => touchFlowActivitySignal(act), 200);
  t0 = Date.now();
  let alive = true;
  fetchWithTransientRetry('/x', {}, { timeoutMs: 800, activity: act }).catch(() => { alive = false; });
  await new Promise(r => setTimeout(r, 2400));
  clearInterval(keep);
  out.progressing = { alive, ms: Date.now() - t0 };
  const act2 = createFlowActivitySignal();
  t0 = Date.now();
  try {
    await fetchWithTransientRetry('/x', {}, { timeoutMs: 800, activity: act2 });
  } catch (e) {
    out.stalled = { ms: Date.now() - t0, stall: !!e.isStall, msg: e.message };
  }
  console.log(JSON.stringify(out));
  process.exit(0);
})();
"""


def _extract(pattern: str, text: str) -> str:
    match = re.search(pattern, text, re.S)
    assert match, f'could not extract {pattern!r} from flow.html'
    return match.group(0)


def _run_harness() -> dict:
    import json

    text = FLOW_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')
    js = (
        _extract(r'  function createFlowActivitySignal\(\).*?\n  \}\n', text)
        + _extract(r'  function touchFlowActivitySignal\(activity\).*?\n  \}\n', text)
        + _extract(
            r"  async function fetchWithTransientRetry\(url, init, opts\).*?"
            r"\n    throw new Error\('Network request failed\.'\);\n  \}\n",
            text,
        )
        + _HARNESS
    )
    with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as handle:
        handle.write(js)
        path = handle.name
    try:
        proc = subprocess.run(['node', path], capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, proc.stderr[:800]
        return json.loads(proc.stdout.strip().splitlines()[-1])
    finally:
        Path(path).unlink(missing_ok=True)


def test_request_without_an_activity_signal_keeps_the_fixed_deadline():
    """Unchanged for every caller that does not stream progress."""
    result = _run_harness()
    assert result['fixed']['stall'] is False
    assert 700 <= result['fixed']['ms'] <= 1800, result['fixed']


def test_a_progressing_request_outlives_its_budget():
    """The whole point: chain length, not the clock, decides how long this takes."""
    result = _run_harness()
    assert result['progressing']['alive'] is True, result['progressing']
    # Comfortably past the 800ms budget a fixed deadline would have enforced.
    assert result['progressing']['ms'] >= 2000, result['progressing']


def test_a_stalled_request_is_aborted_and_named_as_a_stall():
    result = _run_harness()
    assert result['stalled']['stall'] is True, result['stalled']
    assert 'No progress' in result['stalled']['msg']
    # Abort lands within the budget plus the 1s poll granularity.
    assert result['stalled']['ms'] <= 3000, result['stalled']
