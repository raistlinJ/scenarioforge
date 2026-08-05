"""The Execute button must be dead from the click until the run actually ends.

Two failures, both fixed here:

* A double submit starts two concurrent runs against one scenario. Guarding with
  a flag set *after* an awaited confirmation is not enough: while that promise is
  pending the event loop is free and the button is still live.
* The click handler starts a polling loop in a non-awaited async IIFE, so the
  handler's `finally` ran as soon as the run *started*. The button went green and
  clickable for the whole run -- the same double-submit hole, just wider.

The second fix means the button's state can no longer be owned by the click
handler, because the handler returns long before the run ends. It follows one
fact instead -- whether a run is in flight -- expressed as
`setExecuteProgressUI({animate})`, which already carries exactly that meaning at
every call site including the early failure returns. The in-flight flag lives on
the element rather than in the handler's closure so the progress UI can clear it.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import tempfile

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PREVIEW_SCRIPTS = REPO_ROOT / "webapp" / "templates" / "full_preview_scripts.html"
PREVIEW_PAGE = REPO_ROOT / "webapp" / "templates" / "scenarios_preview.html"
FLOW = REPO_ROOT / "webapp" / "templates" / "flow.html"


def _scripts() -> str:
    return PREVIEW_SCRIPTS.read_text(encoding="utf-8")


def _execute_handler() -> str:
    text = _scripts()
    start = text.index("executeRunBtn.addEventListener('click', async () => {")
    return text[start:text.index("\n      });", start)]


def test_button_is_claimed_before_any_await():
    handler = _execute_handler()
    claim_at = handler.index("setExecuteButtonBusy(true);")
    first_await = handler.index("await ")
    assert claim_at < first_await, (
        "the button must be claimed before the awaited confirmation, or a "
        "second click can start a concurrent execute while it is pending"
    )


def test_the_guard_reads_the_elements_flag_not_a_closure():
    handler = _execute_handler()
    assert "executeRunBtn.dataset.executing === '1'" in handler
    assert claim_before_guard_is_impossible(handler)


def claim_before_guard_is_impossible(handler: str) -> bool:
    """The guard must be checked before the claim, or the first click is eaten."""
    return handler.index("dataset.executing === '1'") < handler.index("setExecuteButtonBusy(true);")


def test_cancelling_releases_the_button_for_a_retry():
    handler = _execute_handler()
    # Both back-out paths (saved-XML confirmation and the confirm dialog).
    assert handler.count("releaseExecuteButton()") >= 2


def test_the_handler_does_not_release_on_return():
    """This is the regression: the run outlives the handler."""
    handler = _execute_handler()
    assert "finally {" not in handler, (
        "a finally block releases the button while the polling loop is still running"
    )
    assert "executeRunBtn.disabled = false" not in handler


def test_progress_state_owns_the_button():
    text = _scripts()
    ui = text[text.index("function setExecuteProgressUI"):]
    ui = ui[:ui.index("\n    function ", 10)]
    assert "setExecuteButtonBusy(true)" in ui
    assert "setExecuteButtonBusy(false)" in ui


def test_the_success_path_releases_the_button():
    # This terminal path leaves the bar animating ("Generating Execution
    # Summary"), so it is the one place that must release explicitly.
    text = _scripts()
    summary = text[text.index("function presentExecuteSummary"):]
    summary = summary[:summary.index("\n    function ", 10)]
    assert "setExecuteButtonBusy(false)" in summary


def test_embedded_mode_mirrors_state_to_the_parent():
    # In embedded mode this document owns the run but the visible green button
    # belongs to the Scenarios page, so the state has to travel upward.
    assert "type: 'coretg-preview-execute-state'" in _scripts()
    page = PREVIEW_PAGE.read_text(encoding="utf-8")
    listener = page[page.index("data.type === 'coretg-preview-execute-state'"):]
    listener = listener[:listener.index("} else if")]
    assert "ev.source !== previewFrame.contentWindow" in listener, "only the preview frame may drive it"
    assert "btn.disabled = true" in listener and "btn.disabled = false" in listener
    assert "btn.dataset.idleLabel" in listener, "the original label must be restorable"


def test_flow_page_execute_disables_before_awaiting():
    # The Flow page shares an Execute control; it must not regress either.
    text = FLOW.read_text(encoding="utf-8")
    start = text.index("async function execute() {")
    body = text[start:start + 2500]
    assert body.index("execEl.disabled = true") < body.index("await ")


def _strip_jinja(text: str) -> str:
    text = re.sub(r"\{\{.*?\}\}", "0", text, flags=re.S)
    return re.sub(r"\{%.*?%\}", "", text, flags=re.S)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required to execute the helper")
def test_helper_toggles_a_real_button():
    """Execute the shipped helper against a DOM stub and assert the transitions."""
    text = _scripts()
    helper = text[text.index("function setExecuteButtonBusy"):text.index("\n    function setExecuteProgressUI")]
    harness = """
const btn = { textContent: 'Execute', disabled: false, dataset: {} };
const posted = [];
globalThis.document = { getElementById: (id) => (id === 'executeRunBtn' ? btn : null) };
globalThis.window = {
  parent: { postMessage: (msg) => posted.push(msg) },
  location: { origin: 'https://example.test' },
};
%s
setExecuteButtonBusy(true);
if (btn.disabled !== true) throw new Error('not disabled while busy');
if (btn.dataset.executing !== '1') throw new Error('in-flight flag not set');
if (btn.textContent !== 'Executing\\u2026') throw new Error('label not changed: ' + btn.textContent);
setExecuteButtonBusy(false);
if (btn.disabled !== false) throw new Error('not re-enabled when idle');
if (btn.dataset.executing !== undefined) throw new Error('in-flight flag not cleared');
if (btn.textContent !== 'Execute') throw new Error('label not restored: ' + btn.textContent);
if (posted.length !== 2) throw new Error('parent not notified twice');
if (posted[0].busy !== true || posted[1].busy !== false) throw new Error('wrong busy values');
if (posted[0].type !== 'coretg-preview-execute-state') throw new Error('wrong message type');
setExecuteButtonBusy(false);
if (btn.textContent !== 'Execute') throw new Error('label lost on repeat release');
console.log('OK');
""" % _strip_jinja(helper)
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
        handle.write(harness)
        path = handle.name
    try:
        result = subprocess.run(["node", path], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout
    finally:
        pathlib.Path(path).unlink(missing_ok=True)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required to parse the templates")
@pytest.mark.parametrize("template", [PREVIEW_SCRIPTS, PREVIEW_PAGE])
def test_template_javascript_still_parses(template: pathlib.Path):
    text = template.read_text(encoding="utf-8")
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", text, flags=re.S)
    source = _strip_jinja("\n".join(blocks) if blocks else text)
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
        handle.write(source)
        path = handle.name
    try:
        result = subprocess.run(["node", "--check", path], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr[:800]
    finally:
        pathlib.Path(path).unlink(missing_ok=True)
