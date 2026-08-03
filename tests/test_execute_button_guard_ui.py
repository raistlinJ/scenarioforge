"""The Execute button must stop being clickable the moment it is clicked.

Execute starts a CORE session and invokes the CLI, so a double submit starts two
concurrent runs against one scenario. Guarding only with a flag set *after* an
awaited confirmation is not enough: while that promise is pending the event loop
is free and the button is still live, so a second click passes the guard.
"""

from pathlib import Path

PREVIEW_SCRIPTS = Path("webapp/templates/full_preview_scripts.html")
FLOW = Path("webapp/templates/flow.html")


def _execute_handler() -> str:
    text = PREVIEW_SCRIPTS.read_text(encoding="utf-8")
    start = text.index("executeRunBtn.addEventListener('click', async () => {")
    end = text.index("if (originalLabel) { executeRunBtn.textContent = 'Executing…'; }", start)
    return text[start:end]


def test_button_is_disabled_before_any_await():
    handler = _execute_handler()
    disable_at = handler.index("executeRunBtn.disabled = true;")
    first_await = handler.index("await ")
    assert disable_at < first_await, (
        "the button must be disabled before the awaited confirmation, or a "
        "second click can start a concurrent execute while it is pending"
    )


def test_guard_flag_is_claimed_before_any_await():
    handler = _execute_handler()
    assert handler.index("executing = true;") < handler.index("await ")


def test_cancelling_releases_the_button_for_a_retry():
    handler = _execute_handler()
    # Both back-out paths (saved-XML confirmation and the confirm dialog) restore it.
    assert handler.count("releaseExecuteButton()") >= 2
    assert "executeRunBtn.disabled = false;" in handler
    assert "executing = false;" in handler


def test_run_completion_restores_the_button():
    text = PREVIEW_SCRIPTS.read_text(encoding="utf-8")
    finally_block = text.index("finally {", text.index("executeRunBtn.addEventListener"))
    tail = text[finally_block:finally_block + 400]
    assert "executeRunBtn.disabled = false;" in tail
    assert "executing = false;" in tail


def test_flow_page_execute_disables_before_awaiting():
    # The Flow page shares an Execute control; it must not regress either.
    text = FLOW.read_text(encoding="utf-8")
    start = text.index("async function execute() {")
    body = text[start:start + 2500]
    disable_at = body.index("execEl.disabled = true;")
    first_await = body.index("await ")
    assert disable_at < first_await
