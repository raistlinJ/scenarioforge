"""The import flow's own page reload must not trigger the "leave page?" prompt.

On successful import, the client navigates itself to `/` via
`window.location.replace('/')` to pick up the freshly persisted editor
snapshot. That is the app's own navigation, not the user clicking away, but the
`beforeunload` unsaved-changes guard (`webapp/templates/index.html`) cannot
tell the difference: it fires whenever `hasUnsavedChanges()` is true, which
edits made before opening the import dialog -- or any background autosave that
marks `previewState.dirty` -- leave true. The result was a native "leave
site?" confirmation appearing mid-import, while the import UI still read
"importing".

Every other programmatic navigation in this page (in-app link clicks, the
unsaved-changes modal's own "discard and continue") suppresses the guard first
via `window.coretgAllowUnsavedNavOnce()` / the `_unsavedNavAllowOnce` flag it
sets. The import completion handler must do the same before it navigates.
"""

from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def _import_completion_block() -> str:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    marker = "window.location.replace('/');"
    idx = text.index(marker)
    # A window of context around the navigation call is enough to see whether
    # the bypass was called immediately before it, without depending on exact
    # surrounding formatting.
    return text[max(0, idx - 600):idx + 200]


def test_import_success_navigation_suppresses_the_unsaved_changes_prompt():
    block = _import_completion_block()
    assert "coretgAllowUnsavedNavOnce" in block, (
        "the import flow's post-success reload does not bypass the "
        "unsaved-changes beforeunload guard, so a dirty editor state makes "
        "the browser ask to confirm leaving a page the app itself is reloading"
    )


def test_bypass_call_precedes_the_navigation_not_follows_it():
    block = _import_completion_block()
    bypass_pos = block.find("coretgAllowUnsavedNavOnce")
    nav_pos = block.find("window.location.replace('/')")
    assert bypass_pos != -1 and nav_pos != -1
    assert bypass_pos < nav_pos, (
        "the bypass must run before the navigation it is meant to cover -- "
        "beforeunload fires synchronously on the same navigation attempt, so "
        "calling it after is too late"
    )


def test_the_bypass_helper_itself_is_exposed_and_consulted_by_beforeunload():
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    assert "window.coretgAllowUnsavedNavOnce = function () { _unsavedNavAllowOnce = true; };" in text
    assert "if (_unsavedNavAllowOnce) return;" in text
