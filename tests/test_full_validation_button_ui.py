"""The Execution Summary offers a Full Validation button.

It runs the artifact checks against the session that was just executed. Because
those checks probe a live session, the confirmation warns that routing
convergence and other startup work need time to finish first.
"""

from pathlib import Path

PREVIEW = Path("webapp/templates/full_preview.html")
SCRIPTS = Path("webapp/templates/full_preview_scripts.html")
PARTIAL = Path("webapp/templates/partials/artifact_checks.html")
CORE = Path("webapp/templates/core.html")


def test_summary_footer_has_the_button():
    html = PREVIEW.read_text(encoding="utf-8")
    footer = html[html.index('id="executeSummaryCopyBtn"'):]
    assert 'id="executeSummaryFullValidationBtn"' in footer[:1200]
    assert "Full Validation" in footer[:1200]


def test_confirmation_modal_recommends_waiting_60_seconds():
    html = PREVIEW.read_text(encoding="utf-8")
    modal_at = html.index('id="fullValidationConfirmModal"')
    modal = html[modal_at:modal_at + 2000]
    assert "60 seconds" in modal
    assert "routing convergence" in modal
    # The user must be able to back out.
    assert 'id="fullValidationConfirmBtn"' in modal
    assert "Cancel" in modal


def test_button_opens_the_confirmation_before_running():
    scripts = SCRIPTS.read_text(encoding="utf-8")
    handler_at = scripts.index("executeSummaryFullValidationBtn")
    handler = scripts[handler_at:handler_at + 1400]
    # The confirmation is shown, and the run only starts from its confirm button.
    assert "fullValidationConfirmModal" in handler
    assert "confirmModal.show()" in handler
    assert "startFullValidation()" in handler


def test_validation_handoff_uses_the_shared_runner():
    scripts = SCRIPTS.read_text(encoding="utf-8")
    fn_at = scripts.index("function startFullValidation()")
    fn = scripts[fn_at:fn_at + 900]
    assert "coretgRunArtifactChecks" in fn
    # The summary has no session id; the server resolves it from the scenario.
    assert "session" not in fn.lower().replace("sessions", "")


def test_check_ui_lives_in_one_shared_partial():
    # The CORE page and Full Preview both include it, so the two cannot drift.
    assert PARTIAL.is_file()
    assert "partials/artifact_checks.html" in PREVIEW.read_text(encoding="utf-8")
    assert "partials/artifact_checks.html" in CORE.read_text(encoding="utf-8")
    # The markup should exist only in the partial now.
    assert "artifactCheckModal" not in CORE.read_text(encoding="utf-8")


def test_partial_exposes_a_global_entry_point():
    partial = PARTIAL.read_text(encoding="utf-8")
    assert "window.coretgRunArtifactChecks" in partial
    # Session id is optional so callers that only know the scenario can use it.
    assert "if (sessionId) body.set('session_id', String(sessionId));" in partial
