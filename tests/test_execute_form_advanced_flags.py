from pathlib import Path


TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"
DOCK_PARTIAL_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "dock.html"
FULL_PREVIEW_SCRIPTS_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "full_preview_scripts.html"


def test_preview_execute_offers_only_conflict_cleanup() -> None:
    """Execution moved to the preview page and offers one cleanup option.

    The topology page used to host an execute confirm dialog whose Advanced
    section carried five cleanup toggles (`executeAdvDeepCleanupAfterRun`,
    `executeAdvDockerNukeAll`, ...). That dialog was replaced by the preview-page
    execute flow, which deliberately exposes only `docker_remove_conflicts` --
    and only as a retry after a container-name collision, not as a default.

    This test previously asserted the retired checkboxes existed and were
    pre-checked. It now pins the replacement contract, and that the retired
    destructive toggles do not quietly come back.
    """
    scripts_text = FULL_PREVIEW_SCRIPTS_PATH.read_text(encoding="utf-8", errors="ignore")

    assert "if (o.dockerRemoveConflicts) { form.append('docker_remove_conflicts', '1'); }" in scripts_text
    # First attempt never force-removes; only the post-collision retry opts in.
    assert "buildExecuteForm({ dockerRemoveConflicts: false })" in scripts_text
    assert "buildExecuteForm({ dockerRemoveConflicts: true })" in scripts_text

    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    for retired in (
        'id="executeAdvDeepCleanupAfterRun"',
        'id="executeAdvDockerNukeAll"',
        'id="executeAdvDockerCleanupBeforeRun"',
    ):
        assert retired not in text, f"Retired execute-dialog cleanup control reappeared: {retired}"


def test_topology_page_carries_no_execute_machinery() -> None:
    """The topology page does not execute; that lives on the preview page.

    index.html used to host a full execute pipeline -- a confirm dialog, a run
    poller, progress/summary modals, flow-artifact and custom-service preflights,
    and a window.confirm() fallback for when the dialog markup was missing. All
    of it became unreachable once the dialog markup and its triggers were
    removed, and ~3.6k lines of it were deleted. This pins that it stays gone,
    so the dead pipeline cannot be resurrected by a partial revert.
    """
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    for symbol in (
        "function runSyncWithModal",
        "function promptExecuteConfirmation",
        "function runWithSeedBuild",
        "function setupPreviewModalExecute",
        "function ensureExecuteConfirmElements",
        "function getExecuteConfirmSelections",
        "function ensureExecuteFlowArtifactsReady",
        "function ensureExecuteCustomServicesReady",
        "function submitRunCliRequest",
        "function runAsync",
        "function prepareRunCli",
        "function cancelRun",
        "function buildRunFormData",
        "function getRunCoreConfig",
        "function pushRepoToRemote",
        "function waitForRepoFinalize",
        "function registerExecuteCancelHandler",
    ):
        assert symbol not in text, f"Retired execute machinery is back in index.html: {symbol}"

    # The triggers are gone too, so nothing can re-enter the pipeline.
    for trigger in ('id="fpExecuteBtn"', 'data-action="preview-plan"', 'id="executeConfirmModal"'):
        assert trigger not in text, f"Retired execute trigger reappeared: {trigger}"


def test_execute_dialog_omits_start_core_daemon_checkbox() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    forbidden_snippets = [
        'id="executeAdvStartCoreDaemon"',
        'for="executeAdvStartCoreDaemon"',
        'Start core-daemon\n                                    if stopped',
    ]
    present = [snippet for snippet in forbidden_snippets if snippet in text]
    assert not present, "Execute dialog should prompt for stopped core-daemon instead of showing a start checkbox: " + "; ".join(present)

    assert "Would you like ScenarioForge to try to start core-daemon now?" in text


def test_dock_only_opens_from_manual_show_hide_controls() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    dock_text = DOCK_PARTIAL_PATH.read_text(encoding="utf-8", errors="ignore")

    forbidden_snippets = [
        "showBtn.click(",
        "revealCoreTestDock",
        "revealDock",
        "Ensure dock is visible",
        "Ensure dock visible",
        "Show dock logs",
    ]

    present = [snippet for snippet in forbidden_snippets if snippet in text]
    assert not present, "Unexpected automatic dock reveal behavior in index template: " + "; ".join(present)

    assert "hideBtn.addEventListener('click', () => applyHidden(true));" in dock_text
    assert "showBtn.addEventListener('click', () => applyHidden(false));" in dock_text
    assert "showBtn.click(" not in dock_text


def test_execute_summary_uses_validation_unavailable_details() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const unavailableItems = Array.isArray(summary.validation_unavailable_details)",
        "summary.validation_unavailable_details.filter(Boolean)",
        "renderExecuteSummaryItem(",
        "unavailableItems",
        "unavailableItems.forEach((item) => {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing validation_unavailable details summary wiring: " + "; ".join(missing)


def test_execute_summary_status_icons_do_not_require_emoji_fonts() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    renderer = text.split(
        "function renderExecuteSummaryItem(label, ok, detail, items = [])", maxsplit=1
    )[1].split("function normalizeExecuteRunErrorMessage", maxsplit=1)[0]

    assert "icon.innerHTML = ok" in renderer
    assert '<svg viewBox="0 0 20 20"' in renderer
    assert "icon.setAttribute('aria-label', ok ? 'Passed' : 'Failed')" in renderer
    assert "✅" not in renderer
    assert "❌" not in renderer


def test_execute_summary_includes_flow_live_paths() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const flowLivePathsMissing = Array.isArray(summary.flow_live_paths_missing)",
        "const flowLivePathsChecked = Number.isFinite(Number(summary.flow_live_paths_checked))",
        "const flowLivePathsMissingCount = Number.isFinite(Number(summary.flow_live_paths_missing_count))",
        "'Flow live paths present',",
        "flowLivePathsMissingCount > 0",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow live-path execute summary wiring: " + "; ".join(missing)


def test_scenario_name_input_sanitizes_to_alphanumeric() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "data-field=\"name\"",
        "pattern=\"[A-Za-z0-9]+\"",
        "const sanitized = normalizeScenarioName(raw);",
        "if (sanitized !== raw)",
        "state.scenarios[sidx].name = sanitized;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing scenario-name alphanumeric sanitization wiring: " + "; ".join(missing)
