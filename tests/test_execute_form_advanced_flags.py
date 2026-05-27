from pathlib import Path


TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_build_run_form_data_includes_advanced_flags() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_lines = [
        "if (adv && adv.fixDockerDaemon) form.append('adv_fix_docker_daemon', '1');",
        "if (adv && adv.runCoreCleanup) form.append('adv_run_core_cleanup', '1');",
        "if (adv && adv.deepCleanupAfterRun) form.append('adv_deep_cleanup_after_run', '1');",
        "if (adv && adv.restartCoreDaemon) form.append('adv_restart_core_daemon', '1');",
        "if (adv && adv.startCoreDaemon) form.append('adv_start_core_daemon', '1');",
        "if (adv && adv.autoKillSessions) form.append('adv_auto_kill_sessions', '1');",
    ]

    missing = [line for line in expected_lines if line not in text]
    assert not missing, "Missing execute advanced FormData mapping lines: " + "; ".join(missing)

    forbidden_lines = [
        "if (adv && adv.checkCoreVersion) form.append('adv_check_core_version', '1');",
    ]

    present = [line for line in forbidden_lines if line in text]
    assert not present, "Unexpected CORE version-check FormData mapping lines still present: " + "; ".join(present)


def test_execute_dialog_defaults_enable_deep_and_all_container_cleanup() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        '<input class="form-check-input" type="checkbox" id="executeAdvDeepCleanupAfterRun" checked>',
        '<input class="form-check-input" type="checkbox" id="executeAdvDockerNukeAll" checked>',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing enabled execute cleanup defaults: " + "; ".join(missing)


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


def test_execute_preflights_flow_artifacts_and_regenerates_when_safe() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "async function ensureExecuteFlowArtifactsReady",
        "'/api/flag-sequencing/revalidate_flow'",
        "'/api/flag-sequencing/regenerate_flow_artifacts'",
        "regeneration_would_preserve_resolves === false",
        "Regenerate & Continue",
        "const flowReady = await ensureExecuteFlowArtifactsReady({",
        "if (!flowReady) {",
        "return false;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing execute Flow artifact preflight wiring: " + "; ".join(missing)

    has_unsaved_block = text.split("function hasUnsavedChanges()", 1)[1].split("function showUnsavedChangesModal", 1)[0]
    assert "await window.alertWithModal" not in has_unsaved_block
    assert "Flow preflight exception" not in has_unsaved_block

    preferred_scenario_block = text.split("const resolvePreferredScenarioNameOnLoad = () =>", 1)[1].split("const preferredScenarioName", 1)[0]
    assert "await window.alertWithModal" not in preferred_scenario_block
    assert "Flow preflight exception" not in preferred_scenario_block

    execute_preflight_block = text.split("const flowReady = await ensureExecuteFlowArtifactsReady({", 1)[1].split("appendExecuteDialogLog('Requesting remote CLI run…');", 1)[0]
    assert "Flow preflight exception" in execute_preflight_block
    assert "await window.alertWithModal('Flow Preflight Failed', detail, 'OK', 'danger');" in execute_preflight_block


def test_execute_preflights_custom_services_and_prompts_before_run_request() -> None:
    text = TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "async function ensureExecuteCustomServicesReady",
        "'/core/custom_services/check'",
        "Install Custom Services?",
        "Install & Continue",
        "on_core_machine/custom_services",
        "const servicesReady = await ensureExecuteCustomServicesReady({",
        "if (!servicesReady) {",
        "return false;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing execute custom services preflight wiring: " + "; ".join(missing)

    services_preflight_idx = text.index("const servicesReady = await ensureExecuteCustomServicesReady({")
    run_request_idx = text.index("appendExecuteDialogLog('Requesting remote CLI run…');")
    assert services_preflight_idx < run_request_idx


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
