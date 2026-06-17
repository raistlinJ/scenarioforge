from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"
FLOW_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "flow.html"


def _extract_verify_core_setup_block(text: str) -> str:
    start_token = "async function verifyScenarioCoreSetup"
    end_token = "async function clearScenarioCoreVmSelection"
    start = text.find(start_token)
    end = text.find(end_token)
    if start < 0 or end < 0 or end <= start:
        return text
    return text[start:end]


def test_core_verify_save_uses_direct_local_save() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const runSave = async () => {",
        "if (typeof autoSaveXml !== 'function') {",
        "throw new Error('Save is unavailable on this page.');",
        "await autoSaveXml();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing direct local save snippets in modal path: " + "; ".join(missing)


def test_core_verify_save_does_not_refresh_interfaces_in_step2() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    verify_block = _extract_verify_core_setup_block(text)

    forbidden_snippets = [
        "verifySetStatus('Loading CORE VM interfaces…');",
        "const refreshRes = await refreshHostInterfacesForScenario(sidx, {",
        "One or more selected HITL interfaces no longer exist on the CORE VM",
    ]

    present = [snippet for snippet in forbidden_snippets if snippet in verify_block]
    assert not present, "Unexpected Step 2 interface-refresh gating snippets still present: " + "; ".join(present)


def test_validate_core_connection_clears_docker_fix_flag_in_docker_mode() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "let effectiveAdvFixDockerDaemon = !!advFixDockerDaemon;",
        "if (WEBUI_RUNNING_IN_DOCKER && effectiveAdvFixDockerDaemon) {",
        "coreState.adv_fix_docker_daemon = false;",
        "adv_fix_docker_daemon: effectiveAdvFixDockerDaemon,",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing shared CORE validation docker-fix guard snippets: " + "; ".join(missing)


def test_execute_modal_core_test_prefers_stored_config() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "preferStoredConfig = false,",
        "prefer_stored_config: preferStoredConfig,",
        "preferStoredConfig: true,",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing execute-modal stored-config validation snippets: " + "; ".join(missing)


def test_validate_core_connection_logs_failures_to_dock() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const revealCoreTestDock = () => {",
        "const logCoreTestLine = (message, level = 'INFO', { revealDock = false } = {}) => {",
        "logCoreTestLine(`POST /test_core -> grpc ${requestTarget}:${body.core.port || 50051} ssh ${requestSshHost}:${body.core.ssh_port || 22} vm ${vmKey}${preferStoredConfig ? ' [prefer stored config]' : ''}`);",
        "logCoreTestLine(`FAILED: ${message}${codeText}${httpText}`, 'ERROR', { revealDock: true });",
        "warningLines.forEach((line) => logCoreTestLine(`Warning: ${line}`, 'WARN', { revealDock: true }));",
        "logCoreTestLine(`FAILED: ${message}`, 'ERROR', { revealDock: true });",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing CORE connection dock-log snippets: " + "; ".join(missing)


def test_validate_core_connection_prompts_to_start_missing_daemon() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "_daemonStartPrompted = false,",
        "data.code === 'core_daemon_not_running'",
        "Would you like ScenarioForge to try to start core-daemon now?",
        "window.confirmWithModal('Start core-daemon?', prompt, 'Start core-daemon', 'primary')",
        "autoStartDaemon: true,",
        "_daemonStartPrompted: true,",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing missing-daemon start prompt snippets: " + "; ".join(missing)


def test_execute_progress_modal_unlocks_on_early_failures() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "body: JSON.stringify({ core: coreCfg, cleanup: false, scenario_name: scenarioName }),",
        "body: JSON.stringify({\n                        core: getRunCoreConfig(true, scenarioIndexForRun),\n                        scenario_name: (getScenarioByIndex(scenarioIndexForRun)?.name || activeScenarioCtx.name || '').toString().trim(),\n                    }),",
        "appendExecuteDialogLog('Repository upload failed; aborting run.');",
        "bar.textContent = 'Error';\n                        }\n                        markRunProgressComplete();\n                    }\n                    return false;",
        "appendExecuteDialogLog(`Repository upload exception: ${err?.message || err}`);",
        "appendExecuteDialogLog('Failed to refresh flow/preview plan; aborting run to avoid mismatch.');",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing execute preflight secret/close snippets: " + "; ".join(missing)


def test_build_run_form_data_uses_scenario_scoped_core_without_session_password_restore() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const scenarioIndex = Number.isInteger(options && options.scenarioIndex) ? options.scenarioIndex : null;",
        "form.append('core_json', JSON.stringify(getRunCoreConfig(false, scenarioIndex)));",
        "if ('grpc_host' in source && String(source.grpc_host).trim()) {",
        "if ('grpc_port' in source && source.grpc_port !== undefined && source.grpc_port !== null && String(source.grpc_port).trim()) {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing scenario-scoped async CORE serialization snippets: " + "; ".join(missing)


def test_execute_progress_success_is_normalized_and_can_override_spurious_error_state() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function getExecuteRunReturnCode(runStatus) {",
        "function isExecuteValidationSuccessful(runStatus) {",
        "function didExecuteRunSucceed(runStatus) {",
        "if (isExecuteValidationSuccessful(runStatus)) {",
        "if (executeProgressState.done) {\n            if (!success) return;\n            if (executeProgressBarEl && executeProgressBarEl.classList.contains('bg-success')) return;\n        }",
        "const runSucceeded = didExecuteRunSucceed(data);",
        "if (data.done && didExecuteRunSucceed(data)) {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing execute success normalization snippets: " + "; ".join(missing)


def test_save_xml_button_uses_direct_local_save() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if (typeof autoSaveXml !== 'function') {",
        "throw new Error('Save is unavailable on this page.');",
        "await autoSaveXml();",
        "const xmlPath = await autoSaveXml();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing direct local Save XML snippets: " + "; ".join(missing)

    forbidden = [
        "async function saveXmlViaAvailableHelper(opts = {}) {",
        "await saveXmlViaAvailableHelper();",
        "const xmlPath = await saveXmlViaAvailableHelper();",
    ]
    present = [snippet for snippet in forbidden if snippet in text]
    assert not present, "Unexpected helper-fallback snippets still present: " + "; ".join(present)


def test_topology_save_xml_ajax_uses_local_autosave() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "async function saveXmlAjax() {",
        "if (typeof autoSaveXml !== 'function') {",
        "const xmlPath = await autoSaveXml();",
    ]
    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing local saveXmlAjax snippets: " + "; ".join(missing)

    forbidden = [
        "if (typeof window.coretgSaveXmlViaApi !== 'function')",
        "const xmlPath = await window.coretgSaveXmlViaApi();",
    ]
    present = [snippet for snippet in forbidden if snippet in text]
    assert not present, "Unexpected shared-helper usage in saveXmlAjax: " + "; ".join(present)


def test_flow_save_xml_uses_xml_path_fallback_resolver() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "async function saveXmlViaFlowState(scenarioName) {",
        "const resp = await fetch('/save_xml_api', {",
        "async function resolveXmlPathForSaveWithFallback(scenarioName, options) {",
        "window.coretgGetLatestXmlPathForScenario",
        "xmlPath = await saveXmlViaFlowState(scenario);",
        "'/api/scenario/latest_xml?scenario=' + encodeURIComponent(scenario)",
        "xmlPath = await resolveXmlPathForSaveWithFallback(scenario, { attemptSave: true });",
        "No XML path available. Save XML from Topology/VM Access first.",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow Save XML fallback snippets: " + "; ".join(missing)

    forbidden = [
        "window.coretgSaveXmlViaApi",
        "Save helper unavailable; refresh and try again.",
    ]
    present = [snippet for snippet in forbidden if snippet in text]
    assert not present, "Unexpected shared-helper dependency snippets in flow save paths: " + "; ".join(present)


def test_flow_save_and_preview_do_not_swallow_flow_state_save_failures() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const shouldPersistFlowState = shouldSaveFlowStateToXml(xmlPath);",
        "if (shouldPersistFlowState) {",
        "if (!(await saveFlowStateToXml(xmlPath))) {",
        "throw new Error('Failed to save Flag Sequencing state into XML.');",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing explicit Flag Sequencing save failure handling snippets: " + "; ".join(missing)

    forbidden = [
        "try { await saveFlowStateToXml(xmlPath); } catch (e) { }",
    ]
    present = [snippet for snippet in forbidden if snippet in text]
    assert not present, "Unexpected swallowed Flag Sequencing save failure snippets still present: " + "; ".join(present)


def test_flow_preview_skips_xml_rewrite_when_saved_state_matches() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function buildCurrentFlowStatePayload(options) {",
        "function flowStateXmlSignature(state) {",
        "function shouldSaveFlowStateToXml(xmlPath) {",
        "if (!latestXmlPath || latestXmlPath !== targetXmlPath) return true;",
        "const currentSig = flowStateXmlSignature(buildCurrentFlowStatePayload({ includeUpdatedAt: false }));",
        "return !currentSig || !savedSig || currentSig !== savedSig;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing Flow Preview no-op XML-save guard snippets: " + "; ".join(missing)


def test_flow_restore_rehydrates_duplicate_toggle_from_saved_state() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "allowNodeDuplicates = !!(saved && saved.allow_node_duplicates);",
        "generateNoDuplicatesEl.checked = !!allowNodeDuplicates;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing saved duplicate-toggle restore snippets: " + "; ".join(missing)


def test_flow_ui_shows_validated_vuln_notice_when_present() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const noticeReasons = reasons.filter((reason) => reason.startsWith('No validated/tested vulnerabilities are currently eligible'));",
        "flowEnabledHelpEl.textContent = 'Note: ' + noticeReasons.join(' ');",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing validated-vulnerability notification snippets in flow UI: " + "; ".join(missing)


def test_flow_compose_modal_normalizes_progress_variants() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function setComposeProgressState(label, options) {",
        "composeProgressBarEl.classList.remove('progress-bar-animated', 'progress-bar-striped', 'text-bg-success', 'text-bg-danger');",
        "setComposeProgressState('Working…', { width: '100%', animated: true });",
        "setComposeProgressState(progressLabel, { width: '100%', variant: progressVariant });",
        "setComposeProgressState('Failed', { width: '100%', variant: 'danger' });",
        "updateComposeDialog({ html, statusText: 'Re-Validate failed.', progressLabel: 'Failed', progressVariant: 'danger' });",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow compose progress normalization snippets: " + "; ".join(missing)


def test_flow_generate_does_not_report_success_after_failed_resolve() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "let resolvedOk = !resolveOnGenerate;",
        "resolvedOk = true;",
        "if (resolveOnGenerate && !resolvedOk) {\n        return;\n      }",
        "statusText: 'Generation failed.',",
        "progressVariant: 'danger',",
        "statusText: 'Generation complete.',",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow generate resolve-guard snippets: " + "; ".join(missing)


def test_flow_generate_retries_duplicate_resolve_errors_before_failing() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const duplicateFlagError = _isDuplicateFlagError(e);",
        "if (duplicateFlagError && resolveRetriesRemaining > 0) {",
        "setStatus(`Resolve hit duplicate flags; retrying (${attemptedRetries})…`, true);",
        "appendLoadingLog('Duplicate flags during resolve; resequencing.');",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing duplicate-resolve retry snippets in flow UI: " + "; ".join(missing)

    forbidden = [
        "if (resolveAttempts > 1 || resolveRetriesRemaining <= 0) {",
    ]
    present = [snippet for snippet in forbidden if snippet in text]
    assert not present, "Unexpected duplicate-resolve failure gate still present: " + "; ".join(present)
