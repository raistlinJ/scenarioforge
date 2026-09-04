from pathlib import Path
import shutil
import subprocess
import tempfile

import pytest


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


def test_validate_core_connection_logs_failures_to_dock() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    # The dock-reveal option these calls used to pass was removed -- it invoked a
    # helper that never existed, so it only ever threw. What matters here is that
    # failures and warnings still reach the dock log, which they do. Auto-reveal
    # is deliberately absent; see
    # test_execute_form_advanced_flags.test_dock_only_opens_from_manual_show_hide_controls.
    expected_snippets = [
        "const logCoreTestLine = (message, level = 'INFO') => {",
        "logCoreTestLine(`POST /test_core -> grpc ${requestTarget}:${body.core.port || 50051} ssh ${requestSshHost}:${body.core.ssh_port || 22} vm ${vmKey}${preferStoredConfig ? ' [prefer stored config]' : ''}`);",
        "logCoreTestLine(`FAILED: ${message}${codeText}${httpText}`, 'ERROR');",
        "warningLines.forEach((line) => logCoreTestLine(`Warning: ${line}`, 'WARN'));",
        "logCoreTestLine(`FAILED: ${message}`, 'ERROR');",
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


def test_save_xml_skips_redundant_flow_plan_persist_when_preview_is_current() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function scenarioForXmlPreviewSignature(value) {",
        "'flow_state', 'flowState',",
        "'fullPreview', 'preview', 'saved_xml_path', 'savedXmlPath',",
        "previewState.planNeedsPersist = true;",
        "previewState.planNeedsPersist === true",
        "previewState.dirty === true || previewState.planNeedsPersist === true",
        "const currentPreviewSignature = buildXmlPreviewSignature();",
        "input_signature: currentPreviewSignature,",
        "const matchingCurrentPreview = !!(",
        "activeScenario.plan_preview.input_signature === currentPreviewSignature",
        "if (matchingCurrentPreview) return;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing no-op flow-plan persist guard snippets: " + "; ".join(missing)


def test_unchanged_topology_save_reuses_existing_xml_without_new_snapshot() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function isXmlPreviewUnchanged(source = null) {",
        "function currentSavedXmlPathForActiveScenario() {",
        "if (existingXmlPath && isXmlPreviewUnchanged()) {",
        "[xml-save] No changes detected; reusing ${existingXmlPath}",
        "return existingXmlPath;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing unchanged XML-save fast path snippets: " + "; ".join(missing)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required to execute the signature helper")
def test_xml_preview_signature_ignores_generated_outputs_but_detects_topology_edits() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    start = text.find("function scenarioForXmlPreviewSignature(value) {")
    end = text.find("function noteXmlPreviewSavedSignature", start)
    assert start >= 0 and end > start
    helpers = text[start:end]

    harness = f"""
let state = {{
  scenarios: [{{name: 'Demo', sections: {{Routing: {{items: [{{selected: 'RIP'}}]}}}}}}],
  core: {{host: '127.0.0.1', port: 50051}},
}};
let activeIdx = 0;
globalThis.window = {{coretgGetSeedForScenario: () => 17}};
function getCoreConfig() {{ return state.core; }}
{helpers}
const before = buildXmlPreviewSignature();
state.scenarios[0].plan_preview = {{full_preview: {{routers: [1]}}, input_signature: before}};
state.scenarios[0].flow_state = {{chain_ids: ['1', '2'], updated_at: Date.now()}};
state.scenarios[0].saved_xml_path = '/tmp/Demo.xml';
const generated = buildXmlPreviewSignature();
if (before !== generated) throw new Error('generated outputs changed the input signature');
state.scenarios[0].sections.Routing.items[0].selected = 'OSPFv2';
const edited = buildXmlPreviewSignature();
if (edited === generated) throw new Error('topology edit did not change the input signature');
console.log('OK');
"""
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
        handle.write(harness)
        path = handle.name
    try:
        result = subprocess.run(["node", path], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout
    finally:
        Path(path).unlink(missing_ok=True)


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


def test_flow_save_button_skips_redundant_xml_rewrite() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    start = text.find("async function saveXmlStay()")
    end = text.find("// Bottom-bar buttons:", start)
    assert start >= 0 and end > start
    block = text[start:end]

    expected_snippets = [
        "const shouldPersistFlowState = shouldSaveFlowStateToXml(xmlPath);",
        "if (shouldPersistFlowState) {",
        "if (!(await saveFlowStateToXml(xmlPath))) {",
        "XML is already up to date:",
    ]
    missing = [snippet for snippet in expected_snippets if snippet not in block]
    assert not missing, "Missing Flow Save XML no-op guard snippets: " + "; ".join(missing)


def test_flow_save_button_acknowledges_click_and_reports_noop() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    start = text.find("async function saveXmlStay()")
    end = text.find("// Bottom-bar buttons:", start)
    assert start >= 0 and end > start
    block = text[start:end]

    expected_snippets = [
        "function showFlowSaveFeedback(message, variant = 'success', delay = 2600) {",
        'saveXmlEl.innerHTML = \'<span class="spinner-border spinner-border-sm me-1"',
        "showFlowSaveFeedback('Saved flow state to '",
        "showFlowSaveFeedback('Save confirmed — XML is already up to date.');",
        "showFlowSaveFeedback('Save failed: '",
        "saveXmlEl.innerHTML = originalSaveButtonHtml;",
    ]
    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing Flow Save XML acknowledgement feedback: " + "; ".join(missing)


def test_flow_preview_skips_xml_rewrite_when_saved_state_matches() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function buildCurrentFlowStatePayload(options) {",
        "function flowStateXmlSignature(state) {",
        "function shouldSaveFlowStateToXml(xmlPath) {",
        "if (!latestXmlPath || latestXmlPath !== targetXmlPath) return true;",
        "const currentSig = flowStateXmlSignature(buildCurrentFlowStatePayload({ includeUpdatedAt: false }));",
        "return !currentSig || !savedSig || currentSig !== savedSig;",
        "if (xmlPath && shouldSaveFlowStateToXml(xmlPath)) {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing Flow Preview no-op XML-save guard snippets: " + "; ".join(missing)


def test_flow_restore_ignores_legacy_saved_duplicate_toggle() -> None:
    """Node reuse was removed as a Flow option; a legacy saved value must not revive it.

    This test previously asserted the opposite -- that `allow_node_duplicates`
    was rehydrated into a checkbox. The option was deliberately dropped so every
    generated sequence uses distinct topology nodes, so the guarantee worth
    pinning now is that a stale saved value is discarded rather than restored.
    """
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    assert "allowNodeDuplicates = false;" in text

    forbidden_snippets = [
        "allowNodeDuplicates = !!(saved && saved.allow_node_duplicates);",
        "generateNoDuplicatesEl.checked = !!allowNodeDuplicates;",
    ]

    present = [snippet for snippet in forbidden_snippets if snippet in text]
    assert not present, "Legacy duplicate-toggle restore has returned: " + "; ".join(present)


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
