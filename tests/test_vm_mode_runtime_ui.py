from pathlib import Path
import re


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"
FLOW_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "flow.html"
SCENARIOS_TABS_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "partials" / "scenarios_tabs.html"
CORE_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "core.html"


def test_vm_mode_ui_seeds_runtime_managed_core_defaults() -> None:
    index_text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    flow_text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    tabs_text = SCENARIOS_TABS_PATH.read_text(encoding="utf-8", errors="ignore")

    index_expected = [
        "const WEBUI_RUNTIME_MODE =",
        "const WEBUI_VM_MODE = WEBUI_RUNTIME_MODE === 'vm';",
        "const WEBUI_VM_MODE_DEFAULTS =",
        "function runtimeManagedVmCoreConfigured(hitlState) {",
        "function applyVmModeDefaultsToScenario(scen) {",
        "function getConfiguredHitlInterfaceValidationForScenario(sidx) {",
        "Refresh CORE VM Interfaces to verify the configured HITL interface names.",
        "out of range for",
        "applyVmModeDefaultsToScenario(scen);",
        "if (runtimeManagedVmCoreConfigured(hitlState)) {",
        "if (runtimeManagedVmCoreConfigured(hitl)) {",
        "'VM mode defaults are incomplete. Check the deployment configuration.'",
        "throw new Error('CORE VM not configured (see ' + runtimeModeAccessLabel() + ').');",
    ]
    tabs_expected = [
        "{% if webui_runtime_mode != 'vm' %}",
        "Mode: {{ 'VM' if webui_runtime_mode == 'vm' else 'Native' }}",
    ]
    flow_expected = [
        "setStatus('Configure CORE VM access to enable Execute.', true);",
    ]

    missing = [snippet for snippet in index_expected if snippet not in index_text]
    missing.extend(snippet for snippet in tabs_expected if snippet not in tabs_text)
    missing.extend(snippet for snippet in flow_expected if snippet not in flow_text)
    assert not missing, "Missing VM-mode UI snippets: " + "; ".join(missing)
    match = re.search(
        r"function runtimeManagedVmCoreConfigured\(hitlState\) \{(?P<body>.*?)\n    \}\n",
        index_text,
        re.DOTALL,
    )
    assert match is not None, "runtimeManagedVmCoreConfigured() block not found"
    body = match.group("body")
    assert "const vmKey = (core.vm_key ?? '').toString().trim();" not in body
    assert "coreHost" in body
    assert "coreSshHost" in body
    assert "coreUser" in body

    execute_match = re.search(
        r"function isExecuteCoreVmConfigured\(\) \{(?P<body>.*?)\n    \}\n",
        index_text,
        re.DOTALL,
    )
    assert execute_match is not None, "isExecuteCoreVmConfigured() block not found"
    execute_body = execute_match.group("body")
    assert "runtimeManagedVmCoreConfigured(hitl)" in execute_body
    assert "getConfiguredHitlInterfaceValidationForScenario(scenarioIdx)" in execute_body
    assert "const vmKey = (core?.vm_key ?? '').toString().trim();" in execute_body
    assert "entry.name || `net${idx}`" not in index_text

    validate_match = re.search(
        r"async function validateCoreConnection\(sidx, options = \{\}\) \{(?P<body>.*?)\n    \}\n\n    async function hydrateCoreModalWithSecret",
        index_text,
        re.DOTALL,
    )
    assert validate_match is not None, "validateCoreConnection() block not found"
    validate_body = validate_match.group("body")
    assert "const runtimeManagedVmMode = runtimeManagedVmCoreConfigured(hitlState);" in validate_body
    assert "if (!vmKey && !runtimeManagedVmMode)" in validate_body
    assert "runtime_managed_vm_mode: runtimeManagedVmMode," in validate_body
    assert "const vmLabel = vmKey || (runtimeManagedVmMode ? 'runtime-managed' : '(unset)');" in validate_body
    assert "function sanitizeScenarioCoreForRequest(coreState, includePassword = true, options = {}) {" in index_text


def test_vm_mode_core_management_hides_change_core_vm_action() -> None:
    core_text = CORE_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected = [
        "{% set runtime_managed_vm_mode = (webui_runtime_mode|default('native')|lower) == 'vm' %}",
        "{% if not is_builder_view and not runtime_managed_vm_mode %}",
        "const corePageVmMode = {{ runtime_managed_vm_mode|tojson }};",
        "const allowCoreVmChange = !corePageVmMode;",
        "${(href && allowCoreVmChange) ? `<a class=\"btn btn-sm btn-dark\" id=\"coreVmActionLink\" href=\"${esc(href)}\">Change CORE VM</a>` : ''}",
    ]
    missing = [snippet for snippet in expected if snippet not in core_text]
    assert not missing, "Missing VM-mode Core Management snippets: " + "; ".join(missing)


def test_vm_mode_core_management_nav_allows_runtime_managed_defaults() -> None:
    index_text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    selection_match = re.search(
        r"const hasCoreVmSelection = \(\) => \{(?P<body>.*?)\n            \};",
        index_text,
        re.DOTALL,
    )
    assert selection_match is not None, "hasCoreVmSelection() block not found"
    selection_body = selection_match.group("body")
    assert "if (runtimeManagedVmCoreConfigured(hitlState))" in selection_body
    assert "return true;" in selection_body

    verified_match = re.search(
        r"const hasVerifiedCoreConnection = \(\) => \{(?P<body>.*?)\n            \};",
        index_text,
        re.DOTALL,
    )
    assert verified_match is not None, "hasVerifiedCoreConnection() block not found"
    verified_body = verified_match.group("body")
    assert "if (runtimeManagedVmCoreConfigured(hitlState))" in verified_body
    assert "return true;" in verified_body

    modal_match = re.search(
        r"<div class=\"modal-body\">(?P<body>.*?)</div>",
        index_text[index_text.find('id="coreNavBlockedModal"'):],
        re.DOTALL,
    )
    assert modal_match is not None, "coreNavBlockedModal body not found"
    modal_body = modal_match.group("body")
    assert "{% if webui_runtime_mode == 'vm' %}" in modal_body
    assert "VM mode CORE defaults are incomplete" in modal_body


def test_hitl_summary_prefers_stored_bridge_mapping_over_inventory() -> None:
    index_text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected = [
        "const mappedIfaceId = extIfaceId || extIfaceIdLive;",
        "const extBridge = extBridgeStored || extBridgeLive;",
    ]
    missing = [snippet for snippet in expected if snippet not in index_text]
    assert not missing, "Missing stored-bridge precedence snippets: " + "; ".join(missing)


def test_hitl_verify_updates_bridge_metadata_with_canonical_name() -> None:
    index_text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected = [
        "const resolvedBridgeName = (data && data.bridge_name)",
        "hitlState.core.internal_bridge = resolvedBridgeName;",
        "iface.core_bridge = resolvedBridgeName;",
        "iface.proxmox_target.bridge = resolvedBridgeName;",
        "ext.interface_bridge = resolvedBridgeName;",
    ]
    missing = [snippet for snippet in expected if snippet not in index_text]
    assert not missing, "Missing verify bridge-sync snippets: " + "; ".join(missing)