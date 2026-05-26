from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_hitl_bridge_summary_prefers_live_selected_vm_bridge() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const resolveExternalVmInterface = (inventory, externalVm, preferredBridge = '') => {",
        "const matchByMac = physicalInterfaces.find((vmIface) => ((vmIface?.macaddr ?? '').toString().trim().toLowerCase() === extIfaceMac)) || null;",
        "const matchByBridge = physicalInterfaces.find((vmIface) => ((vmIface?.bridge ?? '').toString().trim() === extBridge)) || null;",
        "const liveExternalIface = resolveExternalVmInterface(",
        "const extIfaceIdLive = (liveExternalIface ? normalizeVmInterfaceId(liveExternalIface) : '').toString().trim();",
        "const extBridgeLive = (liveExternalIface?.bridge ?? '').toString().trim();",
        "const mappedIfaceId = extIfaceIdLive || extIfaceId;",
        "const extBridge = extBridgeLive || extBridgeStored;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing live bridge summary snippets: " + "; ".join(missing)


def test_hitl_bridge_apply_and_verify_sync_external_vm_bridge_metadata() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if (ext && typeof ext === 'object' && !((ext.interface_bridge || '').toString().trim())) {",
        "ext.interface_bridge = bridgeName;",
        "if (ext && typeof ext === 'object') {",
        "ext.interface_bridge = appliedBridgeName;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing external VM bridge sync snippets: " + "; ".join(missing)


def test_hitl_summary_labels_use_resolved_live_external_interface_id() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const liveExternalIface = resolveExternalVmInterface(",
        "const ifaceId = (liveExternalIface ? normalizeVmInterfaceId(liveExternalIface) : (ext.interface_id ?? '')).toString().trim();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing resolved mapped VM interface label snippets: " + "; ".join(missing)


def test_hitl_bridge_summary_excludes_unmapped_interfaces() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const hasExternalVmSelection = !!(ext && (ext.vm_key || ext.vmid || ext.vm_name));",
        "if (!hasExternalVmSelection) return null;",
        ".filter((row) => row && (row.name || row.coreIfaceId || row.extIfaceId));",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing mapped-interface summary filter snippets: " + "; ".join(missing)
