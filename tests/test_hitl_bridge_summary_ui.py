from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_hitl_bridge_summary_prefers_persisted_mapping_over_live_inventory() -> None:
    """The summary trusts the mapping persisted by Verify/Apply over live inventory.

    This test previously required the opposite order. The preference was inverted
    on purpose because Proxmox inventory can be stale until the next refresh,
    which made the summary show a bridge the user had just changed away from.
    The live values are still resolved and still used as the fallback when no
    persisted mapping exists.
    """
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const resolveExternalVmInterface = (inventory, externalVm, preferredBridge = '') => {",
        "const matchByMac = physicalInterfaces.find((vmIface) => ((vmIface?.macaddr ?? '').toString().trim().toLowerCase() === extIfaceMac)) || null;",
        "const matchByBridge = physicalInterfaces.find((vmIface) => ((vmIface?.bridge ?? '').toString().trim() === extBridge)) || null;",
        "const liveExternalIface = resolveExternalVmInterface(",
        "const extIfaceIdLive = (liveExternalIface ? normalizeVmInterfaceId(liveExternalIface) : '').toString().trim();",
        "const extBridgeLive = (liveExternalIface?.bridge ?? '').toString().trim();",
        "const mappedIfaceId = extIfaceId || extIfaceIdLive;",
        "const extBridge = extBridgeStored || extBridgeLive;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing bridge summary snippets: " + "; ".join(missing)

    # Pin the rationale so the order is not "tidied" back by a future refactor.
    assert "inventory can be stale until the next refresh." in text


def test_hitl_bridge_apply_and_verify_sync_external_vm_bridge_metadata() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    # Both paths now overwrite unconditionally. The earlier "only fill when
    # empty" guard was dropped on purpose: the summary treats the persisted
    # mapping as authoritative, so Verify and Apply have to keep it current
    # rather than leaving a stale value in place.
    expected_snippets = [
        "if (ext && typeof ext === 'object') {",
        "ext.interface_bridge = appliedBridgeName;",
        "ext.interface_bridge = resolvedBridgeName;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing external VM bridge sync snippets: " + "; ".join(missing)

    assert "!((ext.interface_bridge || '').toString().trim())" not in text, \
        "Fill-only-when-empty guard is back; it lets a stale bridge survive Verify/Apply"


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
