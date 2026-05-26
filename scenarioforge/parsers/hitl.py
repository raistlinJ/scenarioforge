from __future__ import annotations
import re
import logging
import os
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from .common import find_scenario, has_unexpected_container

logger = logging.getLogger(__name__)


_ATTACHMENT_ALLOWED = {
    "existing_router",
    "existing_switch",
    "new_router",
    "new_switch",
}
_DEFAULT_ATTACHMENT = "existing_router"


_HITL_ROUTER_PEER_IFACE_RE = re.compile(r"^hitl-router-(?P<ifname>.+)-hitl\d+$", re.IGNORECASE)
_IFNAME_ALLOWED_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,15}$")


def _normalize_hitl_ifname(name: str) -> str:
    candidate = (name or "").strip()
    if not candidate:
        return ""
    lower = candidate.lower()
    if lower.startswith("hitl-") and not lower.startswith("hitl-router-"):
        candidate = candidate[5:]
    candidate = candidate.split("@", 1)[0].strip()
    m = _HITL_ROUTER_PEER_IFACE_RE.match(candidate)
    if m:
        extracted = (m.group("ifname") or "").strip()
        if extracted and _IFNAME_ALLOWED_RE.match(extracted):
            return extracted
    return candidate


def _normalize_attachment(value: Any) -> str:
    if value is None:
        return _DEFAULT_ATTACHMENT
    try:
        normalized = str(value).strip().lower().replace('-', '_').replace(' ', '_')
    except Exception:
        return _DEFAULT_ATTACHMENT
    if normalized in _ATTACHMENT_ALLOWED:
        return normalized
    return _DEFAULT_ATTACHMENT


def _normalize_interface_element(element: ET.Element) -> Optional[Dict[str, Any]]:
    name = _normalize_hitl_ifname((element.get("name") or element.get("interface") or "").strip())
    if not name:
        return None
    entry: Dict[str, Any] = {"name": name}
    alias = (element.get("alias") or element.get("display") or element.get("description") or "").strip()
    if alias:
        entry["alias"] = alias
    mac = (element.get("mac") or element.get("hwaddr") or "").strip()
    if mac:
        entry["mac"] = mac
    core_bridge = (element.get("core_bridge") or "").strip()
    if core_bridge:
        entry["core_bridge"] = core_bridge
    entry["attachment"] = _normalize_attachment(element.get("attachment") or element.get("attach"))
    for attr in ("ipv4", "ipv4_addresses"):
        raw = element.get(attr)
        if raw:
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            if parts:
                entry["ipv4"] = parts
            break
    for attr in ("ipv6", "ipv6_addresses"):
        raw = element.get(attr)
        if raw:
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            if parts:
                entry["ipv6"] = parts
            break
    prox_target = {
        "node": (element.get("pve_node") or "").strip(),
        "vmid": (element.get("pve_vmid") or "").strip(),
        "interface_id": (element.get("pve_interface_id") or "").strip(),
        "macaddr": (element.get("pve_macaddr") or "").strip(),
        "bridge": (element.get("pve_bridge") or "").strip(),
        "model": (element.get("pve_model") or "").strip(),
        "vm_name": (element.get("pve_vm_name") or "").strip(),
        "label": (element.get("pve_label") or "").strip(),
    }
    if any(value for value in prox_target.values()):
        entry["proxmox_target"] = prox_target
    external_vm = {
        "vm_key": (element.get("ext_vm_key") or "").strip(),
        "vm_node": (element.get("ext_vm_node") or "").strip(),
        "vm_name": (element.get("ext_vm_name") or "").strip(),
        "vmid": (element.get("ext_vmid") or "").strip(),
        "status": (element.get("ext_status") or "").strip(),
        "interface_id": (element.get("ext_interface_id") or "").strip(),
        "interface_bridge": (element.get("ext_interface_bridge") or "").strip(),
        "interface_mac": (element.get("ext_interface_mac") or "").strip(),
        "interface_model": (element.get("ext_interface_model") or "").strip(),
    }
    if any(value for value in external_vm.values()):
        entry["external_vm"] = external_vm
    return entry


def parse_hitl_info(xml_path: str, scenario_name: Optional[str]) -> Dict[str, Any]:
    """Parse Hardware-In-The-Loop configuration from the scenario XML."""
    result: Dict[str, Any] = {"enabled": False, "interfaces": [], "core": None}
    if not xml_path or not os.path.exists(xml_path):
        return result
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as exc:
        logger.debug("Failed parsing XML for HITL info: %s", exc)
        return result
    if has_unexpected_container(root):
        logger.warning("HITL parse skipped: XML appears to be a CORE session export with <container> elements")
        return result
    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        logger.debug("HITL parse: scenario %s not found", scenario_name)
        return result
    se = scenario.find("ScenarioEditor")
    if se is None:
        se = scenario.find(".//ScenarioEditor")
    if se is None:
        logger.debug("HITL parse: ScenarioEditor missing for scenario %s", scenario_name)
        return result
    hitl_element = se.find("HardwareInLoop")
    if hitl_element is None:
        return result
    enabled_raw = (hitl_element.get("enabled") or "").strip().lower()
    result["enabled"] = enabled_raw in {"1", "true", "yes", "on"}
    interfaces: List[Dict[str, Any]] = []
    for iface_el in hitl_element.findall("Interface"):
        normalized = _normalize_interface_element(iface_el)
        if normalized:
            interfaces.append(normalized)
    result["interfaces"] = interfaces
    core_element = hitl_element.find("CoreConnection")
    if core_element is not None:
        core_cfg = dict(core_element.attrib)
        if core_cfg:
            result["core"] = core_cfg
    return result
