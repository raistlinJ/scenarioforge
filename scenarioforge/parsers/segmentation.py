from __future__ import annotations
import os
import logging
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple
from ..types import SegmentationInfo
from .common import find_scenario

logger = logging.getLogger(__name__)


def parse_segmentation_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[float, List[SegmentationInfo]]:
    density = 0.0
    items: List[SegmentationInfo] = []
    if not os.path.exists(xml_path):
        logger.warning("XML not found for segmentation parse: %s", xml_path)
        return density, items
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse XML for segmentation (%s)", e)
        return density, items
    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found for segmentation parse")
        return density, items
    section = scenario.find(".//section[@name='Segmentation']")
    if section is None:
        return density, items
    den_raw = (section.get("density") or "").strip()
    if den_raw:
        try:
            density = float(den_raw)
            if density < 0:
                density = 0.0
        except Exception:
            logger.warning("Invalid Segmentation density '%s'", den_raw)
            density = 0.0
    for it in section.findall("./item"):
        name = (it.get("selected") or "").strip()
        if not name:
            continue
        try:
            factor = float((it.get("factor") or "0").strip())
        except Exception:
            factor = 0.0
        vm = (it.get("v_metric") or "").strip()
        abs_count = 0
        if vm == "Count":
            try:
                vc = int((it.get("v_count") or "0").strip())
                if vc >= 0:
                    abs_count = vc
            except Exception:
                abs_count = 0
        if factor > 0 or abs_count > 0:
            items.append(SegmentationInfo(name=name, factor=factor, abs_count=abs_count))
    logger.debug("Parsed segmentation: density=%s items=%s", density, [(i.name, i.factor) for i in items])
    return density, items


_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}

# Everything about segmentation that shapes the plan, and what it is when the
# scenario does not say. These live on the Segmentation section rather than on
# the command line because execute enforces the plan rather than planning again:
# a setting supplied only at execute would arrive after the decisions it was
# meant to influence had already been made and reviewed.
#
# `allow_docker_ports` is deliberately absent. It opens ports belonging to
# containers, which do not exist until execute, so it cannot be a plan-time
# input and stays a run-time flag.
SEGMENTATION_SETTING_DEFAULTS: dict = {
    "nat_mode": "SNAT",
    "include_hosts": False,
    "dnat_probability": 0.0,
    "allow_src_subnet_prob": 0.3,
    "allow_dst_subnet_prob": 0.3,
    "accessible_by_pivot": False,
}

# Attribute spellings accepted for each setting, first match wins.
_SETTING_ATTRS: dict = {
    "nat_mode": ("nat_mode", "natMode"),
    "include_hosts": ("include_hosts", "includeHosts", "seg_include_hosts"),
    "dnat_probability": ("dnat_probability", "dnatProbability", "dnat_prob"),
    "allow_src_subnet_prob": ("allow_src_subnet_prob", "allowSrcSubnetProb"),
    "allow_dst_subnet_prob": ("allow_dst_subnet_prob", "allowDstSubnetProb"),
    "accessible_by_pivot": ("accessible_by_pivot", "accessibleByPivot", "pivot_access"),
}


def coerce_bool(value, default: bool = False) -> bool:
    raw = str(value if value is not None else "").strip().lower()
    if raw in _TRUTHY:
        return True
    if raw in _FALSY:
        return False
    return default


def coerce_probability(value, default: float) -> float:
    try:
        return max(0.0, min(1.0, float(str(value).strip())))
    except Exception:
        return default


def coerce_nat_mode(value, default: str = "SNAT") -> str:
    raw = str(value or "").strip().upper()
    return raw if raw in ("SNAT", "MASQUERADE") else default


def parse_segmentation_settings(xml_path: str, scenario_name: Optional[str]) -> dict:
    """The Segmentation section's plan-shaping settings, with defaults filled in.

    Always returns every key, so callers never have to decide what a missing
    attribute means.
    """
    settings = dict(SEGMENTATION_SETTING_DEFAULTS)
    section = None
    if os.path.exists(xml_path):
        try:
            root = ET.parse(xml_path).getroot()
            scenario = find_scenario(root, scenario_name)
            if scenario is not None:
                section = scenario.find(".//section[@name='Segmentation']")
        except Exception as exc:
            logger.warning("Failed to parse XML for segmentation settings (%s)", exc)
    if section is None:
        return settings

    def _raw(key: str):
        for attr in _SETTING_ATTRS[key]:
            value = section.get(attr)
            if value is not None and str(value).strip():
                return value
        return None

    settings["nat_mode"] = coerce_nat_mode(_raw("nat_mode"), settings["nat_mode"])
    settings["include_hosts"] = coerce_bool(_raw("include_hosts"), settings["include_hosts"])
    settings["accessible_by_pivot"] = coerce_bool(
        _raw("accessible_by_pivot"), settings["accessible_by_pivot"]
    )
    for key in ("dnat_probability", "allow_src_subnet_prob", "allow_dst_subnet_prob"):
        settings[key] = coerce_probability(_raw(key), settings[key])
    return settings


def parse_segmentation_accessible_by_pivot(xml_path: str, scenario_name: Optional[str]) -> bool:
    """Read the Segmentation section's "accessible by pivot" toggle.

    Off unless explicitly enabled, so an existing scenario keeps the exact
    segmentation it was authored with.
    """
    if not os.path.exists(xml_path):
        return False
    try:
        root = ET.parse(xml_path).getroot()
    except Exception as exc:
        logger.warning("Failed to parse XML for pivot-access toggle (%s)", exc)
        return False
    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        return False
    section = scenario.find(".//section[@name='Segmentation']")
    if section is None:
        return False
    for attr in ("accessible_by_pivot", "accessibleByPivot", "pivot_access"):
        raw = (section.get(attr) or "").strip().lower()
        if raw:
            return raw in _TRUTHY
    return False
