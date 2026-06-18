from __future__ import annotations

import logging
import os
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

from ..types import PivotInfo
from .common import find_scenario

logger = logging.getLogger(__name__)


def _first_attr(element: ET.Element, *names: str) -> str:
    for name in names:
        value = (element.get(name) or "").strip()
        if value:
            return value
    return ""


def _truthy_attr(element: ET.Element, *names: str) -> bool:
    for name in names:
        value = (element.get(name) or "").strip().lower()
        if value in {"1", "true", "yes", "on", "pivot", "pivot-only", "required"}:
            return True
    return False


def _factor_and_abs_count(element: ET.Element, default_factor: float = 1.0) -> tuple[float, int]:
    try:
        factor = max(0.0, float((element.get("factor") or str(default_factor)).strip()))
    except Exception:
        factor = default_factor
    vm = (element.get("v_metric") or "").strip()
    abs_count = 0
    if vm.lower() == "count":
        try:
            abs_count = max(0, int((element.get("v_count") or "0").strip()))
        except Exception:
            abs_count = 0
    return factor, abs_count


def _pivot_info_from_element(element: ET.Element, *, default_name: str, default_factor: float = 1.0) -> PivotInfo:
    factor, abs_count = _factor_and_abs_count(element, default_factor=default_factor)
    name = (element.get("selected") or element.get("name") or default_name).strip() or default_name
    return PivotInfo(
        name=name,
        factor=factor,
        pivot_node=_first_attr(element, "pivot_node", "pivot", "pivot_host", "source_node", "source", "pivot_source"),
        pivot_role=_first_attr(element, "pivot_role", "source_role", "pivot_source_role"),
        target_node=_first_attr(element, "target_node", "target", "target_host", "destination_node", "destination", "dst", "pivot_target", "pivot_target_node"),
        target_role=_first_attr(element, "target_role", "destination_role", "dst_role", "pivot_target_role"),
        target_ports=_first_attr(element, "target_ports", "ports", "port", "dst_ports", "target_port", "pivot_ports", "pivot_target_ports"),
        target_protocols=_first_attr(element, "target_protocols", "protocols", "protocol", "proto", "target_proto", "pivot_protocols", "pivot_target_protocols"),
        exposure=(_first_attr(element, "target_exposure", "exposure", "SegmentationExposure", "pivot_exposure") or "pivot-only"),
        source_scope=(_first_attr(element, "source_scope", "pivot_scope") or "host"),
        access_provider=(_first_attr(element, "access_provider", "provider", "pivot_provider") or "random"),
        entry_ports=_first_attr(element, "entry_ports", "entry_port", "pivot_ports", "pivot_port"),
        produces=_first_attr(element, "produces", "produces_artifacts"),
        requires=_first_attr(element, "requires", "requires_artifacts"),
        abs_count=abs_count,
    )


def parse_pivoting_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[float, List[PivotInfo]]:
    density = 0.0
    items: List[PivotInfo] = []
    if not os.path.exists(xml_path):
        logger.warning("XML not found for pivoting parse: %s", xml_path)
        return density, items
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as exc:
        logger.warning("Failed to parse XML for pivoting (%s)", exc)
        return density, items

    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found for pivoting parse")
        return density, items

    section = scenario.find(".//section[@name='Pivoting']")
    if section is None:
        section = scenario.find(".//section[@name='Pivots']")
    if section is not None:
        den_raw = (section.get("density") or "").strip()
        if den_raw:
            try:
                density = max(0.0, min(1.0, float(den_raw)))
            except Exception:
                logger.warning("Invalid Pivoting density '%s'", den_raw)
                density = 0.0

        for element in section.findall("./item"):
            info = _pivot_info_from_element(element, default_name="Pivot", default_factor=1.0)
            if info.factor > 0 or info.abs_count > 0:
                items.append(info)

    segmentation_section = scenario.find(".//section[@name='Segmentation']")
    if segmentation_section is not None:
        for element in segmentation_section.findall("./item"):
            if not _truthy_attr(element, "pivot_enabled", "pivot_required", "pivot"):
                continue
            selected = (element.get("selected") or "Segmentation").strip() or "Segmentation"
            info = _pivot_info_from_element(
                element,
                default_name=f"{selected} Pivot",
                default_factor=1.0,
            )
            if info.factor > 0 or info.abs_count > 0:
                items.append(info)
        if items and density <= 0:
            density = 1.0

    logger.debug("Parsed pivoting: density=%s items=%s", density, items)
    return density, items
