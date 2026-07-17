from __future__ import annotations

"""Parse topology-selected flag-node-generators from scenario XML."""

import logging
import os
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

from .common import find_scenario

logger = logging.getLogger(__name__)


def parse_flag_node_generators_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[float, List[dict]]:
    density = 0.0
    items: List[dict] = []
    if not os.path.exists(xml_path):
        return density, items
    try:
        root = ET.parse(xml_path).getroot()
    except Exception as exc:
        logger.warning("Failed to parse XML for flag node generators (%s)", exc)
        return density, items
    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        return density, items
    section = scenario.find(".//section[@name='Flag Node Generators']")
    if section is None:
        return density, items
    try:
        density = max(0.0, min(1.0, float((section.get('density') or '0').strip() or 0)))
    except Exception:
        density = 0.0
    for element in section.findall('./item'):
        selected = (element.get('selected') or '').strip() or 'Random'
        if selected not in {'Random', 'Specific'}:
            continue
        try:
            factor = float((element.get('factor') or '0').strip() or 0)
        except Exception:
            factor = 0.0
        item: dict = {'selected': selected, 'factor': factor}
        metric = (element.get('v_metric') or '').strip()
        if metric:
            item['v_metric'] = metric
        if metric.lower() == 'count':
            try:
                item['v_count'] = max(0, int((element.get('v_count') or '0').strip() or 0))
            except Exception:
                pass
        if selected == 'Specific':
            generator_id = (element.get('g_id') or '').strip()
            generator_name = (element.get('g_name') or '').strip()
            if generator_id:
                item['g_id'] = generator_id
            if generator_name:
                item['g_name'] = generator_name
        items.append(item)
    return density, items
