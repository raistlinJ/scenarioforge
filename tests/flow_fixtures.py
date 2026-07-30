"""Test-only helpers for seeding FlowState that production code would reject.

``_update_flow_state_in_xml`` validates before writing: the chain must be
non-empty, PlanPreview must carry the referenced topology, every vulnerability
node must appear in the chain, and generator kinds must match node kinds. That is
correct for production -- invalid FlowState should never reach disk through the
app.

It does leave negative tests without a way to build their own premise. A test
that asserts "the route ignores a saved chain containing duplicates when
duplicates are disabled" needs exactly that invalid state on disk first, and the
validated writer refuses it.

:func:`write_flow_state_unvalidated` is the escape hatch. It writes the same
``ScenarioEditor/FlagSequencing/FlowState`` element the production path writes,
with the same atomic-replace helper, and skips only the validation. Use it solely
to construct states the app is supposed to reject or ignore; use
``app_backend._update_flow_state_in_xml`` everywhere else so tests keep exercising
the real guardrails.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any

from webapp import app_backend


def _scenario_editor_for(root: ET.Element, scenario_label: str | None) -> ET.Element | None:
    """Mirror the element lookup used by app_backend._update_flow_state_in_xml."""
    scenario_norm = app_backend._normalize_scenario_label(scenario_label or '')
    if root.tag == 'ScenarioEditor':
        return root
    if root.tag == 'Scenario':
        found = root.find('ScenarioEditor')
        return found if found is not None else ET.SubElement(root, 'ScenarioEditor')
    if root.tag == 'Scenarios':
        for scen_el in root.findall('Scenario'):
            name = str(scen_el.get('name') or '').strip()
            if scenario_norm and app_backend._normalize_scenario_label(name) != scenario_norm:
                continue
            found = scen_el.find('ScenarioEditor')
            return found if found is not None else ET.SubElement(scen_el, 'ScenarioEditor')
    return None


def write_flow_state_unvalidated(
    xml_path: str,
    scenario_label: str | None,
    flow_state: dict[str, Any],
) -> None:
    """Write ``flow_state`` into the scenario XML without validating it.

    Raises AssertionError if the scenario's ScenarioEditor cannot be found, so a
    typo in ``scenario_label`` fails loudly instead of silently writing nothing.
    """
    resolved = app_backend._abs_path_or_original(xml_path)
    tree = ET.parse(resolved)
    root = tree.getroot()

    se_target = _scenario_editor_for(root, scenario_label)
    assert se_target is not None, f'ScenarioEditor not found for scenario {scenario_label!r} in {resolved}'

    fs_el = se_target.find('FlagSequencing')
    if fs_el is None:
        fs_el = ET.SubElement(se_target, 'FlagSequencing')
    for child in list(fs_el):
        if child.tag == 'FlowState':
            fs_el.remove(child)
    st_el = ET.SubElement(fs_el, 'FlowState')
    st_el.text = json.dumps(flow_state, separators=(',', ':'), ensure_ascii=False)

    app_backend._write_xml_tree_atomic(tree, resolved)


def read_flow_state(xml_path: str, scenario_label: str | None) -> dict[str, Any] | None:
    """Read back the raw FlowState element, or None when absent."""
    resolved = app_backend._abs_path_or_original(xml_path)
    root = ET.parse(resolved).getroot()
    se_target = _scenario_editor_for(root, scenario_label)
    if se_target is None:
        return None
    fs_el = se_target.find('FlagSequencing')
    if fs_el is None:
        return None
    st_el = fs_el.find('FlowState')
    if st_el is None:
        return None
    raw = str(st_el.text or '').strip()
    if not raw:
        return None
    return json.loads(raw)
