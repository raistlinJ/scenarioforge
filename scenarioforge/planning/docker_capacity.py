from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Tuple

from .node_plan import compute_node_plan, _normalize_role_name
from .vulnerability_plan import VulnerabilityItem, compute_vulnerability_plan


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def extract_node_plan_inputs_from_scenario_payload(scenario_payload: Any) -> tuple[int, List[Tuple[str, float]], List[Tuple[str, int]]]:
    scenario = scenario_payload if isinstance(scenario_payload, dict) else {}
    sections = scenario.get('sections') if isinstance(scenario.get('sections'), dict) else {}
    node_section = sections.get('Node Information') if isinstance(sections.get('Node Information'), dict) else {}

    density_base = 0
    explicit_density_raw = scenario.get('density_count')
    if explicit_density_raw in (None, ''):
        for legacy_key in ('density_count', 'total_nodes', 'base_nodes'):
            if node_section.get(legacy_key) not in (None, ''):
                explicit_density_raw = node_section.get(legacy_key)
                break
    if explicit_density_raw not in (None, ''):
        density_base = max(0, _coerce_int(explicit_density_raw, 0))

    weight_items: List[Tuple[str, float]] = []
    count_items: List[Tuple[str, int]] = []
    for raw_item in (node_section.get('items') or []):
        if not isinstance(raw_item, dict):
            continue
        role = _normalize_role_name(raw_item.get('selected') or raw_item.get('role') or raw_item.get('type') or '')
        metric = str(raw_item.get('v_metric') or '').strip().lower()
        if metric == 'count':
            count = max(0, _coerce_int(raw_item.get('v_count') if raw_item.get('v_count') not in (None, '') else raw_item.get('count'), 0))
            if count > 0:
                count_items.append((role, count))
            continue
        factor = _coerce_float(raw_item.get('factor'), 0.0)
        if factor > 0:
            weight_items.append((role, factor))

    return density_base, weight_items, count_items


def vulnerability_plan_from_section(vuln_section: Any, base_host_pool: int) -> tuple[Dict[str, int], dict]:
    section = vuln_section if isinstance(vuln_section, dict) else {}
    vuln_density = _coerce_float(section.get('density'), 0.0)
    vuln_items: List[VulnerabilityItem] = []

    for raw_item in (section.get('items') or []):
        if not isinstance(raw_item, dict):
            continue
        selected = str(raw_item.get('selected') or '').strip() or 'Random'
        if selected == 'Specific':
            name = str(raw_item.get('v_name') or '').strip() or 'Specific'
        elif selected == 'Random':
            name = selected or 'Random'
        else:
            continue

        metric = str(raw_item.get('v_metric') or '').strip()
        if not metric:
            metric = 'Count' if (selected == 'Specific' and raw_item.get('v_count') not in (None, '')) else 'Weight'
        abs_count = max(0, _coerce_int(raw_item.get('v_count'), 0)) if metric.lower() == 'count' else 0
        factor = _coerce_float(raw_item.get('factor'), 0.0)
        vuln_items.append(
            VulnerabilityItem(
                name=name,
                density=vuln_density,
                abs_count=abs_count,
                kind=selected,
                factor=factor,
                metric=metric,
            )
        )

    return compute_vulnerability_plan(max(0, int(base_host_pool or 0)), vuln_density, vuln_items)


def flag_node_generator_plan_from_section(section_value: Any, base_host_pool: int) -> tuple[Dict[str, int], dict]:
    """Use the same Count/Weight semantics as vulnerabilities for node generators."""
    section = section_value if isinstance(section_value, dict) else {}
    density = _coerce_float(section.get('density'), 0.0)
    items: List[VulnerabilityItem] = []
    for raw_item in (section.get('items') or []):
        if not isinstance(raw_item, dict):
            continue
        selected = str(raw_item.get('selected') or '').strip() or 'Random'
        if selected == 'Specific':
            name = str(raw_item.get('g_id') or raw_item.get('g_name') or '').strip()
            if not name:
                continue
        elif selected == 'Random':
            name = 'Random'
        else:
            continue
        metric = str(raw_item.get('v_metric') or '').strip()
        if not metric:
            metric = 'Count' if (selected == 'Specific' and raw_item.get('v_count') not in (None, '')) else 'Weight'
        count = max(0, _coerce_int(raw_item.get('v_count'), 0)) if metric.lower() == 'count' else 0
        items.append(VulnerabilityItem(name=name, density=density, abs_count=count, kind=selected,
                                       factor=_coerce_float(raw_item.get('factor'), 0.0), metric=metric))
    return compute_vulnerability_plan(max(0, int(base_host_pool or 0)), density, items)


def ensure_role_counts_docker_capacity(role_counts: Dict[str, int], required_docker_hosts: int) -> tuple[Dict[str, int], dict]:
    current_counts: Dict[str, int] = {}
    for role, count in (role_counts or {}).items():
        normalized_role = _normalize_role_name(role)
        current_counts[normalized_role] = current_counts.get(normalized_role, 0) + max(0, _coerce_int(count, 0))

    current_docker_hosts = current_counts.get('Docker', 0)
    # Vulnerability and topology-selected node-generator hosts are additive.
    # They must never consume a Docker count explicitly requested in Node
    # Information, even when that count already exceeds the number of slots.
    shortfall = max(0, _coerce_int(required_docker_hosts, 0))
    if shortfall:
        current_counts['Docker'] = current_docker_hosts + shortfall

    return current_counts, {
        'required_docker_hosts': max(0, _coerce_int(required_docker_hosts, 0)),
        'current_docker_hosts': current_docker_hosts,
        'added_docker_hosts': shortfall,
    }


def ensure_scenario_payload_docker_capacity(scenario_payload: Any) -> tuple[Dict[str, Any], dict]:
    scenario = deepcopy(scenario_payload) if isinstance(scenario_payload, dict) else {}
    sections = scenario.get('sections') if isinstance(scenario.get('sections'), dict) else {}
    vuln_section = sections.get('Vulnerabilities') if isinstance(sections.get('Vulnerabilities'), dict) else {'items': [], 'density': 0.0}
    nodegen_section = sections.get('Flag Node Generators') if isinstance(sections.get('Flag Node Generators'), dict) else {'items': [], 'density': 0.0}

    density_base, weight_items, count_items = extract_node_plan_inputs_from_scenario_payload(scenario)
    role_counts, _node_breakdown = compute_node_plan(density_base, weight_items, count_items)
    vulnerability_plan, _vuln_breakdown = vulnerability_plan_from_section(vuln_section, density_base)
    nodegen_plan, _nodegen_breakdown = flag_node_generator_plan_from_section(nodegen_section, density_base)
    required_docker_hosts = (
        sum(max(0, _coerce_int(count, 0)) for count in (vulnerability_plan or {}).values())
        + sum(max(0, _coerce_int(count, 0)) for count in (nodegen_plan or {}).values())
    )
    _adjusted_counts, repair = ensure_role_counts_docker_capacity(role_counts, required_docker_hosts)
    # Do not rewrite Node Information to materialize additive slots.  That
    # would make normalization non-idempotent and would blur the user's base
    # Docker count with topology-required challenge nodes.  The planner applies
    # this repair when it builds the preview/runtime topology.
    return scenario, repair
