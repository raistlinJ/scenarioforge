"""What a planned node already offers a participant, for pivot selection.

`plan_pivot_access` prefers a node that already exposes a challenge over adding
a bare SSH box, but it can only do that if the caller tells it which nodes offer
what, on which port. The plan knows *names* -- "which vulnerability landed on
node 7" -- and the port lives in that vulnerability's compose file, so this
module bridges the two.

An offering whose port cannot be resolved is left out rather than guessed. The
entry port is what the firewall allow opens; opening the wrong one would leave
the subnet unreachable while the plan claimed otherwise, which is worse than
falling through to a provider that has to be added.

The catalog is read once per process. Preview building runs on every render, so
re-walking the catalog and every compose file it points at would make the toggle
noticeably expensive for a lookup whose answer does not change within a run.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Sequence

from ..utils.pivot_access import ENTRY_FLAG_GEN, ENTRY_VULNERABILITY, PivotEntry

logger = logging.getLogger(__name__)

_PORT_CACHE: Dict[str, List[int]] = {}
_CATALOG_CACHE: Optional[List[Dict[str, Any]]] = None


def _repo_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _catalog() -> List[Dict[str, Any]]:
    global _CATALOG_CACHE
    if _CATALOG_CACHE is None:
        try:
            from ..utils.vuln_process import load_vuln_catalog

            items = load_vuln_catalog(_repo_root())
            _CATALOG_CACHE = [item for item in (items or []) if isinstance(item, dict)]
        except Exception as exc:
            logger.debug("Pivot entry points: vulnerability catalog unavailable: %s", exc)
            _CATALOG_CACHE = []
    return _CATALOG_CACHE


def reset_cache() -> None:
    """Drop the cached catalog, for tests and for a reloaded catalog."""
    global _CATALOG_CACHE
    _CATALOG_CACHE = None
    _PORT_CACHE.clear()


def _catalog_record(name: str) -> Optional[Dict[str, Any]]:
    wanted = str(name or "").strip().lower()
    if not wanted:
        return None
    for item in _catalog():
        for key in ("Name", "name", "label", "id", "Path"):
            if str(item.get(key) or "").strip().lower() == wanted:
                return item
    return None


def ports_for_offering(name: str) -> List[int]:
    """TCP ports the named vulnerability or generator exposes, best effort.

    Empty when the catalog cannot answer, which keeps a guessed port out of a
    firewall rule.
    """
    label = str(name or "").strip()
    if not label:
        return []
    if label in _PORT_CACHE:
        return list(_PORT_CACHE[label])

    ports: List[int] = []
    record = _catalog_record(label)
    if isinstance(record, dict):
        try:
            from ..utils.vuln_process import extract_compose_ports

            for entry in extract_compose_ports(record, out_base="/tmp/vulns") or []:
                try:
                    value = int(entry.get("port"))
                except Exception:
                    continue
                if 0 < value < 65536 and value not in ports:
                    ports.append(value)
        except Exception as exc:
            logger.debug("Pivot entry points: no ports for %s: %s", label, exc)
            ports = []
    _PORT_CACHE[label] = list(ports)
    return list(ports)


def _names_by_node(raw: Any) -> Dict[int, List[str]]:
    out: Dict[int, List[str]] = {}
    if not isinstance(raw, dict):
        return out
    for node_id, names in raw.items():
        try:
            key = int(node_id)
        except Exception:
            continue
        values = names if isinstance(names, (list, tuple)) else [names]
        for name in values:
            text = str(name or "").strip()
            if text and text not in out.setdefault(key, []):
                out[key].append(text)
    return out


def entry_points_for_plan(
    *,
    vulnerabilities_by_node: Any = None,
    flag_generators_by_node: Any = None,
    hosts: Optional[Sequence[Any]] = None,
) -> Dict[int, List[PivotEntry]]:
    """Everything the planner should treat as an existing way into a node.

    Covers the two things a plan can already place on a node -- a vulnerability
    and a flag-node-generator -- plus any provider node an earlier pivot-access
    pass added, so re-planning reuses that node instead of adding another.
    """
    from ..utils.pivot_access import provisioned_entry_points

    out: Dict[int, List[PivotEntry]] = {}

    def _add(node_id: int, kind: str, name: str) -> None:
        for port in ports_for_offering(name):
            out.setdefault(node_id, []).append(
                PivotEntry(kind=kind, port=int(port), protocol="tcp", label=name)
            )

    for node_id, names in _names_by_node(vulnerabilities_by_node).items():
        for name in names:
            _add(node_id, ENTRY_VULNERABILITY, name)
    for node_id, names in _names_by_node(flag_generators_by_node).items():
        for name in names:
            _add(node_id, ENTRY_FLAG_GEN, name)

    for node_id, entries in provisioned_entry_points(hosts or []).items():
        out.setdefault(node_id, []).extend(entries)
    return out
