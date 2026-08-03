"""Guarantee that segmented-off subnets stay reachable through a pivot.

Segmentation walls subnets off with `subnet_block`/`host_block`/`protect_internal`
rules under a default-deny policy. That is the point of it -- but it can leave a
subnet with no way in at all, so a participant who is meant to work their way
into it simply cannot. A real scenario observed this: `172.21.240.0/24` was
blocked from two subnets and none of its seven nodes exposed SSH, so the only
path through the boundary was one chain flow scoped to a single source IP.

The "accessible by pivot" toggle closes that gap. For every walled-off subnet it
designates a **provider**: a node inside the subnet that is reachable from the
blocked side and offers something you can pivot through -- a vulnerability, a
flag-node-generator, or SSH.

Provider selection is hybrid, preferring what already exists:

1. a node in the subnet already offering a vulnerability (the pivot becomes a
   real challenge step);
2. a node already offering a flag-node-generator;
3. a node already running SSH;
4. otherwise an existing **non-slot** host, which gets SSH enabled;
5. otherwise the subnet's own router, which gets SSH enabled;
6. otherwise a new node is added.

Step 5 matters more than it looks: a subnet whose hosts are all unfilled
challenge slots still has a router by construction, and a router is not slot
capacity. It makes the guarantee satisfiable without growing the topology in
almost every real scenario.

Step 4 deliberately skips empty challenge slots. Consuming one would silently
spend capacity the scenario author allocated for challenges, so a provider never
counts against the configured vulnerability or flag-node-generator slot counts.
Anything placed for pivot access is additive.

This module is pure: it decides *what* should be reachable and returns the allow
rules that express it. Writing iptables and mutating the session stays in
`segmentation.py`.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from ..types import NodeInfo

logger = logging.getLogger(__name__)

# What a provider can offer, best first. Order is the selection preference.
ENTRY_VULNERABILITY = "vulnerability"
ENTRY_FLAG_GEN = "flag-node-generator"
ENTRY_SSH = "ssh"

ENTRY_PREFERENCE: tuple[str, ...] = (ENTRY_VULNERABILITY, ENTRY_FLAG_GEN, ENTRY_SSH)

DEFAULT_SSH_PORT = 22

# Roles that reserve challenge capacity. A provider is never taken from one of
# these unless it already hosts a challenge, so the toggle cannot quietly eat a
# slot the author meant for a vulnerability or flag-node-generator.
CHALLENGE_SLOT_ROLES = {"VulnerabilitySlot", "FlagGenSlot"}

# Blocking rule types this module understands.
_BLOCK_TYPES = {"subnet_block", "host_block", "protect_internal"}


@dataclass
class PivotEntry:
    """One reachable way into a provider node."""

    kind: str
    port: int
    protocol: str = "tcp"
    label: str = ""

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "port": int(self.port),
            "protocol": (self.protocol or "tcp").lower(),
            "label": self.label or "",
        }


@dataclass
class PivotProvider:
    """The node chosen to make one walled-off subnet reachable."""

    subnet: str
    node_id: Optional[int]
    node_name: str
    entry: PivotEntry
    blocked_from: List[str] = field(default_factory=list)
    # How the provider was obtained, which is what the UI and reports explain.
    reused: bool = False          # already offered this entry; nothing changed
    needs_service: bool = False   # existing node, SSH must be enabled on it
    added: bool = False           # a node had to be created for this subnet
    role: str = ""

    # A provider never consumes challenge-slot capacity. Kept explicit so the
    # invariant is visible in the plan itself rather than only in this docstring.
    consumes_slot: bool = False

    def as_dict(self) -> dict:
        return {
            "subnet": self.subnet,
            "node_id": self.node_id,
            "node_name": self.node_name,
            "role": self.role,
            "entry": self.entry.as_dict(),
            "blocked_from": list(self.blocked_from),
            "reused": bool(self.reused),
            "needs_service": bool(self.needs_service),
            "added": bool(self.added),
            "consumes_slot": False,
        }


@dataclass
class PivotAccessPlan:
    providers: List[PivotProvider] = field(default_factory=list)
    allow_rules: List[dict] = field(default_factory=list)
    unresolved: List[dict] = field(default_factory=list)

    @property
    def added_nodes(self) -> List[PivotProvider]:
        return [p for p in self.providers if p.added]

    @property
    def services_to_enable(self) -> List[PivotProvider]:
        return [p for p in self.providers if p.needs_service]

    def as_dict(self) -> dict:
        return {
            "providers": [p.as_dict() for p in self.providers],
            "allow_rules": list(self.allow_rules),
            "unresolved": list(self.unresolved),
            "provider_count": len(self.providers),
            "added_node_count": len(self.added_nodes),
            "reused_count": sum(1 for p in self.providers if p.reused),
        }


def _network_of(value: str) -> Optional[ipaddress._BaseNetwork]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except Exception:
        return None


def _host_ip(node: NodeInfo) -> str:
    return str(getattr(node, "ip4", "") or "").split("/")[0].strip()


def _host_network(node: NodeInfo) -> Optional[ipaddress._BaseNetwork]:
    raw = str(getattr(node, "ip4", "") or "").strip()
    if not raw:
        return None
    if "/" not in raw:
        raw = f"{raw}/24"
    return _network_of(raw)


def _is_slot_role(role: str) -> bool:
    normalized = "".join(ch for ch in str(role or "").lower() if ch.isalnum())
    return normalized in {r.lower() for r in CHALLENGE_SLOT_ROLES} or normalized in {
        "vulnerabilityslot",
        "flaggenslot",
    }


def walled_off_details(rules: Sequence[dict]) -> Dict[str, dict]:
    """Blocked destination subnets, their sources, and who enforces the block.

    The enforcing node ids matter: a FORWARD allow only has to be installed on
    the routers that actually carry a block for that path, not on every router
    in the topology.

    Accepts the summary shape (`{"node_id", "service", "rule"}`) as well as bare
    rule dicts, because callers hold both.
    """
    found: Dict[str, dict] = {}

    def _slot(dst: str) -> dict:
        return found.setdefault(dst, {"sources": set(), "enforced_by": set()})

    for entry in rules or []:
        if not isinstance(entry, dict):
            continue
        rule = entry.get("rule") if isinstance(entry.get("rule"), dict) else entry
        if not isinstance(rule, dict):
            continue
        rtype = str(rule.get("type") or "").strip().lower()
        if rtype not in _BLOCK_TYPES:
            continue

        node_id = entry.get("node_id", rule.get("node"))
        try:
            enforcer = int(node_id) if node_id is not None else None
        except Exception:
            enforcer = None

        if rtype == "protect_internal":
            # Blocks every other subnet from reaching this one.
            dst = _network_of(rule.get("subnet"))
            if dst is None:
                continue
            slot = _slot(str(dst))
            slot["sources"].add("*")
            if enforcer is not None:
                slot["enforced_by"].add(enforcer)
            continue

        dst = _network_of(rule.get("dst"))
        src = _network_of(rule.get("src"))
        if dst is None:
            continue
        # A host_block names single addresses; the subnet is what matters for
        # deciding whether a whole segment lost its way in.
        slot = _slot(str(dst))
        slot["sources"].add(str(src) if src is not None else "*")
        if enforcer is not None:
            slot["enforced_by"].add(enforcer)

    return {
        dst: {"sources": sorted(v["sources"]), "enforced_by": sorted(v["enforced_by"])}
        for dst, v in sorted(found.items())
    }


def walled_off_subnets(rules: Sequence[dict]) -> Dict[str, List[str]]:
    """Destination subnets that segmentation blocks, and what they are blocked from."""
    return {dst: v["sources"] for dst, v in walled_off_details(rules).items()}


def _nodes_in(subnet: ipaddress._BaseNetwork, hosts: Iterable[NodeInfo]) -> List[NodeInfo]:
    inside: List[NodeInfo] = []
    for node in hosts or []:
        ip = _host_ip(node)
        if not ip:
            continue
        try:
            if ipaddress.ip_address(ip) in subnet:
                inside.append(node)
        except Exception:
            continue
    return inside


def _pick_existing(
    inside: Sequence[NodeInfo],
    entry_points: Dict[int, Sequence[PivotEntry]],
) -> tuple[Optional[NodeInfo], Optional[PivotEntry]]:
    """The best node already offering a way in, following ENTRY_PREFERENCE."""
    for kind in ENTRY_PREFERENCE:
        for node in inside:
            for entry in entry_points.get(int(node.node_id)) or []:
                if str(entry.kind or "").strip().lower() == kind:
                    return node, entry
    return None, None


def _pick_non_slot(inside: Sequence[NodeInfo]) -> Optional[NodeInfo]:
    """An existing node that can take SSH without spending challenge capacity."""
    for node in inside:
        if not _is_slot_role(getattr(node, "role", "")):
            return node
    return None


def _allow_rule(
    node_id: Optional[int],
    src: str,
    dst_ip: str,
    port: int,
    protocol: str,
    chain: str,
    service: str = "Segmentation",
) -> dict:
    return {
        "node_id": node_id,
        "service": service,
        "rule": {
            "type": "allow",
            "chain": chain,
            "proto": (protocol or "tcp").lower(),
            "port": int(port),
            "src": src,
            "dst": dst_ip,
            "reason": "pivot-access",
        },
    }


def plan_pivot_access(
    rules: Sequence[dict],
    hosts: Sequence[NodeInfo],
    *,
    node_names: Optional[Dict[int, str]] = None,
    entry_points: Optional[Dict[int, Sequence[PivotEntry]]] = None,
    routers: Optional[Sequence[NodeInfo]] = None,
    router_ids: Optional[Iterable[int]] = None,
    ssh_port: int = DEFAULT_SSH_PORT,
    allow_add_nodes: bool = True,
) -> PivotAccessPlan:
    """Ensure every walled-off subnet has a reachable pivot provider.

    `entry_points` maps node_id to what that node already offers, so the planner
    can prefer a real challenge artifact over a plain SSH box. Callers supply
    whatever they know; an empty map simply means every provider falls back to
    SSH.
    """
    plan = PivotAccessPlan()
    node_names = node_names or {}
    entry_points = {int(k): list(v or []) for k, v in (entry_points or {}).items()}
    routers = list(routers or [])
    derived_router_ids = {int(getattr(r, "node_id")) for r in routers if getattr(r, "node_id", None) is not None}
    router_id_list = sorted({int(r) for r in (router_ids or [])} | derived_router_ids)

    blocked = walled_off_details(rules)
    if not blocked:
        return plan

    for subnet_text, detail in blocked.items():
        blocked_from = detail["sources"]
        # Prefer the routers that actually enforce this block; fall back to every
        # known router when the rule did not say who carries it.
        enforcing = [n for n in detail["enforced_by"] if n in set(router_id_list)]
        forward_nodes = enforcing or router_id_list
        subnet = _network_of(subnet_text)
        if subnet is None:
            continue
        inside = _nodes_in(subnet, hosts)
        routers_inside = _nodes_in(subnet, routers)

        node, entry = _pick_existing(inside, entry_points)
        provider: Optional[PivotProvider] = None

        if node is not None and entry is not None:
            provider = PivotProvider(
                subnet=subnet_text,
                node_id=int(node.node_id),
                node_name=node_names.get(int(node.node_id), "") or f"node-{node.node_id}",
                entry=entry,
                blocked_from=list(blocked_from),
                reused=True,
                role=str(getattr(node, "role", "") or ""),
            )
        else:
            # A router in the subnet is never slot capacity, so it is a better
            # last resort than growing the topology.
            fallback = _pick_non_slot(inside) or (routers_inside[0] if routers_inside else None)
            if fallback is not None:
                provider = PivotProvider(
                    subnet=subnet_text,
                    node_id=int(fallback.node_id),
                    node_name=node_names.get(int(fallback.node_id), "") or f"node-{fallback.node_id}",
                    entry=PivotEntry(kind=ENTRY_SSH, port=int(ssh_port), protocol="tcp", label="SSH"),
                    blocked_from=list(blocked_from),
                    needs_service=True,
                    role=str(getattr(fallback, "role", "") or ""),
                )
            elif allow_add_nodes:
                # Every node in the subnet is an unfilled challenge slot. Taking
                # one would spend capacity the author reserved, so add a node.
                provider = PivotProvider(
                    subnet=subnet_text,
                    node_id=None,
                    node_name="",
                    entry=PivotEntry(kind=ENTRY_SSH, port=int(ssh_port), protocol="tcp", label="SSH"),
                    blocked_from=list(blocked_from),
                    added=True,
                    role="Server",
                )
            else:
                plan.unresolved.append({
                    "subnet": subnet_text,
                    "blocked_from": list(blocked_from),
                    "reason": (
                        "no eligible provider: every node in this subnet is an unfilled "
                        "challenge slot, no router is attached to it, and adding nodes "
                        "is disabled"
                    ),
                })
                continue

        plan.providers.append(provider)

        # A provider with no address yet cannot have rules written for it; the
        # caller allocates the node first, then re-plans.
        dst_ip = ""
        if provider.node_id is not None:
            for candidate in list(inside) + list(routers_inside):
                if int(candidate.node_id) == int(provider.node_id):
                    dst_ip = _host_ip(candidate)
                    break
        if not dst_ip:
            continue

        for src in provider.blocked_from:
            selector = "0.0.0.0/0" if src == "*" else src
            # FORWARD on every router that carries a block, so the packet
            # survives the boundary; INPUT on the provider itself, which is
            # where a default-deny policy would otherwise drop it.
            for router_id in forward_nodes:
                plan.allow_rules.append(_allow_rule(
                    router_id, selector, dst_ip,
                    provider.entry.port, provider.entry.protocol, "FORWARD",
                ))
            plan.allow_rules.append(_allow_rule(
                provider.node_id, selector, dst_ip,
                provider.entry.port, provider.entry.protocol, "INPUT",
            ))

    return plan


def entry_points_from_inventory(
    *,
    vulnerable_nodes: Optional[Dict[int, Sequence[dict]]] = None,
    flag_gen_nodes: Optional[Dict[int, Sequence[dict]]] = None,
    ssh_nodes: Optional[Iterable[int]] = None,
    ssh_port: int = DEFAULT_SSH_PORT,
) -> Dict[int, List[PivotEntry]]:
    """Build the `entry_points` map from what the planner already knows.

    Each vulnerability/flag-generator record contributes its exposed ports; a
    record with no usable port still registers the node so it can be preferred
    over a bare SSH box, using the port the caller supplies.
    """
    out: Dict[int, List[PivotEntry]] = {}

    def _add(node_id: int, kind: str, records: Sequence[dict]) -> None:
        entries: List[PivotEntry] = []
        for record in records or []:
            if not isinstance(record, dict):
                continue
            label = str(record.get("name") or record.get("label") or record.get("id") or "").strip()
            ports = record.get("ports")
            if isinstance(ports, (list, tuple)):
                for port in ports:
                    try:
                        value = int(port)
                    except Exception:
                        continue
                    if 0 < value < 65536:
                        entries.append(PivotEntry(kind=kind, port=value, protocol="tcp", label=label))
            else:
                try:
                    value = int(record.get("port"))
                except Exception:
                    value = 0
                if 0 < value < 65536:
                    entries.append(PivotEntry(kind=kind, port=value, protocol="tcp", label=label))
        if entries:
            out.setdefault(int(node_id), []).extend(entries)

    for node_id, records in (vulnerable_nodes or {}).items():
        _add(int(node_id), ENTRY_VULNERABILITY, records)
    for node_id, records in (flag_gen_nodes or {}).items():
        _add(int(node_id), ENTRY_FLAG_GEN, records)
    for node_id in ssh_nodes or []:
        out.setdefault(int(node_id), []).append(
            PivotEntry(kind=ENTRY_SSH, port=int(ssh_port), protocol="tcp", label="SSH")
        )
    return out
