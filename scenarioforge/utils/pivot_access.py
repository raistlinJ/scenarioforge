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
4. otherwise a Docker SSH node is added.

There is deliberately no "turn SSH on for whatever Docker node is already
there" tier. Node images are built offline-safe with no package manager -- the
wrapper only injects a busybox `ip` -- so a minimal image cannot grow an `sshd`,
and enabling the CORE SSH service on it yields an open path to a closed port. A
node that genuinely serves SSH is already covered by tier 3.

**Only Docker-backed nodes are ever eligible.** CORE vnodes -- routers, PCs,
servers, workstations -- get a network namespace but not a mount namespace, so
they share the CORE VM's filesystem. Handing a participant SSH on one is a host
escape, not a pivot. That rules out the routers too, which is why a subnet whose
hosts are all unfilled challenge slots has to grow a node rather than borrow the
router that is already sitting there.

Selection deliberately skips empty challenge slots. Consuming one would silently
spend capacity the scenario author allocated for challenges, so a provider never
counts against the configured vulnerability or flag-node-generator slot counts.
Anything placed for pivot access is additive.

An added provider is a Docker node built from `PIVOT_SSH_IMAGE`, overridable
with `CORETG_PIVOT_SSH_IMAGE`. The planner records the image and the port that
image actually serves on the provider; `planning.full_preview` then allocates
the node into the topology plan, and the builder creates it from that plan.

Once a run has materialised such a node, later re-plans must recognise it
rather than add a second one. That is what `provisioned_entry_points` is for:
it reads the marker the materialiser left on the node and hands the planner an
SSH entry for it, so the provider comes back as the same added node.

This module is pure: it decides *what* should be reachable and returns the allow
rules that express it. Writing iptables and mutating the session stays in
`segmentation.py`.
"""

from __future__ import annotations

import ipaddress
import logging
import os
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

# Image for an added SSH provider. Node images are built offline-safe with no
# package manager, so a provider that must serve SSH has to come from an image
# that already does. Overridable for sites that mirror their own.
PIVOT_SSH_IMAGE = os.environ.get("CORETG_PIVOT_SSH_IMAGE", "lscr.io/linuxserver/openssh-server:latest")


def _env_port(name: str, default: int) -> int:
    try:
        value = int(str(os.environ.get(name) or "").strip())
    except Exception:
        return default
    return value if 0 < value < 65536 else default


# The port `PIVOT_SSH_IMAGE` actually listens on, which is not 22: the default
# image is a rootless sshd serving 2222. This is the port the allow rule opens
# and the port the participant connects to, so it has to follow the image. A
# site pointing `CORETG_PIVOT_SSH_IMAGE` at its own mirror sets this alongside.
PIVOT_SSH_PORT = _env_port("CORETG_PIVOT_SSH_PORT", 2222)

# Marker the materialiser leaves on a node it created, so a later plan reuses
# that node instead of adding another one for the same subnet.
PIVOT_PROVIDER_METADATA_KEY = "pivot_access_provider"

# What a provider's entry port is opened to. See `allow_rules_for_provider`.
ANY_SOURCE = "0.0.0.0/0"

# Roles that reserve challenge capacity. A provider is never taken from one of
# these unless it already hosts a challenge, so the toggle cannot quietly eat a
# slot the author meant for a vulnerability or flag-node-generator.
CHALLENGE_SLOT_ROLES = {"VulnerabilitySlot", "FlagGenSlot"}

# Rule types that isolate a segment, for a plan saved before rules carried their
# effect. Kept only as a fallback; `_effect_of` prefers the recorded effect.
#
# `host_block` is deliberately excluded. It stops one host reaching one host,
# which leaves the rest of the subnet reachable in both directions -- nothing is
# walled off, so there is no accessibility problem to solve. Provisioning a
# provider for it would also be self-defeating: the only node in a /32 is the
# blocked host itself, so the "pivot" would be an SSH allow straight back into
# the host the rule exists to block.
_BLOCK_TYPES = {"subnet_block", "protect_internal"}


@dataclass
class PivotEntry:
    """One reachable way into a provider node."""

    kind: str
    port: int
    protocol: str = "tcp"
    label: str = ""
    # True when this entry belongs to a node an earlier pivot-access plan added.
    # Reusing it is still "added", not "reused": the node exists only because of
    # this feature, and reporting it as pre-existing would hide that.
    provisioned: bool = False

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
    # Set when the provider must be built from an SSH-capable image, which the
    # topology builder materialises.
    image: str = ""
    # The provider's address inside the walled-off subnet. Empty until the node
    # exists, which is exactly when allow rules can first be written for it.
    address: str = ""

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
            "image": self.image or "",
            "address": self.address or "",
            "consumes_slot": False,
        }


@dataclass
class PivotAccessPlan:
    providers: List[PivotProvider] = field(default_factory=list)
    allow_rules: List[dict] = field(default_factory=list)
    unresolved: List[dict] = field(default_factory=list)
    # Every router the FORWARD allows have to be installed on, kept so a caller
    # that materialises a provider afterwards opens the same set of hops.
    router_ids: List[int] = field(default_factory=list)

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


def _is_docker_backed(node: NodeInfo) -> bool:
    """Only Docker-backed nodes can host a pivot.

    A CORE vnode shares the CORE VM's filesystem, so SSH on one hands the
    participant the host rather than a foothold in the scenario.
    """
    try:
        from ..planning.node_plan import is_docker_backed_role
        return bool(is_docker_backed_role(str(getattr(node, "role", "") or "")))
    except Exception:
        normalized = "".join(ch for ch in str(getattr(node, "role", "") or "").lower() if ch.isalnum())
        return normalized in {"docker", "vulnerabilityslot", "flaggenslot"}


def _is_slot_role(role: str) -> bool:
    normalized = "".join(ch for ch in str(role or "").lower() if ch.isalnum())
    return normalized in {r.lower() for r in CHALLENGE_SLOT_ROLES} or normalized in {
        "vulnerabilityslot",
        "flaggenslot",
    }


def walled_off_details(rules: Sequence[dict]) -> Dict[str, dict]:
    """Blocked destination subnets, their sources, and who enforces the block.

    Reads each rule's recorded effect rather than its fields, because the fields
    mean different things depending on the chain the rule landed on. Only a
    *transit* block walls a subnet off: an INPUT rule shields the single node
    running it, whatever subnet its `dst` or `subnet` field happens to name. A
    live run placed a provider node in `192.168.67.0/24` for a rule that
    protected one host in `192.168.12.0/24`.

    A block that protects a single address is skipped for the same reason
    `host_block` always was: the only node in a /32 is the blocked host itself,
    so the "pivot" would be an allow straight back into the thing the rule
    exists to block.

    The enforcing node ids matter: a FORWARD allow only has to be installed on
    the routers that actually carry a block for that path, not on every router
    in the topology.

    Accepts the summary shape (`{"node_id", "service", "rule"}`) as well as bare
    rule dicts, because callers hold both.
    """
    from .segmentation_effects import EFFECT_TRANSIT, effect_of

    found: Dict[str, dict] = {}

    def _slot(dst: str) -> dict:
        return found.setdefault(dst, {"sources": set(), "enforced_by": set()})

    for entry in rules or []:
        if not isinstance(entry, dict):
            continue
        rule = entry.get("rule") if isinstance(entry.get("rule"), dict) else entry
        if not isinstance(rule, dict):
            continue

        effect = effect_of(entry, rule)
        if not isinstance(effect, dict) or not effect.get("blocks"):
            continue
        if str(effect.get("scope") or "") != EFFECT_TRANSIT:
            continue

        dst = _network_of(effect.get("protects"))
        if dst is None or dst.num_addresses <= 1:
            continue

        try:
            node_id = effect.get("enforced_by", entry.get("node_id", rule.get("node")))
            enforcer = int(node_id) if node_id is not None else None
        except Exception:
            enforcer = None

        slot = _slot(str(dst))
        if effect.get("invert_source"):
            # Everything outside the protected network is shut out.
            slot["sources"].add("*")
        else:
            src = _network_of(effect.get("blocks_from"))
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
            if not _is_docker_backed(node):
                continue
            for entry in entry_points.get(int(node.node_id)) or []:
                if str(entry.kind or "").strip().lower() == kind:
                    return node, entry
    return None, None


def _pick_non_slot(inside: Sequence[NodeInfo]) -> Optional[NodeInfo]:
    """A Docker node that can take SSH without spending challenge capacity."""
    for node in inside:
        if _is_docker_backed(node) and not _is_slot_role(getattr(node, "role", "")):
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


def allow_rules_for_provider(
    provider: PivotProvider,
    *,
    router_ids: Sequence[int],
) -> List[dict]:
    """The allow rules that make one provider reachable across the boundary.

    Split out of `plan_pivot_access` because a provider whose node is created
    later -- an added one -- gets its rules once the materialiser has given it
    an address, and both paths must open exactly the same thing.

    The source is `0.0.0.0/0`, not the subnets the block took access away from.
    A provider is the subnet's entrance, and whoever has to walk through it is
    not knowable from the rule that closed the subnet: the participant sits on a
    HITL link subnet that exists in no segmentation rule at all, and what
    actually stops them is the blanket `-P FORWARD DROP` rather than any
    specific block. Scoping the allow to `blocked_from` locked the participant
    out of the one node built to let them in -- and did so only for subnets
    walled off by `subnet_block`, since `protect_internal` yields `*` and opened
    it to everyone by accident. Exactly one port on one node becomes reachable;
    the rest of the subnet stays walled off, which is the whole design.

    Returns nothing while the provider has no address or no port: there is no
    rule to write for a destination that does not exist yet, and a `--dport 0`
    would be a rule that matches nothing while looking like the path is open.
    """
    dst_ip = str(provider.address or "").split("/")[0].strip()
    port = int(provider.entry.port or 0)
    if not dst_ip or port <= 0:
        return []

    out: List[dict] = []
    # FORWARD on every router, so the packet survives the boundary; INPUT on
    # the provider itself, which is where a default-deny policy would
    # otherwise drop it.
    for router_id in router_ids:
        out.append(_allow_rule(
            router_id, ANY_SOURCE, dst_ip,
            port, provider.entry.protocol, "FORWARD",
        ))
    out.append(_allow_rule(
        provider.node_id, ANY_SOURCE, dst_ip,
        port, provider.entry.protocol, "INPUT",
    ))
    return out


def provider_node_name(subnet: str) -> str:
    """Deterministic name for a provider node added for `subnet`.

    Derived from the subnet so the same plan always yields the same name, which
    keeps the topology stable across re-previews and lets a report name the node
    before it exists.
    """
    text = str(subnet or "").split("/")[0].strip()
    slug = "".join(ch if ch.isalnum() else "-" for ch in text).strip("-") or "subnet"
    return f"pivot-{slug}"


def is_pivot_provider_host(host: object) -> bool:
    """True for a node this feature added, in either preview or object form.

    Callers use it to keep such a node out of counts that describe the scenario
    the author configured -- challenge slots and plan-parity totals -- because
    the node is additive and was never part of that configuration.
    """
    metadata = host.get("metadata") if isinstance(host, dict) else getattr(host, "metadata", None)
    return isinstance(metadata, dict) and isinstance(
        metadata.get(PIVOT_PROVIDER_METADATA_KEY), dict
    )


def provisioned_entry_points(hosts: Iterable[object]) -> Dict[int, List[PivotEntry]]:
    """Entry points for provider nodes an earlier plan already added.

    Without this, re-planning against a topology that already carries a provider
    finds nothing it recognises in the subnet and adds a *second* one. Accepts
    preview host payloads (dicts) and node objects alike, because the plan-time
    and execute-time callers hold different shapes.
    """
    out: Dict[int, List[PivotEntry]] = {}
    for host in hosts or []:
        if not is_pivot_provider_host(host):
            continue
        if isinstance(host, dict):
            node_id = host.get("node_id")
            marker = host.get("metadata", {}).get(PIVOT_PROVIDER_METADATA_KEY)
        else:
            node_id = getattr(host, "node_id", None)
            marker = getattr(host, "metadata", {}).get(PIVOT_PROVIDER_METADATA_KEY)
        try:
            key = int(node_id)
        except Exception:
            continue
        try:
            port = int(marker.get("port") or PIVOT_SSH_PORT)
        except Exception:
            port = PIVOT_SSH_PORT
        if not 0 < port < 65536:
            port = PIVOT_SSH_PORT
        out.setdefault(key, []).append(PivotEntry(
            kind=str(marker.get("kind") or ENTRY_SSH),
            port=port,
            protocol=str(marker.get("protocol") or "tcp"),
            label=str(marker.get("label") or "SSH"),
            provisioned=True,
        ))
    return out


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
    participant_subnets: Optional[Sequence[str]] = None,
) -> PivotAccessPlan:
    """Ensure every walled-off subnet has a reachable pivot provider.

    `entry_points` maps node_id to what that node already offers, so the planner
    can prefer a real challenge artifact over a plain SSH box. Callers supply
    whatever they know; an empty map simply means every subnet needs a node
    added, so callers that can resolve ports should.

    `ssh_port` is the port callers use when registering an existing SSH node in
    `entry_points`; it does not apply to an added provider, whose port follows
    the image it runs (`PIVOT_SSH_PORT`).

    `participant_subnets` are the networks a human sits on -- the HITL link
    subnets -- recorded on each provider so reports and guides name the audience
    the entrance was opened for. They are networks, never single addresses: a
    participant who re-addresses within their own subnet is still the same
    participant, and a rule pinned to one address would be defeated by a DHCP
    lease change.
    """
    plan = PivotAccessPlan()
    node_names = node_names or {}
    entry_points = {int(k): list(v or []) for k, v in (entry_points or {}).items()}
    routers = list(routers or [])
    derived_router_ids = {int(getattr(r, "node_id")) for r in routers if getattr(r, "node_id", None) is not None}
    router_id_list = sorted({int(r) for r in (router_ids or [])} | derived_router_ids)

    # Networks only. A bare address arrives as a /32, which describes the
    # audience wrongly: the participant who re-addresses inside their own subnet
    # is the same participant. Widening it would mean guessing a prefix, so a
    # single address is dropped and said out loud instead -- callers hand over
    # the HITL link networks, which are already CIDRs.
    participants: List[str] = []
    for raw in participant_subnets or []:
        net = _network_of(raw)
        if net is None:
            continue
        if net.num_addresses <= 1:
            logger.warning(
                "Pivot access: ignoring participant source %s -- a single address, "
                "not the network the participant sits on", raw,
            )
            continue
        if str(net) not in participants:
            participants.append(str(net))

    blocked = walled_off_details(rules)
    if not blocked:
        return plan

    for subnet_text, detail in blocked.items():
        # The participant has to get in too, and is in no segmentation rule, so
        # they are added to the audience rather than discovered from one.
        blocked_from = list(detail["sources"])
        subnet_net = _network_of(subnet_text)
        for participant in participants:
            if participant in blocked_from:
                continue
            # A participant already inside the walled-off subnet needs no way in.
            participant_net = _network_of(participant)
            if subnet_net is not None and participant_net is not None and participant_net.subnet_of(subnet_net):
                continue
            blocked_from.append(participant)
        # Every router on the path, not just the one carrying the block.
        #
        # Narrowing this to the enforcing router looked tidier and was wrong: a
        # live run showed the enforcer correctly passing the SYN while an
        # upstream router dropped it, because segmentation leaves every router
        # with `-P FORWARD DROP`. A packet has to survive each hop, and the
        # planner cannot know the route, so the allow goes everywhere. The
        # enforcing ids stay in `walled_off_details` for reporting.
        forward_nodes = router_id_list
        subnet = _network_of(subnet_text)
        if subnet is None:
            continue
        inside = _nodes_in(subnet, hosts)

        node, entry = _pick_existing(inside, entry_points)
        provider: Optional[PivotProvider] = None

        if node is not None and entry is not None:
            provider = PivotProvider(
                subnet=subnet_text,
                node_id=int(node.node_id),
                node_name=node_names.get(int(node.node_id), "") or f"node-{node.node_id}",
                entry=entry,
                blocked_from=list(blocked_from),
                # A node this feature added in an earlier pass stays "added":
                # calling it reused would credit the scenario with a node it
                # never asked for.
                reused=not entry.provisioned,
                added=bool(entry.provisioned),
                role=str(getattr(node, "role", "") or ""),
                image=PIVOT_SSH_IMAGE if entry.provisioned else "",
                address=_host_ip(node),
            )
        else:
            if allow_add_nodes:
                # Every node in the subnet is an unfilled challenge slot. Taking
                # one would spend capacity the author reserved, so add a node.
                provider = PivotProvider(
                    subnet=subnet_text,
                    node_id=None,
                    node_name=provider_node_name(subnet_text),
                    entry=PivotEntry(
                        kind=ENTRY_SSH, port=PIVOT_SSH_PORT, protocol="tcp",
                        label="SSH", provisioned=True,
                    ),
                    blocked_from=list(blocked_from),
                    added=True,
                    role="Docker",
                    image=PIVOT_SSH_IMAGE,
                )
            else:
                plan.unresolved.append({
                    "subnet": subnet_text,
                    "blocked_from": list(blocked_from),
                    "reason": (
                        "no eligible provider: nothing in this subnet serves a "
                        "vulnerability, flag-node-generator or SSH, and adding nodes is "
                        "disabled. Routers and other vnodes are never eligible because they "
                        "share the CORE VM filesystem, and a minimal container image cannot "
                        "grow an sshd"
                    ),
                })
                continue

        plan.providers.append(provider)

        # A provider with no address yet cannot have rules written for it. That
        # is the added case: `full_preview` allocates the node, fills in the
        # address and appends the rules through `allow_rules_for_provider`.
        plan.allow_rules.extend(allow_rules_for_provider(provider, router_ids=forward_nodes))

    plan.router_ids = list(router_id_list)
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
