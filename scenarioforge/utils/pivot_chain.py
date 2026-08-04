"""Decide whether a pivot needs its own chain step.

The "accessible by pivot" toggle (`pivot_access`) guarantees a walled-off subnet
keeps one reachable provider. This module answers the next question: does
getting through that provider count as a challenge in its own right?

The rule is capability-based, not node-based. A pivot does **not** need its own
step when the challenge already sitting on the provider hands the participant
code execution on it -- solving that challenge leaves them on the node, so
pivoting onward is a consequence of work they already did, not new work. When
the provider offers no such challenge (a bare SSH box, a router, or a challenge
that only leaks a file or a credential), crossing the boundary *is* separate
work and earns its own step.

`CodeExecution(host)` is the primary test, because the existing fact subsumption
in `vulns.metadata` already routes every RCE-shaped impact through it:

    RootShell(host) -> Shell(host) -> CodeExecution(host)
    WebRCE(app)     -> CodeExecution(host)

so `remote_code_execution`, `command_injection`, `deserialization`, `web_rce`
and `privilege_escalation` all qualify without being enumerated here, while
`auth_bypass`, `arbitrary_file_read`, `sql_injection`, `credential_disclosure`,
`information_disclosure` and friends correctly do not.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .pivot_access import ENTRY_FLAG_GEN, ENTRY_VULNERABILITY
from ..vulns.metadata import _apply_subsumption, _canonical_set, canonical_fact_key

logger = logging.getLogger(__name__)

# Holding any of these on a host means the participant can operate *from* it.
# CodeExecution(host) is what subsumption funnels every RCE impact into;
# Pivot(host) is the ontology's explicit "this host is a pivot" fact, honoured
# so an author can assert it directly.
PIVOT_GRANTING_FACTS: tuple[str, ...] = (
    "CodeExecution(host)",
    "Pivot(host)",
    # Listed explicitly rather than left to subsumption. `_SUBSUMES` maps the
    # one-argument `Shell(host)` to CodeExecution but not the two-argument
    # `Shell(host, user)`, which is equally a shell on the host. Relying on
    # subsumption alone would push a genuine RCE challenge into its own pivot
    # step. Fixing that centrally would change solver behaviour, so the
    # classification compensates here instead.
    "Shell(host, user)",
    "RootShell(host)",
    "Shell(host)",
)

_GRANTING_KEYS = frozenset(canonical_fact_key(f) for f in PIVOT_GRANTING_FACTS)

# How a pivot is represented once classified.
ABSORBED = "absorbed"      # folded into the existing challenge on the provider
OWN_STEP = "own_step"      # a separate challenge in the chain


@dataclass
class PivotStepDecision:
    """Whether one subnet's pivot is its own challenge, and why."""

    subnet: str
    provider_node: str
    disposition: str                      # ABSORBED | OWN_STEP
    reason: str
    granting_facts: List[str] = field(default_factory=list)
    provider_challenge: str = ""
    entry_kind: str = ""
    entry_port: Optional[int] = None
    # Chain index this step belongs before, for own_step pivots. -1 means the
    # chain never visits the subnet, so there is nothing to order it against.
    insert_before: int = -1

    @property
    def is_own_step(self) -> bool:
        return self.disposition == OWN_STEP

    def hint_level(self) -> str:
        """Which tier this pivot's hint belongs in.

        A pivot onto a node that already carries a challenge is discoverable:
        the participant is scanning it anyway and will find the vulnerability or
        the generator's service, so a `medium` nudge is enough.

        A bare SSH box is not discoverable in the same way. There is nothing to
        solve on it and nothing about the scenario says "this is the door" --
        without being told, a participant has no reason to try it at all. That
        earns the most explicit tier.
        """
        kind = (self.entry_kind or "").strip().lower()
        return "medium" if kind in (ENTRY_VULNERABILITY, ENTRY_FLAG_GEN) else "high"

    def hint_levels(self) -> Dict[str, List[str]]:
        """The pivot's hint, keyed by tier, in the shape the guides render.

        Only own_step pivots get one. An absorbed pivot is a consequence of a
        challenge the participant is already being hinted through, so hinting it
        separately would give away that step for free.
        """
        if self.disposition != OWN_STEP:
            return {}
        text = self.instruction()
        return {self.hint_level(): [text]} if text else {}

    def instruction(self) -> str:
        """What the participant actually has to do, for guides and chain rows."""
        if self.disposition != OWN_STEP:
            return ""
        where = f" on {self.provider_node}" if self.provider_node else ""
        port = f":{self.entry_port}" if self.entry_port else ""
        kind = (self.entry_kind or "").strip().lower()
        if kind == "ssh":
            how = f"Gain access over SSH{where}{port}"
        elif kind == "vulnerability":
            how = f"Exploit the vulnerability{where}{port}"
        elif kind == "flag-node-generator":
            how = f"Work the challenge{where}{port}"
        else:
            how = f"Gain access{where}{port}"
        return f"{how}, then pivot through it to reach {self.subnet}."

    def as_dict(self) -> dict:
        return {
            "subnet": self.subnet,
            "provider_node": self.provider_node,
            "disposition": self.disposition,
            "reason": self.reason,
            "granting_facts": list(self.granting_facts),
            "provider_challenge": self.provider_challenge,
            "entry_kind": self.entry_kind,
            "entry_port": self.entry_port,
            "insert_before": self.insert_before,
            "instruction": self.instruction(),
            "hint_level": self.hint_level(),
            "hint_levels": self.hint_levels(),
        }


def granting_facts(provides: Iterable[Any]) -> List[str]:
    """The pivot-granting facts implied by `provides`, after subsumption.

    Empty means completing this challenge does not leave the participant able to
    operate from the host.
    """
    expanded = _apply_subsumption(_canonical_set(provides or []))
    return sorted(fact for fact in expanded if canonical_fact_key(fact) in _GRANTING_KEYS)


def grants_pivot(provides: Iterable[Any]) -> bool:
    """True when a challenge providing these facts leaves the solver on the host."""
    return bool(granting_facts(provides))


def _provides_of(node: Any) -> List[Any]:
    """Every fact spelling a chain node might use to declare what it provides."""
    if not isinstance(node, dict):
        return []
    out: List[Any] = []
    for key in (
        "provides", "Provides", "provides_facts", "ProvidesFacts",
        "effective_provides", "facts_provided", "PivotProduces", "pivot_produces",
    ):
        value = node.get(key)
        if isinstance(value, str):
            out.extend(part for part in value.replace(";", ",").split(",") if part.strip())
        elif isinstance(value, (list, tuple, set)):
            out.extend(value)
    return out


def _node_identifiers(node: Any) -> set:
    """Names a chain node may be known by, lowercased for matching."""
    if not isinstance(node, dict):
        return set()
    out = set()
    for key in ("name", "node", "node_name", "hostname", "host_name",
                "docker_name", "container_name", "id", "node_id"):
        value = str(node.get(key) or "").strip()
        if value:
            out.add(value.lower())
    return out


def _challenge_label(node: Any) -> str:
    if not isinstance(node, dict):
        return ""
    for key in ("challenge", "label", "title", "vuln", "vulnerability",
                "generator", "name", "id"):
        value = str(node.get(key) or "").strip()
        if value:
            return value
    return ""


def classify_pivot(
    provider_name: str,
    subnet: str,
    chain_nodes: Sequence[dict],
    *,
    entry_kind: str = "",
    entry_port: Optional[int] = None,
    extra_provides: Optional[Iterable[Any]] = None,
) -> PivotStepDecision:
    """Decide whether this subnet's pivot needs its own chain step.

    `extra_provides` lets a caller supply facts it knows about the provider that
    are not on the chain node itself (for example a vulnerability record matched
    by node rather than by chain position).
    """
    wanted = str(provider_name or "").strip().lower()
    match: Optional[dict] = None
    for node in chain_nodes or []:
        if wanted and wanted in _node_identifiers(node):
            match = node
            break

    provides: List[Any] = list(extra_provides or [])
    if match is not None:
        provides.extend(_provides_of(match))

    facts = granting_facts(provides)
    challenge = _challenge_label(match) if match is not None else ""

    if facts:
        return PivotStepDecision(
            subnet=subnet,
            provider_node=provider_name,
            disposition=ABSORBED,
            reason=(
                f"the challenge on {provider_name} already grants "
                f"{', '.join(facts)}, so the participant is on the node once they "
                "solve it and pivoting onward is not separate work"
            ),
            granting_facts=facts,
            provider_challenge=challenge,
            entry_kind=entry_kind,
            entry_port=entry_port,
        )

    if match is None:
        why = (
            f"{provider_name} carries no chain challenge, so crossing into "
            f"{subnet} is work on its own"
        )
    else:
        why = (
            f"the challenge on {provider_name} does not grant code execution "
            f"there, so reaching {subnet} through it is separate work"
        )
    return PivotStepDecision(
        subnet=subnet,
        provider_node=provider_name,
        disposition=OWN_STEP,
        reason=why,
        granting_facts=[],
        provider_challenge=challenge,
        entry_kind=entry_kind,
        entry_port=entry_port,
    )


def classify_pivot_access(
    pivot_access: Any,
    chain_nodes: Sequence[dict],
    *,
    provides_by_node: Optional[Dict[str, Iterable[Any]]] = None,
) -> List[PivotStepDecision]:
    """Classify every provider in a `pivot_access` plan.

    Accepts the dict written into `segmentation_summary.json`.
    """
    providers = []
    if isinstance(pivot_access, dict):
        providers = pivot_access.get("providers") or []
    elif isinstance(pivot_access, list):
        providers = pivot_access

    provides_by_node = {str(k).strip().lower(): v for k, v in (provides_by_node or {}).items()}

    out: List[PivotStepDecision] = []
    for provider in providers:
        if not isinstance(provider, dict):
            continue
        name = str(provider.get("node_name") or "").strip()
        entry = provider.get("entry") if isinstance(provider.get("entry"), dict) else {}
        out.append(classify_pivot(
            name,
            str(provider.get("subnet") or ""),
            chain_nodes,
            entry_kind=str(entry.get("kind") or ""),
            entry_port=entry.get("port"),
            extra_provides=provides_by_node.get(name.lower()),
        ))
    return out
