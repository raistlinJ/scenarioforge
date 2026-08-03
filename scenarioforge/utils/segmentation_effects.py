"""What a segmentation rule actually does, as opposed to what it meant to do.

`segmentation_summary.json` records the planner's intent, and its fields change
meaning with the chain a rule lands on. A `subnet_block` on INPUT emits
`-s SRC -j DROP`, which never matches the `dst` the rule records. A
`protect_internal` on INPUT emits `! -s NET -j DROP` on a node that need not be
in NET at all -- it shields that one node, not the network it names.

Every consumer used to re-derive "what does this block" from those fields, and
they disagreed: pivot access read every rule as subnet-scoped and placed a
provider node in a subnet nothing was protecting; the flow checker required a
destination inside the named subnet and so missed host-enforced rules entirely;
the live-session validation skipped `protect_internal` because its name has no
"block" in it, and reported configured drops as faults.

The effect is therefore computed once, where the chain, the node and the rule
are all still in hand, and everything downstream reads it instead of guessing.
It lives in its own module because both `segmentation` and `pivot_access` need
it and the former already imports the latter.
"""

from __future__ import annotations

from typing import Dict, Optional


# The shape of an effect:
#
#   scope        'transit' (FORWARD: packets passing through) or
#                'node' (INPUT: packets arriving at the enforcing node)
#   protects     the address or network the rule shields
#   blocks_from  the address or network it shuts out
#   invert_source  blocks everything EXCEPT blocks_from (protect_internal)
#   blocks       False for rules that deny no path of their own, such as NAT and
#                CUSTOM, which still matter because of default_deny_chain
EFFECT_TRANSIT = "transit"
EFFECT_NODE = "node"


def _empty_effect(scope: str, node_id: object, chain: str) -> Dict[str, object]:
    return {
        "scope": scope,
        "enforced_by": node_id,
        "blocks": False,
        "protects": "",
        "blocks_from": "",
        "invert_source": False,
        "default_deny_chain": chain if chain in ("FORWARD", "INPUT") else "",
    }


def rule_effect(rule: Dict[str, object], *, chain: str, node: object) -> Dict[str, object]:
    """What this rule denies, in terms that do not depend on how it was chosen."""
    chain = str(chain or "").upper()
    scope = EFFECT_TRANSIT if chain == "FORWARD" else EFFECT_NODE
    node_ip = str(getattr(node, "ip4", "") or "").split("/")[0].strip()
    try:
        node_id = int(getattr(node, "node_id", None) if getattr(node, "node_id", None) is not None else rule.get("node"))
    except Exception:
        node_id = rule.get("node")

    effect = _empty_effect(scope, node_id, chain)
    rtype = str(rule.get("type") or "").strip().lower()

    if rtype == "subnet_block":
        effect.update({
            "blocks": True,
            "blocks_from": str(rule.get("src") or ""),
            # On INPUT the rule shields the node it sits on, whatever subnet the
            # planner had in mind when it picked the pair.
            "protects": str(rule.get("dst") or "") if scope == EFFECT_TRANSIT else node_ip,
        })
    elif rtype == "host_block":
        effect.update({
            "blocks": True,
            "blocks_from": str(rule.get("src") or ""),
            "protects": str(rule.get("dst") or ""),
        })
    elif rtype == "protect_internal":
        internal = str(rule.get("subnet") or "")
        effect.update({
            "blocks": True,
            "blocks_from": internal,
            "invert_source": True,
            "protects": internal if scope == EFFECT_TRANSIT else node_ip,
        })
    return effect


def effect_from_iptables(command: str, *, node_ip: str = "") -> Optional[Dict[str, object]]:
    """The effect one iptables command has, read from the command itself.

    Deliberately derived from the emitted text rather than from the planner's
    variables, so it can be checked against `rule_effect` -- an effect that
    disagrees with the rule actually written is the exact fault this whole model
    exists to prevent. Also lets a consumer recover the effect of a rule from a
    plan saved before effects were recorded.

    Returns None for a command that denies nothing.
    """
    tokens = str(command or "").split()
    if not tokens or "DROP" not in tokens:
        return None
    chain = ""
    src = ""
    dst = ""
    invert = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in ("-A", "-I") and index + 1 < len(tokens):
            chain = tokens[index + 1].upper()
            index += 2
            continue
        if token == "!" and index + 1 < len(tokens) and tokens[index + 1] == "-s":
            invert = True
            index += 1
            continue
        if token == "-s" and index + 1 < len(tokens):
            src = tokens[index + 1]
            index += 2
            continue
        if token == "-d" and index + 1 < len(tokens):
            dst = tokens[index + 1]
            index += 2
            continue
        index += 1

    if chain not in ("FORWARD", "INPUT"):
        return None
    scope = EFFECT_TRANSIT if chain == "FORWARD" else EFFECT_NODE
    return {
        "scope": scope,
        "blocks": True,
        # A rule with no `-d` on INPUT still shields exactly one thing: the node
        # running it.
        "protects": dst or (str(node_ip or "").split("/")[0] if scope == EFFECT_NODE else ""),
        "blocks_from": src,
        "invert_source": invert,
    }


