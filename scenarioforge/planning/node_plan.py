from __future__ import annotations
from typing import List, Tuple, Dict

VULNERABILITY_SLOT_ROLE = "VulnerabilitySlot"
FLAG_GEN_SLOT_ROLE = "FlagGenSlot"

# Challenge slots are declared in Node Information but reserve capacity for a
# single kind of flag-sequencing challenge.  A VulnerabilitySlot only ever
# receives a vulnerability, a FlagGenSlot only ever a flag-node-generator.
# Plain Docker hosts remain the catch-all that either kind may land on.
CHALLENGE_SLOT_ROLES = {VULNERABILITY_SLOT_ROLE, FLAG_GEN_SLOT_ROLE}

# Stable order for UI enumerations, CLI help, and error messages.  Sets are
# unordered, so anything user-visible reads from this instead.
HOST_ROLE_DISPLAY_ORDER = (
    "Server",
    "Workstation",
    "PC",
    "Docker",
    VULNERABILITY_SLOT_ROLE,
    FLAG_GEN_SLOT_ROLE,
)

ALLOWED_HOST_ROLES = set(HOST_ROLE_DISPLAY_ORDER)

# Slots are materialized as Docker-backed hosts: they run the same container
# runtime, so anything asking "can this host a container?" must accept them.
DOCKER_BACKED_ROLES = {"Docker"} | CHALLENGE_SLOT_ROLES

# Accepts the canonical spelling plus hyphen/space/underscore variants, so
# `vulnerability-slot`, `Vulnerability Slot` and `VulnerabilitySlot` all land on
# the same role instead of silently falling back to PC.
_ROLE_ALIASES = {
    'vulnerabilityslot': VULNERABILITY_SLOT_ROLE,
    'vulnslot': VULNERABILITY_SLOT_ROLE,
    'flaggenslot': FLAG_GEN_SLOT_ROLE,
    'flagnodegeneratorslot': FLAG_GEN_SLOT_ROLE,
    'flaggeneratorslot': FLAG_GEN_SLOT_ROLE,
}


def _role_alias_key(role: str) -> str:
    return ''.join(ch for ch in (role or '').lower() if ch.isalnum())


def is_docker_backed_role(role: str) -> bool:
    """True when a role runs containers (plain Docker or a challenge slot)."""
    return _normalize_role_name(role) in DOCKER_BACKED_ROLES


def challenge_slot_kind(role: str) -> str:
    """Return 'vulnerability', 'flag-node-generator', or '' for non-slot roles."""
    normalized = _normalize_role_name(role)
    if normalized == VULNERABILITY_SLOT_ROLE:
        return 'vulnerability'
    if normalized == FLAG_GEN_SLOT_ROLE:
        return 'flag-node-generator'
    return ''


def _normalize_role_name(role: str) -> str:
    rl = (role or '').strip()
    if not rl:
        return 'PC'
    if rl.lower() == 'random' or rl.lower() == 'host':
        return 'PC'
    # If already allowed (case-insensitive), standardize capitalization to canonical form
    for ar in ALLOWED_HOST_ROLES:
        if rl.lower() == ar.lower():
            return ar
    aliased = _ROLE_ALIASES.get(_role_alias_key(rl))
    if aliased:
        return aliased
    # Fallback to PC for any unknown label
    return 'PC'

def compute_node_plan(density_base: int, weight_items: List[Tuple[str, float]], count_items: List[Tuple[str, int]]) -> Tuple[Dict[str,int], dict]:
    """Allocate host counts across weight roles and add count roles.

    Enhancements:
    - Supports placeholder role name 'Random' (case-insensitive) for both weight and count rows.
      * Weight rows: aggregate all Random factors and distribute evenly across default role set.
      * Count rows: aggregate Random absolute counts and distribute evenly (largest remainder) across defaults.
    - Default role expansion list (configurable here) chosen to provide representative diversity.

    Returns (role_counts, breakdown) where breakdown includes:
      base_nodes, additive_nodes, combined_nodes, weight_rows, count_rows, weight_sum
      plus new keys: random_weight_factor, random_count_total, expanded_weight_items, expanded_defaults

    Rounding: proportional floor then distribute residual by largest fractional remainder.
    """
    import math as _math
    # Web UI enumeration (excluding 'Random'): ["Server", "Workstation", "PC", "Docker", "Random"]
    DEFAULT_RANDOM_ROLES = ["Server", "Workstation", "PC"]

    # --- Expand Random weight items ---
    norm_weight: List[Tuple[str, float]] = []
    random_weight_factor = 0.0
    for r, f in (weight_items or []):
        if r.strip().lower() == 'random':
            random_weight_factor += float(f or 0.0)
        else:
            norm_weight.append((r, float(f or 0.0)))
    if random_weight_factor > 0:
        share = random_weight_factor / len(DEFAULT_RANDOM_ROLES)
        for dr in DEFAULT_RANDOM_ROLES:
            norm_weight.append((dr, share))

    # Merge duplicate role factors (sum) to stabilize distribution ordering
    merged_weight: Dict[str, float] = {}
    for r, f in norm_weight:
        if f > 0:
            nr = _normalize_role_name(r)
            merged_weight[nr] = merged_weight.get(nr, 0.0) + f
    merged_weight_items = list(merged_weight.items())

    # --- Expand Random count items ---
    norm_count: List[Tuple[str, int]] = []
    random_count_total = 0
    for r, c in (count_items or []):
        if r.strip().lower() == 'random':
            random_count_total += int(c or 0)
        else:
            norm_count.append((_normalize_role_name(r), int(c or 0)))
    if random_count_total > 0:
        base_alloc = random_count_total // len(DEFAULT_RANDOM_ROLES)
        residual = random_count_total - base_alloc * len(DEFAULT_RANDOM_ROLES)
        for idx, dr in enumerate(DEFAULT_RANDOM_ROLES):
            alloc = base_alloc + (1 if idx < residual else 0)
            if alloc > 0:
                norm_count.append((_normalize_role_name(dr), alloc))

    weight_items = merged_weight_items
    count_items = norm_count
    base_nodes = int(density_base or 0)
    weight_sum = sum(f for _, f in weight_items) or 0.0
    role_counts: Dict[str,int] = {}
    if weight_sum > 0 and base_nodes > 0:
        provisional = []
        residual = base_nodes
        for r, f in weight_items:
            share = (f / weight_sum) * base_nodes
            alloc = int(_math.floor(share + 1e-9))
            provisional.append((r, share, alloc))
            residual -= alloc
        if residual > 0:
            frac_sorted = sorted(provisional, key=lambda x: (x[1]-x[2]), reverse=True)
            for i in range(residual):
                rname, sshare, a = frac_sorted[i % len(frac_sorted)]
                frac_sorted[i % len(frac_sorted)] = (rname, sshare, a+1)  # type: ignore
            provisional = frac_sorted
        for r, _, alloc in provisional:
            if alloc > 0:
                nr = _normalize_role_name(r)
                role_counts[nr] = role_counts.get(nr, 0) + alloc
    additive_nodes = 0
    for r, c in count_items:
        c_int = int(c)
        additive_nodes += c_int
        nr = _normalize_role_name(r)
        role_counts[nr] = role_counts.get(nr, 0) + c_int
    breakdown = {
        'base_nodes': base_nodes,
        'additive_nodes': additive_nodes,
        'combined_nodes': base_nodes + additive_nodes,
        'weight_rows': len(weight_items),
        'count_rows': len(count_items),
        'weight_sum': weight_sum,
        'random_weight_factor': random_weight_factor,
        'random_count_total': random_count_total,
        'expanded_weight_items': weight_items,
        'expanded_defaults': DEFAULT_RANDOM_ROLES,
    }
    # Final normalization pass (safety): ensure all keys are in allowed set
    normalized_final: Dict[str,int] = {}
    for r, c in role_counts.items():
        nr = _normalize_role_name(r)
        normalized_final[nr] = normalized_final.get(nr, 0) + int(c)
    breakdown['allowed_roles'] = sorted(list(ALLOWED_HOST_ROLES))
    breakdown['normalized'] = True
    return normalized_final, breakdown
