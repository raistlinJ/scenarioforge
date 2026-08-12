"""Pure, Flask-free helpers for the CORE "Check Artifacts" feature.

The Check Artifacts button on a running session runs nine ordered checks against
the live CORE session:

1. containers   - the expected containers are running on the correct nodes
2. services     - the services that should be running are running
3. ports        - the ports that should be open are open
4. injects      - inject files are present in the right location on the nodes
5. segmentation - firewall/segmentation rules are in place
6. traffic      - traffic scripts are running where they should be
7. reachability - each traffic flow reaches its destination, tested on the
                  flow's own protocol and port (never with ping, which a
                  default-deny segmentation policy legitimately drops)
8. flow pivot   - every Pivot(node) dependency in the challenge chain is
                  traversable from that source node to its target
9. pivot access - every pivot provider is reachable from the participant, so
                  the challenges behind a segmentation boundary stay solvable

Checks 1-4 are derived from the existing post-execution validator
(`_validate_session_nodes_and_injects`). Checks 5-8 are live probes executed on
the CORE VM over SSH. This module keeps the probe-script text, the
validator-summary mapping, and the result shaping side-effect-free so they can
be unit-tested without a live CORE VM. The orchestration/threading and SSH calls
live in ``app_backend``.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
from typing import Any


# Ordered (key, label) checks. The order is the progress order.
CHECK_ORDER: list[tuple[str, str]] = [
    ("containers", "Containers running on correct nodes"),
    ("services", "Services running"),
    ("ports", "Ports open"),
    ("injects", "Inject files placed"),
    ("segmentation", "Firewall/segmentation rules in place"),
    ("traffic", "Required traffic agents running"),
    ("reachability", "Required traffic reaches its destination"),
    ("flow_pivot", "Flow pivot paths traversable (source → target)"),
    ("pivot_access", "Pivot providers reachable from the participant"),
]

CHECK_KEYS = [key for key, _label in CHECK_ORDER]
CHECK_LABELS = {key: label for key, label in CHECK_ORDER}

# status vocabulary: pass | warn | fail | skip | error | pending | running
_FAILING = {"fail", "error"}


def check_plan() -> list[dict[str, Any]]:
    """Initial pending plan the UI renders before any step runs."""
    return [
        {"key": key, "label": label, "status": "pending", "summary": "", "items": []}
        for key, label in CHECK_ORDER
    ]


def _result(key: str, status: str, summary: str, items: list[Any] | None = None) -> dict[str, Any]:
    return {
        "key": key,
        "label": CHECK_LABELS.get(key, key),
        "status": status,
        "summary": summary,
        "items": items or [],
    }


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _name(value: Any) -> str:
    return str(value or "").strip()


# --------------------------------------------------------------------------- #
# Checks 1-4: map the post-execution validator summary into check results
# --------------------------------------------------------------------------- #

def _validation_unavailable(summary: dict[str, Any]) -> str:
    if not isinstance(summary, dict):
        return "validator returned no summary"
    if summary.get("validation_unavailable"):
        return _name(summary.get("error")) or "session validation unavailable"
    return ""


def containers_result(summary: dict[str, Any]) -> dict[str, Any]:
    unavailable = _validation_unavailable(summary)
    if unavailable:
        return _result("containers", "error", unavailable)
    expected = [_name(n) for n in _as_list(summary.get("expected_docker_nodes")) if _name(n)]
    missing = {_name(n) for n in _as_list(summary.get("missing_docker_nodes")) if _name(n)}
    missing_nodes = {_name(n) for n in _as_list(summary.get("missing_nodes")) if _name(n)}
    extra = [_name(n) for n in _as_list(summary.get("extra_docker_nodes")) if _name(n)]
    items: list[dict[str, Any]] = []
    for node in expected:
        node_missing = node in missing or node in missing_nodes
        items.append({
            "name": node,
            "status": "fail" if node_missing else "pass",
            "detail": "not present on the expected node" if node_missing else "present",
        })
    for node in extra:
        items.append({"name": node, "status": "warn", "detail": "unexpected container present"})
    all_missing = missing | (missing_nodes & set(expected))
    if not expected:
        return _result("containers", "skip", "No container nodes expected for this scenario.", items)
    if all_missing:
        return _result("containers", "fail",
                       f"{len(all_missing)} of {len(expected)} expected containers missing.", items)
    return _result("containers", "pass", f"All {len(expected)} expected containers present.", items)


def services_result(summary: dict[str, Any]) -> dict[str, Any]:
    unavailable = _validation_unavailable(summary)
    if unavailable:
        return _result("services", "error", unavailable)
    running = [_name(n) for n in _as_list(summary.get("docker_running")) if _name(n)]
    not_running = [_name(n) for n in _as_list(summary.get("docker_not_running")) if _name(n)]
    missing = [_name(n) for n in _as_list(summary.get("docker_missing")) if _name(n)]
    pending = [_name(n) for n in _as_list(summary.get("docker_start_pending")) if _name(n)]
    # A container in a restart loop answers "running" at every poll, so
    # running-ness alone hides it. CORE applies a docker node's address, default
    # route and traffic agent to the namespace of the container that was live at
    # execute; a restart discards all three, which then surfaces as unrelated
    # routing and traffic faults elsewhere in the checks.
    restarting: dict[str, int] = {}
    for entry in _as_list(summary.get("docker_restarting")):
        if not isinstance(entry, dict):
            continue
        node = _name(entry.get("container"))
        try:
            count = int(entry.get("restart_count"))
        except (TypeError, ValueError):
            continue
        if node and count > 0:
            restarting[node] = count

    items: list[dict[str, Any]] = []
    for node in running:
        if node in restarting:
            items.append({
                "name": node, "status": "fail",
                "detail": (f"running, but has restarted {restarting[node]} time(s): CORE applies "
                           "this node's address, default route and traffic agent at execute and "
                           "nothing reapplies them, so each restart leaves it unconfigured"),
            })
            continue
        items.append({"name": node, "status": "pass", "detail": "running"})
    for node in not_running:
        items.append({"name": node, "status": "fail", "detail": "container not running"})
    for node in missing:
        items.append({"name": node, "status": "fail", "detail": "container missing"})
    for node in pending:
        items.append({"name": node, "status": "warn", "detail": "start pending"})
    total = len(running) + len(not_running) + len(missing)
    if total == 0 and not pending:
        return _result("services", "skip", "No container services expected for this scenario.", items)
    if not_running or missing:
        return _result("services", "fail",
                       f"{len(not_running) + len(missing)} service(s) not running.", items)
    if restarting:
        names = ", ".join(sorted(restarting))
        return _result("services", "fail",
                       f"{len(restarting)} service(s) running but stuck restarting ({names}); "
                       "each restart discards the CORE network configuration applied at execute.",
                       items)
    if pending:
        return _result("services", "warn", f"{len(pending)} service(s) still starting.", items)
    return _result("services", "pass", f"All {len(running)} services running.", items)


def _segmentation_block_rules(segmentation: Any) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """(effect, rule) pairs for every rule that denies a path.

    Read from the runtime `segmentation_summary.json` so a path that segmentation
    is deliberately blocking can be recognised as configured behaviour rather
    than reported as a fault.

    Each rule's recorded effect says what it denies. Matching on the rule's own
    fields instead used to miss two whole classes: `protect_internal` never
    matched because its name has no "block" in it, and a host-enforced rule was
    read as covering the subnet it names rather than the single node running it.
    Both meant a legitimately blocked path was reported as a fault.
    """
    if not isinstance(segmentation, dict):
        return []
    rules_summary = segmentation.get("rules_summary")
    if not isinstance(rules_summary, dict):
        return []
    try:
        from scenarioforge.utils.segmentation_effects import effect_of
    except Exception:
        return []
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for entry in _as_list(rules_summary.get("rules")):
        if not isinstance(entry, dict):
            continue
        rule = entry.get("rule")
        if not isinstance(rule, dict):
            continue
        effect = effect_of(entry, rule)
        if isinstance(effect, dict) and effect.get("blocks"):
            out.append((effect, rule))
    return out


def _blocking_rule_for(src_ip: str, dst_ip: str,
                       rules: list[tuple[dict[str, Any], dict[str, Any]]]) -> dict[str, Any] | None:
    """The configured rule that explains a dropped path, if any."""
    try:
        from scenarioforge.utils.segmentation_effects import effect_blocks
    except Exception:
        return None
    for effect, rule in rules:
        if effect_blocks(effect, _name(src_ip), _name(dst_ip)):
            return rule
    return None


def _segmentation_allow_rules(segmentation: Any) -> list[dict[str, Any]]:
    """Every allow rule the run installed, from the runtime summary."""
    if not isinstance(segmentation, dict):
        return []
    rules_summary = segmentation.get("rules_summary")
    if not isinstance(rules_summary, dict):
        return []
    out: list[dict[str, Any]] = []
    for entry in _as_list(rules_summary.get("rules")):
        rule = entry.get("rule") if isinstance(entry, dict) else None
        if isinstance(rule, dict) and _name(rule.get("type")).lower() == "allow":
            out.append(rule)
    return out


def _segmentation_is_default_deny(segmentation: Any) -> bool:
    """Whether the policy closes everything it does not explicitly open.

    Under default-deny, a port that no rule opens is *meant* to be unreachable
    from anywhere the scenario did not arrange for. Without knowing that, every
    such port reads as a fault -- which for a segmented scenario is most of them.
    """
    if not isinstance(segmentation, dict):
        return False
    rules_summary = segmentation.get("rules_summary")
    if not isinstance(rules_summary, dict):
        return False
    for entry in _as_list(rules_summary.get("rules")):
        rule = entry.get("rule") if isinstance(entry, dict) else None
        if not isinstance(rule, dict):
            continue
        if rule.get("default_deny"):
            return True
        effect = rule.get("effect")
        if isinstance(effect, dict) and _name(effect.get("default_deny_chain")):
            return True
    return False


def _allow_rule_opening(src_ip: str, dst_ip: str, port: Any,
                        allow_rules: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The allow rule that was supposed to open this path, if there is one."""
    try:
        from scenarioforge.utils.segmentation_effects import allow_covers
    except Exception:
        return None
    for rule in allow_rules:
        if allow_covers(rule, _name(src_ip), _name(dst_ip), port):
            return rule
    return None


def _segmentation_runtime_rules_by_node(segmentation: Any) -> dict[str, list[str]]:
    """The live iptables lines each node ended up with, in chain order."""
    out: dict[str, list[str]] = {}
    if not isinstance(segmentation, dict):
        return out
    nodes = segmentation.get("nodes")
    if not isinstance(nodes, dict):
        return out
    for name, info in nodes.items():
        if not isinstance(info, dict):
            continue
        lines = [_name(line) for line in _as_list(info.get("rule_lines")) if _name(line)]
        if lines:
            out[_name(name)] = lines
    return out


def _parse_iptables_line(line: str) -> dict[str, Any] | None:
    """The fields of an ``iptables -S`` line that decide whether it matches."""
    tokens = _name(line).split()
    if len(tokens) < 2 or tokens[0] not in ("-A", "-I"):
        return None
    parsed: dict[str, Any] = {"chain": tokens[1], "src": "", "dst": "",
                              "proto": "", "dport": None, "target": ""}
    index = 2
    while index < len(tokens):
        token = tokens[index]
        value = tokens[index + 1] if index + 1 < len(tokens) else ""
        if token in ("-s", "--source"):
            parsed["src"] = value
        elif token in ("-d", "--destination"):
            parsed["dst"] = value
        elif token in ("-p", "--protocol"):
            parsed["proto"] = value.lower()
        elif token == "--dport":
            try:
                parsed["dport"] = int(value)
            except (TypeError, ValueError):
                parsed["dport"] = None
        elif token == "-j":
            parsed["target"] = value.upper()
        index += 2 if value and not value.startswith("-") else 1
    return parsed


def _iptables_line_matches(parsed: dict[str, Any], src_ip: str, dst_ip: str, port: Any) -> bool:
    """Whether a parsed rule would match this specific packet.

    An absent selector matches everything, which is exactly how a broad DROP
    ends up shadowing a narrow ACCEPT.
    """
    try:
        wanted_port = int(port)
    except (TypeError, ValueError):
        return False
    if parsed.get("dport") is not None and parsed["dport"] != wanted_port:
        return False
    proto = _name(parsed.get("proto"))
    if proto and proto not in ("tcp", "all"):
        return False
    for selector, address in (("src", src_ip), ("dst", dst_ip)):
        cidr = _name(parsed.get(selector))
        if not cidr or cidr in ("0.0.0.0/0", "anywhere"):
            continue
        try:
            if ipaddress.ip_address(_name(address)) not in ipaddress.ip_network(cidr, strict=False):
                return False
        except Exception:
            return False
    return True


def _shadowing_rule(allow_rule: Any, src_ip: str, dst_ip: str, port: Any,
                    node_rules: dict[str, list[str]]) -> str:
    """A DROP that matches this path before its ACCEPT does, described for a reader.

    Returns an empty string when nothing shadows the allow, including when the
    node's live rules were not captured -- an unseen chain is not evidence of a
    problem.
    """
    if not isinstance(allow_rule, dict):
        return ""
    node_name = _name(allow_rule.get("node_name"))
    chain = _name(allow_rule.get("chain")).upper()
    lines = node_rules.get(node_name) or []
    if not lines:
        return ""
    for line in lines:
        parsed = _parse_iptables_line(line)
        if not parsed or (chain and parsed["chain"].upper() != chain):
            continue
        if not _iptables_line_matches(parsed, src_ip, dst_ip, port):
            continue
        target = parsed.get("target")
        if target == "ACCEPT":
            return ""
        if target in ("DROP", "REJECT"):
            return f"'{_name(line)}' on {node_name}"
    return ""


def _blocking_rule_detail(rule: dict[str, Any]) -> str:
    """How a rule is described when it explains a dropped path."""
    effect = rule.get("effect") if isinstance(rule.get("effect"), dict) else {}
    protects = _name(effect.get("protects")) or _name(rule.get("dst")) or _name(rule.get("subnet"))
    blocks_from = _name(effect.get("blocks_from")) or _name(rule.get("src"))
    kind = _name(rule.get("type")) or "segmentation"
    if effect.get("invert_source") and blocks_from:
        source = f"everything outside {blocks_from}"
    else:
        source = blocks_from or "any source"
    where = " on this node" if _name(effect.get("scope")) == "node" else ""
    return f"{kind}: {source} to {protects or 'it'}{where}"


def ports_result(summary: dict[str, Any], probe: Any = None, segmentation: Any = None) -> dict[str, Any]:
    unavailable = _validation_unavailable(summary)
    if unavailable:
        return _result("ports", "error", unavailable)
    checked = _as_list(summary.get("ports_checked"))
    unreachable = _as_list(summary.get("port_unreachable"))
    topo_unreachable = _as_list(summary.get("topology_port_unreachable"))
    details = _as_list(summary.get("port_unreachable_details"))
    items: list[dict[str, Any]] = []

    # Validator published-port results (host-mapped ports; rare in VM mode).
    for entry in details:
        if isinstance(entry, dict):
            node = _name(entry.get("container") or entry.get("node") or entry.get("name"))
            ports = entry.get("ports")
            items.append({"name": node or "?", "status": "fail",
                          "detail": f"unreachable ports: {ports}" if ports else "port(s) unreachable"})
        else:
            items.append({"name": _name(entry), "status": "fail", "detail": "port unreachable"})
    for node in topo_unreachable:
        items.append({"name": _name(node), "status": "fail",
                      "detail": "unreachable across the CORE network (cross-node probe)"})

    # CORE-network port reachability probe: each node's listening service ports
    # are connected to over the emulated network from a node that should reach
    # them (the traffic source for that target where one exists, a same-subnet
    # peer otherwise). This is the meaningful port signal in VM mode, where nodes
    # publish no host ports.
    probe_ok = isinstance(probe, dict) and probe.get("ok")
    net_checks = _as_list(probe.get("checks")) if probe_ok else []
    net_listening = 0
    net_unreachable: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []       # dropped packets with no rule to explain them
    segmented: list[dict[str, Any]] = []     # dropped packets a segmentation rule explains
    by_policy: list[dict[str, Any]] = []     # dropped because nothing opens the path
    transient: list[dict[str, Any]] = []     # refused: port closed since enumeration
    block_rules = _segmentation_block_rules(segmentation)
    allow_rules = _segmentation_allow_rules(segmentation)
    default_deny = _segmentation_is_default_deny(segmentation)
    prober_ip = ""
    if probe_ok:
        nodes = probe.get("nodes") if isinstance(probe.get("nodes"), dict) else {}
        for node, info in sorted(nodes.items()):
            if not isinstance(info, dict):
                continue
            listening = _as_list(info.get("listening"))
            loopback = _as_list(info.get("loopback"))
            net_listening += len(listening)
            if listening:
                # Loopback-only binds (e.g. Tomcat's AJP on 127.0.0.1) are noted
                # but never probed: they are not network-exposed by design.
                loop_note = (f" (plus {', '.join(str(p) for p in loopback)} bound to localhost only)"
                             if loopback else "")
                items.append({"name": f"{node} ({info.get('ip') or 'no ip'})", "status": "pass",
                              "detail": f"listening on {', '.join(str(p) for p in listening)}{loop_note}"})
        default_prober = _name(probe.get("prober"))
        default_info = nodes.get(default_prober) if isinstance(nodes, dict) else None
        prober_ip = _name(default_info.get("ip")) if isinstance(default_info, dict) else ""
        for row in net_checks:
            if not isinstance(row, dict) or row.get("reachable") is not False:
                continue
            error = _name(row.get("error"))
            # Each target is probed from its own vantage point, so the source is
            # read off the row rather than assumed to be one global prober.
            src = _name(row.get("src")) or default_prober
            src_ip = _name(row.get("src_ip")) or prober_ip
            via = _name(row.get("via"))
            via_note = f" [probed from its {via}]" if via else ""
            label = f"{src} → {row.get('node')}:{row.get('port')} ({row.get('ip')})"
            repro = (f" Reproduce: sudo docker exec {src} python3 -c "
                     f"\"import socket; socket.create_connection(('{row.get('ip')}', {row.get('port')}), 2)\"")
            # A timeout / no-route means packets are dropped — the real signal of
            # a blocked path (segmentation/routing). "refused" means the port is
            # closed now: it was listening when we enumerated but has since closed
            # (short-lived AJP/JMX/ephemeral ports), which is a benign timing race,
            # not a reachability failure.
            if error in ("timeout", "no-route"):
                # A drop that a configured segmentation rule explains is the
                # scenario working as designed, not a fault to investigate.
                rule = _blocking_rule_for(src_ip, _name(row.get("ip")), block_rules)
                if rule is not None:
                    segmented.append(row)
                    items.append({
                        "name": label,
                        "status": "pass",
                        "detail": (f"blocked as configured by segmentation "
                                   f"({_blocking_rule_detail(rule)})"),
                    })
                    continue
                # A path the scenario arranged for is a different matter: an
                # allow was installed and the packets were dropped anyway, which
                # is the one shape here worth investigating.
                opened = _allow_rule_opening(src_ip, _name(row.get("ip")), row.get("port"), allow_rules)
                if opened is not None:
                    blocked.append(row)
                    items.append({
                        "name": label,
                        "status": "warn",
                        "detail": (f"packets dropped ({error}) even though an allow rule opens this "
                                   f"path ({opened.get('chain')} {opened.get('src')} -> "
                                   f"{opened.get('dst')}:{opened.get('port')})." + via_note + repro),
                    })
                    continue
                if default_deny:
                    by_policy.append(row)
                    items.append({
                        "name": label,
                        "status": "pass",
                        "detail": ("closed by the default-deny segmentation policy: no rule opens "
                                   "this path, and nothing in the scenario asks for it to be open."
                                   + via_note),
                    })
                    continue
                blocked.append(row)
                items.append({
                    "name": label,
                    "status": "warn",
                    "detail": (f"packets dropped ({error}) and no segmentation rule covers this path."
                               + via_note + repro),
                })
            else:
                transient.append(row)
                items.append({
                    "name": label,
                    "status": "skip",
                    "detail": ("connection refused — the port closed between enumeration and probe "
                               "(short-lived service port), not a reachability failure." + repro),
                })

    net_unreachable = blocked + segmented + by_policy + transient
    published_bad = len(unreachable) + len(topo_unreachable)
    probed = len(net_checks)
    reachable_ok = probed - len(net_unreachable)
    have_any = bool(checked or unreachable or topo_unreachable or net_listening)
    if not have_any:
        return _result("ports", "skip", "No open service ports found to check.", items)
    if published_bad:
        return _result("ports", "fail", f"{published_bad} published port target(s) unreachable.", items)
    node_count = sum(1 for v in (probe.get("nodes") or {}).values() if isinstance(v, dict) and v.get("listening"))
    total_ok = len(checked) + reachable_ok
    notes = []
    from_traffic = sum(1 for r in net_checks
                       if isinstance(r, dict) and _name(r.get("via")) == "traffic source")
    if from_traffic:
        notes.append(f"{from_traffic} probed from their traffic source")
    if segmented:
        notes.append(f"{len(segmented)} blocked as configured by segmentation")
    if by_policy:
        notes.append(f"{len(by_policy)} closed by the default-deny policy")
    if transient:
        notes.append(f"{len(transient)} short-lived port(s) closed during probe")
    tail = f" ({'; '.join(notes)}.)" if notes else ""
    # The warning carries the same tail: a reader deciding whether one dropped
    # path matters needs to know how much of the run was closed on purpose.
    if blocked:
        return _result("ports", "warn",
                       f"{reachable_ok} of {probed} probed service port(s) reachable across the CORE "
                       f"network; {len(blocked)} blocked (dropped packets that no segmentation rule "
                       f"or policy explains).{tail}", items)
    return _result("ports", "pass",
                   f"All {total_ok} stable service port target(s) reachable "
                   f"({net_listening} listening across {node_count} node(s)).{tail}",
                   items)


def injects_result(summary: dict[str, Any]) -> dict[str, Any]:
    unavailable = _validation_unavailable(summary)
    if unavailable:
        return _result("injects", "error", unavailable)
    missing = [_name(n) for n in _as_list(summary.get("injects_missing")) if _name(n)]
    unreadable = [_name(n) for n in _as_list(summary.get("injects_unreadable")) if _name(n)]
    gen_missing = [_name(n) for n in _as_list(summary.get("generator_injects_missing")) if _name(n)]
    expected_by_node = summary.get("inject_files_expected_by_node")
    expected_count = 0
    if isinstance(expected_by_node, dict):
        for paths in expected_by_node.values():
            expected_count += len(_as_list(paths))
    items: list[dict[str, Any]] = []
    for path in missing + gen_missing:
        items.append({"name": path, "status": "fail", "detail": "missing on node"})
    for path in unreadable:
        items.append({"name": path, "status": "warn", "detail": "present but not readable"})
    if expected_count == 0 and not missing and not gen_missing and not unreadable:
        return _result("injects", "skip", "No inject files expected for this scenario.", items)
    if missing or gen_missing:
        return _result("injects", "fail",
                       f"{len(missing) + len(gen_missing)} inject file(s) missing.", items)
    if unreadable:
        return _result("injects", "warn", f"{len(unreadable)} inject file(s) unreadable.", items)
    return _result("injects", "pass", f"All {expected_count} expected inject file(s) placed.", items)


# --------------------------------------------------------------------------- #
# "Expected" flags from the scenario XML (segmentation / traffic sections)
# --------------------------------------------------------------------------- #

def _section_is_active(root: Any, section_name: str) -> bool:
    """A section counts as active when it exists and either declares a positive
    density or carries at least one selected item row."""
    if root is None:
        return False
    try:
        for section in root.iter("section"):
            if _name(section.get("name")).lower() != section_name.lower():
                continue
            density_raw = _name(section.get("density"))
            try:
                if density_raw and float(density_raw) > 0:
                    return True
            except ValueError:
                pass
            for item in list(section):
                if _name(item.get("selected")):
                    return True
        return False
    except Exception:
        return False


def segmentation_expected(root: Any) -> bool:
    return _section_is_active(root, "Segmentation")


def traffic_expected(root: Any) -> bool:
    return _section_is_active(root, "Traffic")


# --------------------------------------------------------------------------- #
# Checks 5-6: live probe scripts (run on the CORE VM) + result shaping
# --------------------------------------------------------------------------- #

def _remote_preamble(sudo_password: str | None, session_id: Any = None) -> str:
    """Shared CORE-VM-side helper code.

    Provides a sudo-with-fallback runner and a unified node executor that shells
    into Docker-backed nodes with ``docker exec`` and into namespaced CORE
    vnodes (routers/PCs) with ``vcmd -c /tmp/pycore.<sid>/<node>``.
    """
    sudo_password_literal = json.dumps(str(sudo_password) if sudo_password else "")
    session_literal = json.dumps(str(session_id) if session_id not in (None, "") else "")
    return (
        "import json, subprocess, glob, os, stat, sys\n"
        f"SUDO_PASSWORD = {sudo_password_literal}\n"
        f"SESSION_ID = {session_literal}\n"
        "PYCORE = ('/tmp/pycore.' + SESSION_ID) if SESSION_ID else ''\n"
        "def _run(cmd, timeout=25):\n"
        "    try:\n"
        "        p = subprocess.run(['sudo','-n']+list(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)\n"
        "        if p.returncode == 0 or not SUDO_PASSWORD:\n"
        "            return p.returncode, str(p.stdout or '')\n"
        "        p = subprocess.run(['sudo','-S','-k','-p','']+list(cmd), input=SUDO_PASSWORD+'\\n', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)\n"
        "        return p.returncode, str(p.stdout or '')\n"
        "    except Exception as e:\n"
        "        return 127, str(e)\n"
        "def _read_json(path):\n"
        "    rc, out = _run(['cat', path])\n"
        "    if rc != 0 or not out.strip():\n"
        "        return None\n"
        "    try:\n"
        "        return json.loads(out)\n"
        "    except Exception:\n"
        "        return None\n"
        # /tmp/traffic and /tmp/segmentation are shared across runs: only the
        # summary/verification JSON is rewritten each execute, while generated
        # .py scripts persist. Treat that JSON's mtime as the run boundary and
        # ignore scripts older than it, so a previous scenario's leftovers are
        # not reported as this scenario's runtime state.
        "STALE_GRACE_S = 300.0\n"
        "def _mtime(path):\n"
        "    try:\n"
        "        return os.path.getmtime(path)\n"
        "    except Exception:\n"
        "        return None\n"
        "def _fresh(paths, ref):\n"
        "    if ref is None:\n"
        "        return list(paths), 0\n"
        "    keep, stale = [], 0\n"
        "    for p in paths:\n"
        "        m = _mtime(p)\n"
        "        if m is None or m >= (ref - STALE_GRACE_S):\n"
        "            keep.append(p)\n"
        "        else:\n"
        "            stale += 1\n"
        "    return keep, stale\n"
        "def _containers():\n"
        "    rc, out = _run(['docker','ps','--format','{{.Names}}'])\n"
        "    if rc != 0:\n"
        "        return []\n"
        "    nested_prefix = ('core-' + SESSION_ID + '-') if SESSION_ID else ''\n"
        "    return [l.strip() for l in out.splitlines()\n"
        "            if l.strip() and 'inject_copy' not in l\n"
        "            and not (nested_prefix and l.strip().startswith(nested_prefix))]\n"
        "def _vnodes():\n"
        "    if not PYCORE or not os.path.isdir(PYCORE):\n"
        "        return []\n"
        "    out = []\n"
        "    for n in sorted(os.listdir(PYCORE)):\n"
        "        try:\n"
        "            if stat.S_ISSOCK(os.stat(os.path.join(PYCORE, n)).st_mode):\n"
        "                out.append(n)\n"
        "        except Exception:\n"
        "            pass\n"
        "    return out\n"
        "def _all_nodes():\n"
        "    return [('docker', n) for n in _containers()] + [('vnode', n) for n in _vnodes()]\n"
        "def _nexec(kind, name, argv, timeout=25):\n"
        "    if kind == 'docker':\n"
        "        return _run(['docker','exec',name]+list(argv), timeout=timeout)\n"
        "    return _run(['vcmd','-c',os.path.join(PYCORE, name),'--']+list(argv), timeout=timeout)\n"
        "def _nexec_python(kind, name, program, timeout=25):\n"
        "    # Challenge images are intentionally minimal and may omit Python.\n"
        "    # Enter only their network namespace and run the CORE VM interpreter,\n"
        "    # so connectivity probes never depend on workload packages.\n"
        "    if kind == 'docker':\n"
        "        rc, pid = _run(['docker','inspect','-f','{{.State.Pid}}',name])\n"
        "        pid = pid.strip()\n"
        "        if rc != 0 or not pid.isdigit() or int(pid) <= 0:\n"
        "            return 127, 'docker network namespace unavailable'\n"
        "        return _run(['nsenter','-t',pid,'-n',sys.executable,'-c',program], timeout=timeout)\n"
        "    return _nexec(kind, name, [sys.executable,'-c',program], timeout=timeout)\n"
        # Interface names Docker gives its own bridges. A CORE-assigned
        # interface is eth0..ethN, so excluding these cannot hide one.
        "def _is_own_bridge(ifname):\n"
        "    n = str(ifname or '').strip().rstrip(':')\n"
        "    return n.startswith('docker') or n.startswith('br-') or n.startswith('virbr')\n"
        "def _node_cidrs(kind, name):\n"
        "    def _cidrs(output):\n"
        "        return [line.strip() for line in output.splitlines()\n"
        "                if '/' in line.strip() and line.strip().split('/', 1)[0].count('.') == 3]\n"
        # A workload can own interfaces of its own. `docker/unauthorized-rce`
        # runs a Docker daemon, whose docker0 bridge carries a global
        # 172.17.0.1/16 alongside the address CORE assigned. Taking the first
        # address then identified the node by its private bridge, and every
        # probe of it was reported as "packets dropped (no-route)" because
        # nothing else on the CORE network can reach that address.
        "    skip_if = \"$2 !~ /^(docker[0-9]+|br-|virbr)/\"\n"
        "    rc, out = _nexec(kind, name, ['sh','-lc',\"ip -4 -o addr show scope global 2>/dev/null | awk '\" + skip_if + \" {print $4}'\"])\n"
        "    cidrs = _cidrs(out) if rc == 0 else []\n"
        "    # Minimal workload images may omit iproute2. Inspect the container's\n"
        "    # network namespace from the CORE VM instead of losing its identity.\n"
        "    if not cidrs and kind == 'docker':\n"
        "        rc, pid = _run(['docker','inspect','-f','{{.State.Pid}}',name])\n"
        "        pid = pid.strip()\n"
        "        if rc == 0 and pid.isdigit() and int(pid) > 0:\n"
        "            rc, out = _run(['nsenter','-t',pid,'-n','ip','-4','-o','addr','show','scope','global'])\n"
        "            if rc == 0:\n"
        "                cidrs = _cidrs('\\n'.join(\n"
        "                    (line.split()[3] if len(line.split()) > 3 else '')\n"
        "                    for line in out.splitlines()\n"
        "                    if len(line.split()) > 1 and not _is_own_bridge(line.split()[1])))\n"
        # `scope global` is the right filter for a CORE address, but an address
        # carrying some other scope is still an address the node can route from.
        # Ask again without the filter rather than reporting the node as having
        # none at all, which is a very different diagnosis.
        "    if not cidrs:\n"
        "        rc, out = _nexec(kind, name, ['sh','-lc',\n"
        "                         \"ip -4 -o addr show 2>/dev/null | awk '\" + skip_if + \" {print $4}'\"])\n"
        "        cidrs = [c for c in (_cidrs(out) if rc == 0 else [])\n"
        "                 if not c.startswith('127.')]\n"
        "    if not cidrs:\n"
        "        return []\n"
        "    return list(dict.fromkeys(cidrs))\n"
        "def _node_addr(kind, name):\n"
        "    cidrs = _node_cidrs(kind, name)\n"
        "    if not cidrs:\n"
        "        return '', ''\n"
        "    return cidrs[0].split('/', 1)[0], cidrs[0]\n"
        # An empty address list has three causes that need different fixes: the
        # node has no interface at all (it was created but never linked into the
        # topology), it has an interface that was never addressed (or lost its
        # address), or the question could not be asked. Reporting them as one
        # state sends the reader after the wrong bug.
        "def _node_links(kind, name):\n"
        "    rc, out = _nexec(kind, name, ['sh','-lc',\n"
        "                     \"ip -o link show 2>/dev/null | awk -F': ' '{print $2}'\"])\n"
        "    names = [l.strip().split('@', 1)[0] for l in str(out or '').splitlines() if l.strip()]\n"
        "    if rc != 0 and not names and kind == 'docker':\n"
        "        rc2, pid = _run(['docker','inspect','-f','{{.State.Pid}}',name])\n"
        "        pid = pid.strip()\n"
        "        if rc2 == 0 and pid.isdigit() and int(pid) > 0:\n"
        "            rc, out = _run(['nsenter','-t',pid,'-n','ip','-o','link','show'])\n"
        "            names = [l.split(':')[1].strip().split('@', 1)[0]\n"
        "                     for l in str(out or '').splitlines() if l.count(':') >= 2]\n"
        "    if rc != 0 and not names:\n"
        "        return {'queried': False, 'links': []}\n"
        "    return {'queried': True,\n"
        "            'links': [n for n in dict.fromkeys(names) if n and n != 'lo']}\n"
    )


def ports_probe_script(sudo_password: str | None = None, session_id: Any = None,
                       max_ports_per_node: int = 12, max_targets: int = 80,
                       traffic_dirs: list[str] | None = None) -> str:
    """VM-side script: discover each node's listening (non-loopback) TCP service
    ports from ``/proc/net/tcp``, then test each one from a node that is
    *supposed* to reach it.

    Probing everything from one arbitrary node measures that node's vantage
    point, not whether the services work: a node on the wrong side of a
    segmentation boundary reports healthy services as unreachable. So each
    target picks its own prober, in order of preference:

    1. the source of a configured traffic flow to that target -- the path the
       scenario actually exercises;
    2. a peer on the target's own subnet, which should reach it whenever the
       service is really listening;
    3. any other node, when the target is alone on its subnet.

    Uses python3, which is present on every node (Docker and vnode).
    """
    # Loopback-bound ports are not network-exposed services, so they must not be
    # treated as ports that "should be open" from another node. /proc stores the
    # IPv4 address little-endian, so 127.x.x.x ends with '7F'; Java/Tomcat style
    # localhost binds also appear in tcp6 as IPv4-mapped (::ffff:127.0.0.1).
    listen_py = (
        "import json\n"
        "def _loop(a, fam):\n"
        "    a=a.upper()\n"
        "    if fam==4: return a.endswith('7F')\n"
        "    if a=='00000000000000000000000001000000': return True\n"
        "    if a.startswith('0000000000000000FFFF0000'): return a.endswith('7F')\n"
        "    return False\n"
        "pub=set(); loop=set()\n"
        "for path,fam in (('/proc/net/tcp',4),('/proc/net/tcp6',6)):\n"
        "    try:\n"
        "        f=open(path); f.readline()\n"
        "        for line in f:\n"
        "            p=line.split()\n"
        "            if len(p)<4 or p[3]!='0A': continue\n"
        "            addr,port=p[1].rsplit(':',1)\n"
        "            (loop if _loop(addr,fam) else pub).add(int(port,16))\n"
        "        f.close()\n"
        "    except Exception: pass\n"
        "loop -= pub\n"
        f"print(json.dumps({{'listening': sorted(pub)[:{int(max_ports_per_node)}], 'loopback': sorted(loop)}}))\n"
    )
    listen_literal = json.dumps(listen_py)
    dirs_literal = json.dumps(traffic_dirs or ["/tmp/traffic"])
    return (
        _remote_preamble(sudo_password, session_id)
        + "import ipaddress\n"
        + f"LISTEN_PY = {listen_literal}\n"
        + f"MAX_TARGETS = {int(max_targets)}\n"
        + f"TRAFFIC_DIRS = {dirs_literal}\n"
        + "def _addr(kind, name):\n"
        + "    return _node_addr(kind, name)\n"
        + "def _net(cidr):\n"
        + "    try:\n"
        + "        return str(ipaddress.ip_network(cidr, strict=False))\n"
        + "    except Exception:\n"
        + "        return ''\n"
        + "def _listening(kind, name):\n"
        + "    rc, out = _nexec_python(kind, name, LISTEN_PY)\n"
        + "    try:\n"
        + "        d = json.loads(out.strip().splitlines()[-1])\n"
        + "        return [int(x) for x in d.get('listening') or []], [int(x) for x in d.get('loopback') or []]\n"
        + "    except Exception:\n"
        + "        return [], []\n"
        + "def _traffic_flows():\n"
        + "    for d in TRAFFIC_DIRS:\n"
        + "        for path in glob.glob(d):\n"
        + "            if not os.path.isdir(path):\n"
        + "                continue\n"
        + "            for f in os.listdir(path):\n"
        + "                if f.endswith('.json') and 'summary' in f.lower():\n"
        + "                    data = _read_json(os.path.join(path, f)) or {}\n"
        + "                    return [x for x in (data.get('flows') or []) if isinstance(x, dict)]\n"
        + "    return []\n"
        + "def main():\n"
        + "    alln = _all_nodes()\n"
        + "    nodes = {}\n"
        + "    for kind, name in alln:\n"
        + "        pub, loop = _listening(kind, name)\n"
        + "        ip, cidr = _addr(kind, name)\n"
        + "        nodes[name] = {'kind': kind, 'ip': ip, 'cidr': cidr, 'net': _net(cidr),\n"
        + "                       'listening': pub, 'loopback': loop}\n"
        + "    by_ip = {}\n"
        + "    for kind, name in alln:\n"
        + "        ip = nodes.get(name, {}).get('ip') or ''\n"
        + "        if ip and ip not in by_ip:\n"
        + "            by_ip[ip] = name\n"
        + "    # (destination, port) -> the source of the flow that uses THAT port.\n"
        + "    # Keyed by port because a node commonly receives several flows from\n"
        + "    # different senders: the allow rules are per flow, so the source of one\n"
        + "    # flow is the wrong vantage point for another flow's port, and for a\n"
        + "    # service port that is no flow's at all.\n"
        + "    flow_src = {}\n"
        + "    for flow in _traffic_flows():\n"
        + "        if str(flow.get('protocol') or '').strip().upper() != 'TCP':\n"
        + "            continue\n"
        + "        s_ip = str(flow.get('src_ip') or '').strip()\n"
        + "        d_ip = str(flow.get('dst_ip') or '').strip()\n"
        + "        try:\n"
        + "            d_port = int(flow.get('dst_port'))\n"
        + "        except Exception:\n"
        + "            continue\n"
        + "        if s_ip and d_ip and (d_ip, d_port) not in flow_src:\n"
        + "            flow_src[(d_ip, d_port)] = s_ip\n"
        + "    def _prober_for(tname, tip, tport):\n"
        + "        s_ip = flow_src.get((tip, int(tport)))\n"
        + "        cand = by_ip.get(s_ip) if s_ip else None\n"
        + "        if cand and cand != tname:\n"
        + "            return cand, 'traffic source'\n"
        + "        # No flow uses this port, so the meaningful question is whether the\n"
        + "        # service answers at all -- which a peer on its own subnet can ask\n"
        + "        # without crossing a segmentation boundary.\n"
        + "        tnet = nodes.get(tname, {}).get('net') or ''\n"
        + "        if tnet:\n"
        + "            for kind, name in alln:\n"
        + "                if name != tname and (nodes.get(name, {}).get('net') or '') == tnet:\n"
        + "                    return name, 'same-subnet peer'\n"
        + "        for kind, name in alln:\n"
        + "            if name != tname and (nodes.get(name, {}).get('ip') or ''):\n"
        + "                return name, 'other subnet (no local peer)'\n"
        + "        return None, ''\n"
        + "    # Group the targets by the node that will probe them, so each\n"
        + "    # prober is entered once no matter how many ports it covers.\n"
        + "    plan = {}\n"
        + "    total = 0\n"
        + "    for kind, name in alln:\n"
        + "        info = nodes.get(name, {})\n"
        + "        ip = info.get('ip') or ''\n"
        + "        if not ip:\n"
        + "            continue\n"
        + "        for port in info.get('listening', []):\n"
        + "            if total >= MAX_TARGETS:\n"
        + "                break\n"
        + "            pname, why = _prober_for(name, ip, port)\n"
        + "            if not pname:\n"
        + "                continue\n"
        + "            plan.setdefault(pname, []).append([name, ip, port, why])\n"
        + "            total += 1\n"
        + "        if total >= MAX_TARGETS:\n"
        + "            break\n"
        + "    kind_of = dict((name, kind) for kind, name in alln)\n"
        + "    checks = []\n"
        + "    for pname, targets in plan.items():\n"
        + "        conn = 'import json,socket,errno\\nR=[]\\nfor n,ip,port,why in ' + json.dumps(targets) + ':\\n'\n"
        + "        conn += ' try:\\n  s=socket.create_connection((ip,int(port)),timeout=2.0); s.close(); R.append([n,ip,port,why,True,\"\"])\\n'\n"
        + "        conn += ' except socket.timeout:\\n  R.append([n,ip,port,why,False,\"timeout\"])\\n'\n"
        + "        conn += ' except OSError as e:\\n'\n"
        + "        conn += '  c=getattr(e,\"errno\",None)\\n'\n"
        + "        conn += '  R.append([n,ip,port,why,False,\"refused\" if c==errno.ECONNREFUSED else (\"no-route\" if c in (errno.EHOSTUNREACH,errno.ENETUNREACH) else \"error\")])\\n'\n"
        + "        conn += 'print(json.dumps(R))\\n'\n"
        + "        rc, out = _nexec_python(kind_of.get(pname), pname, conn, timeout=120)\n"
        + "        src_ip = nodes.get(pname, {}).get('ip') or ''\n"
        + "        try:\n"
        + "            rows = json.loads(out.strip().splitlines()[-1])\n"
        + "        except Exception:\n"
        + "            rows = []\n"
        + "        for row in rows:\n"
        + "            checks.append({'node': row[0], 'ip': row[1], 'port': row[2], 'via': row[3],\n"
        + "                           'src': pname, 'src_ip': src_ip,\n"
        + "                           'reachable': bool(row[4]), 'error': row[5] if len(row) > 5 else ''})\n"
        + "    probers = sorted(plan.keys())\n"
        + "    print(json.dumps({'ok': True, 'prober': (probers[0] if probers else ''),\n"
        + "                      'probers': probers, 'nodes': nodes, 'checks': checks}))\n"
        + "main()\n"
    )
def segmentation_probe_script(sudo_password: str | None = None,
                              session_id: Any = None,
                              seg_dirs: list[str] | None = None) -> str:
    """VM-side script: report the segmentation verification artifact and any
    generated scripts on the VM, plus firewall rules inside every node (Docker
    nodes via ``docker exec``, CORE vnodes via ``vcmd``).

    Only the runtime directory is inspected. ``/tmp/scenarioforge-preview-seg-*``
    holds plan-time scripts that are never deployed, so counting them would
    report segmentation for a scenario that has none.
    """
    dirs = seg_dirs or ["/tmp/segmentation"]
    dirs_literal = json.dumps(dirs)
    return (
        _remote_preamble(sudo_password, session_id)
        + f"SEG_DIRS = {dirs_literal}\n"
        + "def main():\n"
        + "    seg_files = []\n"
        + "    verification = None\n"
        + "    rules_summary = None\n"
        + "    ref = None\n"
        + "    for d in SEG_DIRS:\n"
        + "        for path in glob.glob(d):\n"
        + "            if os.path.isdir(path):\n"
        + "                for f in os.listdir(path):\n"
        + "                    fp = os.path.join(path, f)\n"
        + "                    if f.endswith('.json'):\n"
        + "                        low = f.lower()\n"
        + "                        if ('verif' in low or 'allow' in low) and verification is None:\n"
        + "                            verification = _read_json(fp)\n"
        + "                            ref = _mtime(fp)\n"
        + "                        elif 'summary' in low and rules_summary is None:\n"
        + "                            rules_summary = _read_json(fp)\n"
        + "                    else:\n"
        + "                        seg_files.append(fp)\n"
        + "            elif os.path.isfile(path):\n"
        + "                seg_files.append(path)\n"
        + "    seg_files, seg_stale = _fresh(seg_files, ref)\n"
        + "    nodes = {}\n"
        + "    for kind, name in _all_nodes():\n"
        + "        rc, out = _nexec(kind, name, ['sh','-lc','iptables -S 2>/dev/null || nft list ruleset 2>/dev/null'])\n"
        + "        # Count only real applied rules. Chain policies (-P), chain\n"
        + "        # declarations (-N) and any shell/ssh noise on the stream are not rules.\n"
        + "        non_default = [l.strip() for l in out.splitlines()\n"
        + "                       if l.strip().startswith('-A ') or l.strip().startswith('-I ')]\n"
        # Keep the rules in chain order: iptables takes the first match, so a
        # DROP ahead of an ACCEPT silences it. Order is the whole signal here.
        + "        nodes[name] = {\n"
        + "            'kind': kind,\n"
        + "            'rules_present': bool(non_default),\n"
        + "            'marker': ('custom-seg' in out) or ('scenarioforge' in out.lower()),\n"
        + "            'rule_count': len(non_default),\n"
        + "            'rule_lines': non_default[:200],\n"
        + "        }\n"
        + "    print(json.dumps({'ok': True, 'seg_files': seg_files, 'stale_files': seg_stale, 'verification': verification, 'rules_summary': rules_summary, 'nodes': nodes}))\n"
        + "main()\n"
    )


# The agent writes stats every 10s (`-stats-interval`, traffic_agent/main.go).
# Six missed writes is a generous margin for an emulated node under load while
# still distinguishing a running agent from one that has stopped.
_AGENT_STATS_FRESH_S = 60


def traffic_probe_script(sudo_password: str | None = None,
                         session_id: Any = None,
                         traffic_dirs: list[str] | None = None,
                         node_names_by_id: Any = None) -> str:
    """VM-side script: report the traffic summary artifact and generated traffic
    scripts, traffic processes and CORE IP inside every node (Docker + vnode),
    and reachability along each configured flow. Each ping row carries the exact
    command to reproduce it.

    Only the runtime directory is inspected. ``/tmp/scenarioforge-preview-traffic-*``
    holds plan-time scripts produced during preview that are never deployed, so
    counting them would report running traffic for a scenario that has none.

    ``node_names_by_id`` maps the plan's CORE node ids to node names. Flows are
    matched to running nodes by address first, but an address is not an
    endpoint's identity: a node that came up with a different address than the
    plan recorded -- which is exactly the state worth reporting -- becomes
    unmatchable by IP, and every one of its flows then reported "source node not
    found" instead of being tested at all. The id is stable, so it resolves the
    node and the probe still runs, with its real result.
    """
    dirs = traffic_dirs or ["/tmp/traffic"]
    dirs_literal = json.dumps(dirs)
    names_by_id = {}
    for raw_id, raw_name in (node_names_by_id or {}).items():
        node_id = str(raw_id).strip()
        node_name = str(raw_name).strip()
        if node_id and node_name:
            names_by_id[node_id] = node_name
    names_literal = json.dumps(names_by_id)
    # Finding the agent must not depend on the node's image shipping procps.
    # A Docker node's container IS the scenario's own image, and a minimal
    # vulnerability image often has no `pgrep` or `ps` at all -- on such a node
    # pgrep produced nothing, the node looked idle, and the check reported a
    # sender with no traffic process while the agent was in fact running and
    # moving megabytes. `/proc` is part of the kernel, not a package, so scan it
    # when pgrep is unavailable or finds nothing.
    #
    # The scanner skips its own pid; its parent shell is filtered out below by
    # the `pgrep` substring its command line necessarily contains.
    proc_scan_sh = (
        "pgrep -fa traffic_ 2>/dev/null || pgrep -af traffic_ 2>/dev/null || "
        "{ self=$$; for d in /proc/[0-9]*; do p=${d#/proc/}; "
        "[ \"$p\" = \"$self\" ] && continue; "
        "[ -r \"$d/cmdline\" ] || continue; "
        "c=$(tr '\\0' ' ' < \"$d/cmdline\" 2>/dev/null); "
        "case \"$c\" in *traffic_*) echo \"$p $c\" ;; esac; done; }"
    )
    # Required flows get a few bounded attempts. Routing daemons and freshly
    # launched listeners can converge just after the artifact check starts;
    # one connect attempt made a hard required-path failure unnecessarily
    # timing-sensitive. A refusal remains a failure here: unlike the Flow pivot
    # path check, required traffic needs the destination service, not merely a
    # round trip to the host.
    flow_py = (
        "import json,socket,errno,time\n"
        "ATTEMPTS=3\n"
        "def one(ip,port,proto):\n"
        " proto=(proto or '').upper();last='';method='none'\n"
        " if proto not in ('TCP','UDP') or not port:return [False,'none','flow has no protocol/port to test',0]\n"
        " for attempt in range(1,ATTEMPTS+1):\n"
        "  if proto=='TCP':\n"
        "   method='tcp-handshake'\n"
        "   try:\n"
        "    s=socket.create_connection((ip,int(port)),1.5);s.close();return [True,method,'',attempt]\n"
        "   except socket.timeout:last='timeout'\n"
        "   except OSError as e:\n"
        "    c=getattr(e,'errno',None)\n"
        "    if c==errno.ECONNREFUSED:last='refused'\n"
        "    elif c in (errno.EHOSTUNREACH,errno.ENETUNREACH):last='no-route'\n"
        "    else:last='error'\n"
        "  else:\n"
        "   method='udp-send'\n"
        "   try:\n"
        "    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(0.75);s.connect((ip,int(port)));s.send(b'\\x00'*32)\n"
        "    try:s.recv(1)\n"
        "    except socket.timeout:last='sent'\n"
        "    except OSError as e2:\n"
        "     c2=getattr(e2,'errno',None)\n"
        "     if c2==errno.ECONNREFUSED:last='icmp-port-unreachable'\n"
        "     elif c2 in (errno.EHOSTUNREACH,errno.ENETUNREACH):last='no-route'\n"
        "     else:last='error'\n"
        "    s.close()\n"
        "   except OSError as e:\n"
        "    c=getattr(e,'errno',None);last='no-route' if c in (errno.EHOSTUNREACH,errno.ENETUNREACH) else 'error'\n"
        "  if attempt<ATTEMPTS:time.sleep(0.5)\n"
        " return [None if proto=='UDP' and last=='sent' else False,method,last,ATTEMPTS]\n"
        "R=[]\n"
        "for ip,port,proto,dname in ROWS:\n"
        " ok,method,err,attempts=one(ip,port,proto)\n"
        " R.append([ip,port,proto,dname,ok,method,err,attempts])\n"
        "print(json.dumps(R))\n"
    )
    return (
        _remote_preamble(sudo_password, session_id)
        + f"TRAFFIC_DIRS = {dirs_literal}\n"
        + f"PROC_SCAN = {json.dumps(proc_scan_sh)}\n"
        + f"NODE_NAMES_BY_ID = {names_literal}\n"
        + f"AGENT_FRESH_S = {int(_AGENT_STATS_FRESH_S)}\n"
        + "import datetime as _dt\n"
        + "def _node_agent_log(kind, name):\n"
        # TrafficService writes why it did or did not start here -- a missing
        # config, no binary for the node's architecture, or the agent's own
        # stderr. Same Docker-only restriction as the stats glob below: a vnode
        # shares the host /tmp and would return every node's log.\n
        + "    if kind != 'docker':\n"
        + "        return ''\n"
        + "    rc, out = _nexec(kind, name, ['sh','-lc',\n"
        + "                     'tail -c 800 /tmp/coretg_traffic/output_*.txt 2>/dev/null'])\n"
        + "    lines = [l.strip() for l in str(out or '').splitlines() if l.strip()]\n"
        + "    return lines[-1][:240] if lines else ''\n"
        + "def _node_agent(kind, name):\n"
        + "    # The agent's own stats file is the one liveness signal that needs no\n"
        + "    # tooling in the image at all -- just a readable file -- and it proves\n"
        + "    # progress rather than mere existence. Restricted to Docker nodes: a\n"
        + "    # vnode shares the host's /tmp, so this glob would return every node's\n"
        + "    # stats. Vnodes share the host filesystem and therefore always have\n"
        + "    # pgrep, so they never reach for this fallback.\n"
        + "    if kind != 'docker':\n"
        + "        return {}\n"
        + "    rc, out = _nexec(kind, name, ['sh','-lc',\n"
        + "                     'cat /tmp/coretg_traffic/stats_*.json 2>/dev/null | head -c 8000'])\n"
        + "    try:\n"
        + "        s = json.loads(out[out.index('{'):out.rindex('}') + 1])\n"
        + "    except Exception:\n"
        + "        return {}\n"
        + "    age = None\n"
        + "    try:\n"
        + "        seen = _dt.datetime.strptime(str(s.get('updated_at')), '%Y-%m-%dT%H:%M:%SZ')\n"
        + "        seen = seen.replace(tzinfo=_dt.timezone.utc)\n"
        + "        age = (_dt.datetime.now(_dt.timezone.utc) - seen).total_seconds()\n"
        + "    except Exception:\n"
        + "        age = None\n"
        + "    return {'present': True, 'age_s': age,\n"
        + "            'live': bool(age is not None and age <= AGENT_FRESH_S),\n"
        + "            'bytes_sent': s.get('total_bytes_sent'),\n"
        + "            'bytes_received': s.get('total_bytes_received'),\n"
        + "            'errors': s.get('total_errors'),\n"
        + "            'flows': len(s.get('flows') or [])}\n"
        + "def _ip(kind, name):\n"
        + "    return _node_addr(kind, name)[0]\n"
        + "def _session_dirs():\n"
        + "    try:\n"
        + "        return sorted(os.path.basename(p) for p in glob.glob('/tmp/pycore.*') if os.path.isdir(p))\n"
        + "    except Exception:\n"
        + "        return []\n"
        + f"FLOW_PY = {json.dumps(flow_py)}\n"
        + "def _agent_stats(kind, name, node_id):\n"
        + "    if node_id is None:\n"
        + "        return None\n"
        + "    path = '/tmp/coretg_traffic/stats_' + str(node_id) + '.json'\n"
        + "    rc, out = _nexec(kind, name, ['sh','-lc','cat ' + path + ' 2>/dev/null'])\n"
        + "    try:\n"
        + "        return json.loads(out[out.index('{'):out.rindex('}') + 1])\n"
        + "    except Exception:\n"
        + "        return None\n"
        + "def _flow_entry(stats, flow_id):\n"
        + "    for f in ((stats or {}).get('flows') or []):\n"
        + "        if isinstance(f, dict) and str(f.get('flow')) == flow_id:\n"
        + "            return f\n"
        + "    return None\n"
        + "def _arrival(meta, port, proto, kind_of):\n"
        + "    src_id, dst_id = meta.get('src_id'), meta.get('dst_id')\n"
        + "    if src_id is None or dst_id is None:\n"
        + "        return {}\n"
        + "    base = str(proto).lower() + '-' + str(src_id) + '-' + str(dst_id) + '-' + str(port)\n"
        + "    sname, dname = meta.get('src_name'), meta.get('dst_name')\n"
        + "    tx = _flow_entry(_agent_stats(kind_of.get(sname), sname, src_id), base + '-tx')\n"
        + "    rx = _flow_entry(_agent_stats(kind_of.get(dname), dname, dst_id), base + '-rx')\n"
        + "    out = {'flow_id': base}\n"
        + "    if tx is not None:\n"
        + "        out['bytes_sent'] = tx.get('bytes_sent')\n"
        + "        out['send_errors'] = tx.get('errors')\n"
        + "    if rx is not None:\n"
        + "        out['bytes_received'] = rx.get('bytes_received')\n"
        + "        out['achieved_kbps'] = rx.get('achieved_kbps')\n"
        + "    return out\n"
        + "def _repro_flow(kind, name, ip, port, proto):\n"
        + "    if kind == 'docker':\n"
        + "        prefix = \"sudo nsenter -t $(sudo docker inspect -f '{{.State.Pid}}' \" + name + ') -n '\n"
        + "    else:\n"
        + "        prefix = 'sudo vcmd -c ' + os.path.join(PYCORE, name) + ' -- '\n"
        + "    if str(proto or '').upper() == 'TCP' and port:\n"
        + "        return prefix + sys.executable + ' -c \\'import socket; socket.create_connection((\\\"' + str(ip) + '\\\", ' + str(port) + '), 3)\\''\n"
        + "    return prefix + 'ping -c3 -W2 ' + str(ip)\n"
        + "def _repro(kind, name, ip):\n"
        + "    if kind == 'docker':\n"
        + "        return 'sudo docker exec ' + name + ' ping -c3 -W2 ' + ip\n"
        + "    return 'sudo vcmd -c ' + os.path.join(PYCORE, name) + ' -- ping -c3 -W2 ' + ip\n"
        + "def main():\n"
        + "    traffic_files = []\n"
        + "    summary = None\n"
        + "    ref = None\n"
        + "    for d in TRAFFIC_DIRS:\n"
        + "        for path in glob.glob(d):\n"
        + "            if os.path.isdir(path):\n"
        + "                for f in os.listdir(path):\n"
        + "                    fp = os.path.join(path, f)\n"
        + "                    if f.endswith('.json'):\n"
        + "                        if 'summary' in f.lower() and summary is None:\n"
        + "                            summary = _read_json(fp)\n"
        + "                            ref = _mtime(fp)\n"
        + "                    elif f.startswith('traffic_'):\n"
        + "                        traffic_files.append(fp)\n"
        + "            elif os.path.isfile(path):\n"
        + "                traffic_files.append(path)\n"
        + "    traffic_files, traffic_stale = _fresh(traffic_files, ref)\n"
        + "    alln = _all_nodes()\n"
        + "    nodes = {}\n"
        + "    for kind, name in alln:\n"
        + "        rc, out = _nexec(kind, name, ['sh','-lc', PROC_SCAN])\n"
        + "        procs = [l.strip() for l in out.splitlines()\n"
        + "                 if 'traffic_' in l and 'pgrep' not in l and '/proc/[0-9]' not in l]\n"
        + "        cidrs = _node_cidrs(kind, name)\n"
        + "        ips = [c.split('/',1)[0] for c in cidrs]\n"
        + "        links = _node_links(kind, name) if not ips else {'queried': True, 'links': []}\n"
        + "        nodes[name] = {'kind': kind, 'procs': procs, 'ip': (ips[0] if ips else ''),\n"
        + "                       'ips': ips, 'cidrs': cidrs, 'agent': _node_agent(kind, name),\n"
        + "                       'links': links.get('links') or [],\n"
        + "                       'links_queried': bool(links.get('queried')),\n"
        + "                       'agent_log': _node_agent_log(kind, name)}\n"
        + "    # Reachability follows the configured traffic flows, and each flow is\n"
        + "    # tested on its own protocol and port rather than with ping. Under a\n"
        + "    # default-deny segmentation policy ICMP is normally not in the allow\n"
        + "    # list, so ping fails on paths the scenario deliberately permits.\n"
        + "    #\n"
        + "    # A completed TCP handshake also proves the path works in BOTH\n"
        + "    # directions: the SYN reached the destination and its SYN-ACK came\n"
        + "    # back. That is the return-path guarantee TCP flows need -- a one-way\n"
        + "    # rule or asymmetric route cannot produce a successful connect.\n"
        + "    by_ip = {}\n"
        + "    for kind, name in alln:\n"
        + "        for ip in (nodes.get(name, {}).get('ips') or []):\n"
        + "            if ip and ip not in by_ip:\n"
        + "                by_ip[ip] = (kind, name)\n"
        # An endpoint's identity is its CORE node id, not its address. When a
        # node answers on a different address than the plan recorded, matching
        # by id still finds it, so the flow gets probed and reports what is
        # actually wrong instead of vanishing as an unknown source.
        + "    by_id = {}\n"
        + "    for node_id, node_name in (NODE_NAMES_BY_ID or {}).items():\n"
        + "        for kind, name in alln:\n"
        + "            if name == node_name:\n"
        + "                by_id[str(node_id)] = (kind, name)\n"
        + "                break\n"
        + "    def _endpoint(node_id, ip):\n"
        + "        return by_ip.get(ip) or by_id.get(str(node_id if node_id is not None else ''))\n"
        # Say what the probe actually saw. "Not found" alone cannot distinguish
        # a node discovery that returned nothing from a live topology addressed
        # differently than the plan -- two problems with different fixes.
        + "    seen_ips = sorted(by_ip)\n"
        + "    def _discovery_note():\n"
        + "        if not alln:\n"
        + "            where = (' (session ' + SESSION_ID + ')' if SESSION_ID else ' (no session id was supplied)')\n"
        + "            others = [s for s in _session_dirs() if s != ('pycore.' + SESSION_ID)]\n"
        + "            if PYCORE and not os.path.isdir(PYCORE):\n"
        + "                where += '; ' + PYCORE + ' does not exist'\n"
        + "                where += (', but ' + ', '.join(others) + ' does' if others else '')\n"
        + "            return 'no nodes were discovered on the CORE VM at all' + where\n"
        + "        if not seen_ips:\n"
        + "            return str(len(alln)) + ' node(s) were discovered but none reported an IPv4 address'\n"
        + "        sample = ', '.join(seen_ips[:6]) + (', ...' if len(seen_ips) > 6 else '')\n"
        + "        return (str(len(alln)) + ' node(s) are running with addresses: ' + sample\n"
        + "                + '. The flow was planned for an address none of them has, so the'\n"
        + "                + ' running topology is not the one this traffic plan was built for')\n"
        + "    ping = []\n"
        + "    seen = set()\n"
        + "    plan = {}\n"
        + "    flow_meta = {}\n"
        + "    for flow in ((summary or {}).get('flows') or []):\n"
        + "        if not isinstance(flow, dict):\n"
        + "            continue\n"
        + "        s_ip = str(flow.get('src_ip') or '').strip()\n"
        + "        d_ip = str(flow.get('dst_ip') or '').strip()\n"
        + "        proto = str(flow.get('protocol') or '').strip().upper()\n"
        + "        port = flow.get('dst_port')\n"
        + "        key = (s_ip, d_ip, proto, str(port))\n"
        + "        if key in seen:\n"
        + "            continue\n"
        + "        seen.add(key)\n"
        + "        if not s_ip or not d_ip:\n"
        + "            ping.append({'src': s_ip or 'missing source', 'dst': d_ip or 'missing destination',\n"
        + "                         'ip': d_ip, 'reachable': None, 'cmd': '', 'port': port,\n"
        + "                         'protocol': proto, 'method': 'metadata',\n"
        + "                         'why': 'configured traffic flow is missing its source or destination address'})\n"
        + "            continue\n"
        + "        dst_name = (_endpoint(flow.get('dst_id'), d_ip) or (None, d_ip))[1]\n"
        + "        src = _endpoint(flow.get('src_id'), s_ip)\n"
        + "        if not src:\n"
        + "            ping.append({'src': s_ip, 'dst': dst_name, 'ip': d_ip, 'reachable': None,\n"
        + "                         'cmd': '', 'port': port, 'protocol': proto,\n"
        + "                         'why': ('traffic source node not found for ' + s_ip + ': '\n"
        + "                                 + _discovery_note())})\n"
        + "            continue\n"
        + "        plan.setdefault(src[1], []).append([d_ip, port, proto, dst_name])\n"
        # Carry each endpoint's live address alongside the planned one. "No
        # route" has two very different causes -- a broken route between two
        # correctly addressed nodes, or a flow aimed at an address that exists
        # nowhere in this session -- and only the live addresses separate them.
        + "        flow_meta[(d_ip, str(port), proto)] = {\n"
        + "            'src_id': flow.get('src_id'), 'dst_id': flow.get('dst_id'),\n"
        + "            'dst_name': dst_name, 'src_name': src[1],\n"
        + "            'src_live': (nodes.get(src[1], {}).get('ips') or []),\n"
        + "            'dst_live': (nodes.get(dst_name, {}).get('ips') or []),\n"
        + "            'src_kind': src[0],\n"
        + "            'src_links': (nodes.get(src[1], {}).get('links') or []),\n"
        + "            'src_links_queried': bool(nodes.get(src[1], {}).get('links_queried')),\n"
        + "            'dst_links': (nodes.get(dst_name, {}).get('links') or []),\n"
        + "            'dst_links_queried': bool(nodes.get(dst_name, {}).get('links_queried')),\n"
        + "            'dst_ip_owned': bool(by_ip.get(d_ip))}\n"
        + "    kind_of = dict((name, kind) for kind, name in alln)\n"
        + "    for sn, rows in plan.items():\n"
        + "        sk = kind_of.get(sn)\n"
        + "        prog = 'ROWS = ' + json.dumps(rows) + '\\n' + FLOW_PY\n"
        + "        rc, out = _nexec_python(sk, sn, prog, timeout=120)\n"
        + "        try:\n"
        + "            results = json.loads(out.strip().splitlines()[-1])\n"
        + "        except Exception:\n"
        + "            results = []\n"
        + "        returned = set()\n"
        + "        for d_ip, port, proto, dst_name, ok, method, err, attempts in results:\n"
        + "            returned.add((d_ip, str(port), proto))\n"
        + "            row = {'src': sn, 'dst': dst_name, 'ip': d_ip, 'port': port,\n"
        + "                   'protocol': proto, 'reachable': ok, 'method': method, 'error': err,\n"
        + "                   'attempts': attempts, 'cmd': _repro_flow(sk, sn, d_ip, port, proto)}\n"
        + "            if ok is False:\n"
        + "                # Only now is ping worth running: it separates \"no route at\n"
        + "                # all\" from \"route fine, this port filtered\".\n"
        + "                rc2, out2 = _nexec(sk, sn, ['sh','-lc','ping -c1 -W1 '+d_ip+' >/dev/null 2>&1 && echo OK || echo NO'])\n"
        + "                row['icmp'] = ('OK' in out2)\n"
        + "            meta = flow_meta.get((d_ip, str(port), proto)) or {}\n"
        + "            row['src_live'] = meta.get('src_live') or []\n"
        + "            row['dst_live'] = meta.get('dst_live') or []\n"
        + "            row['dst_ip_owned'] = bool(meta.get('dst_ip_owned'))\n"
        + "            for key in ('src_kind', 'src_links', 'src_links_queried',\n"
        + "                        'dst_links', 'dst_links_queried'):\n"
        + "                if key in meta:\n"
        + "                    row[key] = meta.get(key)\n"
        + "            row.update(_arrival(meta, port, proto, kind_of))\n"
        + "            ping.append(row)\n"
        + "        for d_ip, port, proto, dst_name in rows:\n"
        + "            if (d_ip, str(port), proto) in returned:\n"
        + "                continue\n"
        + "            row = {'src': sn, 'dst': dst_name, 'ip': d_ip, 'port': port,\n"
        + "                   'protocol': proto, 'reachable': None, 'method': 'probe-execution',\n"
        + "                   'error': '', 'cmd': _repro_flow(sk, sn, d_ip, port, proto),\n"
        + "                   'why': 'required traffic probe produced no result'}\n"
        + "            meta = flow_meta.get((d_ip, str(port), proto)) or {}\n"
        + "            row['src_live'] = meta.get('src_live') or []\n"
        + "            row['dst_live'] = meta.get('dst_live') or []\n"
        + "            row['dst_ip_owned'] = bool(meta.get('dst_ip_owned'))\n"
        + "            for key in ('src_kind', 'src_links', 'src_links_queried',\n"
        + "                        'dst_links', 'dst_links_queried'):\n"
        + "                if key in meta:\n"
        + "                    row[key] = meta.get(key)\n"
        + "            row.update(_arrival(meta, port, proto, kind_of))\n"
        + "            ping.append(row)\n"
        + "    print(json.dumps({'ok': True, 'traffic_files': traffic_files, 'stale_files': traffic_stale,\n"
        + "                      'summary': summary, 'nodes': nodes, 'ping': ping,\n"
        + "                      'session': {'id': SESSION_ID, 'pycore': PYCORE,\n"
        + "                                  'pycore_present': bool(PYCORE and os.path.isdir(PYCORE)),\n"
        + "                                  'sessions_present': _session_dirs()}}))\n"
        + "main()\n"
    )


def _blocked_flows(verification: Any) -> list[Any]:
    """Traffic flows that segmentation is still blocking.

    `allow_verification.json` is written by `verify_flows_allowed`, whose job is
    to confirm every generated traffic flow is *permitted*. So `blocked` lists
    flows that cannot get through -- a misconfiguration -- and an empty list is
    the healthy outcome. `flows_total` counts the traffic flows examined, not
    rules that ought to be enforced.
    """
    if not isinstance(verification, dict):
        return []
    return _as_list(verification.get("blocked"))


def _segmentation_rule_count(rules_summary: Any) -> int:
    if not isinstance(rules_summary, dict):
        return 0
    return len(_as_list(rules_summary.get("rules")))


def segmentation_result(probe: Any, *, expected: bool) -> dict[str, Any]:
    """Check 5: are the firewall/segmentation rules the scenario asked for in place?

    Whether segmentation exists comes from the rules it generated (the runtime
    `segmentation_summary.json` plus rules visible inside nodes). The allow
    verification is a separate signal: it flags traffic that segmentation is
    wrongly blocking.
    """
    if not isinstance(probe, dict) or not probe.get("ok"):
        detail = _name(probe.get("error") or probe.get("raw")) if isinstance(probe, dict) else ""
        return _result("segmentation", "error", detail or "segmentation probe failed")
    seg_files = _as_list(probe.get("seg_files"))
    verification = probe.get("verification") if isinstance(probe.get("verification"), dict) else None
    rules_summary = probe.get("rules_summary") if isinstance(probe.get("rules_summary"), dict) else None
    nodes = probe.get("nodes") if isinstance(probe.get("nodes"), dict) else {}
    nodes_with_rules = [n for n, info in nodes.items() if isinstance(info, dict) and info.get("rules_present")]
    rule_count = _segmentation_rule_count(rules_summary)
    blocked = _blocked_flows(verification)
    items: list[dict[str, Any]] = []

    # Traffic that segmentation is blocking is a real defect, so report it first.
    if blocked:
        for flow in blocked[:20]:
            if isinstance(flow, dict):
                target = f"{flow.get('dst_ip')}:{flow.get('dst_port')}"
                proto = _name(flow.get("proto")) or "flow"
                items.append({"name": target, "status": "fail",
                              "detail": f"{proto} traffic flow is blocked by segmentation and cannot arrive"})
            else:
                items.append({"name": _name(flow) or "flow", "status": "fail",
                              "detail": "traffic flow is blocked by segmentation"})
    elif verification is not None:
        checked = verification.get("flows_total")
        checked = checked if isinstance(checked, int) else 0
        items.append({
            "name": "traffic flows permitted",
            "status": "pass" if checked else "skip",
            "detail": (f"all {checked} traffic flow(s) pass the segmentation rules"
                       if checked else "no traffic flows to verify against segmentation"),
        })

    if rule_count:
        items.append({"name": "segmentation rules", "status": "pass",
                      "detail": f"{rule_count} rule(s) generated for this run"})
    if seg_files:
        items.append({"name": "CORE VM", "status": "pass",
                      "detail": f"{len(seg_files)} segmentation script(s) generated"})
    for node, info in sorted(nodes.items()):
        if not isinstance(info, dict) or not info.get("rules_present"):
            continue
        items.append({
            "name": f"{node} ({info.get('kind', '?')})",
            "status": "pass",
            "detail": (f"{info.get('rule_count', 0)} firewall rule(s) applied"
                       + (" [marker]" if info.get("marker") else "")),
        })
    if nodes and not nodes_with_rules:
        items.append({"name": f"{len(nodes)} node(s) probed", "status": "skip",
                      "detail": "no custom firewall rules on any node (Docker nodes and CORE vnodes)"})

    if blocked:
        return _result("segmentation", "fail",
                       f"{len(blocked)} traffic flow(s) blocked by segmentation and cannot arrive.", items)

    applied = bool(rule_count or nodes_with_rules or seg_files)
    if applied:
        bits: list[str] = []
        if rule_count:
            bits.append(f"{rule_count} rule(s)")
        if nodes_with_rules:
            bits.append(f"{len(nodes_with_rules)} node(s) with firewall rules")
        if seg_files:
            bits.append(f"{len(seg_files)} script(s)")
        return _result("segmentation", "pass", "Segmentation in place: " + ", ".join(bits) + ".", items)
    if expected:
        # /tmp/segmentation is the sibling of /tmp/traffic and shares its
        # failure mode: sudo'd docker bind-mounts it, so the daemon can create
        # it as root and the run cannot write its scripts. See traffic_result.
        return _result("segmentation", "skip",
                       "Segmentation is enabled for this scenario but generated no rules. "
                       "If execute logged 'Permission denied' under /tmp/segmentation, that "
                       "directory is owned by root on the CORE host; fix its ownership and "
                       "pin it with an /etc/tmpfiles.d entry so a reboot cannot undo it.", items)
    return _result("segmentation", "skip", "No segmentation configured for this scenario.", items)


def traffic_result(probe: Any, *, expected: bool,
                   node_names_by_id: Any = None) -> dict[str, Any]:
    """Check 6: are the traffic scripts generated and running where they should be?

    Reachability is deliberately NOT part of this check — see reachability_result.
    """
    if not isinstance(probe, dict) or not probe.get("ok"):
        detail = _name(probe.get("error") or probe.get("raw")) if isinstance(probe, dict) else ""
        return _result("traffic", "error", detail or "traffic probe failed")
    traffic_files = _as_list(probe.get("traffic_files"))
    summary = probe.get("summary") if isinstance(probe.get("summary"), dict) else None
    flows = _as_list(summary.get("flows")) if isinstance(summary, dict) else []
    nodes = probe.get("nodes") if isinstance(probe.get("nodes"), dict) else {}
    # "Is the agent running" has two independent witnesses, because neither is
    # available on every image. A process listing needs procps, which a minimal
    # vulnerability image may not ship; the agent's stats file needs only a
    # readable file, but proves liveness solely while it keeps being updated.
    # Either one counts, so a node is only reported idle when both are silent.
    def _agent(info: Any) -> dict[str, Any]:
        agent = info.get("agent") if isinstance(info, dict) else None
        return agent if isinstance(agent, dict) else {}

    nodes_with_procs = [
        n for n, info in nodes.items()
        if isinstance(info, dict) and (_as_list(info.get("procs")) or _agent(info).get("live"))
    ]
    # An agent that wrote stats and then stopped is a third state: neither
    # healthy nor never-started, and the one worth naming in the output.
    nodes_agent_stopped = sorted(
        n for n, info in nodes.items()
        if isinstance(info, dict)
        and n not in nodes_with_procs
        and _agent(info).get("present")
    )
    items: list[dict[str, Any]] = []

    # The runtime traffic_summary.json is rewritten by every execute, so when it
    # is present its flow list is the authority on whether this scenario has
    # traffic at all. Files left in the shared /tmp/traffic directory must never
    # override it, or a scenario with no traffic reports traffic as running.
    if summary is not None and not flows:
        if nodes_with_procs:
            for node in sorted(nodes_with_procs):
                count = len(_as_list(nodes[node].get("procs")))
                items.append({"name": node, "status": "warn",
                              "detail": f"{count} traffic process(es) running, but this scenario "
                                        "configured no traffic flows"})
            return _result("traffic", "warn",
                           f"No traffic configured, yet {len(nodes_with_procs)} node(s) are running "
                           "traffic processes (possibly left over from an earlier scenario).", items)
        return _result("traffic", "skip", "No traffic configured for this scenario.", items)

    if flows:
        items.append({"name": "traffic flows", "status": "pass",
                      "detail": f"{len(flows)} configured flow(s) recorded"})
    if traffic_files:
        items.append({"name": "CORE VM", "status": "pass",
                      "detail": f"{len(traffic_files)} traffic script(s) generated"})
    for node in sorted(nodes_with_procs):
        count = len(_as_list(nodes[node].get("procs")))
        agent = _agent(nodes[node])
        if count:
            detail = f"{count} traffic process(es) running"
        else:
            # Seen only through the stats file: say so, because the absence of a
            # process listing on this node is itself worth knowing.
            detail = "traffic agent active (no process listing available on this image)"
        sent = agent.get("bytes_sent")
        if isinstance(sent, (int, float)) and sent > 0:
            detail += f"; {int(sent):,} bytes sent"
        errors = agent.get("errors")
        if isinstance(errors, (int, float)) and errors > 0:
            detail += f"; {int(errors)} error(s)"
        items.append({"name": node, "status": "pass", "detail": detail})

    # Every configured flow endpoint needs a live traffic agent. A missing
    # sender cannot emit the required traffic; a missing receiver makes UDP
    # delivery unmeasurable and leaves TCP dependent on a listener that the
    # scenario explicitly expected the agent to provide.
    expected_senders: set[str] = set()
    expected_receivers: set[str] = set()
    unresolved_endpoints: list[tuple[str, str]] = []
    ip_to_node: dict[str, str] = {}
    live_nodes = set(nodes_with_procs)
    for node, info in nodes.items():
        if not isinstance(info, dict):
            continue
        addresses = [_name(value) for value in _as_list(info.get("ips")) if _name(value)]
        if not addresses and _name(info.get("ip")):
            addresses = [_name(info.get("ip"))]
        for ip in addresses:
            current = ip_to_node.get(ip)
            # Old probe payloads may include an internal Compose child that shares
            # its CORE parent's address. Prefer the node with the live traffic
            # agent instead of allowing dictionary order to choose the child.
            if current is None or (node in live_nodes and current not in live_nodes):
                ip_to_node[ip] = node
    # Flows record the CORE node id, which is the endpoint's real identity. An
    # address is not: a node that lost or changed its CORE address -- the exact
    # state worth reporting -- becomes unidentifiable precisely when it matters,
    # and its dead agent then reads as an unrelated extra rather than a failure.
    by_id: dict[str, str] = {}
    for raw_id, raw_name in (node_names_by_id or {}).items():
        node_name = _name(raw_name)
        if node_name in nodes:
            by_id[_name(raw_id)] = node_name
    for flow in flows:
        if not isinstance(flow, dict):
            continue
        for role, bucket in (("src", expected_senders), ("dst", expected_receivers)):
            declared_name = _name(flow.get(f"{role}_name"))
            address = _name(flow.get(f"{role}_ip"))
            node_id = _name(flow.get(f"{role}_id"))
            node = (by_id.get(node_id)
                    or (declared_name if declared_name in nodes else "")
                    or ip_to_node.get(address))
            if node:
                bucket.add(node)
            else:
                label = declared_name or address or "missing address"
                if node_id:
                    label = f"{label} (node {node_id})"
                unresolved_endpoints.append(("source" if role == "src" else "destination", label))

    required_agents = expected_senders | expected_receivers
    missing_required = sorted(required_agents - set(nodes_with_procs))
    for node in missing_required:
        agent = _agent(nodes.get(node))
        roles = []
        if node in expected_senders:
            roles.append("source")
        if node in expected_receivers:
            roles.append("destination")
        role_text = "/".join(roles) or "endpoint"
        if agent.get("present"):
            age = agent.get("age_s")
            when = f" (last update {int(age)}s ago)" if isinstance(age, (int, float)) else ""
            detail = (f"required traffic names this node as a {role_text}; its agent ran but has "
                      f"stopped updating stats{when}")
        else:
            detail = (f"required traffic names this node as a {role_text}, but no traffic "
                      "process is running")
        # TrafficService records why it did not start; without this the reason
        # sits on the node and every diagnosis begins with an SSH session.
        agent_log = _name((nodes.get(node) or {}).get("agent_log"))
        if agent_log:
            detail += f". Agent log: {agent_log}"
        items.append({"name": node, "status": "fail", "detail": detail})

    for role, endpoint in unresolved_endpoints:
        items.append({
            "name": endpoint,
            "status": "fail",
            "detail": f"configured traffic {role} was not found in the running CORE session",
        })

    # A stopped agent outside every configured flow is advisory stale state; it
    # does not weaken the hard required-connectivity guarantee.
    stopped_extras = [n for n in nodes_agent_stopped if n not in required_agents]
    for node in stopped_extras:
        age = _agent(nodes[node]).get("age_s")
        when = f" (last update {int(age)}s ago)" if isinstance(age, (int, float)) else ""
        items.append({"name": node, "status": "warn",
                      "detail": f"extra traffic agent ran but has stopped updating stats{when}"})

    # The runtime traffic_summary.json is authoritative about whether traffic was
    # actually configured — the scenario XML's Traffic section can carry a
    # non-zero density with no concrete flows. A present-but-empty summary means
    # no traffic, regardless of the XML. Only when the artifact is missing
    # entirely do we fall back to the scenario's declared intent.
    traffic_configured = bool(flows or traffic_files or nodes_with_procs)
    summary_missing = summary is None and not traffic_files and not nodes_with_procs

    if missing_required or unresolved_endpoints:
        broken = len(missing_required) + len(unresolved_endpoints)
        return _result("traffic", "fail",
                       f"{broken} required traffic endpoint(s) cannot run or be identified.", items)
    if stopped_extras:
        return _result("traffic", "warn",
                       f"{len(nodes_with_procs)} node(s) running required traffic; "
                       f"{len(stopped_extras)} extra node(s) have a stopped traffic agent.", items)
    if traffic_configured:
        bits: list[str] = []
        if flows:
            bits.append(f"{len(flows)} traffic flow(s)")
        if traffic_files:
            bits.append(f"{len(traffic_files)} traffic script(s)")
        if nodes_with_procs:
            bits.append(f"{len(nodes_with_procs)} node(s) running traffic")
        return _result("traffic", "pass", "; ".join(bits), items)
    if summary_missing and expected:
        # The usual cause is ownership, not a bug in traffic generation: the
        # docker preflight runs under sudo earlier in the same execute and
        # bind-mounts /tmp/traffic, and the daemon creates a missing bind-mount
        # source as root. After a reboot empties /tmp, docker therefore wins the
        # race and the traffic phase cannot write into its own directory.
        return _result("traffic", "fail",
                       "The scenario declares traffic, but no runtime traffic_summary.json was found. "
                       "Required traffic cannot be verified; confirm traffic generation ran during execute. "
                       "If execute logged 'Permission denied' under /tmp/traffic, that directory is owned "
                       "by root on the CORE host -- the sudo'd docker preflight bind-mounts it and so "
                       "creates it first whenever /tmp is empty after a reboot. Fix the ownership of "
                       "/tmp/traffic and /tmp/segmentation; an /etc/tmpfiles.d entry makes the fix "
                       "survive reboots.",
                       items)
    return _result("traffic", "skip", "No traffic configured for this scenario.", items)


def flow_pivot_relationships(flow_state: Any) -> list[dict[str, Any]]:
    """Return the distinct source -> target paths required by Flow's chain.

    Flow records a broad list of nodes unlocked by a pivot on the assignment
    that *produces* ``Pivot(source)`` and a specific relationship on every
    chain assignment that *requires* it.  The latter is authoritative for this
    check: probing every broad source-side relationship would test nodes that
    are not part of the generated challenge chain.

    Older saved FlowState payloads may have only source-side records.  Those
    remain usable as a fallback, but target-side and source-side records are
    never mixed.  Repeated assignments and duplicate chain nodes can repeat an
    edge, so edges are deduplicated by both endpoint names rather than by node
    id or assignment identity.
    """
    if not isinstance(flow_state, dict):
        return []
    assignments = flow_state.get("flag_assignments")
    if not isinstance(assignments, list):
        assignments = flow_state.get("assignments")
    if not isinstance(assignments, list):
        return []

    target_entries: list[tuple[int, dict[str, Any]]] = []
    source_entries: list[tuple[int, dict[str, Any]]] = []
    for assignment_index, assignment in enumerate(assignments):
        if not isinstance(assignment, dict):
            continue
        for entry in _as_list(assignment.get("pivot")):
            if not isinstance(entry, dict):
                continue
            role = _name(entry.get("role")).lower()
            if not role:
                requires = " ".join(_name(v) for v in _as_list(entry.get("requires")))
                produces = " ".join(_name(v) for v in _as_list(entry.get("produces")))
                if "Pivot(" in requires:
                    role = "target"
                elif "Pivot(" in produces:
                    role = "source"
            if role == "target":
                target_entries.append((assignment_index, entry))
            elif role == "source":
                source_entries.append((assignment_index, entry))

    selected = target_entries if target_entries else source_entries
    relationships: list[dict[str, Any]] = []
    by_edge: dict[tuple[str, str], dict[str, Any]] = {}

    def _ports(value: Any) -> list[int]:
        values = value if isinstance(value, (list, tuple, set)) else [value]
        out: list[int] = []
        for raw in values:
            if isinstance(raw, str) and "," in raw:
                out.extend(_ports([part.strip() for part in raw.split(",")]))
                continue
            try:
                port = int(raw)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535 and port not in out:
                out.append(port)
        return out

    def _protocols(value: Any) -> list[str]:
        values = value if isinstance(value, (list, tuple, set)) else [value]
        out: list[str] = []
        for raw in values:
            for part in _name(raw).replace(",", " ").split():
                protocol = part.upper()
                if protocol and protocol not in out:
                    out.append(protocol)
        return out

    for assignment_index, entry in selected:
        source = _name(entry.get("source"))
        target = _name(entry.get("target"))
        # Retain malformed target-side metadata so the live check reports a
        # clear failure instead of silently skipping a required pivot.
        edge = (source, target)
        if not source or not target:
            edge = (source or f"<missing-source-{assignment_index}>",
                    target or f"<missing-target-{assignment_index}>")
        current = by_edge.get(edge)
        if current is None:
            current = {
                "source": source,
                "target": target,
                "provider": _name(entry.get("provider")),
                "provider_label": _name(entry.get("provider_label")),
                "exposure": _name(entry.get("exposure")),
                "target_ports": [],
                "target_protocols": [],
                "assignment_indexes": [],
            }
            if not source or not target:
                current["metadata_error"] = (
                    f"Flow pivot metadata on assignment {assignment_index + 1} is missing "
                    f"{'source and target' if not source and not target else 'source' if not source else 'target'}"
                )
            by_edge[edge] = current
            relationships.append(current)
        current["assignment_indexes"].append(assignment_index)
        # A pivot target usually declares no segmentation port, so fall back to the
        # port its offering publishes. Without one the probe has only the node's
        # live listeners to go on, which are empty while a container is still
        # starting -- a healthy target then reads as having no service at all.
        for port in _ports(entry.get("target_ports") or entry.get("inferred_target_ports")):
            if port not in current["target_ports"]:
                current["target_ports"].append(port)
        for protocol in _protocols(entry.get("target_protocols")):
            if protocol not in current["target_protocols"]:
                current["target_protocols"].append(protocol)
        for field in ("provider", "provider_label", "exposure"):
            if not current.get(field) and _name(entry.get(field)):
                current[field] = _name(entry.get(field))

    return relationships


def flow_pivot_probe_script(sudo_password: str | None = None,
                            session_id: Any = None,
                            relationships: Any = None,
                            max_ports_per_target: int = 12) -> str:
    """VM-side probe for Flow's actual ``Pivot(source)`` chain edges.

    The check enters the source node's Docker/CORE namespace and makes a TCP
    connection to the target.  Explicit target ports from Flow metadata win;
    otherwise the target's non-loopback listeners are discovered from
    ``/proc/net/tcp*``.  If the target has no listener, a closed TCP route-probe
    port is used: a returned RST still proves that packets reached the target
    and the reply reached the pivot source.
    """
    pivots = [dict(item) for item in _as_list(relationships) if isinstance(item, dict)]
    pivots_literal = json.dumps(pivots, separators=(",", ":"))
    listen_py = (
        "import json\n"
        "def _loop(a,f):\n"
        " a=a.upper()\n"
        " if f==4:return a.endswith('7F')\n"
        " if a=='00000000000000000000000001000000':return True\n"
        " if a.startswith('0000000000000000FFFF0000'):return a.endswith('7F')\n"
        " return False\n"
        "pub=set()\n"
        "for path,fam in (('/proc/net/tcp',4),('/proc/net/tcp6',6)):\n"
        " try:\n"
        "  f=open(path);f.readline()\n"
        "  for line in f:\n"
        "   p=line.split()\n"
        "   if len(p)<4 or p[3]!='0A':continue\n"
        "   addr,port=p[1].rsplit(':',1)\n"
        "   if not _loop(addr,fam):pub.add(int(port,16))\n"
        "  f.close()\n"
        " except Exception:pass\n"
        f"print(json.dumps(sorted(pub)[:{int(max_ports_per_target)}]))\n"
    )
    path_py = (
        "import json,socket,errno,time\n"
        "ATTEMPTS=3\n"
        "R=[]\n"
        "for idx,target,ips,ports,basis in ROWS:\n"
        " ok=False;method='tcp-connect';err='no ports attempted';used=None;used_ip=(ips[0] if ips else '');attempts=0\n"
        " for attempt in range(1,ATTEMPTS+1):\n"
        "  attempts=attempt\n"
        "  for ip in ips:\n"
        "   used_ip=ip\n"
        "   for port in ports:\n"
        "    used=int(port)\n"
        "    try:\n"
        "     s=socket.create_connection((ip,used),1.5);s.close();ok=True;method='tcp-handshake';err='';break\n"
        "    except socket.timeout:\n"
        "     err='timeout'\n"
        "    except OSError as e:\n"
        "     c=getattr(e,'errno',None)\n"
        "     if c==errno.ECONNREFUSED:ok=True;method='tcp-rst';err='refused';break\n"
        "     if c in (errno.EHOSTUNREACH,errno.ENETUNREACH):err='no-route'\n"
        "     else:err='error'+((':'+str(c)) if c is not None else '')\n"
        "   if ok:break\n"
        "  if ok:break\n"
        "  if attempt<ATTEMPTS:time.sleep(0.5)\n"
        " R.append([idx,target,used_ip,used,basis,ok,method,err,attempts])\n"
        "print(json.dumps(R))\n"
    )
    return (
        _remote_preamble(sudo_password, session_id)
        + f"PIVOTS = {pivots_literal}\n"
        + f"LISTEN_PY = {json.dumps(listen_py)}\n"
        + f"PATH_PY = {json.dumps(path_py)}\n"
        + "def _listening(kind,name):\n"
        + " rc,out=_nexec_python(kind,name,LISTEN_PY)\n"
        + " try:return [int(x) for x in json.loads(out.strip().splitlines()[-1])]\n"
        + " except Exception:return []\n"
        + "def _repro(kind,name,ip,port):\n"
        + " inner='python3 -c \\'import socket; socket.create_connection((\\\"'+str(ip)+'\\\", '+str(port)+'), 3)\\\''\n"
        + " if kind=='docker':return \"sudo nsenter -t $(sudo docker inspect -f '{{.State.Pid}}' \"+name+') -n '+inner\n"
        + " return 'sudo vcmd -c '+os.path.join(PYCORE,name)+' -- '+inner\n"
        + "def main():\n"
        + " runtime={}\n"
        + " for kind,name in _all_nodes():runtime.setdefault(name,kind)\n"
        + " needed=set()\n"
        + " for rel in PIVOTS:\n"
        + "  if rel.get('source'):needed.add(str(rel.get('source')))\n"
        + "  if rel.get('target'):needed.add(str(rel.get('target')))\n"
        + " nodes={}\n"
        + " target_names=set(str(r.get('target')) for r in PIVOTS if r.get('target'))\n"
        + " for name in sorted(needed):\n"
        + "  kind=runtime.get(name)\n"
        + "  if not kind:continue\n"
        + "  cidrs=_node_cidrs(kind,name);ips=[c.split('/',1)[0] for c in cidrs]\n"
        + "  nodes[name]={'kind':kind,'ip':(ips[0] if ips else ''),'ips':ips,'cidrs':cidrs,'listening':(_listening(kind,name) if name in target_names else [])}\n"
        + " checks=[];plan={}\n"
        + " for idx,rel in enumerate(PIVOTS):\n"
        + "  source=str(rel.get('source') or '');target=str(rel.get('target') or '')\n"
        + "  base={'index':idx,'source':source,'target':target}\n"
        + "  if rel.get('metadata_error') or not source or not target:\n"
        + "   base.update({'reachable':False,'error':str(rel.get('metadata_error') or 'missing Flow pivot source or target'),'method':'metadata','cmd':''});checks.append(base);continue\n"
        + "  if source not in nodes:\n"
        + "   base.update({'reachable':False,'error':'source node not found in running CORE session','method':'node-lookup','cmd':''});checks.append(base);continue\n"
        + "  if target not in nodes:\n"
        + "   base.update({'reachable':False,'error':'target node not found in running CORE session','method':'node-lookup','cmd':''});checks.append(base);continue\n"
        + "  ips=[str(x) for x in (nodes[target].get('ips') or []) if str(x)]\n"
        + "  if not ips:\n"
        + "   base.update({'reachable':False,'error':'target node has no usable IPv4 address','method':'node-lookup','cmd':''});checks.append(base);continue\n"
        + "  explicit=[]\n"
        + "  protocols=[str(x).upper() for x in (rel.get('target_protocols') or [])]\n"
        + "  tcp=(not protocols) or ('TCP' in protocols)\n"
        + "  if tcp:\n"
        + "   for value in (rel.get('target_ports') or []):\n"
        + "    try:\n"
        + "     port=int(value)\n"
        + "     if 1<=port<=65535 and port not in explicit:explicit.append(port)\n"
        + "    except Exception:pass\n"
        + "  ports=explicit or list(nodes[target].get('listening') or [])\n"
        + "  basis='Flow target port' if explicit else 'target listening port'\n"
        # No real port means there is nothing on the target for a participant to
        # reach, which is a defect in its own right.  Probing a synthetic closed
        # port instead cannot tell a dropped packet from an absent service under
        # default-deny segmentation, so report the actual condition.
        + "  if not ports:\n"
        + "   if not tcp:\n"
        + "    base.update({'reachable':False,'error':'the Flow pivot declares only '+'/'.join(protocols)+'; this TCP probe cannot validate it','method':'unsupported-protocol','cmd':''});checks.append(base);continue\n"
        + "   base.update({'reachable':False,'error':'the target declares no Flow port and has nothing listening','method':'no-target-port','cmd':''});checks.append(base);continue\n"
        + "  base.update({'ip':ips[0],'candidate_ips':ips,'candidate_ports':ports,'basis':basis,'cmd':_repro(nodes[source]['kind'],source,ips[0],ports[0])})\n"
        + "  plan.setdefault(source,[]).append([idx,target,ips,ports,basis])\n"
        + "  checks.append(base)\n"
        + " for source,rows in plan.items():\n"
        + "  prog='ROWS = '+json.dumps(rows)+'\\n'+PATH_PY\n"
        + "  rc,out=_nexec_python(nodes[source]['kind'],source,prog,timeout=120)\n"
        + "  try:results=json.loads(out.strip().splitlines()[-1])\n"
        + "  except Exception:results=[]\n"
        + "  returned={}\n"
        + "  for row in results:\n"
        + "   if isinstance(row,list) and len(row)>=8:returned[int(row[0])]=row\n"
        + "  for row in rows:\n"
        + "   idx=int(row[0]);result=returned.get(idx);check=checks[idx]\n"
        + "   if not result:\n"
        + "    check.update({'reachable':False,'method':'probe-execution','error':('probe produced no result: '+str(out or '')[-240:])})\n"
        + "   else:\n"
        # Rebuild the reproduce command from the endpoint actually tried. It was
        # first built from candidate[0], but the prober walks every candidate IP
        # and port, so on a multi-candidate failure the reported endpoint and the
        # pasted command named different ports.
        + "    check.update({'ip':result[2],'port':result[3],'basis':result[4],'reachable':bool(result[5]),'method':result[6],'error':result[7],'attempts':(result[8] if len(result)>8 else 1)})\n"
        + "    if result[2] and result[3]:\n"
        + "     check['cmd']=_repro(nodes[source]['kind'],source,result[2],result[3])\n"
        + " print(json.dumps({'ok':True,'pivots':PIVOTS,'nodes':nodes,'checks':checks}))\n"
        + "main()\n"
    )


def flow_pivot_result(probe: Any) -> dict[str, Any]:
    """Shape the live source -> target Flow pivot probe into check 8."""
    if not isinstance(probe, dict) or not probe.get("ok"):
        detail = _name(probe.get("error") or probe.get("raw")) if isinstance(probe, dict) else ""
        return _result("flow_pivot", "error", detail or "Flow pivot path probe failed")

    pivots = [p for p in _as_list(probe.get("pivots")) if isinstance(p, dict)]
    if not pivots:
        return _result(
            "flow_pivot", "skip",
            "No Flow challenge-chain Pivot(node) relationships to check."
        )

    checks_by_index = {
        int(row.get("index")): row
        for row in _as_list(probe.get("checks"))
        if isinstance(row, dict) and isinstance(row.get("index"), int)
    }
    items: list[dict[str, Any]] = []
    failures = 0
    unproven = 0
    for index, pivot in enumerate(pivots):
        source = _name(pivot.get("source")) or "missing source"
        target = _name(pivot.get("target")) or "missing target"
        row = checks_by_index.get(index)
        label = f"{source} → {target}"
        if not isinstance(row, dict):
            failures += 1
            items.append({"name": label, "status": "fail",
                          "detail": "the runtime probe returned no result for this required Flow pivot path"})
            continue
        ip = _name(row.get("ip"))
        port = row.get("port")
        endpoint = f" ({ip}{':' + str(port) if port else ''})" if ip else ""
        method = _name(row.get("method"))
        error = _name(row.get("error"))
        basis = _name(row.get("basis"))
        cmd = _name(row.get("cmd"))
        attempts = row.get("attempts")
        attempts_note = (f" after {attempts} attempts"
                         if isinstance(attempts, int) and attempts > 1 else "")
        if row.get("reachable") is True:
            if method == "tcp-handshake":
                detail = f"TCP handshake completed on {basis or 'target port'}; the path works in both directions"
            elif method == "tcp-rst":
                detail = (f"target returned TCP RST on {basis or 'the probed port'}; packets reached the "
                          "target and its reply reached the pivot source")
            else:
                detail = "runtime path probe reached the target"
            items.append({"name": label + endpoint, "status": "pass", "detail": detail})
            continue
        if method == "unsupported-protocol":
            # A UDP/ICMP-only pivot is not something this TCP probe can judge
            # either way, so it is neither a pass nor a broken path.
            unproven += 1
            items.append({"name": label + endpoint, "status": "warn",
                          "detail": error or "this pivot cannot be validated by the TCP probe"})
            continue
        failures += 1
        if method == "no-target-port":
            detail = ("the target exposes no port for this pivot: no Flow target port is declared "
                      "and nothing is listening on the node, so the participant has no service to "
                      "reach. Check that the target's service started and is bound to a "
                      "non-loopback address")
        elif method == "node-lookup" or method == "metadata":
            detail = error or "Flow pivot endpoint metadata is incomplete"
        elif error == "no-route":
            detail = f"the pivot source has no route to the target{attempts_note}"
        elif error == "timeout":
            detail = (f"the target did not answer from the pivot source{attempts_note}; "
                      "routing or segmentation is blocking the path")
        else:
            detail = error or "the source-to-target runtime probe failed"
        if cmd:
            detail += f". Reproduce: {cmd}"
        items.append({"name": label + endpoint, "status": "fail", "detail": detail})

    if failures:
        return _result(
            "flow_pivot", "fail",
            f"{failures} of {len(pivots)} Flow pivot path(s) cannot reach their target; "
            "the challenge chain is unsolvable.",
            items,
        )
    if unproven:
        return _result(
            "flow_pivot", "warn",
            f"{unproven} of {len(pivots)} Flow pivot path(s) declare a non-TCP protocol and "
            "cannot be validated by this probe.",
            items,
        )
    return _result(
        "flow_pivot", "pass",
        f"All {len(pivots)} Flow pivot path(s) traversable from their source nodes.",
        items,
    )


def participant_probe_sources(participant_subnets: Any) -> list[str]:
    """One representative address per participant network.

    The participant's own address is not knowable and does not matter: what is
    checked is whether their *network* can reach the provider, so any address on
    it answers the question. Pinning the check to one address would make it pass
    or fail on a DHCP lease.
    """
    out: list[str] = []
    for raw in _as_list(participant_subnets):
        text = _name(raw)
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except Exception:
            continue
        if net.num_addresses <= 1:
            continue
        try:
            out.append(str(next(net.hosts())))
        except StopIteration:
            continue
    return out


def hitl_participant_path_probe_rows(segmentation: Any, participant_subnets: Any) -> list[dict[str, Any]]:
    """One live probe row per pivot provider, sourced as close to the participant
    as the scenario allows.

    Always attempted, including without a HITL network: the probe finds its own
    vantage by looking for a router holding an interface on the source subnet, so
    a source nobody routes back to simply yields no vantage and the check says it
    could not verify rather than guessing.
    """
    sources = participant_probe_sources(participant_subnets)
    allow_rules = _segmentation_allow_rules(segmentation)
    rules_summary = segmentation.get("rules_summary") if isinstance(segmentation, dict) else None
    access = rules_summary.get("pivot_access") if isinstance(rules_summary, dict) else None
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for provider in _as_list(access.get("providers") if isinstance(access, dict) else []):
        if not isinstance(provider, dict):
            continue
        address = _name(provider.get("address"))
        entry = provider.get("entry") if isinstance(provider.get("entry"), dict) else {}
        try:
            port = int(entry.get("port"))
        except (TypeError, ValueError):
            continue
        if not address:
            continue
        # With no participant network, ask from outside the subnet the provider
        # guards -- the same stand-in the rule analysis uses, so both halves of
        # the check speak about the same source.
        subnet = _name(provider.get("subnet"))
        probe_sources = sources or [_allow_rule_stand_in(address, port, subnet, allow_rules)
                                    or _outside_address(subnet)]
        for src in probe_sources:
            key = (src, address, port)
            if key in seen:
                continue
            seen.add(key)
            row = {"src": src, "dst": address, "port": port,
                   "label": _name(provider.get("node_name"))}
            # The stand-in is a documentation address, which no node in a CORE
            # topology can hold -- so the vantage search never matched it and
            # the wire test could not run at all, leaving check 9 unable to
            # reach `pass` in any scenario without a participant network.
            # Name the subnet instead and let the VM pick a router that really
            # sits outside it, which is a source the path can also answer.
            if not sources and subnet:
                row["outside_of"] = subnet
            rows.append(row)
    return rows


def _live_path_verdicts(live_probe: Any) -> dict[tuple[str, int], dict[str, Any]]:
    """Live participant-path results keyed by (provider address, port)."""
    out: dict[tuple[str, int], dict[str, Any]] = {}
    if not isinstance(live_probe, dict) or not live_probe.get("ok"):
        return out
    for row in _as_list(live_probe.get("checks")):
        if not isinstance(row, dict):
            continue
        try:
            key = (_name(row.get("dst")), int(row.get("port")))
        except (TypeError, ValueError):
            continue
        out[key] = row
    return out


def pivot_access_result(segmentation: Any, participant_subnets: Any = None,
                        live_probe: Any = None) -> dict[str, Any]:
    """Check 9: can the participant reach each pivot provider?

    A provider is the only way into a subnet segmentation walled off, so a
    participant who cannot reach it cannot solve anything behind that boundary.
    That makes an unreachable provider a broken scenario, not a warning.

    This reads the rules rather than sending packets, because the participant's
    vantage point is not available to probe from: the HITL node is an RJ45 bound
    to a physical interface, not a namespace the check can enter. Reading the
    rules also means the check still runs with nothing plugged in, which is when
    an author is most likely to be looking at it.

    When no HITL network is configured, the question is still meaningful -- can
    anything outside the subnet reach the provider -- so it is asked from an
    address outside the walled-off subnet instead.
    """
    if not isinstance(segmentation, dict) or not segmentation.get("ok"):
        detail = _name(segmentation.get("error")) if isinstance(segmentation, dict) else ""
        return _result("pivot_access", "error", detail or "segmentation probe failed")

    rules_summary = segmentation.get("rules_summary")
    access = rules_summary.get("pivot_access") if isinstance(rules_summary, dict) else None
    providers = _as_list(access.get("providers")) if isinstance(access, dict) else []
    if not providers:
        # Two different features are called "pivot" and this check covers only
        # one of them, so the skip has to say which. A scenario whose challenge
        # chain is full of Pivot() steps can still legitimately skip here.
        return _result(
            "pivot_access", "skip",
            "No pivot providers to check. This covers Segmentation's "
            "\"accessible by pivot\", which places a reachable provider node in a "
            "subnet segmentation walled off — it is off for this scenario, or it is "
            "on and nothing was walled off. Pivot steps in the challenge chain "
            "(a step producing Pivot(node)) are a separate feature measured by "
            "the preceding Flow pivot-path check; turn on accessible_by_pivot in "
            "the Segmentation section "
            "if you want walled-off subnets given an entrance.")

    allow_rules = _segmentation_allow_rules(segmentation)
    sources = participant_probe_sources(participant_subnets)
    node_rules = _segmentation_runtime_rules_by_node(segmentation)
    items: list[dict[str, Any]] = []
    unreachable = 0
    unplaced = 0
    shadowed = 0
    # No HITL network means no participant subnet to ask from, so the question is
    # answered with a stand-in address outside the walled-off subnet. That is a
    # weaker statement than the real one and the summary has to say so.
    used_stand_in = not sources
    live_verdicts = _live_path_verdicts(live_probe)
    # A provider whose live probe could not run is neither proven nor broken.
    # Without a router on the source subnet there is no vantage to ask from, and
    # in that topology the rule analysis is the whole answer available.
    unverified = 0
    unverified_reasons: list[str] = []

    for provider in providers:
        if not isinstance(provider, dict):
            continue
        subnet = _name(provider.get("subnet"))
        name = _name(provider.get("node_name")) or f"provider for {subnet}"
        address = _name(provider.get("address"))
        entry = provider.get("entry") if isinstance(provider.get("entry"), dict) else {}
        port = entry.get("port")
        label = f"{name} ({address or 'no address'}:{port or '?'}) for {subnet}"

        if not address or not port:
            unplaced += 1
            items.append({"name": label, "status": "fail",
                          "detail": ("no node was placed for this subnet, so nothing behind the "
                                     "boundary can be reached")})
            continue

        # Ask from the participant's network where there is one, and from an
        # address outside the walled-off subnet otherwise.
        probes = list(sources)
        origin = "the participant network"
        if not probes:
            # Same stand-in the probe rows use, so both halves of the check
            # speak about one source rather than reaching different verdicts.
            probes = [_allow_rule_stand_in(address, port, subnet, allow_rules)
                      or _outside_address(subnet)]
            origin = "outside the walled-off subnet"
        probes = [p for p in probes if p]
        if not probes:
            continue

        missing = [src for src in probes
                   if _allow_rule_opening(src, address, port, allow_rules) is None]
        if missing:
            unreachable += 1
            items.append({"name": label, "status": "fail",
                          "detail": (f"no allow rule opens this provider from {origin} "
                                     f"({', '.join(missing)}), so the challenges behind "
                                     f"{subnet} cannot be started")})
            continue

        # An allow rule existing is not the same as traffic passing: iptables
        # takes the first match, so a DROP sitting earlier in the same chain
        # silences the allow entirely.
        blocked_by = None
        for src in probes:
            opening = _allow_rule_opening(src, address, port, allow_rules)
            blocked_by = _shadowing_rule(opening, src, address, port, node_rules)
            if blocked_by:
                break
        if blocked_by:
            shadowed += 1
            items.append({"name": label, "status": "fail",
                          "detail": (f"an allow rule opens this provider from {origin}, but "
                                     f"{blocked_by} matches earlier in the same chain and drops "
                                     f"the traffic first, so the challenges behind {subnet} "
                                     "cannot be started")})
            continue
        # A live reply is stronger evidence than the rules: it also settles
        # routing, NAT rewriting and conntrack, which the rules cannot show.
        live = live_verdicts.get((address, int(port))) if str(port).isdigit() else None
        error = _name(live.get("error")) if isinstance(live, dict) else ""
        # The VM may have substituted a real router outside the walled-off
        # subnet for our stand-in address. That is a better source -- it exists,
        # so the reply has somewhere to return to -- but it only settles this
        # check if the same allow rule opens the provider from there too.
        stand_in_src = _name(live.get("src_used")) if isinstance(live, dict) else ""
        stand_in_covered = bool(
            stand_in_src and _allow_rule_opening(stand_in_src, address, port, allow_rules))
        if isinstance(live, dict) and live.get("reachable") and (not stand_in_src or stand_in_covered):
            reply = _name(live.get("reply"))
            proof = ("the target answered SYN-ACK" if reply == "syn-ack"
                     else "the target answered RST, so nothing is listening yet but the "
                          "path carries traffic")
            asked_from = (f"{_name(live.get('source')) or 'a router outside the subnet'} "
                          f"at {stand_in_src}" if stand_in_src
                          else _name(live.get('vantage')) or 'the participant-facing router')
            items.append({"name": label, "status": "pass",
                          "detail": (f"reachable from {origin} on port {port}; verified live "
                                     f"from {asked_from} "
                                     f"-- {proof} and the reply returned along the participant path")})
            continue
        # Anything short of a covered, answered probe from a source we chose
        # ourselves leaves this unverified rather than failed: the stand-in
        # stands for a participant network that does not exist here, so neither
        # its silence nor a reply the rule does not speak about can condemn the
        # real participant path.
        if isinstance(live, dict) and stand_in_src:
            unverified += 1
            if live.get("reachable"):
                reason = (f"the wire test answered from {stand_in_src}, which no allow rule for "
                          "this provider covers, so the reply says nothing about the rule under "
                          "test")
            else:
                reason = (f"asked from {stand_in_src}, a router outside the subnet standing in for the "
                          f"participant, and got no reply ({error or 'no reply'}); with no participant "
                          "network configured this does not show the real participant path is broken")
            if reason not in unverified_reasons:
                unverified_reasons.append(reason)
            items.append({"name": label, "status": "warn",
                          "detail": (f"an allow rule opens this provider from {origin} on port "
                                     f"{port}, but this was not confirmed on the wire: {reason}")})
            continue
        # A genuine silent path is a fault; a probe that could not run is not.
        if isinstance(live, dict) and not error.startswith("no node holds") and not error.startswith("cannot "):
            unreachable += 1
            items.append({"name": label, "status": "fail",
                          "detail": (f"an allow rule opens this provider from {origin}, but a live "
                                     f"probe from {_name(live.get('vantage')) or 'the participant-facing router'} "
                                     f"got no reply ({error or 'no reply'}); the rules "
                                     "permit it but traffic does not return, so check routing and NAT")})
            continue
        unverified += 1
        if error.startswith("no node holds"):
            reason = ("no router holds an interface on that source network, so there is no vantage "
                      "to send from; in that topology the rule analysis above is the whole answer")
        elif error.startswith("cannot "):
            reason = f"the live probe could not run on the vantage router ({error})"
        else:
            reason = "no live probe result was returned for this provider"
        if reason not in unverified_reasons:
            unverified_reasons.append(reason)
        items.append({"name": label, "status": "warn",
                      "detail": (f"an allow rule opens this provider from {origin} on port {port}, "
                                 f"but this was not confirmed on the wire: {reason}")})

    vantage = ("an address outside each walled-off subnet (no participant network is "
               "configured, so this does not prove the real participant network reaches them)"
               if used_stand_in else "the participant network")
    if unplaced or unreachable or shadowed:
        broken = unplaced + unreachable + shadowed
        return _result("pivot_access", "fail",
                       f"{broken} of {len(providers)} pivot provider(s) cannot be reached from "
                       f"{vantage}; the challenges behind those boundaries are unsolvable.", items)
    if unverified:
        # The rules permit it and nothing contradicts them, but no packet
        # confirmed it, so this must not read as a verified participant path.
        return _result("pivot_access", "warn",
                       f"{unverified} of {len(providers)} pivot provider(s) are opened to "
                       f"{vantage} by the rules, but were not confirmed on the wire: "
                       f"{'; '.join(unverified_reasons)}.", items)
    verified_from = ("a router outside each walled-off subnet" if used_stand_in
                     else "the participant-facing router")
    return _result("pivot_access", "pass",
                   f"All {len(providers)} pivot provider(s) reachable from {vantage}, verified "
                   f"live from {verified_from}.", items)


_HITL_PROBE_PY = '\nimport json, random, socket, struct, time\n\nSRC = "__SRC__"\nDST = "__DST__"\nPORT = int("__PORT__")\nBUDGET = float("__BUDGET__")\n\ndef _csum(data):\n    if len(data) % 2:\n        data += b"\\x00"\n    total = 0\n    for i in range(0, len(data), 2):\n        total += (data[i] << 8) + data[i + 1]\n    total = (total >> 16) + (total & 0xFFFF)\n    total += total >> 16\n    return (~total) & 0xFFFF\n\ndef _syn(src, dst, sport, dport, seq):\n    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(1, 65535), 0,\n                     64, socket.IPPROTO_TCP, 0,\n                     socket.inet_aton(src), socket.inet_aton(dst))\n    def _tcp(chk):\n        return struct.pack("!HHLLBBHHH", sport, dport, seq, 0, 5 << 4, 0x02, 5840, chk, 0)\n    pseudo = (socket.inet_aton(src) + socket.inet_aton(dst)\n              + struct.pack("!BBH", 0, socket.IPPROTO_TCP, 20))\n    return ip + _tcp(_csum(pseudo + _tcp(0)))\n\nout = {"src": SRC, "dst": DST, "port": PORT, "reachable": False,\n       "reply": "", "error": "", "attempts": 0}\n\ntry:\n    # SOCK_DGRAM strips the link-layer header, so this also works on the\n    # non-Ethernet links CORE sometimes puts between routers.\n    sniff = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))\n    sniff.settimeout(0.4)\nexcept Exception as exc:\n    out["error"] = "cannot sniff: %s" % exc\n    print(json.dumps(out))\n    raise SystemExit(0)\n\ntry:\n    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)\nexcept Exception as exc:\n    out["error"] = "cannot open raw socket: %s" % exc\n    print(json.dumps(out))\n    raise SystemExit(0)\n\nsrc_raw = socket.inet_aton(SRC)\ndst_raw = socket.inet_aton(DST)\ndeadline = time.time() + BUDGET\n\nfor attempt in range(1, 4):\n    out["attempts"] = attempt\n    sport = random.randint(20000, 60000)\n    try:\n        sender.sendto(_syn(SRC, DST, sport, PORT, random.randint(0, 2 ** 32 - 1)), (DST, 0))\n    except Exception as exc:\n        out["error"] = "send failed: %s" % exc\n        break\n    while time.time() < deadline:\n        try:\n            data = sniff.recv(2048)\n        except socket.timeout:\n            break\n        except Exception:\n            break\n        if len(data) < 20 or (data[0] >> 4) != 4 or data[9] != socket.IPPROTO_TCP:\n            continue\n        # The reply is addressed to the participant, so we only ever see it in\n        # transit -- match it on the exact four-tuple, reversed.\n        if data[12:16] != dst_raw or data[16:20] != src_raw:\n            continue\n        ihl = (data[0] & 0x0F) * 4\n        tcp = data[ihl:ihl + 20]\n        if len(tcp) < 20:\n            continue\n        sport_r, dport_r = struct.unpack("!HH", tcp[0:4])\n        if sport_r != PORT or dport_r != sport:\n            continue\n        flags = tcp[13]\n        if flags & 0x12 == 0x12:\n            out["reachable"] = True\n            out["reply"] = "syn-ack"\n        elif flags & 0x04:\n            out["reachable"] = True\n            out["reply"] = "rst"\n        else:\n            continue\n        break\n    if out["reachable"] or time.time() >= deadline:\n        break\n\nif not out["reachable"] and not out["error"]:\n    out["error"] = "no reply"\nprint(json.dumps(out))\n'


def hitl_participant_path_probe_script(sudo_password: str | None = None,
                                       session_id: Any = None,
                                       probes: Any = None,
                                       budget_seconds: float = 4.0) -> str:
    """VM-side live test of the participant -> provider path.

    Check 9 can only read the rules, because the participant sits behind a
    physical RJ45 that no namespace on this host owns. This gets as close as the
    scenario allows: from the router that holds an interface on the participant
    subnet, send a SYN carrying the participant's source address and watch the
    wire for the answer.

    Nothing is mutated and no address is claimed -- the reply is addressed to the
    participant and merely passes through this router, so it is observed in
    transit rather than received. A SYN-ACK or an RST both prove the round trip;
    only silence means the path is broken. That covers what rule analysis cannot
    see: routing, NAT rewriting and conntrack.
    """
    rows = [dict(item) for item in _as_list(probes) if isinstance(item, dict)]
    return (
        _remote_preamble(sudo_password, session_id)
        + "import ipaddress\n"
        + f"PROBES = {json.dumps(rows, separators=(',', ':'))}\n"
        + f"PROBE_PY = {json.dumps(_HITL_PROBE_PY)}\n"
        + f"BUDGET = {float(budget_seconds)!r}\n"
        + "def _holds(kind, name, address):\n"
        + "    for cidr in _node_cidrs(kind, name):\n"
        + "        try:\n"
        + "            if ipaddress.ip_address(address) in ipaddress.ip_network(cidr, strict=False):\n"
        + "                return True\n"
        + "        except Exception:\n"
        + "            continue\n"
        + "    return False\n"
        # A router interface that sits outside the walled-off subnet. Used when
        # the caller has no participant network and asked for a stand-in: it is
        # both a real source the reply can come back to and its own vantage.
        + "def _outside_router(nodes, subnet):\n"
        + "    try:\n"
        + "        walled = ipaddress.ip_network(subnet, strict=False)\n"
        + "    except Exception:\n"
        + "        return ('', '', '')\n"
        + "    for kind, name in nodes:\n"
        + "        if kind != 'vnode':\n"
        + "            continue\n"
        + "        for cidr in _node_cidrs(kind, name):\n"
        + "            try:\n"
        + "                addr = ipaddress.ip_interface(cidr).ip\n"
        + "            except Exception:\n"
        + "                continue\n"
        + "            if addr not in walled:\n"
        + "                return (kind, name, str(addr))\n"
        + "    return ('', '', '')\n"
        + "def main():\n"
        + "    nodes = _all_nodes()\n"
        + "    checks = []\n"
        + "    vantage_cache = {}\n"
        + "    outside_cache = {}\n"
        + "    for row in PROBES:\n"
        + "        src = str(row.get('src') or '')\n"
        + "        dst = str(row.get('dst') or '')\n"
        + "        port = row.get('port')\n"
        + "        base = {'src': src, 'dst': dst, 'port': port,\n"
        + "                'label': row.get('label') or '', 'vantage': ''}\n"
        + "        if not src or not dst or not port:\n"
        + "            base.update({'reachable': False, 'error': 'incomplete probe row'})\n"
        + "            checks.append(base); continue\n"
        # The router owning an interface on the participant subnet is the
        # closest point to the participant this host can enter.
        + "        if src not in vantage_cache:\n"
        + "            found = ('', '')\n"
        + "            for kind, name in nodes:\n"
        + "                if kind == 'vnode' and _holds(kind, name, src):\n"
        + "                    found = (kind, name); break\n"
        + "            vantage_cache[src] = found\n"
        + "        kind, name = vantage_cache[src]\n"
        # No router sits on the requested source network. When the caller asked
        # for a stand-in rather than a real participant address, any router
        # outside the walled-off subnet answers the same question, and using its
        # own address makes the source real instead of a fiction.
        + "        outside_of = str(row.get('outside_of') or '')\n"
        + "        if not name and outside_of:\n"
        + "            if outside_of not in outside_cache:\n"
        + "                outside_cache[outside_of] = _outside_router(nodes, outside_of)\n"
        + "            kind, name, picked = outside_cache[outside_of]\n"
        + "            if name and picked:\n"
        + "                src = picked\n"
        + "                base['src'] = src\n"
        + "                base['src_used'] = src\n"
        + "                base['source'] = 'router outside ' + outside_of\n"
        + "        if not name:\n"
        + "            base.update({'reachable': False,\n"
        + "                         'error': 'no node holds an interface on the participant subnet'})\n"
        + "            checks.append(base); continue\n"
        + "        base['vantage'] = name\n"
        + "        program = (PROBE_PY.replace('__SRC__', src).replace('__DST__', dst)\n"
        + "                   .replace('__PORT__', str(int(port))).replace('__BUDGET__', str(BUDGET)))\n"
        + "        rc, out = _nexec_python(kind, name, program, timeout=int(BUDGET) + 20)\n"
        + "        parsed = None\n"
        + "        try:\n"
        + "            parsed = json.loads(out.strip().splitlines()[-1])\n"
        + "        except Exception:\n"
        + "            parsed = None\n"
        + "        if not isinstance(parsed, dict):\n"
        + "            base.update({'reachable': False,\n"
        + "                         'error': 'probe produced no result: ' + str(out or '')[-200:]})\n"
        + "        else:\n"
        + "            base.update({'reachable': bool(parsed.get('reachable')),\n"
        + "                         'reply': parsed.get('reply') or '',\n"
        + "                         'error': parsed.get('error') or '',\n"
        + "                         'attempts': parsed.get('attempts') or 0})\n"
        + "        checks.append(base)\n"
        + "    print(json.dumps({'ok': True, 'checks': checks}))\n"
        + "main()\n"
    )


def _allow_rule_stand_in(address: str, port: Any, subnet: str,
                         allow_rules: list[dict[str, Any]]) -> str:
    """A stand-in source taken from whatever actually opens this provider.

    Asking from a documentation address only works when the rule opens the
    provider to everyone. A rule scoped to one source network does not cover
    that address, so the check reported "no allow rule opens this provider" --
    a hard failure produced entirely by our own choice of source. Reading the
    source out of the rule asks the question the scenario actually arranged
    for, and lands on a network the topology is likely to route.
    """
    try:
        walled = ipaddress.ip_network(_name(subnet), strict=False) if subnet else None
    except Exception:
        walled = None
    for rule in allow_rules:
        try:
            if int(rule.get("port")) != int(port):
                continue
        except (TypeError, ValueError):
            continue
        selector = _name(rule.get("src"))
        if not selector or selector in ("*", "0.0.0.0/0"):
            continue
        try:
            network = ipaddress.ip_network(selector, strict=False)
        except Exception:
            continue
        candidates = ([network.network_address] if network.prefixlen >= 31
                      else list(itertools.islice(network.hosts(), 1)))
        for candidate in candidates:
            if walled is not None and candidate in walled:
                continue
            if _allow_rule_opening(str(candidate), address, port, allow_rules):
                return str(candidate)
    return ""


def _outside_address(subnet: str) -> str:
    """An address that is definitely not inside `subnet`.

    Used when no participant network is configured and no allow rule names a
    source network: the provider still has to be reachable from somewhere
    outside the subnet it guards, and that is the same question with a stand-in
    for the participant.
    """
    try:
        net = ipaddress.ip_network(_name(subnet), strict=False)
    except Exception:
        return "203.0.113.1"
    for candidate in ("203.0.113.1", "198.51.100.1", "192.0.2.1"):
        if ipaddress.ip_address(candidate) not in net:
            return candidate
    return "203.0.113.1"


def _unaddressed_note(row: Any, node: str, role: str, consequence: str) -> str:
    """Why a node holds no address — the interfaces answer that, not the address.

    Three states look identical from an empty address list and need different
    fixes: the node has no interface beyond loopback, so it was created but
    never linked into the topology; it has interfaces that were never addressed
    (or lost their address, which is what a container restarted after execute
    looks like); or its interfaces could not be listed at all.
    """
    links = [_name(v) for v in _as_list(row.get(f"{role}_links")) if _name(v)]
    queried = bool(row.get(f"{role}_links_queried"))
    kind = _name(row.get("src_kind")) if role == "src" else ""
    if links:
        lost = (" (a container that restarted after execute comes up unconfigured)"
                if kind == "docker" else "")
        return (f"{node} has {', '.join(links)} but no IPv4 address on it, {consequence}: "
                f"its CORE addressing was never applied or has been lost{lost}")
    if queried:
        return (f"{node} has no network interface beyond loopback, {consequence}: the node is "
                "running but was never linked into the topology, so no address could be "
                "applied to it")
    return (f"{node} has no IPv4 address of its own and its interfaces could not be listed, "
            f"{consequence}: its CORE addressing was never applied or has been lost")


def _addressing_note(row: Any) -> str:
    """Say whether a failing flow is even aimed at an address that exists.

    "No route" has two causes that need opposite fixes. Either two correctly
    addressed nodes have no path between them — a routing or segmentation
    problem — or the flow targets an address no node in this session owns,
    which means the traffic artifacts were built against different addressing
    and no amount of routing will help. The endpoints' live addresses are the
    only thing that tells them apart, so report them here rather than leaving
    the reader to go and look.
    """
    if not isinstance(row, dict):
        return ""
    target = _name(row.get("ip"))
    dst_name = _name(row.get("dst"))
    src_name = _name(row.get("src"))
    dst_live = [_name(v) for v in _as_list(row.get("dst_live")) if _name(v)]
    src_live = [_name(v) for v in _as_list(row.get("src_live")) if _name(v)]
    if row.get("dst_ip_owned"):
        return ""
    # A node with no address of its own has no route to anywhere, which is a
    # node-configuration fault, not a traffic-plan one. Say that first: it is
    # the same evidence but a completely different fix.
    if "src_live" in row and not src_live:
        return f". {_unaddressed_note(row, src_name, 'src', 'so it has no route to anything')}"
    if not dst_live:
        # Regenerating the traffic plan cannot help an endpoint that holds no
        # address, so do not suggest it here.
        if dst_name and "dst_live" in row:
            return f". {_unaddressed_note(row, dst_name, 'dst', 'so nothing can reach it')}"
        return ""
    note = f". No running node holds {target}: {dst_name} is at {', '.join(dst_live)}"
    if src_live:
        note += f", and {src_name} is at {', '.join(src_live)}"
    note += (". This flow was generated against different addressing than the running "
             "session, so it cannot connect until the traffic artifacts are regenerated "
             "by an execute against this topology")
    return note


def reachability_result(probe: Any) -> dict[str, Any]:
    """Check 7: can each traffic source actually reach its destination?

    Each configured flow is tested on its own protocol and port, not with ping.
    Under a default-deny segmentation policy ICMP is usually not in the allow
    list, so pinging would report healthy, deliberately-permitted flows as
    broken.

    For TCP this also settles the return path. A completed handshake means the
    SYN arrived and the destination's SYN-ACK came back, which a one-way rule or
    an asymmetric route could not produce. UDP has no handshake, so the sender
    cannot tell whether anything arrived. For UDP the evidence comes from the
    receiving agent's own byte counter instead: the traffic agent labels each
    flow `<proto>-<src_id>-<dst_id>-<port>-tx|rx`, so the destination's `-rx`
    entry is a direct measurement of what landed. Bytes received settles the
    flow; bytes sent with none received is a real, silent failure that no
    sender-side test could see.
    """
    if not isinstance(probe, dict) or not probe.get("ok"):
        detail = _name(probe.get("error") or probe.get("raw")) if isinstance(probe, dict) else ""
        return _result("reachability", "error", detail or "reachability probe failed")
    ping = _as_list(probe.get("ping"))
    items: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    reachable_count = 0
    tcp_verified = 0
    arrival_confirmed = 0

    for row in ping:
        if not isinstance(row, dict):
            continue
        reachable = row.get("reachable")
        cmd = _name(row.get("cmd"))
        port = row.get("port")
        proto = _name(row.get("protocol")).upper()
        method = _name(row.get("method"))
        err = _name(row.get("error"))
        attempts = row.get("attempts")
        attempts_note = (f" after {attempts} attempts"
                         if isinstance(attempts, int) and attempts > 1 else "")
        flow_desc = f" [{proto or 'flow'}{':' + str(port) if port else ''}]"
        label = f"{row.get('src')} → {row.get('dst')} ({row.get('ip') or 'no ip'}){flow_desc}"

        # What the agents themselves measured. `received` is the only direct
        # evidence that a UDP datagram arrived, since UDP cannot report back.
        sent = row.get("bytes_sent")
        received = row.get("bytes_received")
        kbps = row.get("achieved_kbps")
        has_counters = isinstance(sent, int) or isinstance(received, int)
        arrived = isinstance(received, int) and received > 0
        sending = isinstance(sent, int) and sent > 0
        if arrived:
            arrival_confirmed += 1

        # A flow whose bytes are landing at the destination is confirmed,
        # whatever the sender-side probe could or could not tell.
        if arrived and reachable is None:
            reachable_count += 1
            rate = f" at {kbps} kbps" if isinstance(kbps, (int, float)) and kbps else ""
            items.append({"name": label, "status": "pass",
                          "detail": (f"confirmed at the destination: the receiving agent counted "
                                     f"{received:,} bytes{rate}")})
            continue
        # Sending with nothing arriving is a silent failure the sender cannot see.
        if sending and isinstance(received, int) and received == 0:
            failures.append(row)
            items.append({"name": label, "status": "fail",
                          "detail": (f"the sender has written {sent:,} bytes but the receiving "
                                     "agent has counted none, so this traffic is being dropped in "
                                     "flight. For UDP nothing reports this back to the sender — "
                                     "check for a segmentation rule covering this port, or a "
                                     "receiver that is not listening")})
            continue

        # Old probe payloads reported RST/ICMP-port-unreachable as proof of the
        # network path. That is useful for a route-only diagnostic, but required
        # traffic needs a listening receiver. Reject it even if an older probe
        # marked the host response reachable.
        if err in ("refused", "icmp-port-unreachable"):
            failures.append(row)
            status = "fail"
            if err == "refused":
                detail = (f"the target host replied{attempts_note}, but refused the required TCP connection; "
                          "the destination service is not listening")
            else:
                detail = (f"the target host returned ICMP port-unreachable{attempts_note}; no UDP receiver is "
                          "listening for this required flow")
            if cmd:
                detail += f". Reproduce: {cmd}"
            items.append({"name": label, "status": status, "detail": detail})
            continue

        if reachable is True:
            reachable_count += 1
            status = "pass"
            if method == "tcp-handshake":
                tcp_verified += 1
                detail = ("TCP handshake completed — the path works in both directions "
                          "(the destination's SYN-ACK came back)")
                if arrived:
                    detail += f"; the receiving agent has counted {received:,} bytes"
            else:
                detail = "reachable"
        elif reachable is False:
            failures.append(row)
            status = "fail"
            icmp = row.get("icmp")
            if err == "no-route":
                detail = (f"no route to the destination{attempts_note} — the source cannot reach that network at all")
                detail += _addressing_note(row)
            elif icmp is True:
                detail = (f"the host answers ping but the {proto or 'flow'} port is filtered or closed"
                          f"{attempts_note}, "
                          "so this flow cannot carry data. Look for a segmentation rule covering "
                          "this port")
            else:
                detail = (f"the {proto or 'flow'} flow cannot reach its destination{attempts_note} and the host does "
                          "not answer ping either, so the whole path is blocked")
            if cmd:
                detail += f". Reproduce: {cmd}"
        else:
            status = "fail"
            failures.append(row)
            why = _name(row.get("why"))
            if why:
                detail = why
            elif method == "udp-send":
                detail = ("required UDP delivery was not confirmed at the destination")
                if not has_counters:
                    detail += (": no receiving-agent counters were readable for this flow")
                elif not sending:
                    detail += (": the sending agent has written no bytes")
                else:
                    detail += (": sender counters exist, but no receiving byte count is available")
            else:
                detail = err or "required flow has no successful protocol/port probe"
            if cmd:
                detail += f". Reproduce: {cmd}"
        items.append({"name": label, "status": status, "detail": detail})

    if not ping:
        summary = probe.get("summary") if isinstance(probe.get("summary"), dict) else {}
        configured = [f for f in _as_list(summary.get("flows")) if isinstance(f, dict)]
        if configured:
            return _result(
                "reachability", "fail",
                f"No runtime results were produced for {len(configured)} configured traffic flow(s).",
                items,
            )
        return _result("reachability", "skip",
                       "No traffic flows configured, so there are no source → destination pairs to verify.",
                       items)
    if failures:
        first_cmd = _name(failures[0].get("cmd"))
        tail = f" First: {first_cmd}" if first_cmd else ""
        return _result("reachability", "fail",
                       f"{reachable_count} of {len(ping)} traffic flow(s) confirmed; "
                       f"{len(failures)} required flow(s) are not delivering.{tail}", items)
    notes = []
    if tcp_verified:
        notes.append(f"{tcp_verified} TCP flow(s) verified in both directions")
    if arrival_confirmed:
        notes.append(f"{arrival_confirmed} confirmed by bytes counted at the destination")
    note = f" ({'; '.join(notes)}.)" if notes else ""
    return _result("reachability", "pass",
                   f"All {reachable_count} required traffic flow(s) reach their destination.{note}",
                   items)


# --------------------------------------------------------------------------- #
# Overall roll-up
# --------------------------------------------------------------------------- #

def overall_status(results: list[dict[str, Any]]) -> str:
    statuses = {_name(r.get("status")) for r in results if isinstance(r, dict)}
    if statuses & _FAILING:
        return "fail"
    if "warn" in statuses:
        return "warn"
    if "pending" in statuses or "running" in statuses:
        return "running"
    return "pass"


def overall_summary(results: list[dict[str, Any]]) -> str:
    counts: dict[str, int] = {}
    for r in results:
        if isinstance(r, dict):
            counts[_name(r.get("status"))] = counts.get(_name(r.get("status")), 0) + 1
    order = ["pass", "warn", "fail", "error", "skip"]
    parts = [f"{counts[s]} {s}" for s in order if counts.get(s)]
    return ", ".join(parts) if parts else "no checks run"
