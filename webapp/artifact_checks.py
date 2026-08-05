"""Pure, Flask-free helpers for the CORE "Check Artifacts" feature.

The Check Artifacts button on a running session runs seven ordered checks against
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
8. pivot access - every pivot provider is reachable from the participant, so
                  the challenges behind a segmentation boundary stay solvable

Checks 1-4 are derived from the existing post-execution validator
(`_validate_session_nodes_and_injects`). Checks 5-7 are live probes executed on
the CORE VM over SSH. This module keeps the probe-script text, the
validator-summary mapping, and the result shaping side-effect-free so they can
be unit-tested without a live CORE VM. The orchestration/threading and SSH calls
live in ``app_backend``.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any


# Ordered (key, label) for the six checks. The order is the progress order.
CHECK_ORDER: list[tuple[str, str]] = [
    ("containers", "Containers running on correct nodes"),
    ("services", "Services running"),
    ("ports", "Ports open"),
    ("injects", "Inject files placed"),
    ("segmentation", "Firewall/segmentation rules in place"),
    ("traffic", "Traffic agents running"),
    ("reachability", "Nodes reachable (traffic source → destination)"),
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
    items: list[dict[str, Any]] = []
    for node in running:
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
        "import json, subprocess, glob, os, stat\n"
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
        "def _node_addr(kind, name):\n"
        "    def _cidrs(output):\n"
        "        return [line.strip() for line in output.splitlines()\n"
        "                if '/' in line.strip() and line.strip().split('/', 1)[0].count('.') == 3]\n"
        "    rc, out = _nexec(kind, name, ['sh','-lc',\"ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}'\"])\n"
        "    cidrs = _cidrs(out) if rc == 0 else []\n"
        "    # Minimal workload images may omit iproute2. Inspect the container's\n"
        "    # network namespace from the CORE VM instead of losing its identity.\n"
        "    if not cidrs and kind == 'docker':\n"
        "        rc, pid = _run(['docker','inspect','-f','{{.State.Pid}}',name])\n"
        "        pid = pid.strip()\n"
        "        if rc == 0 and pid.isdigit() and int(pid) > 0:\n"
        "            rc, out = _run(['nsenter','-t',pid,'-n','ip','-4','-o','addr','show','scope','global'])\n"
        "            if rc == 0:\n"
        "                cidrs = _cidrs('\\n'.join(line.split()[3] if len(line.split()) > 3 else '' for line in out.splitlines()))\n"
        "    if not cidrs:\n"
        "        return '', ''\n"
        "    return cidrs[0].split('/', 1)[0], cidrs[0]\n"
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
        + "    rc, out = _nexec(kind, name, ['python3','-c', LISTEN_PY])\n"
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
        + "        rc, out = _nexec(kind_of.get(pname), pname, ['python3','-c', conn], timeout=120)\n"
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
        + "        nodes[name] = {\n"
        + "            'kind': kind,\n"
        + "            'rules_present': bool(non_default),\n"
        + "            'marker': ('custom-seg' in out) or ('scenarioforge' in out.lower()),\n"
        + "            'rule_count': len(non_default),\n"
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
                         traffic_dirs: list[str] | None = None) -> str:
    """VM-side script: report the traffic summary artifact and generated traffic
    scripts, traffic processes and CORE IP inside every node (Docker + vnode),
    and reachability along each configured flow. Each ping row carries the exact
    command to reproduce it.

    Only the runtime directory is inspected. ``/tmp/scenarioforge-preview-traffic-*``
    holds plan-time scripts produced during preview that are never deployed, so
    counting them would report running traffic for a scenario that has none.
    """
    dirs = traffic_dirs or ["/tmp/traffic"]
    dirs_literal = json.dumps(dirs)
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
    return (
        _remote_preamble(sudo_password, session_id)
        + f"TRAFFIC_DIRS = {dirs_literal}\n"
        + f"PROC_SCAN = {json.dumps(proc_scan_sh)}\n"
        + f"AGENT_FRESH_S = {int(_AGENT_STATS_FRESH_S)}\n"
        + "import datetime as _dt\n"
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
        + "FLOW_PY = " + '"import json, socket, errno\\ndef one(ip, port, proto):\\n    if proto == \'TCP\' and port:\\n        try:\\n            s = socket.create_connection((ip, int(port)), 3.0); s.close()\\n            return [True, \'tcp-handshake\', \'\']\\n        except socket.timeout:\\n            return [False, \'tcp-handshake\', \'timeout\']\\n        except OSError as e:\\n            c = getattr(e, \'errno\', None)\\n            if c == errno.ECONNREFUSED:\\n                return [True, \'tcp-handshake\', \'refused\']\\n            if c in (errno.EHOSTUNREACH, errno.ENETUNREACH):\\n                return [False, \'tcp-handshake\', \'no-route\']\\n            return [False, \'tcp-handshake\', \'error\']\\n    if proto == \'UDP\' and port:\\n        try:\\n            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2.0)\\n            s.connect((ip, int(port))); s.send(b\'\\\\x00\' * 32)\\n            try:\\n                s.recv(1)\\n            except socket.timeout:\\n                pass\\n            except OSError as e2:\\n                c2 = getattr(e2, \'errno\', None)\\n                if c2 == errno.ECONNREFUSED:\\n                    s.close(); return [True, \'udp-send\', \'icmp-port-unreachable\']\\n                if c2 in (errno.EHOSTUNREACH, errno.ENETUNREACH):\\n                    s.close(); return [False, \'udp-send\', \'no-route\']\\n            s.close(); return [None, \'udp-send\', \'sent\']\\n        except OSError as e:\\n            c = getattr(e, \'errno\', None)\\n            if c in (errno.EHOSTUNREACH, errno.ENETUNREACH):\\n                return [False, \'udp-send\', \'no-route\']\\n            return [None, \'udp-send\', \'error\']\\n    return [None, \'none\', \'flow has no protocol/port to test\']\\nR = []\\nfor ip, port, proto, dname in ROWS:\\n    ok, method, err = one(ip, port, (proto or \'\').upper())\\n    R.append([ip, port, proto, dname, ok, method, err])\\nprint(json.dumps(R))\\n"' + "\n"
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
        + "    if str(proto or '').upper() == 'TCP' and port:\n"
        + "        inner = 'python3 -c \\'import socket; socket.create_connection((\\\"' + str(ip) + '\\\", ' + str(port) + '), 3)\\''\n"
        + "    else:\n"
        + "        inner = 'ping -c3 -W2 ' + str(ip)\n"
        + "    if kind == 'docker':\n"
        + "        return 'sudo docker exec ' + name + ' ' + inner\n"
        + "    return 'sudo vcmd -c ' + os.path.join(PYCORE, name) + ' -- ' + inner\n"
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
        + "        nodes[name] = {'kind': kind, 'procs': procs, 'ip': _ip(kind, name),\n"
        + "                       'agent': _node_agent(kind, name)}\n"
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
        + "        ip = nodes.get(name, {}).get('ip') or ''\n"
        + "        if ip and ip not in by_ip:\n"
        + "            by_ip[ip] = (kind, name)\n"
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
        + "        if not s_ip or not d_ip or key in seen:\n"
        + "            continue\n"
        + "        seen.add(key)\n"
        + "        dst_name = (by_ip.get(d_ip) or (None, d_ip))[1]\n"
        + "        src = by_ip.get(s_ip)\n"
        + "        if not src:\n"
        + "            ping.append({'src': s_ip, 'dst': dst_name, 'ip': d_ip, 'reachable': None,\n"
        + "                         'cmd': '', 'port': port, 'protocol': proto,\n"
        + "                         'why': 'traffic source node not found for ' + s_ip})\n"
        + "            continue\n"
        + "        plan.setdefault(src[1], []).append([d_ip, port, proto, dst_name])\n"
        + "        flow_meta[(d_ip, str(port), proto)] = {\n"
        + "            'src_id': flow.get('src_id'), 'dst_id': flow.get('dst_id'),\n"
        + "            'dst_name': dst_name, 'src_name': src[1]}\n"
        + "    kind_of = dict((name, kind) for kind, name in alln)\n"
        + "    for sn, rows in plan.items():\n"
        + "        sk = kind_of.get(sn)\n"
        + "        prog = 'ROWS = ' + json.dumps(rows) + '\\n' + FLOW_PY\n"
        + "        rc, out = _nexec(sk, sn, ['python3','-c', prog], timeout=90)\n"
        + "        try:\n"
        + "            results = json.loads(out.strip().splitlines()[-1])\n"
        + "        except Exception:\n"
        + "            results = []\n"
        + "        for d_ip, port, proto, dst_name, ok, method, err in results:\n"
        + "            row = {'src': sn, 'dst': dst_name, 'ip': d_ip, 'port': port,\n"
        + "                   'protocol': proto, 'reachable': ok, 'method': method, 'error': err,\n"
        + "                   'cmd': _repro_flow(sk, sn, d_ip, port, proto)}\n"
        + "            if ok is False:\n"
        + "                # Only now is ping worth running: it separates \"no route at\n"
        + "                # all\" from \"route fine, this port filtered\".\n"
        + "                rc2, out2 = _nexec(sk, sn, ['sh','-lc','ping -c1 -W1 '+d_ip+' >/dev/null 2>&1 && echo OK || echo NO'])\n"
        + "                row['icmp'] = ('OK' in out2)\n"
        + "            meta = flow_meta.get((d_ip, str(port), proto)) or {}\n"
        + "            row.update(_arrival(meta, port, proto, kind_of))\n"
        + "            ping.append(row)\n"
        + "    print(json.dumps({'ok': True, 'traffic_files': traffic_files, 'stale_files': traffic_stale, 'summary': summary, 'nodes': nodes, 'ping': ping}))\n"
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
        return _result("segmentation", "skip",
                       "Segmentation is enabled for this scenario but generated no rules.", items)
    return _result("segmentation", "skip", "No segmentation configured for this scenario.", items)


def traffic_result(probe: Any, *, expected: bool) -> dict[str, Any]:
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

    # Nodes that a flow names as a sender but where no traffic process is running.
    expected_senders: set[str] = set()
    ip_to_node: dict[str, str] = {}
    live_nodes = set(nodes_with_procs)
    for node, info in nodes.items():
        if not isinstance(info, dict):
            continue
        ip = _name(info.get("ip"))
        if not ip:
            continue
        current = ip_to_node.get(ip)
        # Old probe payloads may include an internal Compose child that shares
        # its CORE parent's address. Prefer the node with the live traffic
        # agent instead of allowing dictionary order to choose the child.
        if current is None or (node in live_nodes and current not in live_nodes):
            ip_to_node[ip] = node
    for flow in flows:
        if isinstance(flow, dict):
            node = ip_to_node.get(_name(flow.get("src_ip")))
            if node:
                expected_senders.add(node)
    missing_senders = sorted(expected_senders - set(nodes_with_procs))
    for node in missing_senders:
        agent = _agent(nodes.get(node))
        if agent.get("present"):
            age = agent.get("age_s")
            when = f" (last update {int(age)}s ago)" if isinstance(age, (int, float)) else ""
            detail = ("flow names this node as a traffic source; its agent ran but has "
                      f"stopped updating stats{when}")
        else:
            detail = "flow names this node as a traffic source, but no traffic process is running"
        items.append({"name": node, "status": "warn", "detail": detail})

    # A receiver whose agent died is just as broken as a sender's, and nothing
    # above would catch it: expected_senders only covers flow sources.
    stopped_others = [n for n in nodes_agent_stopped if n not in set(missing_senders)]
    for node in stopped_others:
        age = _agent(nodes[node]).get("age_s")
        when = f" (last update {int(age)}s ago)" if isinstance(age, (int, float)) else ""
        items.append({"name": node, "status": "warn",
                      "detail": f"traffic agent ran but has stopped updating stats{when}"})

    # The runtime traffic_summary.json is authoritative about whether traffic was
    # actually configured — the scenario XML's Traffic section can carry a
    # non-zero density with no concrete flows. A present-but-empty summary means
    # no traffic, regardless of the XML. Only when the artifact is missing
    # entirely do we fall back to the scenario's declared intent.
    traffic_configured = bool(flows or traffic_files or nodes_with_procs)
    summary_missing = summary is None and not traffic_files and not nodes_with_procs

    if missing_senders:
        return _result("traffic", "warn",
                       f"{len(nodes_with_procs)} node(s) running traffic; {len(missing_senders)} "
                       "expected sender(s) have no traffic process.", items)
    if stopped_others:
        return _result("traffic", "warn",
                       f"{len(nodes_with_procs)} node(s) running traffic; {len(stopped_others)} "
                       "node(s) have a stopped traffic agent.", items)
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
        return _result("traffic", "warn",
                       "The scenario declares traffic, but no runtime traffic_summary.json was found. "
                       "Confirm traffic generation ran during execute.", items)
    return _result("traffic", "skip", "No traffic configured for this scenario.", items)


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


def pivot_access_result(segmentation: Any, participant_subnets: Any = None) -> dict[str, Any]:
    """Check 8: can the participant reach each pivot provider?

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
            "(a step producing Pivot(node)) are a separate feature and are not "
            "measured here; turn on accessible_by_pivot in the Segmentation section "
            "if you want walled-off subnets given an entrance.")

    allow_rules = _segmentation_allow_rules(segmentation)
    sources = participant_probe_sources(participant_subnets)
    items: list[dict[str, Any]] = []
    unreachable = 0
    unplaced = 0

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
            probes = [_outside_address(subnet)]
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
        else:
            items.append({"name": label, "status": "pass",
                          "detail": f"reachable from {origin} on port {port}"})

    if unplaced or unreachable:
        broken = unplaced + unreachable
        return _result("pivot_access", "fail",
                       f"{broken} of {len(providers)} pivot provider(s) cannot be reached by the "
                       f"participant; the challenges behind those boundaries are unsolvable.", items)
    return _result("pivot_access", "pass",
                   f"All {len(providers)} pivot provider(s) reachable from the participant.", items)


def _outside_address(subnet: str) -> str:
    """An address that is definitely not inside `subnet`.

    Used when no participant network is configured: the provider still has to be
    reachable from somewhere outside the subnet it guards, and that is the same
    question with a stand-in for the participant.
    """
    try:
        net = ipaddress.ip_network(_name(subnet), strict=False)
    except Exception:
        return "203.0.113.1"
    for candidate in ("203.0.113.1", "198.51.100.1", "192.0.2.1"):
        if ipaddress.ip_address(candidate) not in net:
            return candidate
    return "203.0.113.1"


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
    unreachable: list[dict[str, Any]] = []
    reachable_count = 0
    tcp_verified = 0
    unconfirmed = 0
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
            unreachable.append(row)
            items.append({"name": label, "status": "warn",
                          "detail": (f"the sender has written {sent:,} bytes but the receiving "
                                     "agent has counted none, so this traffic is being dropped in "
                                     "flight. For UDP nothing reports this back to the sender — "
                                     "check for a segmentation rule covering this port, or a "
                                     "receiver that is not listening")})
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
                if err == "refused":
                    detail = ("host replied (RST), so the path works in both directions, but "
                              "nothing is listening on this port right now")
            elif err == "icmp-port-unreachable":
                detail = "datagram arrived (destination replied ICMP port-unreachable)"
            else:
                detail = "reachable"
        elif reachable is False:
            unreachable.append(row)
            status = "warn"
            icmp = row.get("icmp")
            if err == "no-route":
                detail = ("no route to the destination — the source cannot reach that network at all")
            elif icmp is True:
                detail = (f"the host answers ping but the {proto or 'flow'} port is filtered or closed, "
                          "so this flow cannot carry data. Look for a segmentation rule covering "
                          "this port")
            else:
                detail = (f"the {proto or 'flow'} flow cannot reach its destination and the host does "
                          "not answer ping either, so the whole path is blocked")
            if cmd:
                detail += f". Reproduce: {cmd}"
        else:
            status = "skip"
            unconfirmed += 1
            why = _name(row.get("why"))
            if why:
                detail = why
            elif method == "udp-send":
                detail = ("UDP datagram sent with no routing error; UDP is connectionless so "
                          "delivery cannot be confirmed from the sender")
                if not has_counters:
                    detail += (". No agent counters were readable for this flow, so arrival "
                               "could not be confirmed at the destination either")
                elif not sending:
                    detail += (". The sending agent has written no bytes yet, so there is "
                               "nothing for the destination to receive")
            else:
                detail = "flow has no protocol/port to test"
        items.append({"name": label, "status": status, "detail": detail})

    if not ping:
        return _result("reachability", "skip",
                       "No traffic flows configured, so there are no source → destination pairs to verify.",
                       items)
    if unreachable:
        first_cmd = _name(unreachable[0].get("cmd"))
        tail = f" First: {first_cmd}" if first_cmd else ""
        return _result("reachability", "warn",
                       f"{reachable_count} of {len(ping)} traffic flow(s) confirmed; "
                       f"{len(unreachable)} cannot reach their destination.{tail}", items)
    notes = []
    if tcp_verified:
        notes.append(f"{tcp_verified} TCP flow(s) verified in both directions")
    if arrival_confirmed:
        notes.append(f"{arrival_confirmed} confirmed by bytes counted at the destination")
    if unconfirmed:
        notes.append(f"{unconfirmed} UDP flow(s) sent but not confirmable")
    note = f" ({'; '.join(notes)}.)" if notes else ""
    return _result("reachability", "pass",
                   f"All {reachable_count} testable traffic flow(s) reach their destination.{note}",
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
