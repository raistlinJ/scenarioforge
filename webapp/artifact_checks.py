"""Pure, Flask-free helpers for the CORE "Check Artifacts" feature.

The Check Artifacts button on a running session runs six ordered checks against
the live CORE session:

1. containers   - the expected containers are running on the correct nodes
2. services     - the services that should be running are running
3. ports        - the ports that should be open are open
4. injects      - inject files are present in the right location on the nodes
5. segmentation - firewall/segmentation rules are in place
6. traffic      - traffic scripts are running and nodes are reachable (ping)

Checks 1-4 are derived from the existing post-execution validator
(`_validate_session_nodes_and_injects`). Checks 5-6 are live probes executed on
the CORE VM over SSH. This module keeps the probe-script text, the
validator-summary mapping, and the result shaping side-effect-free so they can
be unit-tested without a live CORE VM. The orchestration/threading and SSH calls
live in ``app_backend``.
"""

from __future__ import annotations

import json
from typing import Any


# Ordered (key, label) for the six checks. The order is the progress order.
CHECK_ORDER: list[tuple[str, str]] = [
    ("containers", "Containers running on correct nodes"),
    ("services", "Services running"),
    ("ports", "Ports open"),
    ("injects", "Inject files placed"),
    ("segmentation", "Firewall/segmentation rules in place"),
    ("traffic", "Traffic scripts running & nodes reachable"),
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


def ports_result(summary: dict[str, Any]) -> dict[str, Any]:
    unavailable = _validation_unavailable(summary)
    if unavailable:
        return _result("ports", "error", unavailable)
    checked = _as_list(summary.get("ports_checked"))
    unreachable = _as_list(summary.get("port_unreachable"))
    topo_unreachable = _as_list(summary.get("topology_port_unreachable"))
    details = _as_list(summary.get("port_unreachable_details"))
    items: list[dict[str, Any]] = []
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
    if not checked and not unreachable and not topo_unreachable:
        return _result("ports", "skip", "No ports to check for this scenario.", items)
    bad = len(unreachable) + len(topo_unreachable)
    if bad:
        return _result("ports", "fail", f"{bad} port target(s) unreachable.", items)
    return _result("ports", "pass", f"All {len(checked)} checked port target(s) reachable.", items)


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
        "def _containers():\n"
        "    rc, out = _run(['docker','ps','--format','{{.Names}}'])\n"
        "    return [l.strip() for l in out.splitlines() if l.strip() and 'inject_copy' not in l] if rc == 0 else []\n"
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
    )


def segmentation_probe_script(sudo_password: str | None = None,
                              session_id: Any = None,
                              seg_dirs: list[str] | None = None) -> str:
    """VM-side script: report the segmentation verification artifact and any
    generated scripts on the VM, plus firewall rules inside every node (Docker
    nodes via ``docker exec``, CORE vnodes via ``vcmd``)."""
    dirs = seg_dirs or ["/tmp/segmentation", "/tmp/scenarioforge-preview-seg-*"]
    dirs_literal = json.dumps(dirs)
    return (
        _remote_preamble(sudo_password, session_id)
        + f"SEG_DIRS = {dirs_literal}\n"
        + "def main():\n"
        + "    seg_files = []\n"
        + "    verification = None\n"
        + "    for d in SEG_DIRS:\n"
        + "        for path in glob.glob(d):\n"
        + "            if os.path.isdir(path):\n"
        + "                for f in os.listdir(path):\n"
        + "                    fp = os.path.join(path, f)\n"
        + "                    if f.endswith('.json'):\n"
        + "                        if ('verif' in f.lower() or 'allow' in f.lower()) and verification is None:\n"
        + "                            verification = _read_json(fp)\n"
        + "                    else:\n"
        + "                        seg_files.append(fp)\n"
        + "            elif os.path.isfile(path):\n"
        + "                seg_files.append(path)\n"
        + "    nodes = {}\n"
        + "    for kind, name in _all_nodes():\n"
        + "        rc, out = _nexec(kind, name, ['sh','-lc','iptables -S 2>/dev/null || nft list ruleset 2>/dev/null'])\n"
        + "        rules = [l for l in out.splitlines() if l.strip()]\n"
        + "        non_default = [l for l in rules if not l.strip().startswith('-P ') and l.strip() not in ('-N DOCKER','')]\n"
        + "        nodes[name] = {\n"
        + "            'kind': kind,\n"
        + "            'rules_present': bool(non_default),\n"
        + "            'marker': ('custom-seg' in out) or ('scenarioforge' in out.lower()),\n"
        + "            'rule_count': len(non_default),\n"
        + "        }\n"
        + "    print(json.dumps({'ok': True, 'seg_files': seg_files, 'verification': verification, 'nodes': nodes}))\n"
        + "main()\n"
    )


def traffic_probe_script(sudo_password: str | None = None,
                         session_id: Any = None,
                         traffic_dirs: list[str] | None = None) -> str:
    """VM-side script: report the traffic summary artifact and generated traffic
    scripts, traffic processes and CORE IP inside every node (Docker + vnode),
    and a ping matrix from a prober node to every other node's IP. Each ping row
    carries the exact command to reproduce it."""
    dirs = traffic_dirs or ["/tmp/traffic", "/tmp/scenarioforge-preview-traffic-*"]
    dirs_literal = json.dumps(dirs)
    return (
        _remote_preamble(sudo_password, session_id)
        + f"TRAFFIC_DIRS = {dirs_literal}\n"
        + "def _ip(kind, name):\n"
        + "    rc, out = _nexec(kind, name, ['sh','-lc',\"ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1\"])\n"
        + "    ips = [l.strip() for l in out.splitlines() if l.strip()]\n"
        + "    return ips[0] if ips else ''\n"
        + "def _repro(kind, name, ip):\n"
        + "    if kind == 'docker':\n"
        + "        return 'sudo docker exec ' + name + ' ping -c3 -W2 ' + ip\n"
        + "    return 'sudo vcmd -c ' + os.path.join(PYCORE, name) + ' -- ping -c3 -W2 ' + ip\n"
        + "def main():\n"
        + "    traffic_files = []\n"
        + "    summary = None\n"
        + "    for d in TRAFFIC_DIRS:\n"
        + "        for path in glob.glob(d):\n"
        + "            if os.path.isdir(path):\n"
        + "                for f in os.listdir(path):\n"
        + "                    fp = os.path.join(path, f)\n"
        + "                    if f.endswith('.json'):\n"
        + "                        if 'summary' in f.lower() and summary is None:\n"
        + "                            summary = _read_json(fp)\n"
        + "                    elif f.startswith('traffic_'):\n"
        + "                        traffic_files.append(fp)\n"
        + "            elif os.path.isfile(path):\n"
        + "                traffic_files.append(path)\n"
        + "    alln = _all_nodes()\n"
        + "    nodes = {}\n"
        + "    for kind, name in alln:\n"
        + "        rc, out = _nexec(kind, name, ['sh','-lc','pgrep -fa traffic_ 2>/dev/null || pgrep -af traffic_ 2>/dev/null'])\n"
        + "        procs = [l.strip() for l in out.splitlines() if 'traffic_' in l and 'pgrep' not in l]\n"
        + "        nodes[name] = {'kind': kind, 'procs': procs, 'ip': _ip(kind, name)}\n"
        + "    ping = []\n"
        + "    prober = alln[0] if alln else None\n"
        + "    if prober:\n"
        + "        pk, pn = prober\n"
        + "        for kind, name in alln:\n"
        + "            if name == pn:\n"
        + "                continue\n"
        + "            ip = nodes.get(name, {}).get('ip') or ''\n"
        + "            if not ip:\n"
        + "                ping.append({'src': pn, 'dst': name, 'ip': '', 'reachable': None, 'cmd': ''})\n"
        + "                continue\n"
        + "            rc, out = _nexec(pk, pn, ['sh','-lc','ping -c1 -W1 '+ip+' >/dev/null 2>&1 && echo OK || echo NO'])\n"
        + "            ping.append({'src': pn, 'dst': name, 'ip': ip, 'reachable': ('OK' in out), 'cmd': _repro(pk, pn, ip)})\n"
        + "    print(json.dumps({'ok': True, 'traffic_files': traffic_files, 'summary': summary, 'nodes': nodes, 'ping': ping, 'prober': (prober[1] if prober else '')}))\n"
        + "main()\n"
    )


def _flows_total(verification: Any) -> int | None:
    if not isinstance(verification, dict):
        return None
    total = verification.get("flows_total")
    return total if isinstance(total, int) else None


def segmentation_result(probe: Any, *, expected: bool) -> dict[str, Any]:
    if not isinstance(probe, dict) or not probe.get("ok"):
        detail = _name(probe.get("error") or probe.get("raw")) if isinstance(probe, dict) else ""
        return _result("segmentation", "error", detail or "segmentation probe failed")
    seg_files = _as_list(probe.get("seg_files"))
    verification = probe.get("verification") if isinstance(probe.get("verification"), dict) else None
    nodes = probe.get("nodes") if isinstance(probe.get("nodes"), dict) else {}
    nodes_with_rules = [n for n, info in nodes.items() if isinstance(info, dict) and info.get("rules_present")]
    items: list[dict[str, Any]] = []

    # The execute-time verification artifact is the authoritative signal for
    # compose port-allow segmentation: it records how many restricted flows
    # exist and how many were confirmed blocked.
    flows_total = _flows_total(verification)
    verified_status = ""
    if flows_total is not None and verification is not None:
        blocked = _as_list(verification.get("blocked"))
        blocked_count = verification.get("blocked_count")
        if not isinstance(blocked_count, int):
            blocked_count = len(blocked)
        if flows_total > 0:
            verified_status = "pass" if blocked_count >= flows_total else "fail"
            items.append({
                "name": "segmentation enforcement",
                "status": verified_status,
                "detail": f"{blocked_count}/{flows_total} restricted flow(s) verified blocked",
            })
        else:
            items.append({
                "name": "segmentation enforcement",
                "status": "skip",
                "detail": "no cross-node restricted flows to enforce",
            })

    if seg_files:
        items.append({"name": "CORE VM", "status": "pass",
                      "detail": f"{len(seg_files)} segmentation script(s) generated"})
    for node, info in sorted(nodes.items()):
        if not isinstance(info, dict):
            continue
        present = bool(info.get("rules_present"))
        # Nodes legitimately carry no custom firewall rules, so absence is
        # informational (skip), not a warning.
        items.append({
            "name": f"{node} ({info.get('kind', '?')})",
            "status": "pass" if present else "skip",
            "detail": (f"{info.get('rule_count', 0)} firewall rule(s) applied"
                       + (" [marker]" if info.get("marker") else "")) if present
                      else "no custom firewall rules",
        })

    # Decision, most authoritative signal first.
    if verified_status == "fail":
        blocked_count = verification.get("blocked_count") if isinstance(verification, dict) else None
        return _result("segmentation", "fail",
                       f"Segmentation not fully enforced: only {blocked_count} of {flows_total} "
                       "restricted flow(s) are blocked.", items)
    if verified_status == "pass":
        return _result("segmentation", "pass",
                       f"Segmentation enforced: all {flows_total} restricted flow(s) blocked.", items)
    if not expected:
        return _result("segmentation", "skip",
                       "No segmentation configured for this scenario.", items)
    if flows_total == 0:
        return _result("segmentation", "skip",
                       "Segmentation configured, but it produced no cross-node restricted flows to enforce.", items)
    if seg_files or nodes_with_rules:
        return _result("segmentation", "pass",
                       f"Segmentation in place ({len(seg_files)} script(s), "
                       f"{len(nodes_with_rules)} node(s) with rules).", items)
    return _result("segmentation", "fail",
                   "Segmentation is configured but no verification artifact, rules, or scripts were found.", items)


def traffic_result(probe: Any, *, expected: bool) -> dict[str, Any]:
    if not isinstance(probe, dict) or not probe.get("ok"):
        detail = _name(probe.get("error") or probe.get("raw")) if isinstance(probe, dict) else ""
        return _result("traffic", "error", detail or "traffic probe failed")
    traffic_files = _as_list(probe.get("traffic_files"))
    summary = probe.get("summary") if isinstance(probe.get("summary"), dict) else None
    flows = _as_list(summary.get("flows")) if isinstance(summary, dict) else []
    nodes = probe.get("nodes") if isinstance(probe.get("nodes"), dict) else {}
    ping = _as_list(probe.get("ping"))
    nodes_with_procs = [n for n, info in nodes.items() if isinstance(info, dict) and _as_list(info.get("procs"))]
    items: list[dict[str, Any]] = []

    if flows:
        items.append({"name": "traffic flows", "status": "pass",
                      "detail": f"{len(flows)} configured flow(s) recorded"})
    if traffic_files:
        items.append({"name": "CORE VM", "status": "pass",
                      "detail": f"{len(traffic_files)} traffic script(s) generated"})
    for node in sorted(nodes_with_procs):
        count = len(_as_list(nodes[node].get("procs")))
        items.append({"name": node, "status": "pass", "detail": f"{count} traffic process(es) running"})

    unreachable: list[dict[str, Any]] = []
    reachable_count = 0
    for row in ping:
        if not isinstance(row, dict):
            continue
        reachable = row.get("reachable")
        cmd = _name(row.get("cmd"))
        if reachable is True:
            reachable_count += 1
            detail = "reachable"
            status = "pass"
        elif reachable is False:
            unreachable.append(row)
            detail = ("unreachable — the target may be down or blocked by segmentation. "
                      + (f"Reproduce with: {cmd}. " if cmd else "")
                      + "Then check the node is up and shares a network with the source.")
            status = "warn"
        else:
            detail = "no IP resolved for the target node; cannot ping"
            status = "skip"
        items.append({
            "name": f"ping {row.get('src')} → {row.get('dst')} ({row.get('ip') or 'no ip'})",
            "status": status,
            "detail": detail,
        })

    traffic_ok = bool(traffic_files or nodes_with_procs or flows)
    if expected and not traffic_ok:
        return _result("traffic", "warn",
                       "Traffic is configured, but no traffic flows, scripts, or processes were found. "
                       "Confirm traffic generation ran during execute.", items)
    if unreachable:
        first_cmd = _name(unreachable[0].get("cmd"))
        tail = f" First: {first_cmd}" if first_cmd else ""
        return _result("traffic", "warn",
                       f"{reachable_count} node(s) reachable, {len(unreachable)} not reachable by ping "
                       f"(may be intentional segmentation — reproduce the per-row command to confirm).{tail}", items)
    if not traffic_ok and not ping:
        return _result("traffic", "skip", "No traffic configured and no reachability probes ran.", items)
    bits: list[str] = []
    if flows:
        bits.append(f"{len(flows)} traffic flow(s)")
    if traffic_files:
        bits.append(f"{len(traffic_files)} traffic script(s)")
    if nodes_with_procs:
        bits.append(f"{len(nodes_with_procs)} node(s) running traffic")
    if reachable_count:
        bits.append(f"{reachable_count} node(s) reachable by ping")
    detail = "; ".join(bits) if bits else "No traffic configured; reachability probed."
    return _result("traffic", "pass", detail, items)


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
