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
    ("traffic", "Traffic scripts running"),
    ("reachability", "Nodes reachable (traffic source → destination)"),
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


def ports_result(summary: dict[str, Any], probe: Any = None) -> dict[str, Any]:
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
    # are connected to from a prober node over the emulated network. This is the
    # meaningful port signal in VM mode, where nodes publish no host ports.
    probe_ok = isinstance(probe, dict) and probe.get("ok")
    net_checks = _as_list(probe.get("checks")) if probe_ok else []
    net_listening = 0
    net_unreachable: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []       # dropped packets (timeout/no-route)
    transient: list[dict[str, Any]] = []     # refused: port closed since enumeration
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
        prober = _name(probe.get("prober"))
        for row in net_checks:
            if not isinstance(row, dict) or row.get("reachable") is not False:
                continue
            error = _name(row.get("error"))
            repro = (f" Reproduce: sudo docker exec {prober} python3 -c "
                     f"\"import socket; socket.create_connection(('{row.get('ip')}', {row.get('port')}), 2)\"")
            # A timeout / no-route means packets are dropped — the real signal of
            # a blocked path (segmentation/routing). "refused" means the port is
            # closed now: it was listening when we enumerated but has since closed
            # (short-lived AJP/JMX/ephemeral ports), which is a benign timing race,
            # not a reachability failure.
            if error in ("timeout", "no-route"):
                blocked.append(row)
                items.append({
                    "name": f"{prober} → {row.get('node')}:{row.get('port')} ({row.get('ip')})",
                    "status": "warn",
                    "detail": (f"packets dropped ({error}) — likely blocked by segmentation/routing."
                               + repro),
                })
            else:
                transient.append(row)
                items.append({
                    "name": f"{prober} → {row.get('node')}:{row.get('port')} ({row.get('ip')})",
                    "status": "skip",
                    "detail": ("connection refused — the port closed between enumeration and probe "
                               "(short-lived service port), not a reachability failure." + repro),
                })

    net_unreachable = blocked + transient
    published_bad = len(unreachable) + len(topo_unreachable)
    probed = len(net_checks)
    reachable_ok = probed - len(net_unreachable)
    have_any = bool(checked or unreachable or topo_unreachable or net_listening)
    if not have_any:
        return _result("ports", "skip", "No open service ports found to check.", items)
    if published_bad:
        return _result("ports", "fail", f"{published_bad} published port target(s) unreachable.", items)
    if blocked:
        return _result("ports", "warn",
                       f"{reachable_ok} of {probed} probed service port(s) reachable across the CORE "
                       f"network; {len(blocked)} blocked (dropped packets — likely segmentation).", items)
    node_count = sum(1 for v in (probe.get("nodes") or {}).values() if isinstance(v, dict) and v.get("listening"))
    total_ok = len(checked) + reachable_ok
    tail = (f" ({len(transient)} short-lived port(s) closed during probe.)" if transient else "")
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


def ports_probe_script(sudo_password: str | None = None, session_id: Any = None,
                       max_ports_per_node: int = 12, max_targets: int = 80) -> str:
    """VM-side script: discover each node's listening (non-loopback) TCP service
    ports from ``/proc/net/tcp`` and test cross-node reachability by connecting
    from a prober node over the CORE network. Uses python3, which is present on
    every node (Docker and vnode)."""
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
    return (
        _remote_preamble(sudo_password, session_id)
        + f"LISTEN_PY = {listen_literal}\n"
        + f"MAX_TARGETS = {int(max_targets)}\n"
        + "def _ip(kind, name):\n"
        + "    rc, out = _nexec(kind, name, ['sh','-lc',\"ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1\"])\n"
        + "    ips = [l.strip() for l in out.splitlines() if l.strip()]\n"
        + "    return ips[0] if ips else ''\n"
        + "def _listening(kind, name):\n"
        + "    rc, out = _nexec(kind, name, ['python3','-c', LISTEN_PY])\n"
        + "    try:\n"
        + "        d = json.loads(out.strip().splitlines()[-1])\n"
        + "        return [int(x) for x in d.get('listening') or []], [int(x) for x in d.get('loopback') or []]\n"
        + "    except Exception:\n"
        + "        return [], []\n"
        + "def main():\n"
        + "    alln = _all_nodes()\n"
        + "    nodes = {}\n"
        + "    for kind, name in alln:\n"
        + "        pub, loop = _listening(kind, name)\n"
        + "        nodes[name] = {'kind': kind, 'ip': _ip(kind, name), 'listening': pub, 'loopback': loop}\n"
        + "    prober = alln[0] if alln else None\n"
        + "    targets = []\n"
        + "    if prober:\n"
        + "        pn = prober[1]\n"
        + "        for kind, name in alln:\n"
        + "            if name == pn:\n"
        + "                continue\n"
        + "            ip = nodes.get(name, {}).get('ip') or ''\n"
        + "            if not ip:\n"
        + "                continue\n"
        + "            for port in nodes.get(name, {}).get('listening', []):\n"
        + "                targets.append([name, ip, port])\n"
        + "                if len(targets) >= MAX_TARGETS:\n"
        + "                    break\n"
        + "            if len(targets) >= MAX_TARGETS:\n"
        + "                break\n"
        + "    checks = []\n"
        + "    if prober and targets:\n"
        + "        conn = 'import json,socket,errno\\nR=[]\\nfor n,ip,port in ' + json.dumps(targets) + ':\\n'\n"
        + "        conn += ' try:\\n  s=socket.create_connection((ip,int(port)),timeout=2.0); s.close(); R.append([n,ip,port,True,\"\"])\\n'\n"
        + "        conn += ' except socket.timeout:\\n  R.append([n,ip,port,False,\"timeout\"])\\n'\n"
        + "        conn += ' except OSError as e:\\n'\n"
        + "        conn += '  c=getattr(e,\"errno\",None)\\n'\n"
        + "        conn += '  R.append([n,ip,port,False,\"refused\" if c==errno.ECONNREFUSED else (\"no-route\" if c in (errno.EHOSTUNREACH,errno.ENETUNREACH) else \"error\")])\\n'\n"
        + "        conn += 'print(json.dumps(R))\\n'\n"
        + "        rc, out = _nexec(prober[0], prober[1], ['python3','-c', conn], timeout=90)\n"
        + "        try:\n"
        + "            for row in json.loads(out.strip().splitlines()[-1]):\n"
        + "                n, ip, port, ok = row[0], row[1], row[2], row[3]\n"
        + "                err = row[4] if len(row) > 4 else ''\n"
        + "                checks.append({'node': n, 'ip': ip, 'port': port, 'reachable': bool(ok), 'error': err})\n"
        + "        except Exception:\n"
        + "            pass\n"
        + "    print(json.dumps({'ok': True, 'prober': (prober[1] if prober else ''), 'nodes': nodes, 'checks': checks}))\n"
        + "main()\n"
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
        + "    # Reachability follows the configured traffic flows: ping from each\n"
        + "    # flow's source node to its destination, which is the path traffic\n"
        + "    # actually needs. Nodes are matched to a flow by their CORE IP.\n"
        + "    by_ip = {}\n"
        + "    for kind, name in alln:\n"
        + "        ip = nodes.get(name, {}).get('ip') or ''\n"
        + "        if ip and ip not in by_ip:\n"
        + "            by_ip[ip] = (kind, name)\n"
        + "    ping = []\n"
        + "    seen_pairs = set()\n"
        + "    for flow in ((summary or {}).get('flows') or []):\n"
        + "        if not isinstance(flow, dict):\n"
        + "            continue\n"
        + "        s_ip = str(flow.get('src_ip') or '').strip()\n"
        + "        d_ip = str(flow.get('dst_ip') or '').strip()\n"
        + "        if not s_ip or not d_ip or (s_ip, d_ip) in seen_pairs:\n"
        + "            continue\n"
        + "        seen_pairs.add((s_ip, d_ip))\n"
        + "        src = by_ip.get(s_ip)\n"
        + "        dst_name = (by_ip.get(d_ip) or (None, d_ip))[1]\n"
        + "        if not src:\n"
        + "            ping.append({'src': s_ip, 'dst': dst_name, 'ip': d_ip, 'reachable': None,\n"
        + "                         'cmd': '', 'why': 'traffic source node not found for ' + s_ip})\n"
        + "            continue\n"
        + "        sk, sn = src\n"
        + "        rc, out = _nexec(sk, sn, ['sh','-lc','ping -c1 -W1 '+d_ip+' >/dev/null 2>&1 && echo OK || echo NO'])\n"
        + "        ping.append({'src': sn, 'dst': dst_name, 'ip': d_ip, 'reachable': ('OK' in out),\n"
        + "                     'cmd': _repro(sk, sn, d_ip), 'port': flow.get('dst_port'),\n"
        + "                     'protocol': flow.get('protocol')})\n"
        + "    print(json.dumps({'ok': True, 'traffic_files': traffic_files, 'summary': summary, 'nodes': nodes, 'ping': ping}))\n"
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
    # List only nodes that actually carry rules. Emitting a row per rule-free
    # node buries the signal under one line per node in the topology.
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

    # Nodes that a flow names as a sender but where no traffic process is running.
    expected_senders: set[str] = set()
    ip_to_node = {
        _name(info.get("ip")): node
        for node, info in nodes.items()
        if isinstance(info, dict) and _name(info.get("ip"))
    }
    for flow in flows:
        if isinstance(flow, dict):
            node = ip_to_node.get(_name(flow.get("src_ip")))
            if node:
                expected_senders.add(node)
    missing_senders = sorted(expected_senders - set(nodes_with_procs))
    for node in missing_senders:
        items.append({"name": node, "status": "warn",
                      "detail": "flow names this node as a traffic source, but no traffic process is running"})

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


def reachability_result(probe: Any) -> dict[str, Any]:
    """Check 7: can each traffic source actually reach its destination?

    Probed along the configured traffic flows (source node -> destination IP),
    which is the path traffic depends on, rather than an arbitrary node pair.
    """
    if not isinstance(probe, dict) or not probe.get("ok"):
        detail = _name(probe.get("error") or probe.get("raw")) if isinstance(probe, dict) else ""
        return _result("reachability", "error", detail or "reachability probe failed")
    ping = _as_list(probe.get("ping"))
    items: list[dict[str, Any]] = []
    unreachable: list[dict[str, Any]] = []
    reachable_count = 0

    for row in ping:
        if not isinstance(row, dict):
            continue
        reachable = row.get("reachable")
        cmd = _name(row.get("cmd"))
        port = row.get("port")
        proto = _name(row.get("protocol"))
        flow_desc = f" [{proto or 'flow'}{':' + str(port) if port else ''}]"
        if reachable is True:
            reachable_count += 1
            status, detail = "pass", "reachable"
        elif reachable is False:
            unreachable.append(row)
            status = "warn"
            detail = ("traffic destination not reachable from its source — traffic for this flow "
                      "cannot arrive. Check the destination node is up and shares a network/route "
                      "with the source" + (f". Reproduce: {cmd}" if cmd else ""))
        else:
            status = "skip"
            detail = _name(row.get("why")) or "could not resolve the flow's source node; cannot ping"
        items.append({
            "name": f"{row.get('src')} → {row.get('dst')} ({row.get('ip') or 'no ip'}){flow_desc}",
            "status": status,
            "detail": detail,
        })

    if not ping:
        return _result("reachability", "skip",
                       "No traffic flows configured, so there are no source → destination pairs to verify.",
                       items)
    if unreachable:
        first_cmd = _name(unreachable[0].get("cmd"))
        tail = f" First: {first_cmd}" if first_cmd else ""
        return _result("reachability", "warn",
                       f"{reachable_count} of {len(ping)} traffic path(s) reachable; "
                       f"{len(unreachable)} destination(s) unreachable from their source.{tail}", items)
    return _result("reachability", "pass",
                   f"All {reachable_count} traffic source → destination path(s) reachable.", items)


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
