"""Generate a downloadable, self-checking "Solutions Script" for a scenario.

The script walks the resolved Attack Flow chain and, for each
flag-node-generator step, establishes the documented entry point (SSH, HTTP,
or a raw TCP protocol dialog), attempts to retrieve the step's flag, and
reports PASS / FAIL / INCONCLUSIVE with reasoning. It is meant to be run by a
facilitator from their own machine, either directly (when the host routes to
the CORE node subnet) or tunnelled through the CORE VM over SSH.

Design notes
------------
* Only ``flag-node-generator`` steps are handled. Vulnerability and
  flag-generator steps do not ship machine-runnable ``access_instructions``
  yet, so they are emitted as SKIPPED with their human hints for context.
* ``access_instructions`` are written for humans (interactive ``ssh``, literal
  ``<user>`` placeholders, and the occasionally wrong ``{{FLAG_FILE}}``), so we
  do not replay them verbatim. Instead we detect the entry-point tool from the
  documented commands and derive a deterministic retrieval attempt from the
  resolved artifacts, asserting the known ``Flag(flag_id)`` value.
* This module is intentionally Flask-free and side-effect-free so the
  substitution and strategy logic can be unit-tested directly.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import shlex
from typing import Any


TOOL_VERSION = "1"


# --------------------------------------------------------------------------- #
# Small resolved-artifact helpers
# --------------------------------------------------------------------------- #

def _clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _valid_ipv4(value: Any) -> str:
    text = _clean(value)
    if not text:
        return ""
    # Accept a bare address or the first token of "ip/prefix" or "ip port".
    token = re.split(r"[\s/]+", text)[0]
    try:
        ipaddress.IPv4Address(token)
        return token
    except Exception:
        return ""


def _node_ipv4(node: dict[str, Any]) -> str:
    for key in ("ipv4", "ip4", "ip"):
        found = _valid_ipv4(node.get(key)) if isinstance(node, dict) else ""
        if found:
            return found
    return ""


def _canon(key: str) -> str:
    """Whitespace-insensitive artifact key, e.g. ``Credential(user, password)``
    and ``Credential(user,password)`` collapse to the same lookup token. The
    solver treats those as distinct facts, so callers must not rely on an exact
    spelling when reading resolved values here."""
    return re.sub(r"\s+", "", _clean(key)).lower()


def _find_output(outputs: dict[str, Any], *needles: str) -> str:
    """Return the value of the first output key containing every needle."""
    if not isinstance(outputs, dict):
        return ""
    wants = [n.lower() for n in needles]
    for key, value in outputs.items():
        low = _canon(key)
        if all(w.replace(" ", "") in low for w in wants):
            return _clean(value)
    return ""


def _port_from(outputs: dict[str, Any]) -> str:
    raw = _find_output(outputs, "PortForward")
    if not raw:
        return ""
    # Values seen in the wild: 2222, "host:2222", "2222/tcp".
    matches = re.findall(r"\d+", raw)
    return matches[-1] if matches else ""


def _credential_from(outputs: dict[str, Any]) -> tuple[str, str]:
    raw = _find_output(outputs, "credential", "password") or _find_output(outputs, "credential")
    if not raw:
        return "", ""
    if ":" in raw:
        user, _, password = raw.partition(":")
        return user.strip(), password.strip()
    return raw.strip(), ""


def _expected_flag(assignment: dict[str, Any], outputs: dict[str, Any]) -> str:
    flag = _clean(assignment.get("flag_value"))
    if flag:
        return flag
    return _find_output(outputs, "flag(flag_id)") or _find_output(outputs, "flag", "id")


def _is_node_generator(assignment: dict[str, Any]) -> bool:
    kind = _clean(assignment.get("type") or assignment.get("kind")).lower()
    return kind == "flag-node-generator"


# --------------------------------------------------------------------------- #
# access_instructions parsing + placeholder substitution
# --------------------------------------------------------------------------- #

_FENCE_RE = re.compile(r"```([a-zA-Z0-9_-]*)\n(.*?)```", re.DOTALL)


def _substitute(text: str, *, node_name: str, node_ip: str, outputs: dict[str, Any],
                step_vars: dict[str, Any] | None) -> str:
    """Resolve ``{{PLACEHOLDER}}`` tokens the same way the participant guide
    does, preferring a concrete IP for ``{{NODE}}`` so the command is runnable.
    ``step_vars`` (a manifest ``vars`` map of placeholder -> artifact key) wins
    over the heuristic table when present."""
    if not text:
        return ""
    user, password = _credential_from(outputs)
    node_target = node_ip or node_name

    table = {
        "NODE": node_target,
        "NODE_NAME": node_name,
        "NODE_IP": node_ip,
        "PORT": _port_from(outputs),
        "USERNAME": user or "user",
        "PASSWORD": password or "password",
        "CREDENTIAL": _find_output(outputs, "credential"),
        "FLAG_FILE": _find_output(outputs, "flagfile"),
        "PATH": _find_output(outputs, "directory"),
        "ENDPOINT": _find_output(outputs, "endpoint") or "/",
        "TOKEN": _find_output(outputs, "token"),
        "API_KEY": _find_output(outputs, "apikey"),
        "KEY_FILE": _find_output(outputs, "sshprivatekey") or _find_output(outputs, "keyfile"),
    }

    # Manifest-declared vars override the heuristic table with the exact
    # resolved artifact value.
    if isinstance(step_vars, dict):
        for placeholder, artifact_key in step_vars.items():
            name = _clean(placeholder)
            if not name:
                continue
            key = _clean(artifact_key)
            if _canon(key) in ("node_name", "node"):
                table[name] = node_target
            else:
                table[name] = _find_output(outputs, key) or table.get(name, "")

    def _repl(match: "re.Match[str]") -> str:
        name = match.group(1).strip()
        return str(table.get(name, match.group(0)))

    return re.sub(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}", _repl, text)


def _iter_steps(assignment: dict[str, Any]) -> list[dict[str, Any]]:
    access = assignment.get("access_instructions")
    if not isinstance(access, dict):
        return []
    steps = access.get("steps")
    return [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []


def _human_steps(assignment: dict[str, Any], *, node_name: str, node_ip: str,
                 outputs: dict[str, Any]) -> list[str]:
    """Flatten the documented steps into substituted, human-readable lines."""
    lines: list[str] = []
    for index, step in enumerate(_iter_steps(assignment), start=1):
        title = _substitute(_clean(step.get("title")) or f"Step {index}",
                            node_name=node_name, node_ip=node_ip,
                            outputs=outputs, step_vars=step.get("vars"))
        lines.append(f"Step {index}: {title}")
        body = _substitute(_clean(step.get("instructions")),
                          node_name=node_name, node_ip=node_ip,
                          outputs=outputs, step_vars=step.get("vars"))
        for raw in body.splitlines():
            row = raw.rstrip()
            if row.strip():
                lines.append(f"    {row}")
    return lines


def _fenced_blocks(assignment: dict[str, Any], *, node_name: str, node_ip: str,
                   outputs: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """Return (lang, lines) for every fenced code block across all steps, with
    placeholders already substituted."""
    blocks: list[tuple[str, list[str]]] = []
    for step in _iter_steps(assignment):
        body = _substitute(_clean(step.get("instructions")),
                          node_name=node_name, node_ip=node_ip,
                          outputs=outputs, step_vars=step.get("vars"))
        for lang, code in _FENCE_RE.findall(body):
            lines = [ln.rstrip() for ln in code.splitlines() if ln.strip()]
            if lines:
                blocks.append((lang.strip().lower(), lines))
    return blocks


_ENTRY_TOOLS = {"ssh", "sshpass", "scp", "sftp", "curl", "wget", "nc", "ncat", "netcat"}


def _entry_tool(blocks: list[tuple[str, list[str]]]) -> str:
    """Return the first recognized entry-point tool anywhere in the documented
    shell commands. Scanning every line (not just the first) matters because
    steps often lead with setup like ``chmod 600 key`` before the real ``ssh``."""
    for lang, lines in blocks:
        if lang and lang not in ("bash", "sh", "shell", "console", ""):
            continue
        for line in lines:
            for token in line.strip().split():
                verb = token.lstrip("$|").strip().lower()
                if verb in _ENTRY_TOOLS:
                    return verb
                if verb and not verb.startswith("-"):
                    # Stop at the first real command word on a line; a later
                    # pipeline segment can still surface a tool via its own token.
                    break
    return ""


def _ssh_command_line(blocks: list[tuple[str, list[str]]]) -> str:
    for lang, lines in blocks:
        if lang and lang not in ("bash", "sh", "shell", "console", ""):
            continue
        for line in lines:
            stripped = line.strip()
            if re.match(r"^(sshpass\s+.*\s+)?ssh\b", stripped):
                return stripped
    return ""


def _ssh_params(blocks: list[tuple[str, list[str]]], outputs: dict[str, Any]) -> tuple[str, str, str]:
    """Resolve (user, password, key_path) for an SSH step, preferring the
    resolved Credential and falling back to the documented ``user@host`` /
    ``-i keyfile`` in the command for key-based logins."""
    user, password = _credential_from(outputs)
    key = _find_output(outputs, "sshprivatekey") or _find_output(outputs, "keyfile")
    command = _ssh_command_line(blocks)
    if command:
        if not user:
            match = re.search(r"(\S+)@[\w.\-]+", command)
            if match:
                user = match.group(1)
        if not key:
            match = re.search(r"-i\s+(\S+)", command)
            if match:
                key = match.group(1)
    return user, password, key


# --------------------------------------------------------------------------- #
# Per-node retrieval strategy
# --------------------------------------------------------------------------- #

class _NodeCheck:
    __slots__ = ("seq", "node_id", "label", "ip", "flag", "strategy",
                 "retrieval", "human", "skip_reason")

    def __init__(self, *, seq: int, node_id: str, label: str, ip: str, flag: str,
                 strategy: str, retrieval: str, human: list[str], skip_reason: str):
        self.seq = seq
        self.node_id = node_id
        self.label = label
        self.ip = ip
        self.flag = flag
        self.strategy = strategy
        self.retrieval = retrieval  # bash snippet writing candidate output to stdout
        self.human = human
        self.skip_reason = skip_reason  # non-empty => emitted as SKIPPED


_FLAG_SEARCH_ROOTS = "~ /root /home /workspace /support /srv /var/www /data /opt"


def _ssh_retrieval(ip: str, port: str, user: str, password: str, key: str = "") -> str:
    remote = (
        "grep -rslI 'FLAG{' " + _FLAG_SEARCH_ROOTS + " 2>/dev/null | head -n 20; "
        "grep -rshI 'FLAG{' " + _FLAG_SEARCH_ROOTS + " 2>/dev/null | head -n 40"
    )
    opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8"
    key_opt = f"-i {shlex.quote(key)} " if key else ""
    inner = (
        f"ssh {opts} {key_opt}-p {shlex.quote(port or '22')} "
        f"{shlex.quote(f'{user}@{ip}')} {shlex.quote(remote)}"
    )
    if password and not key:
        return f"sshpass -p {shlex.quote(password)} {inner}"
    return inner


def _append_query(url: str, params: list[tuple[str, str]]) -> str:
    if not params:
        return url
    sep = "&" if "?" in url else "?"
    query = "&".join(f"{name}={value}" for name, value in params)
    return f"{url}{sep}{query}"


def _http_retrieval(ip: str, port: str, blocks: list[tuple[str, list[str]]], outputs: dict[str, Any],
                    *, gates: list["_HttpGate"] | None = None,
                    basic_auth: tuple[str, str] | None = None) -> str:
    gates = gates or []
    # A gate value supplied both as a query parameter and as a header covers
    # whichever the service actually checks.
    query_params = [(g.param, g.value) for g in gates if g.param and g.value]
    header_args = "".join(
        f" -H {shlex.quote(f'{g.header}: {g.value}')}" for g in gates if g.header and g.value
    )
    auth_arg = ""
    if basic_auth and basic_auth[0]:
        auth_arg = f" -u {shlex.quote(f'{basic_auth[0]}:{basic_auth[1]}')}"

    # Prefer the exact URLs the documented curl commands target.
    urls: list[str] = []
    for _lang, lines in blocks:
        for line in lines:
            for match in re.findall(r"https?://[^\s'\"]+", line):
                if match not in urls:
                    urls.append(match)
    if not urls:
        endpoint = _find_output(outputs, "endpoint") or "/"
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        # No documented command means no scheme hint; try both.
        urls.append(f"https://{ip}:{port}{endpoint}")
        urls.append(f"http://{ip}:{port}{endpoint}")
    parts = [
        f"curl -sk --max-time 12{auth_arg}{header_args} {shlex.quote(_append_query(url, query_params))} 2>/dev/null"
        for url in urls[:4]
    ]
    return "; ".join(parts)


class _HttpGate:
    """A prior-fact value a gated HTTP step must present, along with the query
    parameter and/or header name the challenge accepts it under."""
    __slots__ = ("fact", "param", "header", "value")

    def __init__(self, fact: str, param: str, header: str, value: str):
        self.fact = fact
        self.param = param
        self.header = header
        self.value = value


_FACT_TOKEN_RE = re.compile(r"^[A-Z][A-Za-z0-9]*\([^)]*\)$")
_HEADER_TOKEN_RE = re.compile(r"^[Xx]-[A-Za-z0-9-]+$")
_PARAM_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_GATE_PHRASES = ("provide the previous", "submit the prior", "present the", "supply the")


def _http_gates(assignment: dict[str, Any], inputs: dict[str, Any],
                known_facts: dict[str, str]) -> list["_HttpGate"]:
    """Parse header/param gate instructions and bind each required fact to its
    resolved value (from this node's inputs, or a prior step's outputs)."""
    gates: list[_HttpGate] = []
    seen: set[str] = set()
    for step in _iter_steps(assignment):
        text = _clean(step.get("instructions"))
        if not text:
            continue
        if not any(phrase in text.lower() for phrase in _GATE_PHRASES):
            continue
        tokens = re.findall(r"`([^`]+)`", text)
        fact = next((t for t in tokens if _FACT_TOKEN_RE.match(t)), "")
        if not fact or _canon(fact) in seen:
            continue
        param = next((t for t in tokens if _PARAM_TOKEN_RE.match(t)), "")
        header = next((t for t in tokens if _HEADER_TOKEN_RE.match(t)), "")
        if not param and not header:
            continue
        value = _clean(inputs.get(fact)) or _find_output(inputs, *fact.split("(")[0].split()) \
            or known_facts.get(_canon(fact), "")
        if not value:
            continue
        seen.add(_canon(fact))
        gates.append(_HttpGate(fact=fact, param=param, header=header, value=value))
    return gates


def _uses_basic_auth(blocks: list[tuple[str, list[str]]]) -> bool:
    for lang, lines in blocks:
        if lang and lang not in ("bash", "sh", "shell", "console", ""):
            continue
        for line in lines:
            if re.search(r"\bcurl\b.*\s-u\b", line) or " --user " in f" {line} ":
                return True
    return False


def _has_nfs_mount(blocks: list[tuple[str, list[str]]]) -> bool:
    for _lang, lines in blocks:
        for line in lines:
            if re.search(r"\bmount\b.*\bnfs", line):
                return True
    return False


def _nfs_export(outputs: dict[str, Any]) -> str:
    """Return the NFS export name. ``Directory(host, path)`` holds it when it is
    a clean absolute path; a CORE-VM run directory is not an export, so fall
    back to the conventional ``/exports``."""
    directory = _find_output(outputs, "directory")
    if directory.startswith("/") and "/flag_node_generators_runs/" not in directory \
            and "/flag_generators_runs/" not in directory:
        return directory
    return "/exports"


def _nfs_retrieval(ip: str, port: str, export: str) -> str:
    export = export or "/exports"
    target = f"{ip}:{export}"
    return (
        "t=$(mktemp -d 2>/dev/null || echo /tmp/sfnfs.$$); mkdir -p \"$t\"; "
        f"mount -t nfs4 -o nolock,soft,timeo=50,vers=4,port={shlex.quote(port)} {shlex.quote(target)} \"$t\" 2>/dev/null "
        f"|| mount -t nfs -o nolock,soft,timeo=50,port={shlex.quote(port)} {shlex.quote(target)} \"$t\" 2>/dev/null; "
        "grep -rshI 'FLAG{' \"$t\" 2>/dev/null | head -n 40; "
        "umount \"$t\" 2>/dev/null; rmdir \"$t\" 2>/dev/null"
    )


def _nc_retrieval(ip: str, port: str, blocks: list[tuple[str, list[str]]]) -> str:
    dialog: list[str] = []
    for lang, lines in blocks:
        if lang == "text":
            dialog.extend(lines)
    if dialog:
        payload = "\n".join(dialog)
        return f"printf {shlex.quote(payload + chr(10))} | nc -w 8 {shlex.quote(ip)} {shlex.quote(port)} 2>/dev/null"
    return f": | nc -w 8 {shlex.quote(ip)} {shlex.quote(port)} 2>/dev/null"


def _build_node_check(seq: int, node: dict[str, Any], assignment: dict[str, Any],
                      known_facts: dict[str, str] | None = None) -> _NodeCheck:
    node_id = _clean(node.get("id"))
    label = _clean(node.get("name") or node.get("label")) or node_id
    ip = _node_ipv4(node)
    outputs = assignment.get("resolved_outputs") if isinstance(assignment.get("resolved_outputs"), dict) else {}
    inputs = assignment.get("resolved_inputs") if isinstance(assignment.get("resolved_inputs"), dict) else {}
    known_facts = known_facts or {}
    flag = _expected_flag(assignment, outputs)
    human = _human_steps(assignment, node_name=label, node_ip=ip, outputs=outputs)

    def _skip(reason: str, strategy: str = "manual") -> _NodeCheck:
        return _NodeCheck(seq=seq, node_id=node_id, label=label, ip=ip, flag=flag,
                          strategy=strategy, retrieval="", human=human, skip_reason=reason)

    if not _is_node_generator(assignment):
        return _skip("not a flag-node-generator (no runnable access instructions)")
    if not _iter_steps(assignment):
        return _skip("no access_instructions provided by this generator")
    if not ip:
        return _skip("no IPv4 resolved for this node; cannot target it")

    blocks = _fenced_blocks(assignment, node_name=label, node_ip=ip, outputs=outputs)
    verb = _entry_tool(blocks)
    port = _port_from(outputs)
    has_endpoint = bool(_find_output(outputs, "endpoint"))

    def _http_check() -> _NodeCheck:
        gates = _http_gates(assignment, inputs, known_facts)
        basic_auth = _credential_from(outputs) if _uses_basic_auth(blocks) else None
        return _NodeCheck(seq=seq, node_id=node_id, label=label, ip=ip, flag=flag,
                          strategy="http",
                          retrieval=_http_retrieval(ip, port, blocks, outputs, gates=gates, basic_auth=basic_auth),
                          human=human, skip_reason="")

    # No recognized entry tool in the documented commands (e.g. a header-gated
    # HTTP step, or an NFS export that starts with apt-get/mkdir/mount).
    if not verb:
        if _has_nfs_mount(blocks):
            if not port:
                return _skip("NFS step is missing a resolved PortForward port", strategy="nfs")
            return _NodeCheck(seq=seq, node_id=node_id, label=label, ip=ip, flag=flag,
                              strategy="nfs", retrieval=_nfs_retrieval(ip, port, _nfs_export(outputs)),
                              human=human, skip_reason="")
        if has_endpoint and port:
            return _http_check()
        return _skip("entry point requires manual setup not automated in v1")

    if verb in ("ssh", "sshpass", "scp", "sftp"):
        user, password, key = _ssh_params(blocks, outputs)
        if not user:
            return _skip("SSH step is missing a resolved user/credential", strategy="ssh")
        if key and not port:
            port = "2222"
        return _NodeCheck(seq=seq, node_id=node_id, label=label, ip=ip, flag=flag,
                          strategy="ssh", retrieval=_ssh_retrieval(ip, port, user, password, key),
                          human=human, skip_reason="")

    if verb in ("curl", "wget"):
        return _http_check()

    # nc / ncat / netcat
    if not port:
        return _skip("TCP step is missing a resolved PortForward port", strategy="nc")
    return _NodeCheck(seq=seq, node_id=node_id, label=label, ip=ip, flag=flag,
                      strategy="nc", retrieval=_nc_retrieval(ip, port, blocks),
                      human=human, skip_reason="")


# --------------------------------------------------------------------------- #
# Bash rendering
# --------------------------------------------------------------------------- #

class _PivotCheck:
    """A pivot the participant has to perform before a step becomes reachable.

    Verified by connecting to the provider's entry port, because that is the
    thing the rest of the subnet depends on: if it does not answer, every
    challenge behind that boundary is unreachable no matter how well it was
    built. The script does not then tunnel through it -- solving the provider's
    own challenge is the participant's work, and the steps behind it are checked
    from the CORE VM, which reaches the node subnets directly.
    """

    __slots__ = ("seq", "label", "subnet", "provider", "ip", "port", "kind", "instruction")

    def __init__(self, *, seq: str, subnet: str, provider: str, ip: str, port: str,
                 kind: str, instruction: str):
        self.seq = seq
        self.label = f"pivot into {subnet}" if subnet else "pivot"
        self.subnet = subnet
        self.provider = provider
        self.ip = ip
        self.port = port
        self.kind = kind
        self.instruction = instruction


def own_step_pivots(flag_assignments: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """The own_step pivot decisions carried on the assignments, deduplicated.

    Mirrors what the guides render, so a facilitator reading the guide and one
    running the script see the same pivots.
    """
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for assignment in (flag_assignments or []):
        if not isinstance(assignment, dict):
            continue
        decisions = assignment.get("pivot_decisions")
        if not isinstance(decisions, list):
            continue
        for decision in decisions:
            if not isinstance(decision, dict):
                continue
            if _clean(decision.get("disposition")) != "own_step":
                continue
            key = (_clean(decision.get("subnet")), _clean(decision.get("provider_node")))
            if key in seen:
                continue
            seen.add(key)
            out.append(decision)
    return out


def _build_pivot_check(decision: dict[str, Any], seq: str) -> _PivotCheck | None:
    ip = _valid_ipv4(decision.get("provider_address"))
    port = _clean(decision.get("entry_port"))
    if not ip or not port:
        # Nothing to connect to. The plan reports such a provider as unresolved
        # and execute warns about it; inventing a check here would be a
        # confident answer to a question nobody can ask.
        return None
    return _PivotCheck(
        seq=seq,
        subnet=_clean(decision.get("subnet")),
        provider=_clean(decision.get("provider_node")),
        ip=ip,
        port=port,
        kind=_clean(decision.get("entry_kind")) or "entry",
        instruction=_clean(decision.get("instruction")),
    )


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _bash_literal(value: str) -> str:
    return shlex.quote(value)


def align_assignments(chain_nodes: list[dict[str, Any]],
                      flag_assignments: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Return one assignment per chain node, matched by ``node_id`` then by
    position, mirroring how the guides align them."""
    by_node: dict[str, dict[str, Any]] = {}
    ordered = flag_assignments if isinstance(flag_assignments, list) else []
    for item in ordered:
        if not isinstance(item, dict):
            continue
        nid = _clean(item.get("node_id"))
        if nid and nid not in by_node:
            by_node[nid] = item
    aligned: list[dict[str, Any]] = []
    for index, node in enumerate(chain_nodes or []):
        if not isinstance(node, dict):
            aligned.append({})
            continue
        nid = _clean(node.get("id"))
        source = by_node.get(nid)
        if source is None and index < len(ordered) and isinstance(ordered[index], dict):
            source = ordered[index]
        aligned.append(dict(source) if isinstance(source, dict) else {})
    return aligned


def build_solutions_script(scenario: str,
                           chain_nodes: list[dict[str, Any]],
                           flag_assignments: list[dict[str, Any]] | None,
                           *,
                           tool_version: str = TOOL_VERSION) -> str:
    """Render an executable bash Solutions Script for the resolved chain."""
    scenario_label = _clean(scenario) or "scenario"
    nodes = [n for n in (chain_nodes or []) if isinstance(n, dict) and _clean(n.get("id"))]
    aligned = align_assignments(nodes, flag_assignments)

    # Accumulate resolved facts as we walk the chain so a later gated step can
    # present a value an earlier step produced. The consuming node usually
    # already carries the value in its own resolved_inputs, but this covers the
    # general cross-step case too.
    known_facts: dict[str, str] = {}
    checks: list[_NodeCheck] = []
    for index, node in enumerate(nodes):
        assignment = aligned[index] if index < len(aligned) else {}
        checks.append(_build_node_check(index + 1, node, assignment, known_facts))
        for source_key in ("resolved_outputs", "resolved_inputs"):
            source = assignment.get(source_key)
            if isinstance(source, dict):
                for key, value in source.items():
                    text = _clean(value)
                    if text:
                        known_facts.setdefault(_canon(key), text)

    # Pivots that are their own step gate a chain step; `insert_before` names
    # which. Keyed by that index so each one is emitted just before the step it
    # unlocks, which is where the guides put it too.
    pivots_by_index: dict[int, list[_PivotCheck]] = {}
    pivot_total = 0
    for decision in own_step_pivots(flag_assignments):
        try:
            index = int(decision.get("insert_before"))
        except Exception:
            index = -1
        pivot_total += 1
        built = _build_pivot_check(decision, f"P{pivot_total}")
        if built is None:
            continue
        pivots_by_index.setdefault(index, []).append(built)
    pivot_checks = [c for group in pivots_by_index.values() for c in group]

    runnable = sum(1 for c in checks if not c.skip_reason)

    out: list[str] = []
    w = out.append

    w("#!/usr/bin/env bash")
    w("#")
    w(f"# ScenarioForge Solutions Script  (format v{tool_version})")
    w(f"# Scenario : {scenario_label}")
    w(f"# Steps    : {len(checks)} total, {runnable} auto-checkable (flag-node-generator only)")
    if pivot_checks:
        w(f"# Pivots   : {len(pivot_checks)} pivot step(s) verified by reaching the provider's entry port")
    w("#")
    w("# Verifies each challenge step by establishing the documented entry point")
    w("# and retrieving its flag. Run directly if this host routes to the CORE")
    w("# node subnet, or tunnel each command through the CORE VM with --ssh-host.")
    w("#")
    w("# Usage:")
    w("#   ./solutions_<scenario>.sh [--ssh-host H] [--ssh-user U] [--ssh-key K] [--ssh-port P] [-v]")
    w("#")
    w("# Requires: bash, grep, base64. Per strategy: sshpass+ssh (SSH steps),")
    w("#           curl (HTTP steps), nc (TCP steps).")
    w("")
    w("set -u")
    w("")
    w('SSH_HOST=""; SSH_USER=""; SSH_KEY=""; SSH_PORT=""; VERBOSE=0')
    w("while [ $# -gt 0 ]; do")
    w('  case "$1" in')
    w('    --ssh-host) SSH_HOST="$2"; shift 2;;')
    w('    --ssh-user) SSH_USER="$2"; shift 2;;')
    w('    --ssh-key) SSH_KEY="$2"; shift 2;;')
    w('    --ssh-port) SSH_PORT="$2"; shift 2;;')
    w('    -v|--verbose) VERBOSE=1; shift;;')
    w('    -h|--help) grep -E "^# " "$0" | sed "s/^# \\{0,1\\}//"; exit 0;;')
    w('    *) echo "unknown argument: $1" >&2; exit 2;;')
    w("  esac")
    w("done")
    w("")
    w("PASS=0; FAIL=0; SKIP=0; INCONCLUSIVE=0")
    w('RESULTS=""')
    w("")
    w("# Run a base64-encoded bash payload either locally or, when --ssh-host is")
    w("# set, inside the CORE VM (which can reach the emulated node subnet).")
    w("run_payload() {")
    w('  local payload_b64="$1"')
    w('  if [ -n "$SSH_HOST" ]; then')
    w('    local key_opt=""')
    w('    [ -n "$SSH_KEY" ] && key_opt="-i $SSH_KEY"')
    w('    local port_opt=""')
    w('    [ -n "$SSH_PORT" ] && port_opt="-p $SSH_PORT"')
    w('    local user="${SSH_USER:-$USER}"')
    w('    # shellcheck disable=SC2086')
    w('    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \\')
    w('        $key_opt $port_opt "$user@$SSH_HOST" "echo $payload_b64 | base64 -d | bash" 2>&1')
    w("  else")
    w('    echo "$payload_b64" | base64 -d | bash 2>&1')
    w("  fi")
    w("}")
    w("")
    w("record() {")
    w('  local status="$1"; local seq="$2"; local label="$3"; local reason="$4"')
    w('  case "$status" in')
    w('    PASS) PASS=$((PASS+1));;')
    w('    FAIL) FAIL=$((FAIL+1));;')
    w('    SKIP) SKIP=$((SKIP+1));;')
    w('    INCONCLUSIVE) INCONCLUSIVE=$((INCONCLUSIVE+1));;')
    w("  esac")
    w('  printf "  [%-12s] step %s: %s\\n" "$status" "$seq" "$label"')
    w('  [ -n "$reason" ] && printf "               %s\\n" "$reason"')
    w('  RESULTS="${RESULTS}${status} step ${seq}: ${label}\\n"')
    w("}")
    w("")
    w("check_step() {")
    w('  # args: seq label ip flag strategy retrieval_b64')
    w('  local seq="$1"; local label="$2"; local ip="$3"; local flag="$4"')
    w('  local strategy="$5"; local retrieval_b64="$6"')
    w('  echo "----------------------------------------------------------------"')
    w('  printf "Step %s — %s  (%s @ %s)\\n" "$seq" "$label" "$strategy" "$ip"')
    w('  local out')
    w('  out="$(run_payload "$retrieval_b64")"')
    w('  if [ "$VERBOSE" = "1" ]; then')
    w('    printf "%s\\n" "$out" | sed "s/^/      | /"')
    w("  fi")
    w('  if [ -z "$flag" ]; then')
    w('    record "INCONCLUSIVE" "$seq" "$label" "no expected flag was resolved for this step"')
    w("    return")
    w("  fi")
    w('  if printf "%s" "$out" | grep -qF "$flag"; then')
    w('    record "PASS" "$seq" "$label" "retrieved expected flag $flag"')
    w('  elif [ -z "$out" ]; then')
    w('    record "FAIL" "$seq" "$label" "entry point unreachable or produced no output (challenge may be broken)"')
    w("  else")
    w('    record "INCONCLUSIVE" "$seq" "$label" "reached the service but did not auto-locate $flag; complete the manual steps"')
    w("  fi")
    w("}")
    w("")
    w("check_pivot() {")
    w('  # args: seq label ip port kind')
    w('  local seq="$1"; local label="$2"; local ip="$3"; local port="$4"; local kind="$5"')
    w('  echo "----------------------------------------------------------------"')
    w('  printf "Pivot %s — %s  (%s @ %s:%s)\\n" "$seq" "$label" "$kind" "$ip" "$port"')
    w('  # A provider that does not answer makes every challenge behind that')
    w('  # boundary unreachable, however well those challenges were built.')
    w("  local payload")
    w('  # The two answers must not be substrings of one another, and the match is')
    w('  # anchored: a bare `grep -q REACHABLE` matches UNREACHABLE and calls every')
    w('  # closed port open. Found by running this against a port nothing served.')
    w('  payload="$(printf %s "timeout 6 bash -c \'</dev/tcp/'"$ip"'/'"$port"'\' >/dev/null 2>&1 && echo PIVOT_OPEN || echo PIVOT_SHUT" | base64 | tr -d "\\n")"')
    w('  local out')
    w('  out="$(run_payload "$payload")"')
    w('  if [ "$VERBOSE" = "1" ]; then')
    w('    printf "%s\\n" "$out" | sed "s/^/      | /"')
    w("  fi")
    w('  if printf "%s" "$out" | grep -qx PIVOT_OPEN; then')
    w('    record "PASS" "$seq" "$label" "provider reachable at $ip:$port"')
    w("  else")
    w('    record "FAIL" "$seq" "$label" "provider unreachable at $ip:$port — everything behind this boundary is unsolvable"')
    w("  fi")
    w("}")
    w("")
    w("skip_step() {")
    w('  local seq="$1"; local label="$2"; local reason="$3"')
    w('  echo "----------------------------------------------------------------"')
    w('  record "SKIP" "$seq" "$label" "$reason"')
    w("}")
    w("")
    w('echo "================================================================"')
    w(f'echo "ScenarioForge Solutions Script — {scenario_label}"')
    w('[ -n "$SSH_HOST" ] && echo "Execution: via CORE VM at $SSH_HOST" || echo "Execution: direct (this host must route to the node subnet)"')
    w('echo "================================================================"')
    w("")

    def _emit_pivots(index: int) -> None:
        for pivot in pivots_by_index.get(index, []):
            w(f"# --- Pivot {pivot.seq}: {pivot.label} ---")
            if pivot.instruction:
                w("# " + pivot.instruction.replace("\\", "\\\\"))
            if pivot.provider:
                w(f"# Provider: {pivot.provider}")
            w("check_pivot {seq} {label} {ip} {port} {kind}".format(
                seq=_bash_literal(pivot.seq),
                label=_bash_literal(pivot.label),
                ip=_bash_literal(pivot.ip),
                port=_bash_literal(pivot.port),
                kind=_bash_literal(pivot.kind),
            ))
            w("")

    for check in checks:
        _emit_pivots(check.seq - 1)
        label_lit = _bash_literal(check.label)
        if check.human:
            w(f"# --- Step {check.seq}: {check.label} — documented steps ---")
            for line in check.human:
                w("# " + line.replace("\\", "\\\\"))
        if check.skip_reason:
            w(f"skip_step {check.seq} {label_lit} {_bash_literal(check.skip_reason)}")
        else:
            w("check_step {seq} {label} {ip} {flag} {strategy} {payload}".format(
                seq=check.seq,
                label=label_lit,
                ip=_bash_literal(check.ip),
                flag=_bash_literal(check.flag),
                strategy=_bash_literal(check.strategy),
                payload=_bash_literal(_b64(check.retrieval)),
            ))
        w("")

    # A pivot whose subnet the chain never visits has nothing to be ordered
    # against (insert_before is -1), but it is still a way in that has to work.
    for index in sorted(k for k in pivots_by_index if k < 0 or k >= len(checks)):
        _emit_pivots(index)

    w('echo "================================================================"')
    w('printf "Summary: %s passed, %s failed, %s inconclusive, %s skipped (of %s steps)\\n" \\')
    w(f'  "$PASS" "$FAIL" "$INCONCLUSIVE" "$SKIP" "{len(checks) + len(pivot_checks)}"')
    w('echo "================================================================"')
    w('if [ "$FAIL" -gt 0 ]; then exit 1; fi')
    w('exit 0')
    w("")
    return "\n".join(out)
