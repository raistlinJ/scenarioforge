from __future__ import annotations
import argparse
from copy import deepcopy
import datetime
import fnmatch
import importlib
import json
import logging
import random
import re
import uuid
import os
import shlex
import subprocess
import sys
import time
import shutil
import select
from xml.etree import ElementTree as ET
from typing import Any, Dict, Tuple

try:  # pragma: no cover - env bootstrap is exercised indirectly in integration paths
    from webapp.env_loader import load_runtime_env_files as _load_runtime_env_files
except Exception:  # pragma: no cover - keep CLI usable even if web helpers are unavailable
    _load_runtime_env_files = None  # type: ignore

if _load_runtime_env_files is not None:
    try:
        _load_runtime_env_files(include_example=False)
    except Exception:
        pass

try:  # pragma: no cover - exercised indirectly via CLI subprocess tests
    from core.api.grpc import client  # type: ignore
    CORE_GRPC_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - fallback path executed in CI without CORE
    client = None  # type: ignore
    CORE_GRPC_AVAILABLE = False
from .types import NodeInfo
from .parsers.node_info import parse_node_info
from .parsers.routing import parse_routing_info
from .parsers.traffic import parse_traffic_info
from .parsers.segmentation import parse_segmentation_info
from .parsers.vulnerabilities import parse_vulnerabilities_info
from .parsers.pivoting import parse_pivoting_info
from .parsers.planning_metadata import parse_planning_metadata
from .parsers.services import parse_services
from .parsers.hitl import parse_hitl_info
from .utils.segmentation import apply_preview_segmentation_rules
from .utils.allocation import compute_role_counts
from .builders.topology import (
    _docker_node_compose_path,
    build_star_from_roles,
    build_segmented_topology,
    build_multi_switch_topology,
)
from .utils.traffic import generate_traffic_scripts
from .utils.report import write_report
from .utils.vuln_process import (
    load_vuln_catalog,
    select_vulnerabilities,
    process_vulnerabilities,
    prepare_compose_for_nodes,
    prepare_compose_for_assignments,
    assign_compose_to_nodes,
    resolve_vulnerability_catalog_entry,
    detect_docker_conflicts_for_compose_files,
    remove_docker_conflicts,
)


def _compose_assignments_summary(
    prepared_assignments: Dict[str, Dict[str, Any]] | None,
    files: list[str] | None,
    *,
    timestamp: int | None = None,
) -> Dict[str, Any]:
    assignments: Dict[str, Dict[str, Any]] = {}
    for node_name, record in (prepared_assignments or {}).items():
        try:
            assignments[str(node_name)] = dict(record or {})
        except Exception:
            assignments[str(node_name)] = {}
    return {
        'timestamp': int(time.time()) if timestamp is None else int(timestamp),
        'assignments': assignments,
        'files': list(files or []),
    }


def _write_compose_assignments_summary(
    prepared_assignments: Dict[str, Dict[str, Any]] | None,
    files: list[str] | None,
    *,
    out_base: str = '/tmp/vulns',
    timestamp: int | None = None,
) -> str:
    os.makedirs(out_base, exist_ok=True)
    path = os.path.join(out_base, 'compose_assignments.json')
    summary = _compose_assignments_summary(
        prepared_assignments,
        files,
        timestamp=timestamp,
    )
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(summary, handle, indent=2)
        handle.write('\n')
    return path


def _preview_vuln_slot_overrides(
    preview_full: Any,
    *,
    vuln_items: list[dict] | None,
    catalog: list[Dict[str, str]] | None,
    slot_names: list[str],
) -> Dict[str, Dict[str, str]]:
    """Best-effort force slot->vuln compose mapping based on preview_full.

    The orchestration/preview plan can already contain an explicit mapping of which
    host IDs get which vulnerability names (vulnerabilities_by_node). When present,
    we should honor that mapping to maintain preview parity and avoid falling back
    to the standard docker template.

    Returns a dict keyed by slot key (e.g., slot-1) to a compose record.
    """
    try:
        if not isinstance(preview_full, dict):
            return {}
        vbn = preview_full.get('vulnerabilities_by_node') or preview_full.get('vulnerabilities_preview') or {}
        if not isinstance(vbn, dict) or not vbn:
            return {}
        hosts_preview = preview_full.get('hosts') or []
        if not isinstance(hosts_preview, list) or not hosts_preview:
            return {}

        ordered_hosts = sorted(hosts_preview, key=lambda h: (h.get('node_id', 0) if isinstance(h, dict) else 0))
        slot_map: dict[int, str] = {}
        for idx, h in enumerate(ordered_hosts):
            if not isinstance(h, dict):
                continue
            try:
                hid = int(h.get('node_id'))
            except Exception:
                continue
            slot_map[hid] = f"slot-{idx+1}"

        slot_set = set(str(s) for s in (slot_names or []))
        items = vuln_items or []
        cat = catalog or []

        def _record_for_name(vname: str) -> Dict[str, str] | None:
            name = str(vname or '').strip()
            if not name:
                return None
            # Prefer explicit v_path from vuln_items (Scenario XML "Specific" rows).
            for it in items:
                if not isinstance(it, dict):
                    continue
                if str(it.get('v_name') or '').strip() != name:
                    continue
                path = str(it.get('v_path') or '').strip()
                if not path:
                    continue
                vec = str(it.get('v_vector') or it.get('Vector') or '').strip()
                return {'Type': 'docker-compose', 'Name': name, 'Path': path, 'Vector': vec}
            # Fallback: find by catalog name.
            for r in cat:
                if not isinstance(r, dict):
                    continue
                if str(r.get('Name') or '').strip() != name:
                    continue
                path = str(r.get('Path') or '').strip()
                if not path:
                    continue
                vec = str(r.get('Vector') or '').strip()
                return {'Type': 'docker-compose', 'Name': name, 'Path': path, 'Vector': vec}
            return None

        overrides: Dict[str, Dict[str, str]] = {}
        for key, names in vbn.items():
            try:
                hid = int(key)
            except Exception:
                continue
            slot = slot_map.get(hid)
            if not slot or slot not in slot_set:
                continue
            # vbn values are commonly list[str] of vuln names; accept scalar too.
            chosen = None
            if isinstance(names, list) and names:
                for cand in names:
                    if isinstance(cand, str) and cand.strip():
                        chosen = cand.strip()
                        break
            elif isinstance(names, str) and names.strip():
                chosen = names.strip()
            if not chosen:
                continue
            rec = _record_for_name(chosen)
            if rec:
                overrides[slot] = rec
        return overrides
    except Exception:
        return {}


def _merge_vuln_slot_assignments_with_preview(
    assignments_slots: Any,
    *,
    overrides: Dict[str, Dict[str, str]] | None,
    preview_full: Any,
) -> Dict[str, Dict[str, str]]:
    try:
        base: Dict[str, Dict[str, str]] = {}
        if isinstance(assignments_slots, dict):
            base = {
                str(k): v
                for k, v in assignments_slots.items()
                if isinstance(k, str) and isinstance(v, dict)
            }
        ov = overrides or {}
        if not ov:
            return base

        vbn = None
        if isinstance(preview_full, dict):
            vbn = preview_full.get('vulnerabilities_by_node') or preview_full.get('vulnerabilities_preview') or {}
        has_explicit_preview_map = isinstance(vbn, dict) and bool(vbn)

        if has_explicit_preview_map:
            return {str(k): v for k, v in ov.items() if isinstance(k, str) and isinstance(v, dict)}

        merged = dict(base)
        for k, rec in ov.items():
            if isinstance(k, str) and isinstance(rec, dict):
                merged[k] = rec
        return merged
    except Exception:
        return assignments_slots if isinstance(assignments_slots, dict) else {}


def _flow_assignment_node_ids(flow_state: Any) -> set[int]:
    try:
        if not isinstance(flow_state, dict):
            return set()
        assigns = flow_state.get('flag_assignments')
        if not isinstance(assigns, list):
            return set()
        node_ids: set[int] = set()
        for entry in assigns:
            if not isinstance(entry, dict):
                continue
            raw = entry.get('node_id')
            if raw is None:
                continue
            try:
                node_ids.add(int(raw))
            except Exception:
                continue
        return node_ids
    except Exception:
        return set()


def _slot_names_for_flow_nodes(
    *,
    flow_state: Any,
    preview_full: Any,
    slot_names: list[str],
) -> list[str]:
    try:
        if not isinstance(preview_full, dict):
            return []
        hosts_preview = preview_full.get('hosts')
        if not isinstance(hosts_preview, list) or not hosts_preview:
            return []
        flow_node_ids = _flow_assignment_node_ids(flow_state)
        if not flow_node_ids:
            return []

        ordered_hosts = sorted(
            hosts_preview,
            key=lambda h: (h.get('node_id', 0) if isinstance(h, dict) else 0),
        )
        allowed_slots: list[str] = []
        slot_set = set(str(s) for s in (slot_names or []))
        for idx, host in enumerate(ordered_hosts):
            if not isinstance(host, dict):
                continue
            try:
                host_id = int(host.get('node_id'))
            except Exception:
                continue
            if host_id not in flow_node_ids:
                continue
            slot = f"slot-{idx + 1}"
            if slot in slot_set:
                allowed_slots.append(slot)

        seen: set[str] = set()
        out: list[str] = []
        for slot in allowed_slots:
            if slot in seen:
                continue
            seen.add(slot)
            out.append(slot)
        return out
    except Exception:
        return []


def _core_session_id(session: Any) -> int | None:
    try:
        sid = getattr(session, 'id', None) or getattr(session, 'session_id', None)
        return int(sid) if sid is not None else None
    except Exception:
        return None


def _core_state_str(value: Any) -> str:
    if value is None:
        return ''
    try:
        # CORE sometimes uses IntEnum-like objects
        name = getattr(value, 'name', None)
        if isinstance(name, str) and name:
            return name.strip().lower()
    except Exception:
        pass
    try:
        text = str(value).strip()
    except Exception:
        text = ''
    if not text:
        return ''

    # Common string forms: 'SessionState.RUNTIME'
    try:
        if '.' in text:
            tail = text.split('.')[-1].strip()
            if tail:
                text = tail
    except Exception:
        pass

    # Numeric states: try mapping via core_pb2 if available.
    if text.isdigit():
        try:
            from core.api.grpc import core_pb2  # type: ignore

            return str(core_pb2.SessionState.Name(int(text))).strip().lower()
        except Exception:
            pass
    try:
        low = text.lower()
        # Normalize common CORE variants like RUNTIME_STATE -> runtime_state
        low = low.replace('-', '_').replace(' ', '_')
        while '__' in low:
            low = low.replace('__', '_')
        return low
    except Exception:
        return text.lower()


def _is_runtime_state(state: str) -> bool:
    s = _core_state_str(state).replace('-', '_').replace(' ', '_')
    while '__' in s:
        s = s.replace('__', '_')
    return s in {'runtime', 'runtime_state'}


def _is_configuration_state(state: str) -> bool:
    s = _core_state_str(state).replace('-', '_').replace(' ', '_')
    while '__' in s:
        s = s.replace('__', '_')
    return s in {'configuration', 'configuration_state'}


def _is_shutdown_state(state: str) -> bool:
    s = _core_state_str(state).replace('-', '_').replace(' ', '_')
    while '__' in s:
        s = s.replace('__', '_')
    return s in {'shutdown', 'shutdown_state'}


def _docker_use_sudo_enabled() -> bool:
    try:
        v = os.getenv('CORETG_DOCKER_USE_SUDO')
        if v is None:
            return False
        return str(v).strip().lower() not in ('0', 'false', 'no', 'off', '')
    except Exception:
        return False


def _docker_sudo_password_env() -> str | None:
    try:
        pw = os.getenv('CORETG_DOCKER_SUDO_PASSWORD')
        if pw is None:
            return None
        pw = str(pw).rstrip('\n')
        return pw if pw.strip() else None
    except Exception:
        return None


def _docker_permission_denied(text: str) -> bool:
    t = (text or '').lower()
    return (
        'got permission denied' in t
        or 'permission denied' in t
        or 'cannot connect to the docker daemon' in t
        or ('docker daemon' in t and 'permission' in t)
        or ('dial unix' in t and 'docker.sock' in t and 'permission' in t)
    )


def _docker_sudo_prefix() -> tuple[list[str], str | None]:
    """Return sudo prefix and stdin input (if needed) for docker commands."""
    if not shutil.which('sudo'):
        return [], None
    pw = _docker_sudo_password_env()
    if pw:
        return ['sudo', '-S', '-p', ''], pw + '\n'
    return ['sudo', '-n'], None


def _run_docker_cmd(args: list[str], *, timeout_s: float = 20.0, allow_sudo_retry: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a docker command, honoring CORETG_DOCKER_USE_SUDO and auto-retrying on permission errors."""
    # Primary attempt
    tried_sudo = False
    prefix: list[str] = []
    stdin_input: str | None = None
    if _docker_use_sudo_enabled():
        prefix, stdin_input = _docker_sudo_prefix()
        tried_sudo = bool(prefix)
    proc = subprocess.run(
        prefix + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=float(timeout_s or 20.0),
        input=stdin_input,
    )
    if proc.returncode == 0:
        return proc
    if not allow_sudo_retry:
        return proc
    if tried_sudo:
        return proc
    # Retry with sudo if we hit docker socket permission issues.
    if _docker_permission_denied(proc.stdout or ''):
        sp, sp_in = _docker_sudo_prefix()
        if sp:
            proc2 = subprocess.run(
                sp + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=float(timeout_s or 20.0),
                input=sp_in,
            )
            return proc2
    return proc


def _run_local_cmd(args: list[str], *, timeout_s: float = 30.0, allow_sudo_retry: bool = False) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=float(timeout_s or 30.0),
    )
    if proc.returncode == 0:
        return proc
    if not allow_sudo_retry:
        return proc
    if args and str(args[0]).strip() == 'sudo':
        return proc
    out_text = str(proc.stdout or '').lower()
    if ('permission denied' not in out_text) and ('must be root' not in out_text) and ('operation not permitted' not in out_text):
        return proc
    prefix, stdin_input = _docker_sudo_prefix()
    if not prefix:
        return proc
    return subprocess.run(
        prefix + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=float(timeout_s or 30.0),
        input=stdin_input,
    )


class _AutoFlushTextStream:
    def __init__(self, handle: Any):
        self._handle = handle

    def write(self, text: str) -> Any:
        result = self._handle.write(text)
        try:
            self._handle.flush()
        except Exception:
            pass
        return result

    def flush(self) -> None:
        try:
            self._handle.flush()
        except Exception:
            pass

    def __getattr__(self, name: str) -> Any:
        return getattr(self._handle, name)


class _CaptureTextStream(_AutoFlushTextStream):
    def __init__(self, handle: Any, *, max_chars: int = 1_000_000):
        super().__init__(handle)
        self._max_chars = max(1, int(max_chars))
        self._captured = ''

    def write(self, text: str) -> Any:
        value = str(text or '')
        self._captured = (self._captured + value)[-self._max_chars:]
        return super().write(value)

    def getvalue(self) -> str:
        return self._captured


def _cleanup_stale_vuln_temp_files() -> list[str]:
    removed: list[str] = []
    root = '/tmp/vulns'
    try:
        if not os.path.isdir(root):
            return removed
    except Exception:
        return removed
    patterns = (
        'docker-compose-*.yml',
        'docker-compose-*.orig.yml',
        'compose_assignments.json',
        'docker-wrap-*',
    )
    try:
        entries = os.listdir(root)
    except Exception:
        return removed
    for name in entries:
        if not any(fnmatch.fnmatch(name, pattern) for pattern in patterns):
            continue
        path = os.path.join(root, name)
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.remove(path)
            removed.append(path)
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return removed


def _best_effort_cli_execute_cleanup(args: Any, core: Any) -> bool:
    if str(getattr(args, 'phase', '') or '').strip().lower() != 'execute':
        return False

    core_cleanup_before_run = bool(getattr(args, 'core_cleanup_before_run', True))
    docker_cleanup_before_run = bool(getattr(args, 'docker_cleanup_before_run', True))
    overwrite_existing_images = bool(getattr(args, 'overwrite_existing_images', True))
    docker_remove_all_containers = bool(getattr(args, 'docker_remove_all_containers', False))
    reconnect_required = False

    if core_cleanup_before_run:
        blocking_ids: list[int] = []
        try:
            sessions = core.get_sessions() or []
        except Exception:
            sessions = []
        for sess in sessions:
            sid = _core_session_id(sess)
            if sid is None:
                continue
            state = _core_state_str(getattr(sess, 'state', None))
            if _is_shutdown_state(state):
                continue
            try:
                blocking_ids.append(int(sid))
            except Exception:
                continue
        if blocking_ids:
            logging.info('Execute cleanup: active CORE sessions detected: %s', ', '.join(str(x) for x in blocking_ids))
        try:
            proc = _run_local_cmd(['core-cleanup'], timeout_s=45.0, allow_sudo_retry=True)
            if proc.returncode == 0:
                reconnect_required = True
                logging.info('Execute cleanup: core-cleanup completed')
            else:
                logging.warning('Execute cleanup: core-cleanup exited %s: %s', proc.returncode, (proc.stdout or '').strip()[-1200:])
        except Exception as exc:
            logging.warning('Execute cleanup: core-cleanup failed: %s', exc)
        for cmd in (
            ['sh', '-lc', "find /var/lib/core -name '*.conf' -mtime +1 -delete 2>/dev/null || true"],
            ['sh', '-lc', "find /tmp -name 'pycore.*' -mtime +1 -delete 2>/dev/null || true"],
        ):
            try:
                _run_local_cmd(cmd, timeout_s=25.0, allow_sudo_retry=True)
            except Exception:
                pass

    if docker_cleanup_before_run or docker_remove_all_containers or overwrite_existing_images:
        if not shutil.which('docker'):
            logging.warning('Execute cleanup: docker not found; skipping docker cleanup')
            return reconnect_required

        if docker_remove_all_containers:
            remove_all_script = (
                "ids=$(docker ps -a --format '{{.ID}} {{.Names}}' | "
                "grep -vE ' core-daemon$| registry:2$' | awk '{print $1}'); "
                "if [ -n \"$ids\" ]; then "
                "imgs=$(docker inspect -f '{{.Image}}' $ids 2>/dev/null | sort -u); "
                "echo \"$ids\" | xargs -r docker rm -f; "
                "if [ -n \"$imgs\" ]; then echo \"$imgs\" | xargs -r docker rmi -f || true; fi; "
                "fi"
            )
            try:
                proc = _run_local_cmd(['sh', '-lc', remove_all_script], timeout_s=120.0, allow_sudo_retry=True)
                if proc.returncode == 0:
                    logging.info('Execute cleanup: removed non-essential Docker containers')
                else:
                    logging.warning('Execute cleanup: remove-all-containers exited %s: %s', proc.returncode, (proc.stdout or '').strip()[-1200:])
            except Exception as exc:
                logging.warning('Execute cleanup: remove-all-containers failed: %s', exc)

        if docker_cleanup_before_run:
            for cmd in (
                ['docker', 'container', 'prune', '-f'],
                ['docker', 'image', 'prune', '-f'],
                ['docker', 'network', 'prune', '-f'],
                ['docker', 'volume', 'prune', '-f'],
            ):
                try:
                    proc = _run_docker_cmd(cmd, timeout_s=120.0, allow_sudo_retry=True)
                    if proc.returncode != 0:
                        logging.warning('Execute cleanup: %s exited %s: %s', ' '.join(cmd), proc.returncode, (proc.stdout or '').strip()[-1200:])
                except Exception as exc:
                    logging.warning('Execute cleanup: %s failed: %s', ' '.join(cmd), exc)
            try:
                removed = _cleanup_stale_vuln_temp_files()
                if removed:
                    logging.info('Execute cleanup: removed %d stale /tmp/vulns artifacts', len(removed))
            except Exception:
                pass
            for script, label in (
                ("docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^coretg-gen-[^:]+:' | xargs -r docker rmi -f", 'old generator images'),
                ("docker images --format '{{.Repository}}:{{.Tag}}' | grep '_wrapper' | xargs -r docker rmi -f", 'wrapper images'),
            ):
                try:
                    proc = _run_local_cmd(['sh', '-lc', script], timeout_s=120.0, allow_sudo_retry=True)
                    if proc.returncode == 0:
                        logging.info('Execute cleanup: cleaned %s', label)
                    else:
                        logging.warning('Execute cleanup: cleanup for %s exited %s: %s', label, proc.returncode, (proc.stdout or '').strip()[-1200:])
                except Exception as exc:
                    logging.warning('Execute cleanup: cleanup for %s failed: %s', label, exc)

        elif overwrite_existing_images:
            try:
                proc = _run_local_cmd(
                    ['sh', '-lc', "docker images --format '{{.Repository}}:{{.Tag}}' | grep '_wrapper' | xargs -r docker rmi -f"],
                    timeout_s=120.0,
                    allow_sudo_retry=True,
                )
                if proc.returncode == 0:
                    logging.info('Execute cleanup: removed wrapper images')
                else:
                    logging.warning('Execute cleanup: wrapper image cleanup exited %s: %s', proc.returncode, (proc.stdout or '').strip()[-1200:])
            except Exception as exc:
                logging.warning('Execute cleanup: wrapper image cleanup failed: %s', exc)

    return reconnect_required


def _remove_local_flow_scenario_roots(scenario_norm: str) -> list[str]:
    removed: list[str] = []
    scenario_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', str(scenario_norm or '').strip())
    if not scenario_safe:
        return removed
    for subdir in ('flag_generators_runs', 'flag_node_generators_runs'):
        root = os.path.join('/tmp/vulns', subdir, f'flow-{scenario_safe}')
        try:
            if os.path.isdir(root):
                shutil.rmtree(root, ignore_errors=True)
                removed.append(root)
        except Exception:
            continue
    return removed


def _best_effort_cli_flag_sequencing_cleanup(
    args: Any,
    *,
    backend: Any,
    core_cfg: dict[str, Any] | None,
    scenario_name: str | None,
    run_remote: bool,
) -> None:
    if str(getattr(args, 'phase', '') or '').strip().lower() != 'flag-sequencing':
        return
    if not bool(getattr(args, 'flow_cleanup_before_run', True)):
        return
    flow_mode_norm = str(getattr(args, 'flow_mode', '') or '').strip().lower()
    if flow_mode_norm in {'preview'}:
        return

    scenario_norm = ''
    try:
        scenario_norm = backend._normalize_scenario_label(scenario_name or '')
    except Exception:
        scenario_norm = str(scenario_name or '').strip().lower().replace(' ', '-')

    if run_remote and isinstance(core_cfg, dict):
        try:
            core_cfg = backend._require_core_ssh_credentials(core_cfg)
        except Exception as exc:
            logging.warning('Flow cleanup: remote cleanup skipped because SSH credentials are unavailable: %s', exc)
            return
        try:
            sudo_pw = str(core_cfg.get('ssh_password') or '').strip()
        except Exception:
            sudo_pw = ''
        script = (
            "import glob, json, os, re, shutil, subprocess\n"
            f"SCEN={json.dumps(str(scenario_norm or ''))}\n"
            f"SUDO_PW={json.dumps(str(sudo_pw or ''))}\n"
            "scenario_safe=re.sub(r'[^a-zA-Z0-9_-]', '_', SCEN)\n"
            "removed=[]\n"
            "for subdir in ('flag_generators_runs','flag_node_generators_runs'):\n"
            "  root=os.path.join('/tmp/vulns', subdir, f'flow-{scenario_safe}')\n"
            "  if root and os.path.isdir(root):\n"
            "    shutil.rmtree(root, ignore_errors=True)\n"
            "    removed.append(root)\n"
            "for pattern in ('/tmp/vulns/docker-compose-*.yml','/tmp/vulns/docker-compose-*.orig.yml','/tmp/vulns/compose_assignments.json','/tmp/vulns/docker-wrap-*'):\n"
            "  for path in glob.glob(pattern):\n"
            "    try:\n"
            "      if os.path.isdir(path) and not os.path.islink(path):\n"
            "        shutil.rmtree(path, ignore_errors=True)\n"
            "      else:\n"
            "        os.remove(path)\n"
            "      removed.append(path)\n"
            "    except FileNotFoundError:\n"
            "      pass\n"
            "    except Exception:\n"
            "      pass\n"
            "def _run(cmd):\n"
            "  full=list(cmd)\n"
            "  stdin=None\n"
            "  if SUDO_PW:\n"
            "    full=['sudo','-E','-S','-p','','-k'] + full\n"
            "    stdin=SUDO_PW + '\\n'\n"
            "  p=subprocess.run(full, check=False, capture_output=True, text=True, input=stdin, timeout=120)\n"
            "  return {'cmd': full, 'rc': int(p.returncode or 0), 'out': (p.stdout or '')[-800:], 'err': (p.stderr or '')[-800:]}\n"
            "def _run_shell(text):\n"
            "  return _run(['sh','-lc',text])\n"
            "docker_ok=shutil.which('docker') is not None or os.path.exists('/usr/bin/docker')\n"
            "results=[]\n"
            "if docker_ok:\n"
            "  results.append(_run(['docker','container','prune','-f']))\n"
            "  results.append(_run(['docker','image','prune','-f']))\n"
            "  results.append(_run(['docker','network','prune','-f']))\n"
            "  results.append(_run(['docker','volume','prune','-f']))\n"
            "  results.append(_run_shell(\"docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^coretg-gen-[^:]+:' | xargs -r docker rmi -f\"))\n"
            "  results.append(_run_shell(\"docker images --format '{{.Repository}}:{{.Tag}}' | grep '_wrapper' | xargs -r docker rmi -f\"))\n"
            "print(json.dumps({'removed': removed, 'results': results, 'docker_ok': docker_ok}))\n"
        )
        try:
            payload = backend._run_remote_python_json(
                core_cfg,
                script,
                logger=backend.app.logger,
                label='flow.cleanup.remote',
                timeout=180.0,
            )
            removed = payload.get('removed') if isinstance(payload, dict) and isinstance(payload.get('removed'), list) else []
            logging.info('Flow cleanup: remote preclean complete (removed=%d)', len(removed))
        except Exception as exc:
            logging.warning('Flow cleanup: remote cleanup failed: %s', exc)
        return

    try:
        removed_roots = _remove_local_flow_scenario_roots(scenario_norm)
        if removed_roots:
            logging.info('Flow cleanup: removed %d stale local flow run directories', len(removed_roots))
    except Exception:
        pass
    try:
        removed = _cleanup_stale_vuln_temp_files()
        if removed:
            logging.info('Flow cleanup: removed %d stale /tmp/vulns artifacts', len(removed))
    except Exception:
        pass
    if not shutil.which('docker'):
        return
    for cmd in (
        ['docker', 'container', 'prune', '-f'],
        ['docker', 'image', 'prune', '-f'],
        ['docker', 'network', 'prune', '-f'],
        ['docker', 'volume', 'prune', '-f'],
    ):
        try:
            proc = _run_docker_cmd(cmd, timeout_s=120.0, allow_sudo_retry=True)
            if proc.returncode != 0:
                logging.warning('Flow cleanup: %s exited %s: %s', ' '.join(cmd), proc.returncode, (proc.stdout or '').strip()[-1200:])
        except Exception as exc:
            logging.warning('Flow cleanup: %s failed: %s', ' '.join(cmd), exc)
    for script_text, label in (
        ("docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^coretg-gen-[^:]+:' | xargs -r docker rmi -f", 'old generator images'),
        ("docker images --format '{{.Repository}}:{{.Tag}}' | grep '_wrapper' | xargs -r docker rmi -f", 'wrapper images'),
    ):
        try:
            proc = _run_local_cmd(['sh', '-lc', script_text], timeout_s=120.0, allow_sudo_retry=True)
            if proc.returncode == 0:
                logging.info('Flow cleanup: cleaned %s', label)
            else:
                logging.warning('Flow cleanup: cleanup for %s exited %s: %s', label, proc.returncode, (proc.stdout or '').strip()[-1200:])
        except Exception as exc:
            logging.warning('Flow cleanup: cleanup for %s failed: %s', label, exc)


def _docker_container_state(name: str) -> dict[str, Any]:
    """Best-effort docker inspect state for a container name."""
    name = str(name or '').strip()
    if not name:
        return {'name': name, 'exists': False, 'running': False, 'status': '', 'exit_code': None, 'error': 'empty name'}
    if not shutil.which('docker'):
        return {'name': name, 'exists': None, 'running': None, 'status': '', 'exit_code': None, 'error': 'docker not found'}
    try:
        p = _run_docker_cmd(['docker', 'inspect', '--format', '{{json .State}}', name], timeout_s=20.0)
    except Exception as exc:
        return {'name': name, 'exists': False, 'running': False, 'status': '', 'exit_code': None, 'error': f'{exc.__class__.__name__}: {exc}'}
    if p.returncode != 0:
        return {
            'name': name,
            'exists': False,
            'running': False,
            'status': '',
            'exit_code': None,
            'error': (p.stdout or '').strip() or f'docker inspect failed rc={p.returncode}',
        }
    raw = (p.stdout or '').strip()
    try:
        st = json.loads(raw) if raw else {}
    except Exception:
        st = {}
    running = None
    status = ''
    exit_code = None
    try:
        if isinstance(st, dict):
            running = st.get('Running')
            status = str(st.get('Status') or '').strip()
            exit_code = st.get('ExitCode')
    except Exception:
        pass
    return {
        'name': name,
        'exists': True,
        'running': bool(running) if running is not None else None,
        'status': status,
        'exit_code': exit_code,
        'error': None,
    }


def _docker_container_config(name: str) -> dict[str, Any]:
    """Best-effort docker inspect config for a container name."""
    name = str(name or '').strip()
    if not name:
        return {'name': name, 'exists': False, 'image': None, 'cmd': None, 'entrypoint': None, 'error': 'empty name'}
    if not shutil.which('docker'):
        return {'name': name, 'exists': None, 'image': None, 'cmd': None, 'entrypoint': None, 'error': 'docker not found'}
    try:
        p = _run_docker_cmd(['docker', 'inspect', '--format', '{{json .Config}}', name], timeout_s=20.0)
    except Exception as exc:
        return {'name': name, 'exists': False, 'image': None, 'cmd': None, 'entrypoint': None, 'error': f'{exc.__class__.__name__}: {exc}'}
    if p.returncode != 0:
        return {
            'name': name,
            'exists': False,
            'image': None,
            'cmd': None,
            'entrypoint': None,
            'error': (p.stdout or '').strip() or f'docker inspect failed rc={p.returncode}',
        }
    raw = (p.stdout or '').strip()
    try:
        cfg = json.loads(raw) if raw else {}
    except Exception:
        cfg = {}
    image = None
    cmd = None
    entrypoint = None
    try:
        if isinstance(cfg, dict):
            image = cfg.get('Image')
            cmd = cfg.get('Cmd')
            entrypoint = cfg.get('Entrypoint')
    except Exception:
        pass
    return {
        'name': name,
        'exists': True,
        'image': str(image) if image is not None else None,
        'cmd': cmd,
        'entrypoint': entrypoint,
        'error': None,
    }


def _expected_container_config_from_compose(compose_path: str, service: str) -> dict[str, Any] | None:
    """Best-effort parse of expected image/cmd/entrypoint from a compose YAML."""
    p = str(compose_path or '').strip()
    svc = str(service or '').strip()
    if not p or not svc or not os.path.exists(p):
        return None
    try:
        import yaml  # type: ignore
    except Exception:
        return None
    try:
        with open(p, 'r', encoding='utf-8', errors='ignore') as fh:
            obj = yaml.safe_load(fh) or {}
    except Exception:
        return None
    services = obj.get('services') if isinstance(obj, dict) else None
    if not isinstance(services, dict):
        return None
    body = services.get(svc)
    if not isinstance(body, dict):
        return None
    out: dict[str, Any] = {'service': svc, 'compose_path': p}
    try:
        if isinstance(body.get('image'), str):
            out['image'] = body.get('image')
    except Exception:
        pass
    try:
        if body.get('command') is not None:
            out['command'] = body.get('command')
    except Exception:
        pass
    try:
        if body.get('entrypoint') is not None:
            out['entrypoint'] = body.get('entrypoint')
    except Exception:
        pass
    return out


def _maybe_seed_docker_sudo_password_from_stdin() -> None:
    """Best-effort read a sudo password from stdin into CORETG_DOCKER_SUDO_PASSWORD.

    The Web UI's remote runner can supply the SSH password on stdin (so it isn't placed
    on the command line). ScenarioForge also spawns subprocesses (e.g.
    `scripts/run_flag_generator.py`) that only read the password from the environment.

    This function bridges that gap for remote SSH runs.
    """
    try:
        if str(os.getenv('CORETG_DOCKER_SUDO_PASSWORD') or '').strip():
            return
        flag = str(os.getenv('CORETG_DOCKER_SUDO_PASSWORD_STDIN') or '').strip().lower()
        if flag not in ('1', 'true', 'yes', 'y', 'on'):
            return
        if sys.stdin is None:
            return
        # Avoid blocking if stdin isn't a pipe/pty with data.
        r, _w, _x = select.select([sys.stdin], [], [], 0.2)
        if not r:
            return
        line = sys.stdin.readline()
        pw = (line or '').rstrip('\n')
        if pw.strip():
            os.environ['CORETG_DOCKER_SUDO_PASSWORD'] = pw
    except Exception:
        return


def _docker_compose_restart_service(compose_path: str, service: str, *, timeout_s: float = 120.0) -> dict[str, Any]:
    """Best-effort restart a single service from a compose file.

    Intended as a recovery path when CORE starts a Docker node before our compose
    override has taken effect (leading to "vanilla" containers).
    """
    p = str(compose_path or '').strip()
    svc = str(service or '').strip()
    if not p or not svc:
        return {'ok': False, 'error': 'empty compose/service', 'compose_path': p, 'service': svc}
    if not os.path.exists(p):
        return {'ok': False, 'error': 'compose missing', 'compose_path': p, 'service': svc}
    if not shutil.which('docker'):
        return {'ok': False, 'error': 'docker not found', 'compose_path': p, 'service': svc}

    try:
        cmd = ['docker', 'compose', '-f', p, 'up', '-d', svc]
        proc = _run_docker_cmd(cmd, timeout_s=float(timeout_s or 120.0), allow_sudo_retry=True)
    except Exception as exc:
        return {'ok': False, 'error': f'{exc.__class__.__name__}: {exc}', 'compose_path': p, 'service': svc, 'cmd': cmd}
    out = (proc.stdout or '').strip()
    if proc.returncode != 0:
        return {'ok': False, 'error': f'docker compose up rc={proc.returncode}', 'compose_path': p, 'service': svc, 'cmd': cmd, 'output': out[-2400:]}
    return {'ok': True, 'compose_path': p, 'service': svc, 'cmd': cmd, 'output': out[-2400:]}


def _wait_for_docker_running(
    names: list[str],
    *,
    timeout_s: float = 30.0,
    poll_s: float = 0.5,
    log_every_s: float = 10.0,
) -> dict[str, Any]:
    names = [str(n).strip() for n in (names or []) if str(n).strip()]
    names = sorted(set(names))
    if not names:
        return {'total': 0, 'running': [], 'not_running': [], 'items': []}
    deadline = time.time() + max(0.1, float(timeout_s))
    next_log_at = time.time() + max(1.0, float(log_every_s or 10.0))
    last_items: list[dict[str, Any]] = []
    while time.time() < deadline:
        items = [_docker_container_state(nm) for nm in names]
        last_items = items
        not_running = []
        running = []
        for it in items:
            if it.get('running') is True:
                running.append(it.get('name'))
            else:
                not_running.append(it.get('name'))
        if not not_running:
            return {'total': len(names), 'running': running, 'not_running': [], 'items': items}
        now = time.time()
        if now >= next_log_at:
            try:
                pending_status = []
                for it in items:
                    if it.get('running') is True:
                        continue
                    nm = str(it.get('name') or '').strip()
                    st = str(it.get('status') or '').strip() or 'unknown'
                    pending_status.append(f"{nm}({st})")
                if pending_status:
                    logging.info(
                        "Waiting for Docker runtime (%d/%d running): %s",
                        len(running),
                        len(names),
                        ", ".join(pending_status[:8]),
                    )
            except Exception:
                pass
            next_log_at = now + max(1.0, float(log_every_s or 10.0))
        time.sleep(max(0.05, float(poll_s)))
    # timeout
    not_running2 = []
    running2 = []
    for it in last_items:
        if it.get('running') is True:
            running2.append(it.get('name'))
        else:
            not_running2.append(it.get('name'))
    return {'total': len(names), 'running': running2, 'not_running': not_running2, 'items': last_items}


def _tail_core_daemon_journal(
    *,
    lines: int = 200,
    since_seconds: int = 300,
    since_epoch: float | None = None,
) -> str | None:
    """Best-effort capture of recent core-daemon logs when running on the CORE VM.

    This is a diagnostic fallback only. gRPC session state is still the primary signal.
    """
    try:
        if sys.platform != 'linux':
            return None
        if not shutil.which('journalctl'):
            return None
    except Exception:
        return None

    try:
        n = int(lines)
    except Exception:
        n = 200
    n = max(50, min(n, 2000))
    since_arg = ''
    if since_epoch is not None:
        try:
            since_arg = f"@{float(since_epoch):.3f}"
        except Exception:
            since_arg = ''
    if not since_arg:
        try:
            since_s = int(since_seconds)
        except Exception:
            since_s = 300
        since_s = max(30, min(since_s, 3600))
        since_arg = f"-{since_s} seconds"

    cmd = [
        'journalctl',
        '--no-pager',
        '-u',
        'core-daemon',
        '-n',
        str(n),
        '--since',
        since_arg,
    ]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
    except Exception:
        return None
    out = (p.stdout or '').strip()
    return out or None


def _should_collect_core_daemon_runtime_diag(start_error: str | None) -> bool:
    txt = str(start_error or '').strip().lower()
    if not txt:
        return False
    return (
        ('did not reach runtime' in txt)
        or ('stayed in "configuration"' in txt)
        or ('state=configuration' in txt)
    )


def _extract_core_daemon_runtime_hint(journal_tail: str) -> str | None:
    try:
        lines = [str(x or '').strip() for x in str(journal_tail or '').splitlines()]
    except Exception:
        return None
    lines = [ln for ln in lines if ln]
    if not lines:
        return None

    for ln in reversed(lines):
        if 'service does not exist' in ln.lower():
            return ln
    for ln in reversed(lines):
        if 'ast constructor recursion depth mismatch' in ln.lower():
            return ln
    for ln in reversed(lines):
        if 'mako.exceptions.syntaxexception:' in ln.lower():
            return ln
    for ln in reversed(lines):
        if 'servicebooterror:' in ln.lower():
            return ln
    for ln in reversed(lines):
        if 'core.errors.coreerror:' in ln.lower():
            return ln
    for ln in reversed(lines):
        lowered = ln.lower()
        if (
            'thread pool exception' in lowered
            or 'corecommanderror:' in lowered
            or 'traceback (most recent call last)' in lowered
            or 'failed to validate' in lowered
            or 'operation not permitted' in lowered
        ):
            return ln
    for ln in reversed(lines):
        lowered = ln.lower()
        if ' error ' in f' {lowered} ' or ' exception ' in f' {lowered} ':
            return ln
    return None


def _extract_core_daemon_boot_error(journal_tail: str) -> str | None:
    """Return a node boot error only when CORE reported a thread-pool failure."""
    try:
        text = str(journal_tail or '')
    except Exception:
        return None
    if 'thread pool exception' not in text.lower():
        return None

    markers = (
        'ast constructor recursion depth mismatch',
        'mako.exceptions.syntaxexception:',
        'servicebooterror:',
        'corecommanderror:',
        'required dependency was not included in node services',
    )
    lines = [str(line or '').strip() for line in text.splitlines() if str(line or '').strip()]
    for marker in markers:
        for line in reversed(lines):
            if marker in line.lower():
                return line
    return 'core-daemon reported a node boot thread-pool exception'


def _get_core_session_state(core: Any, session_id: int) -> str:
    try:
        sessions = core.get_sessions() or []
    except Exception:
        sessions = []
    for sess in sessions:
        sid = _core_session_id(sess)
        if sid is None or int(sid) != int(session_id):
            continue
        try:
            return _core_state_str(getattr(sess, 'state', None))
        except Exception:
            return ''
    return ''


def _latest_core_daemon_session_state(session_id: int, *, lines: int = 300, since_seconds: int = 90) -> str:
    """Best-effort parse of latest core-daemon `session:set_state` for one session id."""
    try:
        tail = _tail_core_daemon_journal(lines=lines, since_seconds=since_seconds)
    except Exception:
        tail = None
    if not tail:
        return ''

    sid = int(session_id)
    latest = ''
    pat = re.compile(r"changing\s+session\((\d+)\)\s+to\s+state\s+([A-Za-z0-9_.-]+)", re.IGNORECASE)
    for raw in tail.splitlines():
        line = str(raw or '').strip()
        if not line:
            continue
        m = pat.search(line)
        if not m:
            continue
        try:
            line_sid = int(m.group(1))
        except Exception:
            continue
        if line_sid != sid:
            continue
        latest = _core_state_str(m.group(2))
    return latest


def _wait_for_core_runtime(core: Any, session_id: int, *, timeout_s: float = 30.0, poll_s: float = 0.5) -> tuple[bool, str]:
    effective_timeout = max(0.1, min(float(timeout_s), 600.0))
    deadline = time.time() + effective_timeout
    journal_poll_s = 5.0
    next_journal_check = 0.0
    next_progress_log = 0.0
    last_state = ''
    while time.time() < deadline:
        state = _get_core_session_state(core, session_id)
        if state:
            last_state = state
        if _is_runtime_state(state):
            return True, state
        if _is_shutdown_state(state):
            return False, state

        now = time.time()
        if now >= next_progress_log:
            try:
                state_for_log = state or last_state or 'unknown'
                remain = max(0.0, deadline - now)
                logging.info(
                    "CORE state check (session=%s): %s (%.1fs remaining)",
                    int(session_id),
                    state_for_log,
                    remain,
                )
            except Exception:
                pass
            next_progress_log = now + journal_poll_s

        if now >= next_journal_check:
            try:
                journal_state = _latest_core_daemon_session_state(
                    int(session_id),
                    lines=300,
                    since_seconds=int(min(max(30.0, effective_timeout + 20.0), 180.0)),
                )
                if journal_state:
                    last_state = journal_state
                    if _is_runtime_state(journal_state):
                        return True, journal_state
                    if _is_shutdown_state(journal_state):
                        return False, journal_state
            except Exception:
                pass
            next_journal_check = now + journal_poll_s

        time.sleep(max(0.05, min(float(poll_s), journal_poll_s)))

    return False, last_state


def _docker_compose_node_names(docker_by_name: Any) -> list[str]:
    names: list[str] = []
    try:
        if isinstance(docker_by_name, dict):
            for nm, rec in docker_by_name.items():
                if not isinstance(rec, dict):
                    continue
                if (rec.get('Type') or '').strip().lower() != 'docker-compose':
                    continue
                names.append(str(nm))
    except Exception:
        names = []
    return sorted(set([n for n in names if n]))


def _should_tolerate_configuration_state_for_docker(
    session_state: str,
    docker_names: list[str],
    docker_runtime: dict[str, Any] | None,
    *,
    mismatches: list[dict[str, Any]] | None = None,
) -> bool:
    if not _is_configuration_state(session_state):
        return False
    if not docker_names:
        return False
    if not isinstance(docker_runtime, dict):
        return False
    if list(docker_runtime.get('not_running') or []):
        return False
    if list(mismatches or []):
        return False
    return True


def _flow_state_from_xml(xml_path: str, scenario_name: str | None) -> dict[str, Any] | None:
    if not xml_path or not os.path.exists(xml_path):
        return None
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return None
    scen_el = None
    try:
        scenarios = root.findall('.//Scenario')
        if scenario_name:
            for sc in scenarios:
                nm = (sc.get('name') or '').strip()
                if nm and nm == str(scenario_name).strip():
                    scen_el = sc
                    break
        if scen_el is None and scenarios:
            scen_el = scenarios[0]
    except Exception:
        scen_el = None
    if scen_el is None:
        return None
    try:
        flow_el = scen_el.find('.//FlagSequencing/FlowState')
        if flow_el is None:
            return None
        raw = (flow_el.text or '').strip()
        if not raw:
            return None
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _export_flow_assignments_to_env(xml_path: str, scenario_name: str | None) -> None:
    try:
        fs = _flow_state_from_xml(xml_path, scenario_name)
        assigns = fs.get('flag_assignments') if isinstance(fs, dict) else None
        if isinstance(assigns, list) and assigns:
            os.environ['CORETG_FLOW_ASSIGNMENTS_JSON'] = json.dumps(assigns, ensure_ascii=False)
    except Exception:
        pass


def _flow_read_outputs_map_from_artifacts_dir(artifacts_dir: str) -> dict[str, Any]:
    """Read realized generator outputs from a staged Flow artifacts directory."""
    try:
        directory = str(artifacts_dir or '').strip()
        if not directory:
            return {}
        base_dir = os.path.abspath(os.path.join('/tmp', 'vulns'))
        resolved_dir = os.path.abspath(directory)
        if os.path.commonpath([resolved_dir, base_dir]) != base_dir:
            return {}
        if not os.path.isdir(resolved_dir):
            return {}
        outputs_path = os.path.join(resolved_dir, 'outputs.json')
        if not os.path.isfile(outputs_path):
            return {}
        with open(outputs_path, 'r', encoding='utf-8') as handle:
            payload = json.load(handle) or {}
        outputs = payload.get('outputs') if isinstance(payload, dict) else None
        return outputs if isinstance(outputs, dict) else {}
    except Exception:
        return {}


def _flow_assignments_have_runtime(flag_assignments: Any) -> bool:
    if not isinstance(flag_assignments, list) or not flag_assignments:
        return False
    for assignment in flag_assignments:
        if not isinstance(assignment, dict):
            continue
        flag_value = str(assignment.get('flag_value') or '').strip()
        outputs = assignment.get('resolved_outputs') if isinstance(assignment.get('resolved_outputs'), dict) else None
        has_outputs = bool(isinstance(outputs, dict) and outputs)
        if not flag_value and isinstance(outputs, dict):
            flag_value = str(outputs.get('Flag(flag_id)') or outputs.get('flag') or '').strip()
        if flag_value or has_outputs:
            return True
        if str(assignment.get('artifacts_dir') or assignment.get('run_dir') or '').strip():
            return True
    return False


def _flow_state_requires_cli_execute_runtime(flow_state: Any) -> bool:
    if not isinstance(flow_state, dict):
        return False
    if flow_state.get('flow_enabled') is False:
        return False
    flag_assignments = flow_state.get('flag_assignments') if isinstance(flow_state.get('flag_assignments'), list) else None
    if isinstance(flag_assignments, list) and flag_assignments:
        return True
    chain_ids = flow_state.get('chain_ids') if isinstance(flow_state.get('chain_ids'), list) else []
    chain = flow_state.get('chain') if isinstance(flow_state.get('chain'), list) else []
    return bool(chain_ids or chain or ('flag_assignments' in flow_state))


def _inject_source_for_precheck(inject_value: Any) -> str:
    text = str(inject_value or '').strip()
    if not text:
        return ''
    for sep in ('->', '=>'):
        if sep in text:
            return text.split(sep, 1)[0].strip()
    return text


def _plan_supports_flow(role_counts: Any, vulnerabilities_plan: Any) -> bool:
    try:
        docker_hosts = int((role_counts or {}).get('Docker') or 0)
    except Exception:
        docker_hosts = 0
    vuln_targets = 0
    if isinstance(vulnerabilities_plan, dict):
        for value in vulnerabilities_plan.values():
            try:
                vuln_targets += max(0, int(value or 0))
            except Exception:
                continue
    return docker_hosts > 0 or vuln_targets > 0


def _is_temporary_preview_xml_path(path_value: Any) -> bool:
    try:
        resolved = os.path.abspath(str(path_value or '').strip())
    except Exception:
        resolved = str(path_value or '').strip()
    if not resolved:
        return False
    norm = resolved.replace('\\', '/').lower()
    try:
        parent = os.path.basename(os.path.dirname(resolved)).lower()
    except Exception:
        parent = ''
    return '/outputs/tmp-preview-' in norm or parent.startswith('tmp-preview-')


def _validate_flow_state_for_cli_execute(
    flow_state: Any,
    *,
    remote_execution_expected: bool = False,
    require_local_runtime_paths: bool = False,
) -> tuple[bool, str | None, list[dict[str, Any]]]:
    if not isinstance(flow_state, dict):
        return True, None, []
    if flow_state.get('flow_enabled') is False:
        return True, None, []

    flag_assignments = flow_state.get('flag_assignments') if isinstance(flow_state.get('flag_assignments'), list) else None
    if not isinstance(flag_assignments, list) or not flag_assignments:
        if _flow_state_requires_cli_execute_runtime(flow_state):
            return (
                False,
                'Flow is enabled, but XML has no resolved Flow runtime values. '
                'Run Generate (resolve) and Save XML before Execute.',
                [],
            )
        return True, None, []

    if not _flow_assignments_have_runtime(flag_assignments):
        return (
            False,
            'Flow is enabled, but XML has no resolved Flow runtime values. '
            'Run Generate (resolve) and Save XML before Execute.',
            [],
        )

    missing_values: list[dict[str, Any]] = []
    missing_flow_paths: list[dict[str, Any]] = []
    seen_missing_flow_paths: set[tuple[str, str, str]] = set()

    for idx, assignment in enumerate(flag_assignments):
        if not isinstance(assignment, dict):
            continue
        generator_id = str(assignment.get('id') or assignment.get('generator_id') or '').strip()
        node_id = str(assignment.get('node_id') or '').strip()
        outputs = assignment.get('resolved_outputs') if isinstance(assignment.get('resolved_outputs'), dict) else None
        flag_value = str(assignment.get('flag_value') or '').strip()
        if not flag_value and isinstance(outputs, dict):
            try:
                flag_value = str(outputs.get('Flag(flag_id)') or outputs.get('flag') or '').strip()
            except Exception:
                flag_value = ''
        artifacts_dir = str(assignment.get('artifacts_dir') or assignment.get('run_dir') or '').strip()
        has_outputs = False
        if artifacts_dir:
            if remote_execution_expected and not require_local_runtime_paths:
                has_outputs = True
            else:
                try:
                    has_outputs = bool(_flow_read_outputs_map_from_artifacts_dir(artifacts_dir))
                except Exception:
                    has_outputs = False
        if (not has_outputs) and isinstance(outputs, dict) and outputs:
            has_outputs = True
        if not flag_value and not has_outputs:
            missing_values.append({
                'index': idx,
                'node_id': node_id,
                'generator_id': generator_id,
                'reason': 'missing flag outputs',
            })
        elif artifacts_dir and ((not remote_execution_expected) or require_local_runtime_paths) and (not os.path.isdir(artifacts_dir)):
            missing_values.append({
                'index': idx,
                'node_id': node_id,
                'generator_id': generator_id,
                'reason': 'missing artifacts_dir',
                'artifacts_dir': artifacts_dir,
            })

        def _add_missing_flow_path(path_type: str, path_value: str) -> None:
            candidate = str(path_value or '').strip()
            if not candidate or not os.path.isabs(candidate):
                return
            if remote_execution_expected and not require_local_runtime_paths:
                return
            if os.path.exists(candidate):
                return
            key = (str(idx), path_type, candidate)
            if key in seen_missing_flow_paths:
                return
            seen_missing_flow_paths.add(key)
            missing_flow_paths.append({
                'index': idx,
                'node_id': node_id,
                'generator_id': generator_id,
                'reason': f'missing {path_type}',
                'path_type': path_type,
                'path': candidate,
            })

        _add_missing_flow_path('artifacts_dir', artifacts_dir)
        inject_files = assignment.get('inject_files') if isinstance(assignment.get('inject_files'), list) else []
        for inject_raw in inject_files:
            _add_missing_flow_path('inject_source', _inject_source_for_precheck(inject_raw))

    details = list(missing_values)
    details.extend(missing_flow_paths)
    if details:
        return (
            False,
            'Execute requires pre-generated Flow values saved in the XML. '
            'Run Generate (resolve) and save the XML before executing via CLI.',
            details,
        )
    return True, None, []


def _plan_summary_from_full_preview(full_prev: dict[str, Any]) -> dict[str, Any]:
    try:
        role_counts = full_prev.get('role_counts') or {}
    except Exception:
        role_counts = {}
    hosts_total = len(full_prev.get('hosts') or [])
    routers_planned = len(full_prev.get('routers') or [])
    switches = full_prev.get('switches_detail') or []
    services_plan = full_prev.get('services_plan') or full_prev.get('services_preview') or {}
    vuln_plan = full_prev.get('vulnerabilities_plan') or {}
    if not vuln_plan:
        try:
            preview = full_prev.get('vulnerabilities_preview') or {}
            if isinstance(preview, dict):
                counts: dict[str, int] = {}
                for value in preview.values():
                    if not isinstance(value, list):
                        continue
                    for name in value:
                        item = str(name or '').strip()
                        if item:
                            counts[item] = counts.get(item, 0) + 1
                if counts:
                    vuln_plan = counts
        except Exception:
            pass
    return {
        'hosts_total': hosts_total,
        'routers_planned': routers_planned,
        'hosts_allocated': 0,
        'routers_allocated': 0,
        'role_counts': role_counts,
        'services_plan': services_plan,
        'services_assigned': {},
        'vulnerabilities_plan': vuln_plan,
        'vulnerabilities_assigned': 0,
        'r2r_policy': full_prev.get('r2r_policy_preview') or {},
        'r2s_policy': full_prev.get('r2s_policy_preview') or {},
        'switches_allocated': len(switches),
        'notes': ['generated_from_full_preview'],
        'full_preview_seed': full_prev.get('seed'),
    }


def _normalize_plan_count_dict(raw: Any) -> dict[str, int]:
    if isinstance(raw, dict):
        normalized: dict[str, int] = {}
        for key, value in raw.items():
            text = str(key or '').strip()
            if not text:
                continue
            try:
                normalized[text] = int(value) if value is not None else 0
            except Exception:
                try:
                    normalized[text] = int(float(value))
                except Exception:
                    normalized[text] = 0
        return normalized
    if isinstance(raw, list):
        counts: dict[str, int] = {}
        for item in raw:
            text = str(item or '').strip()
            if not text:
                continue
            counts[text] = counts.get(text, 0) + 1
        return counts
    return {}


def _canonicalize_jsonish_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _canonicalize_jsonish_keys(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_canonicalize_jsonish_keys(item) for item in value]
    return value


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_ready(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, '__dict__'):
        try:
            return {key: _json_ready(item) for key, item in vars(value).items() if not key.startswith('_')}
        except Exception:
            pass
    try:
        return str(value)
    except Exception:
        return repr(value)


def _normalize_plan_summary(summary: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    normalized = dict(summary)
    normalized['role_counts'] = _normalize_plan_count_dict(summary.get('role_counts'))
    normalized['services_plan'] = _normalize_plan_count_dict(summary.get('services_plan'))
    normalized['vulnerabilities_plan'] = _normalize_plan_count_dict(summary.get('vulnerabilities_plan'))
    try:
        normalized['r2r_policy'] = _canonicalize_jsonish_keys(_json_ready(summary.get('r2r_policy')))
    except Exception:
        normalized['r2r_policy'] = _canonicalize_jsonish_keys(summary.get('r2r_policy'))
    try:
        normalized['r2s_policy'] = _canonicalize_jsonish_keys(_json_ready(summary.get('r2s_policy')))
    except Exception:
        normalized['r2s_policy'] = _canonicalize_jsonish_keys(summary.get('r2s_policy'))
    return normalized


def _diff_plan_summaries(flow_summary: dict[str, Any], xml_summary: dict[str, Any]) -> list[dict[str, Any]]:
    diffs: list[dict[str, Any]] = []
    flow_norm = _normalize_plan_summary(flow_summary)
    xml_norm = _normalize_plan_summary(xml_summary)

    for key in ['hosts_total', 'routers_planned', 'switches_allocated']:
        flow_value = flow_norm.get(key)
        xml_value = xml_norm.get(key)
        if flow_value != xml_value:
            diffs.append({'field': key, 'flow': flow_value, 'xml': xml_value})

    for key in ['role_counts', 'services_plan', 'vulnerabilities_plan']:
        flow_map = flow_norm.get(key) if isinstance(flow_norm.get(key), dict) else {}
        xml_map = xml_norm.get(key) if isinstance(xml_norm.get(key), dict) else {}
        for subkey in sorted(set(flow_map.keys()) | set(xml_map.keys())):
            flow_value = flow_map.get(subkey, 0)
            xml_value = xml_map.get(subkey, 0)
            if flow_value != xml_value:
                diffs.append({'field': f'{key}.{subkey}', 'flow': flow_value, 'xml': xml_value})

    for key in ['r2r_policy', 'r2s_policy']:
        flow_value = flow_norm.get(key)
        xml_value = xml_norm.get(key)
        if flow_value != xml_value:
            diffs.append({'field': key, 'flow': flow_value, 'xml': xml_value})

    return diffs


def _current_plan_summary_for_execute(
    *,
    orchestrated_plan: dict[str, Any],
    r2r_policy: dict[str, Any] | None,
    r2s_policy: dict[str, Any] | None,
    routing_items: list[Any],
    routing_plan: dict[str, Any] | None,
    segmentation_density: Any,
    segmentation_items: Any,
    traffic_plan: Any,
    seed: int | None,
    ip4_prefix: str,
    ip_mode: str,
    ip_region: str,
    hitl_preview_reservations: dict[str, Any] | None,
) -> dict[str, Any]:
    full_prev = build_full_preview(
        role_counts=orchestrated_plan.get('role_counts') or {},
        routers_planned=int(orchestrated_plan.get('routers_planned') or 0),
        services_plan=orchestrated_plan.get('service_plan') or {},
        vulnerabilities_plan=orchestrated_plan.get('vulnerability_plan'),
        r2r_policy=r2r_policy,
        r2s_policy=r2s_policy,
        routing_items=routing_items,
        routing_plan=routing_plan or {},
        segmentation_density=segmentation_density,
        segmentation_items=segmentation_items,
        traffic_plan=traffic_plan,
        seed=seed,
        ip4_prefix=ip4_prefix,
        ip_mode=ip_mode,
        ip_region=ip_region,
        base_scenario=orchestrated_plan.get('base_scenario'),
        reserved_ipv4_addrs=sorted((hitl_preview_reservations or {}).get('ip_addresses') or []),
        reserved_ipv4_networks=sorted((hitl_preview_reservations or {}).get('network_cidrs') or []),
    )
    return _plan_summary_from_full_preview(full_prev)


def _csv_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        raw_items = str(value).replace(";", ",").split(",")
    out: list[str] = []
    for item in raw_items:
        text = str(item or "").strip()
        if text:
            out.append(text)
    return out


def _ip_only(value: Any) -> str:
    text = str(value or "").strip()
    return text.split("/", 1)[0] if text else ""


def _subnet_of_ip4(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        import ipaddress

        raw = text if "/" in text else f"{text}/24"
        return str(ipaddress.ip_network(raw, strict=False))
    except Exception:
        return ""


def _pivot_ssh_compose_template_path() -> str:
    return os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "generator_templates",
            "pivot-ssh-compose",
            "docker-compose.yml",
        )
    )


def _pivot_ssh_compose_record() -> Dict[str, Any]:
    return {
        "Type": "docker-compose",
        "Name": "pivot-ssh-container",
        "Path": _pivot_ssh_compose_template_path(),
        "Vector": "pivot-ssh-fallback",
        "PivotAccessProvider": "ssh-fallback",
        "ReplaceComposeServiceWithNode": "true",
        "compose_ports": [{"service": "pivot_ssh", "protocol": "tcp", "port": 2222}],
        "SegmentationExposure": "public",
        "SegmentationPorts": ["2222"],
        "SegmentationProtocols": ["tcp"],
    }


def _apply_pivoting_to_docker_nodes(
    *,
    session: object,
    hosts: list[NodeInfo],
    docker_nodes: Dict[str, Dict[str, Any]],
    pivot_items: list[Any],
) -> Dict[str, Any]:
    import fnmatch

    node_by_name: Dict[str, NodeInfo] = {}
    for host in hosts or []:
        node_name = ""
        try:
            node_obj = session.get_node(host.node_id) if session is not None and hasattr(session, "get_node") else None
            node_name = str(getattr(node_obj, "name", None) or getattr(node_obj, "label", None) or "").strip()
        except Exception:
            node_name = ""
        if not node_name:
            node_name = f"node-{host.node_id}"
        node_by_name[node_name] = host

    def _matches(host: NodeInfo, node_name: str, node_selector: str, role_selector: str) -> bool:
        node_selector = str(node_selector or "").strip()
        role_selector = str(role_selector or "").strip()
        if node_selector:
            selectors = _csv_values(node_selector)
            node_ok = False
            for selector in selectors:
                selector_l = selector.lower()
                node_l = node_name.lower()
                role_l = str(host.role or "").strip().lower()
                if selector == str(host.node_id) or selector_l == node_l or selector_l == role_l or fnmatch.fnmatchcase(node_l, selector_l):
                    node_ok = True
                    break
            if not node_ok:
                return False
        if role_selector:
            roles = [role.lower() for role in _csv_values(role_selector)]
            if str(host.role or "").strip().lower() not in roles:
                return False
        return True

    def _source_for_pivot(host: NodeInfo, scope: str) -> str:
        scope_norm = str(scope or "host").strip().lower().replace("_", "-")
        if scope_norm in ("subnet", "lan", "same-subnet"):
            return _subnet_of_ip4(host.ip4)
        return _ip_only(host.ip4)

    def _provider_name(value: Any) -> str:
        provider = str(value or "random").strip().lower().replace("_", "-")
        aliases = {
            "random": "auto",
            "ssh": "ssh-fallback",
            "ssh-server": "ssh-fallback",
            "fallback-ssh": "ssh-fallback",
            "flag-node": "flag-node-generator",
            "flagnode": "flag-node-generator",
            "flag-nodegen": "flag-node-generator",
            "vuln": "vulnerability",
        }
        return aliases.get(provider, provider or "auto")

    def _default_pivot_produces(pivot_names: list[str], provider: str) -> list[str]:
        if provider in ("none", "manual"):
            return []
        facts: list[str] = []
        for node_name in pivot_names:
            if not node_name:
                continue
            facts.extend([f"Shell({node_name})", f"Pivot({node_name})"])
        return list(dict.fromkeys(facts))

    def _default_target_requires(pivot_names: list[str], provider: str) -> list[str]:
        if provider in ("none", "manual"):
            return []
        return [f"Pivot({node_name})" for node_name in pivot_names if node_name]

    def _merge_record_list(record: Dict[str, Any], key: str, values: list[str]) -> None:
        if not isinstance(record, dict) or not values:
            return
        existing = _csv_values(record.get(key))
        record[key] = list(dict.fromkeys(existing + values))

    def _can_replace_with_ssh_container(record: Any) -> bool:
        if not isinstance(record, dict):
            return False
        if str(record.get("CoreTGVulnAssignment") or record.get("coretg_vuln_assignment") or "").strip():
            return False
        vector = str(record.get("Vector") or record.get("vector") or "").strip().lower()
        if vector in {"flag-nodegen", "flag-node-generator", "vulnerability", "vuln"}:
            return False
        name = str(record.get("Name") or record.get("name") or "").strip().lower()
        if name and name not in {"standard-ubuntu-docker-core", "pivot-ssh-container"} and "standard" not in name and "pivot-ssh" not in name:
            return False
        return True

    def _record_text(record: Any, *keys: str) -> str:
        if not isinstance(record, dict):
            return ""
        values: list[str] = []
        for key in keys:
            try:
                value = record.get(key)
            except Exception:
                value = None
            if value not in (None, ""):
                values.append(str(value).strip())
        return " ".join(value for value in values if value).lower()

    def _is_vulnerability_record(record: Any) -> bool:
        if not isinstance(record, dict):
            return False
        if str(record.get("CoreTGVulnAssignment") or record.get("coretg_vuln_assignment") or "").strip():
            return True
        text = _record_text(record, "Vector", "vector", "Type", "type", "Name", "name")
        return any(token in text for token in ("vulnerability", "vuln"))

    def _is_flag_node_record(record: Any) -> bool:
        text = _record_text(record, "Vector", "vector", "Type", "type", "Name", "name")
        return "flag-node-generator" in text or "flag-nodegen" in text or "flag node generator" in text

    def _candidate_provider(record: Any) -> str:
        if _is_flag_node_record(record):
            return "flag-node-generator"
        if _is_vulnerability_record(record):
            return "vulnerability"
        if _can_replace_with_ssh_container(record):
            return "ssh-fallback"
        return "auto"

    def _record_matches_provider(record: Any, provider: str) -> bool:
        if provider == "vulnerability":
            return _is_vulnerability_record(record)
        if provider == "flag-node-generator":
            return _is_flag_node_record(record)
        if provider == "ssh-fallback":
            return _can_replace_with_ssh_container(record)
        if provider == "auto":
            return _is_vulnerability_record(record) or _is_flag_node_record(record) or _can_replace_with_ssh_container(record)
        return False

    def _infer_pivot_matches(provider: str, excluded_names: set[str]) -> list[tuple[str, NodeInfo]]:
        candidates: list[tuple[int, str, NodeInfo]] = []
        provider_order = {
            "vulnerability": 0,
            "flag-node-generator": 1,
            "ssh-fallback": 2,
            "auto": 3,
        }
        for node_name in sorted(docker_nodes.keys()):
            if node_name in excluded_names:
                continue
            host = node_by_name.get(node_name)
            if host is None:
                continue
            record = docker_nodes.get(node_name)
            if not _record_matches_provider(record, provider):
                continue
            effective_provider = _candidate_provider(record)
            priority = provider_order.get(effective_provider, 99)
            candidates.append((priority, node_name, host))
        if not candidates:
            return []
        candidates.sort(key=lambda item: (item[0], item[1]))
        _priority, node_name, host = candidates[0]
        return [(node_name, host)]

    def _infer_target_matches(pivot_names: set[str]) -> list[tuple[str, NodeInfo]]:
        inferred: list[tuple[str, NodeInfo]] = []
        for node_name in sorted(docker_nodes.keys()):
            if node_name in pivot_names:
                continue
            host = node_by_name.get(node_name)
            if host is None:
                continue
            inferred.append((node_name, host))
        return inferred

    def _resolved_access_provider(requested_provider: str, pivot_names: list[str], requires: list[str], explicit_produces: list[str]) -> str:
        if requested_provider != "auto":
            return requested_provider
        if requires or explicit_produces:
            return "auto"
        for provider in ("vulnerability", "flag-node-generator", "ssh-fallback"):
            if any(_candidate_provider(docker_nodes.get(name)) == provider for name in pivot_names):
                return provider
        return "auto"

    def _install_ssh_container_record(pivot_name: str, idx: int) -> bool:
        record = docker_nodes.get(pivot_name)
        if record is None:
            warnings.append(f"pivot[{idx}] ssh fallback requires pivot source '{pivot_name}' to be a Docker node")
            return False
        if not _can_replace_with_ssh_container(record):
            warnings.append(f"pivot[{idx}] ssh fallback skipped for '{pivot_name}': pivot source already has a compose assignment")
            return False
        template_path = _pivot_ssh_compose_template_path()
        if not os.path.exists(template_path):
            warnings.append(f"pivot[{idx}] ssh fallback template missing: {template_path}")
            return False
        record.clear()
        record.update(_pivot_ssh_compose_record())
        return True

    applied: list[dict[str, Any]] = []
    warnings: list[str] = []
    ssh_fallback_nodes: set[str] = set()
    for idx, item in enumerate(pivot_items or [], start=1):
        pivot_node = str(getattr(item, "pivot_node", "") or "").strip()
        pivot_role = str(getattr(item, "pivot_role", "") or "").strip()
        target_node = str(getattr(item, "target_node", "") or "").strip()
        target_role = str(getattr(item, "target_role", "") or "").strip()
        requested_provider = _provider_name(getattr(item, "access_provider", "random"))

        explicit_pivot = bool(pivot_node or pivot_role)
        explicit_target = bool(target_node or target_role)
        target_matches = [
            (node_name, host)
            for node_name, host in node_by_name.items()
            if node_name in docker_nodes and _matches(host, node_name, target_node, target_role)
        ] if explicit_target else []
        explicit_target_names = {name for name, _host in target_matches}
        pivot_matches = [
            (node_name, host)
            for node_name, host in node_by_name.items()
            if _matches(host, node_name, pivot_node, pivot_role)
        ] if explicit_pivot else _infer_pivot_matches(requested_provider, explicit_target_names)
        pivot_names_for_exclusion = {name for name, _host in pivot_matches}
        if not explicit_target:
            target_matches = _infer_target_matches(pivot_names_for_exclusion)
        if not pivot_matches:
            warnings.append(f"pivot[{idx}] skipped: no pivot source matched or could be inferred")
            continue
        if not target_matches:
            warnings.append(f"pivot[{idx}] skipped: no docker target node matched or could be inferred")
            continue

        source_scope = str(getattr(item, "source_scope", "host") or "host")
        sources = list(dict.fromkeys([
            source
            for _name, host in pivot_matches
            for source in [_source_for_pivot(host, source_scope)]
            if source
        ]))
        if not sources:
            warnings.append(f"pivot[{idx}] skipped: matched pivot nodes had no IPv4 source")
            continue

        target_ports = _csv_values(getattr(item, "target_ports", "") or "")
        target_protocols = _csv_values(getattr(item, "target_protocols", "") or "")
        exposure = str(getattr(item, "exposure", "pivot-only") or "pivot-only").strip() or "pivot-only"
        item_name = str(getattr(item, "name", "Pivot") or "Pivot")
        pivot_node_names = [name for name, _host in pivot_matches]
        requires = _csv_values(getattr(item, "requires", "") or "")
        explicit_produces = _csv_values(getattr(item, "produces", "") or "")
        access_provider = _resolved_access_provider(requested_provider, pivot_node_names, requires, explicit_produces)
        produces = list(dict.fromkeys(explicit_produces + _default_pivot_produces(pivot_node_names, access_provider)))
        target_requires = _default_target_requires(pivot_node_names, access_provider)
        for pivot_name in pivot_node_names:
            pivot_record = docker_nodes.get(pivot_name)
            if isinstance(pivot_record, dict):
                _merge_record_list(pivot_record, "PivotProduces", produces)
        if access_provider == "ssh-fallback":
            for pivot_name, _pivot_host in pivot_matches:
                if _install_ssh_container_record(pivot_name, idx):
                    ssh_fallback_nodes.add(pivot_name)
                    logging.info("Pivoting: assigned Docker SSH fallback container on %s", pivot_name)
                    pivot_record = docker_nodes.get(pivot_name)
                    if isinstance(pivot_record, dict):
                        _merge_record_list(pivot_record, "PivotProduces", produces)
        for target_name, target_host in target_matches:
            record = docker_nodes.get(target_name)
            if not isinstance(record, dict):
                continue
            existing_sources = _csv_values(record.get("SegmentationSources"))
            merged_sources = list(dict.fromkeys(existing_sources + sources))
            record["SegmentationExposure"] = exposure
            record["SegmentationSources"] = merged_sources
            record["PivotAccessProvider"] = access_provider
            _merge_record_list(record, "PivotRequires", target_requires)
            if target_ports:
                existing_ports = _csv_values(record.get("SegmentationPorts"))
                record["SegmentationPorts"] = list(dict.fromkeys(existing_ports + target_ports))
            if target_protocols:
                existing_protocols = _csv_values(record.get("SegmentationProtocols"))
                record["SegmentationProtocols"] = list(dict.fromkeys(existing_protocols + target_protocols))
            record.setdefault("PivotPlan", [])
            if isinstance(record.get("PivotPlan"), list):
                record["PivotPlan"].append(item_name)
            applied.append({
                "name": item_name,
                "pivot_nodes": pivot_node_names,
                "target_node": target_name,
                "target_ip": _ip_only(target_host.ip4),
                "target_ports": target_ports,
                "target_protocols": target_protocols,
                "exposure": exposure,
                "access_provider": access_provider,
                "requested_access_provider": requested_provider,
                "sources": merged_sources,
                "produces": produces,
                "requires": requires,
                "target_requires": target_requires,
            })

    return {
        "rules": applied,
        "warnings": warnings,
        "nodes": sorted({str(entry.get("target_node")) for entry in applied if entry.get("target_node")}),
        "ssh_fallback_nodes": sorted(ssh_fallback_nodes),
        "ssh_service_nodes": [],
    }


from .utils.services import ensure_service
from .utils.hitl import attach_hitl_rj45_nodes, collect_hitl_preview_ip_reservations

# Ensure planning.full_preview is importable even if an older installed scenarioforge shadows repo version
try:  # pragma: no cover
    from .planning.full_preview import build_full_preview  # noqa: F401
except ModuleNotFoundError:
    # Fallback not required in tests; skip if unavailable
    pass


def _canonicalize_legacy_routing_preview(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Remove the retired Routing placeholder without inventing a protocol."""

    def _repair(value: Any, *, parent_key: str = '') -> Any:
        if isinstance(value, list):
            return [_repair(item, parent_key=parent_key) for item in value]
        if not isinstance(value, dict):
            return value

        repaired: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if (
                key_text == 'Routing'
                and parent_key in {'routing_plan', 'simple_plan'}
            ):
                continue
            next_item = item
            if (
                key_text == 'protocol'
                and str(item or '').strip().lower() == 'routing'
            ):
                next_item = ''
            repaired[key_text] = _repair(next_item, parent_key=key_text)
        return repaired

    repaired_payload = _repair(payload)
    return repaired_payload if isinstance(repaired_payload, dict) else payload


def _load_preview_plan_from_xml(preview_plan_path: str, scenario_label: str | None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Load a preview/flow plan from ScenarioEditor/PlanPreview embedded in XML."""
    if not os.path.exists(preview_plan_path):
        raise ValueError(f"preview plan XML not found: {preview_plan_path}")
    try:
        tree = ET.parse(preview_plan_path)
        root = tree.getroot()
    except Exception as exc:
        raise ValueError(f"failed to parse preview plan XML: {exc}")

    scenario_norm = (scenario_label or '').strip().lower()
    se_target = None
    try:
        if root.tag == 'ScenarioEditor':
            se_target = root
        elif root.tag == 'Scenario':
            se_target = root.find('ScenarioEditor')
        elif root.tag == 'Scenarios':
            for scen_el in root.findall('Scenario'):
                name = (scen_el.get('name') or '').strip()
                if scenario_norm and name.strip().lower() != scenario_norm:
                    continue
                se_target = scen_el.find('ScenarioEditor')
                if se_target is not None:
                    break
    except Exception:
        se_target = None

    if se_target is None:
        raise ValueError('ScenarioEditor not found in preview plan XML')
    plan_el = se_target.find('PlanPreview')
    raw = (plan_el.text or '').strip() if plan_el is not None else ''
    if not raw:
        raise ValueError('PlanPreview missing in preview plan XML')
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise ValueError(f"PlanPreview invalid JSON: {exc}")
    if not isinstance(payload, dict):
        raise ValueError('preview plan must be a JSON object')

    payload = _canonicalize_legacy_routing_preview(payload)
    full_preview = payload.get('full_preview')
    if isinstance(full_preview, dict):
        return payload, full_preview

    # Backward-compat: treat the whole JSON object as a full_preview payload.
    if any(k in payload for k in ('nodes', 'links', 'display_artifacts', 'flow', 'metadata')):
        wrapped = {'full_preview': payload, 'metadata': {}}
        return wrapped, payload

    raise ValueError('unrecognized preview plan format (expected {"full_preview": {...}})')


def _load_preview_plan(preview_plan_path: str, scenario_label: str | None = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Load a persisted preview/flow plan JSON or embedded PlanPreview from XML."""
    if preview_plan_path.lower().endswith('.xml'):
        return _load_preview_plan_from_xml(preview_plan_path, scenario_label)
    with open(preview_plan_path, 'r', encoding='utf-8') as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError('preview plan must be a JSON object')

    payload = _canonicalize_legacy_routing_preview(payload)
    full_preview = payload.get('full_preview')
    if isinstance(full_preview, dict):
        return payload, full_preview

    # Backward-compat: treat the whole JSON object as a full_preview payload.
    # Heuristic: full_preview is expected to have node/link collections and/or display artifacts.
    if any(k in payload for k in ('nodes', 'links', 'display_artifacts', 'flow', 'metadata')):
        wrapped = {'full_preview': payload, 'metadata': {}}
        return wrapped, payload

    raise ValueError('unrecognized preview plan format (expected {"full_preview": {...}})')


def _run_offline_report(
    args,
    role_counts: Dict[str, int],
    routing_items: list,
    services: list,
    orchestrated_plan: Dict[str, Any],
    generation_meta: Dict[str, Any],
):
    """Generate a report without contacting core-daemon.

    This path is used in CI where CORE gRPC is unavailable. It mirrors the
    report-writing branch and emits the canonical stdout line so web code can parse it.
    """
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    # Build minimal configs from XML for inclusion in the report metadata
    try:
        routing_density, routing_items2 = parse_routing_info(args.xml, args.scenario)
    except Exception:
        routing_density, routing_items2 = None, []
    routing_cfg = {
        "density": routing_density,
        "items": [{
            "protocol": getattr(i, 'protocol', ''),
            "factor": getattr(i, 'factor', 0.0),
        } for i in (routing_items2 or [])],
    }

    try:
        traffic_density, traffic_items = parse_traffic_info(args.xml, args.scenario)
    except Exception:
        traffic_density, traffic_items = None, []
    traffic_cfg = {
        "density": traffic_density,
        "items": [{
            "kind": getattr(i, 'kind', ''),
            "factor": getattr(i, 'factor', 0.0),
            "pattern": getattr(i, 'pattern', ''),
            "rate_kbps": getattr(i, 'rate_kbps', 0.0),
            "period_s": getattr(i, 'period_s', 0.0),
            "jitter_pct": getattr(i, 'jitter_pct', 0.0),
            "content_type": getattr(i, 'content_type', ''),
        } for i in (traffic_items or [])],
    }

    try:
        services_list = parse_services(args.xml, args.scenario)
    except Exception:
        services_list = []
    services_cfg = [
        {"name": getattr(s, 'name', ''), "factor": getattr(s, 'factor', 0.0), "density": getattr(s, 'density', 0.0)}
        for s in (services_list or [])
    ]

    try:
        seg_density, seg_items = parse_segmentation_info(args.xml, args.scenario)
    except Exception:
        seg_density, seg_items = None, []
    segmentation_cfg = {
        "density": seg_density,
        "items": [
            {"name": getattr(i, 'name', ''), "factor": getattr(i, 'factor', 0.0)}
            for i in (seg_items or [])
        ] if seg_items else [],
    }

    try:
        vuln_density, vuln_items, vuln_flag_type = parse_vulnerabilities_info(args.xml, args.scenario)
    except Exception:
        vuln_density, vuln_items, vuln_flag_type = None, [], None
    vulnerabilities_cfg = {
        "density": vuln_density,
        "items": vuln_items or [],
        "flag_type": vuln_flag_type,
    }

    try:
        pivot_density, pivot_items = parse_pivoting_info(args.xml, args.scenario)
    except Exception:
        pivot_density, pivot_items = None, []
    pivoting_cfg = {
        "density": pivot_density,
        "items": [
            {
                "name": getattr(item, 'name', ''),
                "factor": getattr(item, 'factor', 0.0),
                "pivot_node": getattr(item, 'pivot_node', ''),
                "pivot_role": getattr(item, 'pivot_role', ''),
                "target_node": getattr(item, 'target_node', ''),
                "target_role": getattr(item, 'target_role', ''),
                "target_ports": getattr(item, 'target_ports', ''),
                "target_protocols": getattr(item, 'target_protocols', ''),
                "exposure": getattr(item, 'exposure', ''),
                "source_scope": getattr(item, 'source_scope', ''),
                "access_provider": getattr(item, 'access_provider', ''),
            }
            for item in (pivot_items or [])
        ],
    }
    if pivot_items:
        generation_meta['pivoting_items'] = pivoting_cfg['items']

    from datetime import datetime as _dt
    report_dir = os.path.join(repo_root, "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"scenario_report_{_dt.now().strftime('%m-%d-%y-%H-%M-%S-%f')}.md")

    report_path, summary_path = write_report(
        report_path,
        args.scenario,
        routers=[],
        router_protocols={},
        switches=[],
        hosts=[],
        service_assignments={},
        traffic_summary_path=None,
        segmentation_summary_path=None,
        metadata=generation_meta,
        routing_cfg=routing_cfg,
        traffic_cfg=traffic_cfg,
        services_cfg=services_cfg,
        segmentation_cfg=segmentation_cfg,
        vulnerabilities_cfg=vulnerabilities_cfg,
        pivoting_cfg=pivoting_cfg,
    )

    logging.info("Scenario report written to %s", report_path)
    try:
        print(f"Scenario report written to {report_path}", flush=True)
    except Exception:
        pass
    if summary_path:
        logging.info("Scenario summary written to %s", summary_path)
        try:
            print(f"Scenario summary written to {summary_path}", flush=True)
        except Exception:
            pass
    return 0


def _load_web_backend_module() -> Any:
    return importlib.import_module('webapp.app_backend')


def _cli_option_provided(*option_names: str) -> bool:
    try:
        argv_tokens = list(sys.argv[1:])
    except Exception:
        argv_tokens = []
    for token in argv_tokens:
        for option_name in option_names:
            if token == option_name or token.startswith(f'{option_name}='):
                return True
    return False


def _is_loopback_host(value: Any) -> bool:
    try:
        text = str(value or '').strip().lower()
    except Exception:
        return False
    return text in {'', 'localhost', '127.0.0.1', '::1'}


def _cli_runtime_mode(backend: Any | None = None) -> str:
    if backend is not None:
        try:
            mode = str(backend._webui_runtime_mode() or '').strip().lower()
        except Exception:
            mode = ''
        if mode:
            return mode
    try:
        mode = str(
            os.environ.get('CORETG_WEBUI_MODE')
            or os.environ.get('CORETG_RUNTIME_MODE')
            or ''
        ).strip().lower()
    except Exception:
        mode = ''
    return mode or 'native'


def _cli_vm_mode_config_issues(
    backend: Any,
    *,
    phase: str,
    core_cfg: dict[str, Any],
    has_saved_core_source: bool,
    hitl_config: dict[str, Any] | None = None,
) -> list[str]:
    if _cli_runtime_mode(backend) != 'vm':
        return []

    issues: list[str] = []
    if phase in {'execute', 'topo', 'flag-sequencing'} and not has_saved_core_source:
        issues.append('scenario XML is missing saved CORE VM connection data (CoreConnection or HardwareInLoop/CoreConnection)')

    host = str(core_cfg.get('host') or '').strip()
    try:
        port = int(core_cfg.get('port') or 0)
    except Exception:
        port = 0
    ssh_host = str(core_cfg.get('ssh_host') or '').strip()
    try:
        ssh_port = int(core_cfg.get('ssh_port') or 0)
    except Exception:
        ssh_port = 0
    ssh_username = str(core_cfg.get('ssh_username') or '').strip()
    ssh_password = str(core_cfg.get('ssh_password') or '').strip()

    if not host:
        issues.append('CORE_HOST / grpc host')
    if port <= 0:
        issues.append('CORE_PORT / grpc port')
    if not ssh_host:
        issues.append('CORE_SSH_HOST')
    if ssh_port <= 0:
        issues.append('CORE_SSH_PORT')
    if not ssh_username:
        issues.append('CORE_SSH_USERNAME')
    if not ssh_password:
        issues.append('CORE_SSH_PASSWORD')

    if ssh_host == '12.0.0.100' and ssh_username == 'sampleuser' and ssh_password == 'samplepassword':
        issues.append('CORE_SSH_HOST / CORE_SSH_USERNAME / CORE_SSH_PASSWORD still use the template values from .scenarioforge.env(.example)')

    try:
        vm_defaults = backend._webui_vm_mode_defaults(include_password=False)
    except Exception:
        vm_defaults = {}
    vm_hitl = vm_defaults.get('hitl') if isinstance(vm_defaults, dict) and isinstance(vm_defaults.get('hitl'), dict) else {}
    vm_hitl_enabled = bool(vm_hitl.get('enabled'))

    if phase == 'new' and vm_hitl_enabled:
        vm_ifaces = vm_hitl.get('interfaces') if isinstance(vm_hitl.get('interfaces'), list) else []
        if not any(isinstance(iface, dict) and str(iface.get('name') or '').strip() for iface in vm_ifaces):
            issues.append('CORETG_VM_MODE_HITL_CORE_IFX_NAME (vm-mode HITL interface name)')

    if phase in {'execute', 'topo'}:
        cfg = hitl_config if isinstance(hitl_config, dict) else {}
        scenario_hitl_enabled = bool(cfg.get('enabled'))
        hitl_ifaces = cfg.get('interfaces') if isinstance(cfg.get('interfaces'), list) else []
        if scenario_hitl_enabled and not any(isinstance(iface, dict) and str(iface.get('name') or '').strip() for iface in hitl_ifaces):
            issues.append('scenario XML HardwareInLoop interface configuration required by vm mode')

    return issues


def _emit_vm_mode_cli_error(
    *,
    phase: str,
    xml_path: str,
    scenario_name: str | None,
    issues: list[str],
    output_path: str | None = None,
    json_output: bool = True,
    emit_validation_marker: bool = False,
) -> int:
    if json_output:
        _emit_phase_json(
            {
                'ok': False,
                'phase': phase,
                'xml_path': xml_path,
                'scenario': scenario_name,
                'error': f'VM mode requires additional configuration before the {phase} phase can run.',
                'missing': list(issues or []),
            },
            output_path=output_path,
            stream=sys.stderr,
        )
    else:
        logging.error('VM mode requires additional configuration before the %s phase can run.', phase)
        for issue in issues or []:
            logging.error('Missing or unconfigured: %s', issue)
        if phase == 'execute' and emit_validation_marker:
            _print_post_execution_validation_summary(
                {
                    'ok': False,
                    'error': f'VM mode requires additional configuration before the {phase} phase can run.',
                    'validation_unavailable': True,
                    'validation_unavailable_details': list(issues or []),
                    'cli_post_execution_validation': True,
                    'scenario_xml_path': xml_path,
                },
                stream=sys.stderr,
            )
    return 1


def _resolve_cli_core_context(args: Any, *, backend: Any, scenario_name: str | None) -> tuple[str, dict[str, Any], bool]:
    scenario_norm = ''
    try:
        scenario_norm = backend._normalize_scenario_label(scenario_name or '')
    except Exception:
        scenario_norm = str(scenario_name or '').strip().lower().replace(' ', '-')

    xml_core_cfg = None
    try:
        xml_core_cfg = backend._core_config_from_xml_path(
            os.path.abspath(args.xml),
            scenario_norm,
            include_password=True,
        )
    except Exception:
        xml_core_cfg = None

    saved_core_cfg: dict[str, Any] | None = None
    has_saved_core_source = isinstance(xml_core_cfg, dict) and bool(xml_core_cfg)
    if scenario_norm and has_saved_core_source:
        try:
            saved_core_cfg = backend._select_core_config_for_page(
                scenario_norm,
                include_password=True,
            )
        except TypeError:
            try:
                saved_core_cfg = backend._select_core_config_for_page(
                    scenario_norm,
                    backend._load_run_history(),
                    include_password=True,
                )
            except Exception:
                saved_core_cfg = None
        except Exception:
            saved_core_cfg = None

    cli_override: dict[str, Any] = {}
    if _cli_option_provided('--host'):
        cli_override['host'] = args.host
        cli_override['grpc_host'] = args.host
    if _cli_option_provided('--port'):
        cli_override['port'] = args.port
        cli_override['grpc_port'] = args.port
    if _cli_option_provided('--ssh-host'):
        cli_override['ssh_host'] = args.ssh_host
    if _cli_option_provided('--ssh-port'):
        cli_override['ssh_port'] = args.ssh_port
    if _cli_option_provided('--ssh-username'):
        cli_override['ssh_username'] = args.ssh_username
    if _cli_option_provided('--ssh-password'):
        cli_override['ssh_password'] = args.ssh_password
    if _cli_option_provided('--venv-bin'):
        cli_override['venv_bin'] = args.venv_bin

    credential_fill: dict[str, Any] | None = None
    fill_matching_credentials = getattr(backend, '_fill_matching_core_credentials', None)
    if callable(fill_matching_credentials) and isinstance(xml_core_cfg, dict):
        try:
            credential_fill = fill_matching_credentials(xml_core_cfg, saved_core_cfg)
        except Exception:
            credential_fill = None
    if credential_fill is None:
        credential_fill = dict(xml_core_cfg or {})
        if isinstance(saved_core_cfg, dict):
            xml_secret_id = str(credential_fill.get('core_secret_id') or '').strip()
            saved_secret_id = str(saved_core_cfg.get('core_secret_id') or '').strip()
            same_secret = bool(xml_secret_id and saved_secret_id and xml_secret_id == saved_secret_id)
            same_target = all(
                str(credential_fill.get(key) or '').strip()
                and str(credential_fill.get(key) or '').strip() == str(saved_core_cfg.get(key) or '').strip()
                for key in ('ssh_host', 'ssh_port', 'ssh_username')
            )
            if same_secret or same_target:
                if credential_fill.get('ssh_password') in (None, ''):
                    credential_fill['ssh_password'] = saved_core_cfg.get('ssh_password')

    # The XML is the connection ground truth. Saved WebUI state may provide a
    # matching password, while explicit CLI options remain the final override.
    merged = backend._merge_core_configs(
        credential_fill,
        cli_override if cli_override else None,
        include_password=True,
    )
    try:
        merged = backend._prefer_explicit_or_ssh_core_host(
            merged,
            xml_core_cfg,
            cli_override if cli_override else None,
        )
    except Exception:
        pass
    if scenario_norm and str(merged.get('core_secret_id') or '').strip():
        try:
            merged = backend._apply_core_secret_to_config(merged, scenario_norm)
        except Exception:
            pass
    try:
        normalized = backend._normalize_core_config(merged, include_password=True)
        if isinstance(normalized, dict) and isinstance(merged, dict):
            for key, value in merged.items():
                if key not in normalized:
                    normalized[key] = value
        merged = normalized
    except Exception:
        pass
    return scenario_norm, (merged if isinstance(merged, dict) else {}), bool(has_saved_core_source)


def _resolve_cli_authoritative_xml_path(args: Any, *, backend: Any) -> None:
    if str(getattr(args, 'phase', '') or '').strip().lower() not in {'execute', 'topo', 'flag-sequencing'}:
        return
    # A direct CLI invocation must execute the exact file named by --xml.
    # WebUI callers resolve and synchronize their authoritative XML before
    # launching the CLI.
    if _cli_option_provided('--xml'):
        try:
            args.xml = os.path.abspath(str(args.xml))
        except Exception:
            pass
        return
    try:
        resolved = backend._resolve_preexecute_xml_path(
            getattr(args, 'xml', None),
            getattr(args, 'scenario', None),
        )
    except Exception:
        return
    resolved_text = str(resolved or '').strip()
    if not resolved_text:
        return
    try:
        args.xml = os.path.abspath(resolved_text)
    except Exception:
        args.xml = resolved_text


def _maybe_prepare_cli_execute_hitl_xml(
    args: Any,
    *,
    backend: Any,
    scenario_name: str | None,
) -> tuple[list[str], list[dict[str, Any]]]:
    if str(getattr(args, 'phase', '') or '').strip().lower() != 'execute':
        return [], []
    try:
        xml_path = os.path.abspath(str(getattr(args, 'xml', '') or '').strip())
    except Exception:
        xml_path = str(getattr(args, 'xml', '') or '').strip()
    if not xml_path:
        return [], []

    try:
        payload_for_core = backend._parse_scenarios_xml(xml_path)
    except Exception:
        return [], []
    if not isinstance(payload_for_core, dict):
        return [], []

    scenario_payload = None
    scen_list = payload_for_core.get('scenarios') if isinstance(payload_for_core.get('scenarios'), list) else None
    if isinstance(scen_list, list) and scen_list:
        if scenario_name:
            scenario_name_text = str(scenario_name or '').strip()
            for scen_entry in scen_list:
                if not isinstance(scen_entry, dict):
                    continue
                if str(scen_entry.get('name') or '').strip() == scenario_name_text:
                    scenario_payload = scen_entry
                    break
        if scenario_payload is None:
            scenario_payload = next((entry for entry in scen_list if isinstance(entry, dict)), None)
    if not isinstance(scenario_payload, dict):
        return [], []

    hitl_cfg = scenario_payload.get('hitl') if isinstance(scenario_payload.get('hitl'), dict) else None
    if not isinstance(hitl_cfg, dict) or not hitl_cfg:
        return [], []

    try:
        _scenario_norm, effective_core_cfg, _has_saved_core_source = _resolve_cli_core_context(
            args,
            backend=backend,
            scenario_name=scenario_name,
        )
    except Exception:
        effective_core_cfg = {}

    try:
        validated_hitl_cfg, hitl_errors, hitl_changes = backend._validate_hitl_interface_names_for_execute(
            hitl_cfg,
            effective_core_cfg,
        )
    except Exception as exc:
        return [f'Failed to validate HITL interface names before execute: {exc}'], []

    if hitl_errors or not hitl_changes:
        return list(hitl_errors or []), list(hitl_changes or [])

    if not hasattr(backend, '_build_scenarios_xml'):
        return [], list(hitl_changes or [])

    try:
        scenario_copy = dict(scenario_payload)
        scenario_copy['hitl'] = validated_hitl_cfg
        temp_tree = backend._build_scenarios_xml({
            'scenarios': [scenario_copy],
            'core': payload_for_core.get('core') if isinstance(payload_for_core.get('core'), dict) else None,
        })
        ts = backend._local_timestamp_safe() if hasattr(backend, '_local_timestamp_safe') else datetime.datetime.now().strftime('%m-%d-%y-%H-%M-%S')
        run_tag = str(uuid.uuid4())[:8]
        outputs_dir = backend._outputs_dir() if hasattr(backend, '_outputs_dir') else (os.path.dirname(xml_path) or os.getcwd())
        out_dir = os.path.join(outputs_dir, f'tmp-cli-exec-hitl-{ts}-{run_tag}')
        os.makedirs(out_dir, exist_ok=True)
        previous_xml_path = xml_path
        stem = os.path.splitext(os.path.basename(xml_path))[0].strip() or 'scenario'
        resolved_xml_path = os.path.join(out_dir, f'{stem}.xml')
        temp_tree.write(resolved_xml_path, encoding='utf-8', xml_declaration=True)
        args.xml = resolved_xml_path
        try:
            preview_plan_arg = str(getattr(args, 'preview_plan', '') or '').strip()
        except Exception:
            preview_plan_arg = ''
        if preview_plan_arg:
            try:
                if os.path.abspath(preview_plan_arg) == os.path.abspath(previous_xml_path):
                    args.preview_plan = resolved_xml_path
            except Exception:
                if preview_plan_arg == previous_xml_path:
                    args.preview_plan = resolved_xml_path
    except Exception as exc:
        return [f'Failed to materialize validated HITL execute XML: {exc}'], []

    return [], list(hitl_changes or [])


def _cli_has_env_remote_source(backend: Any, core_cfg: dict[str, Any]) -> bool:
    if _cli_runtime_mode(backend) != 'vm':
        return False
    if str(os.environ.get('CORETG_CLI_DISABLE_REMOTE_DELEGATION') or '').strip().lower() in {'1', 'true', 'yes', 'y', 'on'}:
        return False
    try:
        env_cfg = backend._core_backend_defaults(include_password=True)
    except Exception:
        env_cfg = None
    if not isinstance(env_cfg, dict) or not env_cfg:
        return False
    ssh_host = str(core_cfg.get('ssh_host') or env_cfg.get('ssh_host') or '').strip()
    ssh_username = str(core_cfg.get('ssh_username') or env_cfg.get('ssh_username') or '').strip()
    ssh_password = str(core_cfg.get('ssh_password') or env_cfg.get('ssh_password') or '').strip()
    target_host = str(core_cfg.get('host') or env_cfg.get('host') or '').strip()
    if not ssh_host or not ssh_username or not ssh_password:
        return False
    return not (_is_loopback_host(ssh_host) and _is_loopback_host(target_host))


class _BackendProxy:
    def __init__(self, base: Any, **overrides: Any) -> None:
        self._base = base
        self._overrides = dict(overrides)

    def __getattr__(self, name: str) -> Any:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._base, name)


def _cli_should_delegate_remote(core_cfg: dict[str, Any]) -> bool:
    if str(os.environ.get('CORETG_CLI_REMOTE_DELEGATED') or '').strip().lower() in {'1', 'true', 'yes', 'y', 'on'}:
        return False
    if not isinstance(core_cfg, dict) or not core_cfg:
        return False
    ssh_host = str(core_cfg.get('ssh_host') or '').strip()
    ssh_username = str(core_cfg.get('ssh_username') or '').strip()
    ssh_password = str(core_cfg.get('ssh_password') or '').strip()
    target_host = str(core_cfg.get('host') or '').strip()
    if not ssh_host or not ssh_username or not ssh_password:
        return False
    return not (_is_loopback_host(ssh_host) and _is_loopback_host(target_host))


_POST_EXECUTION_VALIDATION_OPTIONS = {
    '-post-execution-validation',
    '--post-execution-validation',
}

_POST_EXECUTION_ERROR_FIELDS = (
    ('missing_nodes', 'Missing scenario nodes'),
    ('missing_docker_nodes', 'Missing expected Docker nodes'),
    ('missing_vuln_nodes', 'Missing expected vulnerability nodes'),
    ('docker_missing', 'Missing Docker containers'),
    ('docker_not_running', 'Docker containers not running'),
    ('generator_outputs_missing', 'Missing generator outputs'),
    ('flow_live_paths_missing', 'Missing Flow runtime paths'),
)

_POST_EXECUTION_WARNING_FIELDS = (
    ('extra_nodes', 'Unexpected scenario nodes'),
    ('extra_docker_nodes', 'Unexpected Docker nodes'),
    ('docker_start_pending', 'Docker containers still starting'),
    ('injects_missing', 'Missing container injects'),
    ('generator_injects_missing', 'Missing generator inject sources'),
)


def _cli_color_enabled(stream: Any) -> bool:
    if str(os.environ.get('NO_COLOR') or '').strip():
        return False
    force_color = str(os.environ.get('FORCE_COLOR') or '').strip().lower()
    if force_color and force_color not in {'0', 'false', 'no', 'off'}:
        return True
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def _cli_colored(text: str, color_code: str, *, stream: Any) -> str:
    if not _cli_color_enabled(stream):
        return text
    return f'\033[{color_code}m{text}\033[0m'


def _post_execution_validation_issues(
    summary: dict[str, Any] | None,
) -> tuple[list[tuple[str, list[str]]], list[tuple[str, list[str]]]]:
    errors: list[tuple[str, list[str]]] = []
    warnings: list[tuple[str, list[str]]] = []
    if not isinstance(summary, dict):
        return [('Validation unavailable', ['no validation summary returned'])], warnings

    validation_error = str(summary.get('error') or '').strip()
    flow_copy_error = str(summary.get('flow_artifact_copy_error') or '').strip()
    if summary.get('validation_unavailable') is True:
        details = summary.get('validation_unavailable_details')
        values = [str(value) for value in details] if isinstance(details, list) else []
        if validation_error:
            values.insert(0, validation_error)
        errors.append(('Validation unavailable', values or ['post-execution validation could not run']))
    elif validation_error:
        errors.append(('Validation error', [validation_error]))
    if flow_copy_error:
        errors.append(('Flow artifact copy failed', [flow_copy_error]))

    def _collect(
        fields: tuple[tuple[str, str], ...],
        target: list[tuple[str, list[str]]],
    ) -> None:
        for key, label in fields:
            raw_values = summary.get(key)
            if not isinstance(raw_values, list):
                continue
            values = [str(value).strip() for value in raw_values if str(value).strip()]
            if values:
                target.append((label, values))

    _collect(_POST_EXECUTION_ERROR_FIELDS, errors)
    _collect(_POST_EXECUTION_WARNING_FIELDS, warnings)
    if summary.get('ok') is False and not errors and not warnings:
        errors.append(('Validation failed', ['validator reported an unsuccessful result']))
    return errors, warnings


def _print_post_execution_validation_summary(
    summary: dict[str, Any],
    *,
    stream: Any = None,
    artifact_path: str | None = None,
) -> bool:
    target = stream if stream is not None else sys.stdout
    errors, warnings = _post_execution_validation_issues(summary)
    if errors:
        status = _cli_colored('FAILED', '31', stream=target)
    elif warnings:
        status = _cli_colored('PASSED WITH WARNINGS', '33', stream=target)
    else:
        status = _cli_colored('PASSED', '32', stream=target)

    print('', file=target)
    print(f'Post-execution validation: {status}', file=target)
    for label, values in errors:
        heading = _cli_colored(f'ERROR: {label} ({len(values)})', '31', stream=target)
        print(f'  {heading}', file=target)
        for value in values[:10]:
            print(_cli_colored(f'    - {value}', '31', stream=target), file=target)
        if len(values) > 10:
            print(_cli_colored(f'    - ... and {len(values) - 10} more', '31', stream=target), file=target)
    for label, values in warnings:
        heading = _cli_colored(f'WARNING: {label} ({len(values)})', '33', stream=target)
        print(f'  {heading}', file=target)
        for value in values[:10]:
            print(_cli_colored(f'    - {value}', '33', stream=target), file=target)
        if len(values) > 10:
            print(_cli_colored(f'    - ... and {len(values) - 10} more', '33', stream=target), file=target)
    if not errors and not warnings:
        expected_count = len(summary.get('expected_nodes') or [])
        docker_count = len(summary.get('docker_running') or [])
        print(f'  Nodes validated: {expected_count}; Docker containers running: {docker_count}', file=target)
    if artifact_path:
        print(f'  Validation summary: {artifact_path}', file=target)
    print(
        'VALIDATION_SUMMARY_JSON: '
        + json.dumps(summary, sort_keys=True, separators=(',', ':'), default=str),
        file=target,
    )
    try:
        target.flush()
    except Exception:
        pass
    return not errors


def _print_post_execution_validation_unavailable(
    error: str,
    *,
    stream: Any = None,
    session_id: int | None = None,
    details: list[str] | None = None,
) -> bool:
    summary: dict[str, Any] = {
        'ok': False,
        'error': str(error or 'post-execution validation could not run'),
        'validation_unavailable': True,
        'cli_post_execution_validation': True,
    }
    if session_id is not None:
        summary['session_id'] = int(session_id)
    clean_details = [
        str(value).strip()
        for value in (details or [])
        if str(value).strip()
    ]
    if clean_details:
        summary['validation_unavailable_details'] = clean_details
    return _print_post_execution_validation_summary(summary, stream=stream)


def _extract_last_json_marker(text: str, marker: str) -> dict[str, Any] | None:
    for raw_line in reversed(str(text or '').splitlines()):
        line = str(raw_line or '').strip()
        if marker not in line:
            continue
        try:
            payload = json.loads(line.split(marker, 1)[1].strip())
        except Exception:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def _remote_execute_failure_detail(output_text: str) -> str | None:
    lines = [
        str(raw_line or '').strip()
        for raw_line in str(output_text or '').splitlines()
        if str(raw_line or '').strip()
    ]
    priority_markers = (
        'Start validation failed:',
        'CORE daemon node boot failure:',
        'CORE daemon runtime hint:',
        'Failed to start/validate CORE session:',
    )
    for marker in priority_markers:
        for line in reversed(lines):
            if marker.lower() in line.lower():
                return line[-2000:]
    for line in reversed(lines):
        lowered = line.lower()
        if ' error ' in f' {lowered} ' or 'exception' in lowered or 'failed' in lowered:
            return line[-2000:]
    return lines[-1][-2000:] if lines else None


def _run_cli_post_execution_validation(
    *,
    backend: Any,
    args: Any,
    core_cfg: dict[str, Any],
    session_id: int,
    stream: Any = None,
) -> bool:
    target = stream if stream is not None else sys.stdout
    xml_path = os.path.abspath(str(getattr(args, 'xml', '') or '').strip())
    scenario_name = str(getattr(args, 'scenario', '') or '').strip() or None
    preview_plan_path = str(
        getattr(args, 'preview_plan', '')
        or getattr(args, '_resolved_preview_plan_path', '')
        or xml_path
    ).strip()
    flow_state = _flow_state_from_xml(xml_path, scenario_name)
    flow_enabled = _flow_state_requires_cli_execute_runtime(flow_state)
    out_dir = os.path.join(os.path.dirname(xml_path) or os.getcwd(), 'core-post')
    copy_error = ''
    copy_meta: dict[str, Any] | None = None

    if flow_enabled:
        copy_meta = {
            'remote': True,
            'core_cfg': core_cfg,
            'remote_base_dir': str(os.environ.get('CORE_REMOTE_BASE_DIR') or '/tmp/scenarioforge'),
            'flow_copy_required': True,
        }
        try:
            print('[validate] Copying Flow artifacts into running containers...', file=target)
            backend._maybe_copy_flow_artifacts_into_containers(
                copy_meta,
                stage='cli-postrun',
                log_prefix='[validate] ',
            )
            if not copy_meta.get('flow_artifacts_copied'):
                copy_error = str(copy_meta.get('flow_artifact_copy_error') or '').strip()
                if not copy_error:
                    copy_error = (
                        'Flow artifact copy did not complete. '
                        'Check compose_assignments.json and Docker copy diagnostics on the CORE VM.'
                    )
            copy_summary = copy_meta.get('flow_artifact_copy_summary')
            if isinstance(copy_summary, dict):
                items = copy_summary.get('items')
                if isinstance(items, list):
                    copied_ok = sum(
                        1 for item in items
                        if isinstance(item, dict) and item.get('ok')
                    )
                    print(
                        f'[validate] Flow artifact copy targets: {copied_ok}/{len(items)} succeeded.',
                        file=target,
                    )
                    for item in items:
                        if not isinstance(item, dict) or item.get('ok'):
                            continue
                        node = str(item.get('node') or 'unknown')
                        error = str(item.get('error') or '').strip()
                        errors = item.get('errors') if isinstance(item.get('errors'), list) else []
                        detail = error or (str(errors[0]) if errors else 'copy failed')
                        print(f'[validate] Flow artifact copy failed for {node}: {detail}', file=target)
        except Exception as exc:
            copy_error = f'Flow artifact copy failed: {exc}'

    try:
        session_xml_path = backend._grpc_save_current_session_xml_with_config(
            core_cfg,
            out_dir,
            session_id=str(session_id),
        )
        if not session_xml_path:
            raise RuntimeError('CORE session XML export returned no path')
        summary = backend._validate_session_nodes_and_injects(
            scenario_xml_path=xml_path,
            session_xml_path=session_xml_path,
            core_cfg=core_cfg,
            preview_plan_path=preview_plan_path or None,
            scenario_label=scenario_name,
            flow_enabled=flow_enabled,
        )
        if not isinstance(summary, dict):
            raise RuntimeError('validator returned no summary')
    except Exception as exc:
        summary = {
            'ok': False,
            'error': str(exc),
            'validation_unavailable': True,
        }
        session_xml_path = None

    if (
        flow_enabled
        and isinstance(summary, dict)
        and bool(summary.get('injects_missing'))
        and session_xml_path
    ):
        try:
            print(
                '[validate] Missing injects detected after copy; repairing once and revalidating...',
                file=target,
            )
            retry_meta = {
                'remote': True,
                'core_cfg': core_cfg,
                'remote_base_dir': str(os.environ.get('CORE_REMOTE_BASE_DIR') or '/tmp/scenarioforge'),
                'flow_copy_required': True,
            }
            backend._maybe_copy_flow_artifacts_into_containers(
                retry_meta,
                stage='cli-validation-retry',
                log_prefix='[validate] ',
            )
            if retry_meta.get('flow_artifacts_copied'):
                retry_summary = backend._validate_session_nodes_and_injects(
                    scenario_xml_path=xml_path,
                    session_xml_path=session_xml_path,
                    core_cfg=core_cfg,
                    preview_plan_path=preview_plan_path or None,
                    scenario_label=scenario_name,
                    flow_enabled=flow_enabled,
                )
                if isinstance(retry_summary, dict):
                    summary = retry_summary
                    summary['flow_copy_retried_after_validation'] = True
                    copy_error = ''
            else:
                copy_error = str(retry_meta.get('flow_artifact_copy_error') or copy_error).strip()
        except Exception as exc:
            copy_error = f'Flow artifact repair retry failed: {exc}'

    if copy_error:
        summary['flow_artifact_copy_error'] = copy_error
        summary['ok'] = False
    summary['cli_post_execution_validation'] = True
    summary['session_id'] = int(session_id)
    summary['scenario_xml_path'] = xml_path
    if session_xml_path:
        summary['session_xml_path'] = str(session_xml_path)

    artifact_path = os.path.join(out_dir, f'validation-session-{int(session_id)}.json')
    try:
        os.makedirs(out_dir, exist_ok=True)
        with open(artifact_path, 'w', encoding='utf-8') as handle:
            json.dump(summary, handle, indent=2, sort_keys=True, default=str)
            handle.write('\n')
    except Exception:
        artifact_path = None

    return _print_post_execution_validation_summary(
        summary,
        stream=target,
        artifact_path=artifact_path,
    )


def _build_remote_cli_tokens(
    *,
    remote_xml_path: str,
    remote_preview_plan_path: str | None,
    remote_host: str,
    remote_port: int,
    remote_scenario_name: str | None = None,
    include_preview_plan: bool = False,
) -> list[str]:
    try:
        source_tokens = list(sys.argv[1:])
    except Exception:
        source_tokens = []

    out_tokens: list[str] = []
    saw_xml = False
    saw_preview = False
    saw_host = False
    saw_port = False
    saw_scenario = False
    idx = 0
    while idx < len(source_tokens):
        token = source_tokens[idx]
        if token in _POST_EXECUTION_VALIDATION_OPTIONS:
            idx += 1
            continue
        if token == '--xml':
            out_tokens.extend(['--xml', remote_xml_path])
            saw_xml = True
            idx += 2
            continue
        if token == '--preview-plan':
            replacement = remote_preview_plan_path or remote_xml_path
            out_tokens.extend(['--preview-plan', replacement])
            saw_preview = True
            idx += 2
            continue
        if token == '--host':
            out_tokens.extend(['--host', remote_host])
            saw_host = True
            idx += 2
            continue
        if token == '--port':
            out_tokens.extend(['--port', str(remote_port)])
            saw_port = True
            idx += 2
            continue
        if token == '--scenario':
            replacement = str(remote_scenario_name or '').strip()
            if replacement:
                out_tokens.extend(['--scenario', replacement])
            else:
                out_tokens.extend(source_tokens[idx:idx + 2])
            saw_scenario = True
            idx += 2
            continue
        if token.startswith('--xml='):
            out_tokens.append(f'--xml={remote_xml_path}')
            saw_xml = True
            idx += 1
            continue
        if token.startswith('--preview-plan='):
            replacement = remote_preview_plan_path or remote_xml_path
            out_tokens.append(f'--preview-plan={replacement}')
            saw_preview = True
            idx += 1
            continue
        if token.startswith('--host='):
            out_tokens.append(f'--host={remote_host}')
            saw_host = True
            idx += 1
            continue
        if token.startswith('--port='):
            out_tokens.append(f'--port={int(remote_port)}')
            saw_port = True
            idx += 1
            continue
        if token.startswith('--scenario='):
            replacement = str(remote_scenario_name or '').strip()
            if replacement:
                out_tokens.append(f'--scenario={replacement}')
            else:
                out_tokens.append(token)
            saw_scenario = True
            idx += 1
            continue
        out_tokens.append(token)
        idx += 1

    if not saw_xml:
        out_tokens.extend(['--xml', remote_xml_path])
    if remote_preview_plan_path and include_preview_plan and not saw_preview:
        out_tokens.extend(['--preview-plan', remote_preview_plan_path])
    if not saw_host:
        out_tokens.extend(['--host', remote_host])
    if not saw_port:
        out_tokens.extend(['--port', str(int(remote_port))])
    scenario_name = str(remote_scenario_name or '').strip()
    if scenario_name and not saw_scenario:
        out_tokens.extend(['--scenario', scenario_name])
    return out_tokens


def _scenario_tag_for_cli(xml_path: str, scenario_name: str | None) -> str:
    try:
        out_dir_for_tag = os.path.dirname(xml_path) if xml_path else ''
        upload_base = os.path.basename(out_dir_for_tag) if out_dir_for_tag else ''
        parts = []
        if upload_base:
            parts.append(upload_base)
        if scenario_name:
            parts.append(str(scenario_name))
        candidate = '-'.join(parts) if parts else (str(scenario_name or 'scenario') or 'scenario')
    except Exception:
        candidate = str(scenario_name or 'scenario') or 'scenario'
    safe = []
    for char in candidate:
        safe.append(char if (char.isalnum() or char in {'-', '_'}) else '-')
    normalized = ''.join(safe).strip('-_') or 'scenario'
    while '--' in normalized:
        normalized = normalized.replace('--', '-')
    return normalized[:80] or 'scenario'


def _maybe_delegate_cli_to_remote(args: Any, *, backend: Any, scenario_name: str | None) -> int | None:
    if args.phase not in {'execute', 'topo'}:
        return None

    scenario_norm, core_cfg, has_saved_core_source = _resolve_cli_core_context(
        args,
        backend=backend,
        scenario_name=scenario_name,
    )
    env_remote_source = _cli_has_env_remote_source(backend, core_cfg)

    if not _cli_option_provided('--host'):
        try:
            args.host = str(core_cfg.get('host') or args.host)
        except Exception:
            pass
    if not _cli_option_provided('--port'):
        try:
            args.port = int(core_cfg.get('port') or args.port)
        except Exception:
            pass

    vm_mode_issues = _cli_vm_mode_config_issues(
        backend,
        phase=str(args.phase or 'execute'),
        core_cfg=core_cfg,
        has_saved_core_source=has_saved_core_source,
        hitl_config=getattr(args, '_prefetched_hitl_config', None),
    )
    if vm_mode_issues:
        return _emit_vm_mode_cli_error(
            phase=str(args.phase or 'execute'),
            xml_path=os.path.abspath(args.xml),
            scenario_name=scenario_name,
            issues=vm_mode_issues,
            json_output=False,
            emit_validation_marker=bool(getattr(args, 'post_execution_validation', False)),
        )

    if (not has_saved_core_source and not env_remote_source) or not _cli_should_delegate_remote(core_cfg):
        return None

    core_cfg = backend._require_core_ssh_credentials(core_cfg)
    xml_path = os.path.abspath(args.xml)
    preview_plan_path = os.path.abspath(args.preview_plan) if args.preview_plan else None
    resolved_preview_plan_path = str(getattr(args, '_resolved_preview_plan_path', '') or '').strip() or None
    if resolved_preview_plan_path:
        try:
            resolved_preview_plan_path = os.path.abspath(resolved_preview_plan_path)
        except Exception:
            pass
    if preview_plan_path is None:
        preview_plan_path = resolved_preview_plan_path
    run_id = f'cli-{uuid.uuid4().hex[:8]}'
    progress_stream = _CaptureTextStream(sys.stdout)
    remote_output_stream = progress_stream
    remote_client = backend._open_ssh_client(core_cfg)
    try:
        target_label = str(core_cfg.get('vm_name') or core_cfg.get('vm_key') or '').strip()
        target_suffix = f' ({target_label})' if target_label else ''
        progress_stream.write(
            f"[remote] Target: {core_cfg.get('ssh_username')}@{core_cfg.get('ssh_host')}:"
            f"{core_cfg.get('ssh_port')}{target_suffix}; CORE {core_cfg.get('host')}:{core_cfg.get('port')}\n"
        )
        install_custom_services = getattr(backend, '_install_custom_services_to_core_vm', None)
        if args.phase == 'execute' and callable(install_custom_services) and core_cfg.get('ssh_password'):
            try:
                progress_stream.write('[remote] Refreshing custom CORE services...\n')
            except Exception:
                pass
            try:
                install_custom_services(
                    remote_client,
                    sudo_password=core_cfg.get('ssh_password'),
                    logger=logging.getLogger(__name__),
                    core_cfg=core_cfg,
                )
            except Exception as exc:
                message = f'Failed to refresh custom CORE services before remote execute: {exc}'
                logging.error('%s', message)
                if bool(getattr(args, 'post_execution_validation', False)):
                    _print_post_execution_validation_unavailable(
                        message,
                        stream=progress_stream,
                        details=[str(exc)],
                    )
                return 1
        try:
            progress_stream.write('[remote] Preparing remote workspace and uploads...\n')
        except Exception:
            pass
        remote_ctx = backend._prepare_remote_cli_context(
            client=remote_client,
            run_id=run_id,
            xml_path=xml_path,
            preview_plan_path=preview_plan_path,
            log_handle=progress_stream,
            upload_only_injected_artifacts=False,
            core_cfg=core_cfg,
        )

        remote_python = backend._select_remote_python_interpreter(remote_client, core_cfg)
        remote_host = backend._remote_core_target_host(core_cfg, default='127.0.0.1')
        try:
            remote_port = int(core_cfg.get('port') or 50051)
        except Exception:
            remote_port = 50051

        remote_tokens = _build_remote_cli_tokens(
            remote_xml_path=remote_ctx['xml_path'],
            remote_preview_plan_path=remote_ctx.get('preview_plan_path'),
            remote_host=remote_host,
            remote_port=remote_port,
            remote_scenario_name=str(getattr(args, 'scenario', None) or scenario_name or '').strip() or None,
            include_preview_plan=bool(preview_plan_path),
        )
        cli_cmd = ' '.join(
            shlex.quote(arg)
            for arg in [remote_python, '-u', '-m', 'scenarioforge.cli', *remote_tokens]
        )

        docker_env_parts: list[str] = []
        docker_use_sudo = core_cfg.get('docker_use_sudo')
        docker_strict_pull = core_cfg.get('docker_strict_pull')
        docker_build_pull = core_cfg.get('docker_build_pull')
        if docker_use_sudo is None:
            docker_use_sudo = True
        if docker_strict_pull is None:
            docker_strict_pull = True
        if docker_build_pull is None:
            docker_build_pull = False
        if getattr(backend, '_coerce_bool', lambda v: bool(v))(docker_use_sudo):
            docker_env_parts.append('CORETG_DOCKER_USE_SUDO=1')
        if getattr(backend, '_coerce_bool', lambda v: bool(v))(docker_strict_pull):
            docker_env_parts.append('CORETG_DOCKER_STRICT_PULL=1')
        docker_env_parts.append(
            'CORETG_DOCKER_BUILD_PULL=1'
            if getattr(backend, '_coerce_bool', lambda v: bool(v))(docker_build_pull)
            else 'CORETG_DOCKER_BUILD_PULL=0'
        )
        docker_env_parts.append('CORETG_COMPOSE_SET_CONTAINER_NAME=1')
        if core_cfg.get('ssh_password') and getattr(backend, '_coerce_bool', lambda v: bool(v))(docker_use_sudo):
            docker_env_parts.append('CORETG_DOCKER_SUDO_PASSWORD_STDIN=1')

        flow_env_parts = [
            'CORETG_FLOW_ARTIFACTS_MODE=copy',
            'CORETG_CLI_REMOTE_DELEGATED=1',
        ]
        if remote_ctx.get('base_dir'):
            flow_env_parts.append(f"CORE_REMOTE_BASE_DIR={shlex.quote(str(remote_ctx.get('base_dir')))}")

        scenario_tag = _scenario_tag_for_cli(xml_path, scenario_name)
        docker_env_prefix = (' '.join(docker_env_parts) + ' ') if docker_env_parts else ''
        flow_env_prefix = (' '.join(flow_env_parts) + ' ') if flow_env_parts else ''
        remote_command = (
            f"cd {shlex.quote(str(remote_ctx['repo_dir']))} && "
            f"CORETG_SCENARIO_TAG={shlex.quote(scenario_tag)} {flow_env_prefix}{docker_env_prefix}PYTHONUNBUFFERED=1 {cli_cmd}"
        )

        logging.info(
            'Delegating CLI %s to remote CORE host via SSH %s:%s (scenario=%s, core=%s:%s)',
            args.phase,
            core_cfg.get('ssh_host'),
            core_cfg.get('ssh_port'),
            scenario_name or scenario_norm,
            remote_host,
            remote_port,
        )
        try:
            progress_stream.write('[remote] Starting CLI execution...\n')
            if getattr(args, 'verbose', False):
                progress_stream.write(f'[remote] Command: {cli_cmd}\n')
        except Exception:
            pass

        stdin, stdout, stderr = remote_client.exec_command(remote_command, get_pty=True, timeout=None)
        if 'CORETG_DOCKER_SUDO_PASSWORD_STDIN=1' in docker_env_parts:
            try:
                stdin.write(str(core_cfg.get('ssh_password') or '') + '\n')
                stdin.flush()
            except Exception:
                pass
        try:
            stdin.close()
        except Exception:
            pass
        backend._relay_remote_channel_to_log(
            stdout.channel,
            remote_output_stream,
            redact_tokens=[str(core_cfg.get('ssh_password') or '')],
        )
        exit_code = int(stdout.channel.recv_exit_status())
        output_text = progress_stream.getvalue()
        child_session_validation = _extract_last_json_marker(
            output_text,
            'CORE_SESSION_VALIDATION_JSON:',
        )
        if exit_code != 0:
            if args.phase == 'execute' and bool(getattr(args, 'post_execution_validation', False)):
                detail = _remote_execute_failure_detail(output_text)
                message = f'remote execute failed before post-execution validation (exit code {exit_code})'
                if detail:
                    message = f'{message}: {detail}'
                failure_session_id = None
                if isinstance(child_session_validation, dict):
                    try:
                        failure_session_id = int(child_session_validation.get('session_id'))
                    except Exception:
                        failure_session_id = None
                if failure_session_id is None:
                    match = re.search(r'CORE_SESSION_ID:\s*(\d+)', output_text)
                    try:
                        failure_session_id = int(match.group(1)) if match else None
                    except Exception:
                        failure_session_id = None
                _print_post_execution_validation_unavailable(
                    message,
                    stream=progress_stream,
                    session_id=failure_session_id,
                    details=[detail] if detail else None,
                )
            return exit_code
        if args.phase != 'execute':
            return exit_code

        session_id = None
        extract_session_id = getattr(backend, '_extract_session_id_from_text', None)
        if callable(extract_session_id):
            try:
                session_id = extract_session_id(output_text)
            except Exception:
                session_id = None
        if session_id in (None, '') and isinstance(child_session_validation, dict):
            session_id = child_session_validation.get('session_id')
        if session_id in (None, ''):
            match = re.search(r'CORE_SESSION_ID:\s*(\d+)', output_text)
            session_id = match.group(1) if match else None
        try:
            session_id_int = int(session_id) if session_id not in (None, '') else None
        except Exception:
            session_id_int = None
        if session_id_int is None:
            message = (
                'Remote execute exited successfully but did not report a CORE session id; '
                'treating the run as failed.'
            )
            logging.error(message)
            if bool(getattr(args, 'post_execution_validation', False)):
                _print_post_execution_validation_unavailable(
                    message,
                    stream=progress_stream,
                )
            return 1

        list_sessions = getattr(backend, '_list_active_core_sessions_via_remote_python', None)
        if not callable(list_sessions):
            message = (
                'Remote execute reported CORE session %s, but session verification is unavailable; '
                'treating the run as failed.'
            )
            logging.error(message, session_id_int)
            if bool(getattr(args, 'post_execution_validation', False)):
                _print_post_execution_validation_unavailable(
                    message % session_id_int,
                    stream=progress_stream,
                    session_id=session_id_int,
                )
            return 1
        try:
            sessions = list_sessions(core_cfg, errors=[], logger=logging.getLogger(__name__)) or []
        except TypeError:
            sessions = list_sessions(core_cfg) or []
        except Exception as exc:
            message = f'Failed to verify remote CORE session {session_id_int}: {exc}'
            logging.error('%s', message)
            if bool(getattr(args, 'post_execution_validation', False)):
                _print_post_execution_validation_unavailable(
                    message,
                    stream=progress_stream,
                    session_id=session_id_int,
                )
            return 1

        verified = None
        for item in sessions:
            if not isinstance(item, dict):
                continue
            try:
                if int(item.get('id')) == session_id_int:
                    verified = item
                    break
            except Exception:
                continue
        state = str((verified or {}).get('state') or '').strip()
        normalized_state = _core_state_str(state)
        child_configuration_tolerated = bool(
            isinstance(child_session_validation, dict)
            and child_session_validation.get('validation_ok') is True
            and child_session_validation.get('configuration_tolerated') is True
        )
        state_is_runtime = _is_runtime_state(normalized_state)
        state_is_tolerated_configuration = (
            child_configuration_tolerated
            and _is_configuration_state(normalized_state)
        )
        if verified is None or not (state_is_runtime or state_is_tolerated_configuration):
            message = (
                'Remote execute reported CORE session %s, but it is not present in runtime state '
                'on %s:%s (state=%s).'
            )
            logging.error(
                message,
                session_id_int,
                core_cfg.get('ssh_host'),
                core_cfg.get('ssh_port'),
                state or 'missing',
            )
            if bool(getattr(args, 'post_execution_validation', False)):
                rendered = message % (
                    session_id_int,
                    core_cfg.get('ssh_host'),
                    core_cfg.get('ssh_port'),
                    state or 'missing',
                )
                _print_post_execution_validation_unavailable(
                    rendered,
                    stream=progress_stream,
                    session_id=session_id_int,
                )
            return 1

        progress_stream.write(
            f"[remote] Verified CORE session {session_id_int} is {state} on "
            f"{core_cfg.get('ssh_host')}:{core_cfg.get('ssh_port')}{target_suffix}.\n"
        )
        if bool(getattr(args, 'post_execution_validation', False)):
            validation_ok = _run_cli_post_execution_validation(
                backend=backend,
                args=args,
                core_cfg=core_cfg,
                session_id=session_id_int,
                stream=progress_stream,
            )
            if not validation_ok:
                return 1
        return 0
    finally:
        try:
            remote_client.close()
        except Exception:
            pass


def _emit_phase_json(payload: Any, *, output_path: str | None = None, stream: Any = None) -> None:
    text = json.dumps(_json_ready(payload), indent=2, sort_keys=True, ensure_ascii=False)
    target = stream if stream is not None else sys.stdout
    print(text, file=target)
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as handle:
            handle.write(text)
            handle.write('\n')


def _response_payload_and_status(response: Any) -> tuple[int, Any]:
    status_code = 200
    payload = None
    raw = response
    if isinstance(response, tuple):
        raw = response[0]
        if len(response) >= 2:
            try:
                status_code = int(response[1])
            except Exception:
                status_code = 200
    if hasattr(raw, 'status_code'):
        try:
            status_code = int(getattr(raw, 'status_code'))
        except Exception:
            pass
    if hasattr(raw, 'get_json'):
        try:
            payload = raw.get_json(silent=True)
        except TypeError:
            try:
                payload = raw.get_json()
            except Exception:
                payload = None
        except Exception:
            payload = None
    if payload is None and hasattr(raw, 'get_data'):
        try:
            text = raw.get_data(as_text=True)
        except Exception:
            text = ''
        if text:
            try:
                payload = json.loads(text)
            except Exception:
                payload = {'raw': text}
    return status_code, payload


def _cli_phase_scenario(args: Any, *, backend: Any | None = None) -> str | None:
    scenario_name = str(getattr(args, 'scenario', '') or '').strip()
    if scenario_name:
        return scenario_name
    backend_module = backend
    if backend_module is None:
        try:
            backend_module = _load_web_backend_module()
        except Exception:
            backend_module = None
    if backend_module is not None:
        try:
            names = backend_module._scenario_names_from_xml(os.path.abspath(args.xml))
            if isinstance(names, list) and names:
                return str(names[0] or '').strip() or None
        except Exception:
            pass
    return None


def _cli_phase_chain_ids(args: Any) -> list[str]:
    chain_ids: list[str] = []
    multi = getattr(args, 'flow_chain_ids', None)
    if isinstance(multi, list):
        for item in multi:
            text = str(item or '').strip()
            if text:
                chain_ids.append(text)
    csv_value = str(getattr(args, 'flow_chain_ids_csv', '') or '').strip()
    if csv_value:
        for item in csv_value.split(','):
            text = str(item or '').strip()
            if text:
                chain_ids.append(text)
    deduped: list[str] = []
    seen: set[str] = set()
    for item in chain_ids:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _run_preview_plan_phase(args: Any) -> int:
    backend = _load_web_backend_module()
    xml_path = os.path.abspath(args.xml)
    scenario_name = _cli_phase_scenario(args, backend=backend)
    try:
        result = backend._planner_persist_flow_plan(
            xml_path=xml_path,
            scenario=scenario_name,
            seed=args.seed,
            persist_plan_file=False,
        )
    except Exception as exc:
        _emit_phase_json(
            {
                'ok': False,
                'phase': 'preview-plan',
                'xml_path': xml_path,
                'scenario': scenario_name,
                'error': str(exc),
            },
            output_path=args.plan_output,
            stream=sys.stderr,
        )
        return 1

    payload = {
        'ok': True,
        'phase': 'preview-plan',
        'xml_path': result.get('xml_path') or xml_path,
        'scenario': result.get('scenario') or scenario_name,
        'seed': result.get('seed'),
        'preview_plan_path': result.get('preview_plan_path') or xml_path,
        'full_preview': result.get('full_preview'),
        'plan': result.get('plan'),
    }
    _emit_phase_json(payload, output_path=args.plan_output)
    return 0


def _run_new_phase(args: Any) -> int:
    backend = _load_web_backend_module()
    xml_path = os.path.abspath(args.xml)
    parent_dir = os.path.dirname(xml_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    existed_before = os.path.exists(xml_path)

    if existed_before and not getattr(args, 'force', False):
        _emit_phase_json(
            {
                'ok': False,
                'phase': 'new',
                'xml_path': xml_path,
                'error': 'XML file already exists. Re-run with --force to overwrite it.',
            },
            output_path=args.plan_output,
            stream=sys.stderr,
        )
        return 1
    if os.path.isdir(xml_path):
        _emit_phase_json(
            {
                'ok': False,
                'phase': 'new',
                'xml_path': xml_path,
                'error': 'XML path points to a directory, not a file.',
            },
            output_path=args.plan_output,
            stream=sys.stderr,
        )
        return 1

    scenario_name = str(getattr(args, 'scenario', '') or '').strip()
    if not scenario_name:
        try:
            scenario_name = os.path.splitext(os.path.basename(xml_path))[0].strip()
        except Exception:
            scenario_name = ''
    if not scenario_name:
        scenario_name = 'Scenario 1'

    payload = backend._default_scenarios_payload_for_names([scenario_name])
    if not isinstance(payload, dict):
        payload = {'scenarios': [{'name': scenario_name}], 'core': {}}

    scenario_payload = None
    try:
        scenarios_list = payload.get('scenarios') if isinstance(payload.get('scenarios'), list) else None
        if isinstance(scenarios_list, list) and scenarios_list:
            scenario_payload = scenarios_list[0]
    except Exception:
        scenario_payload = None
    if not isinstance(scenario_payload, dict):
        scenario_payload = {'name': scenario_name, 'sections': {}}
        payload['scenarios'] = [scenario_payload]

    sections = scenario_payload.get('sections') if isinstance(scenario_payload.get('sections'), dict) else {}
    scenario_payload['sections'] = sections

    density_count_value = getattr(args, 'density_count', None)
    if density_count_value is not None:
        try:
            density_count_value = int(density_count_value)
        except Exception:
            density_count_value = -1
        if density_count_value < 0:
            _emit_phase_json(
                {
                    'ok': False,
                    'phase': 'new',
                    'xml_path': xml_path,
                    'scenario': scenario_name,
                    'error': 'Invalid --density-count value. Expected a non-negative integer.',
                },
                output_path=args.plan_output,
                stream=sys.stderr,
            )
            return 1
        scenario_payload['density_count'] = density_count_value

    seeded_any = False
    role_specs = list(getattr(args, 'seed_roles', None) or [])

    def _parse_seed_selection_spec(raw_spec: Any, *, option_name: str) -> tuple[str, int | None]:
        text = str(raw_spec or '').strip()
        if not text:
            raise ValueError(f'Invalid {option_name} value: empty string.')
        if '=' not in text:
            return text, None
        selected_raw, count_raw = text.rsplit('=', 1)
        selected_name = str(selected_raw or '').strip()
        if not selected_name:
            raise ValueError(f'Invalid {option_name} value: {text!r}. Expected NAME=COUNT.')
        count_token = str(count_raw or '').strip()
        if count_token.lower() == 'density':
            return selected_name, None
        try:
            count_value = int(count_token)
        except Exception as exc:
            raise ValueError(f'Invalid {option_name} value: {text!r}. Expected NAME=COUNT or NAME=density.') from exc
        if count_value < 0:
            raise ValueError(f'Invalid {option_name} value: {text!r}. Count must be non-negative.')
        return selected_name, count_value

    def _equalize_density_item_factors(items: list[dict[str, Any]]) -> None:
        density_items = [
            item
            for item in (items or [])
            if isinstance(item, dict) and str(item.get('v_metric') or '').strip().lower() != 'count'
        ]
        if not density_items:
            return
        equal_factor = 1.0 / float(len(density_items))
        for item in density_items:
            item['factor'] = equal_factor

    if role_specs:
        normalize_role = getattr(backend, '_normalize_node_information_role', None)
        node_items: list[dict[str, Any]] = []
        for raw_spec in role_specs:
            text = str(raw_spec or '').strip()
            if not text or '=' not in text:
                _emit_phase_json(
                    {
                        'ok': False,
                        'phase': 'new',
                        'xml_path': xml_path,
                        'scenario': scenario_name,
                        'error': f'Invalid --seed-role value: {text!r}. Expected ROLE=COUNT.',
                    },
                    output_path=args.plan_output,
                    stream=sys.stderr,
                )
                return 1
            role_raw, count_raw = text.split('=', 1)
            role_name = str(role_raw or '').strip()
            if callable(normalize_role):
                try:
                    role_name = normalize_role(role_name) or role_name
                except Exception:
                    pass
            try:
                count_value = int(str(count_raw or '').strip())
            except Exception:
                count_value = -1
            if role_name not in {'Server', 'Workstation', 'PC', 'Docker'} or count_value < 0:
                _emit_phase_json(
                    {
                        'ok': False,
                        'phase': 'new',
                        'xml_path': xml_path,
                        'scenario': scenario_name,
                        'error': f'Invalid --seed-role value: {text!r}. Allowed roles are Server, Workstation, PC, Docker with non-negative counts.',
                    },
                    output_path=args.plan_output,
                    stream=sys.stderr,
                )
                return 1
            if count_value == 0:
                continue
            node_items.append({
                'selected': role_name,
                'factor': 1.0,
                'v_metric': 'Count',
                'v_count': count_value,
            })
        node_section = sections.get('Node Information') if isinstance(sections.get('Node Information'), dict) else {}
        node_section['total_nodes'] = 0
        node_section['items'] = node_items
        sections['Node Information'] = node_section
        seeded_any = True

    routing_specs = list(getattr(args, 'seed_routing_specs', None) or [])
    if routing_specs:
        normalize_routing = getattr(backend, '_normalize_routing_item_selection', None)
        routing_items_seeded: list[dict[str, Any]] = []
        for raw_spec in routing_specs:
            try:
                routing_seed_name, routing_seed_count = _parse_seed_selection_spec(
                    raw_spec,
                    option_name='--seed-routing',
                )
            except ValueError as exc:
                _emit_phase_json(
                    {
                        'ok': False,
                        'phase': 'new',
                        'xml_path': xml_path,
                        'scenario': scenario_name,
                        'error': str(exc),
                    },
                    output_path=args.plan_output,
                    stream=sys.stderr,
                )
                return 1
            routing_name = routing_seed_name
            if callable(normalize_routing):
                try:
                    routing_name = normalize_routing(routing_seed_name) or routing_seed_name
                except Exception:
                    pass
            if routing_seed_count == 0:
                continue
            routing_item: dict[str, Any] = {'selected': routing_name, 'factor': 1.0}
            if routing_seed_count is not None:
                routing_item['v_metric'] = 'Count'
                routing_item['v_count'] = routing_seed_count
            routing_items_seeded.append(routing_item)
        if routing_items_seeded:
            _equalize_density_item_factors(routing_items_seeded)
            routing_section = sections.get('Routing') if isinstance(sections.get('Routing'), dict) else {}
            routing_section['density'] = float(getattr(args, 'seed_routing_density', 0.5) or 0.5)
            routing_section['items'] = routing_items_seeded
            sections['Routing'] = routing_section
            seeded_any = True

    traffic_specs = list(getattr(args, 'seed_traffic_specs', None) or [])
    if traffic_specs:
        normalize_traffic = getattr(backend, '_normalize_traffic_item_selection', None)
        traffic_items_seeded: list[dict[str, Any]] = []
        for raw_spec in traffic_specs:
            try:
                traffic_seed_name, traffic_seed_count = _parse_seed_selection_spec(
                    raw_spec,
                    option_name='--seed-traffic',
                )
            except ValueError as exc:
                _emit_phase_json(
                    {
                        'ok': False,
                        'phase': 'new',
                        'xml_path': xml_path,
                        'scenario': scenario_name,
                        'error': str(exc),
                    },
                    output_path=args.plan_output,
                    stream=sys.stderr,
                )
                return 1
            traffic_name = traffic_seed_name
            if callable(normalize_traffic):
                try:
                    traffic_name = normalize_traffic(traffic_seed_name) or traffic_seed_name
                except Exception:
                    pass
            if traffic_seed_count == 0:
                continue
            traffic_item: dict[str, Any] = {
                'selected': traffic_name,
                'factor': 1.0,
                'pattern': 'Random',
                'content_type': 'Random',
                'rate_kbps': 'Random',
                'period_s': 'Random',
                'jitter_pct': 'Random',
            }
            if traffic_seed_count is not None:
                traffic_item['v_metric'] = 'Count'
                traffic_item['v_count'] = traffic_seed_count
            traffic_items_seeded.append(traffic_item)
        if traffic_items_seeded:
            _equalize_density_item_factors(traffic_items_seeded)
            traffic_section = sections.get('Traffic') if isinstance(sections.get('Traffic'), dict) else {}
            traffic_section['density'] = float(getattr(args, 'seed_traffic_density', 0.5) or 0.5)
            traffic_section['items'] = traffic_items_seeded
            sections['Traffic'] = traffic_section
            seeded_any = True

    service_specs = list(getattr(args, 'seed_service_specs', None) or [])
    if service_specs:
        normalize_service = getattr(backend, '_normalize_service_item_selection', None)
        service_items_seeded: list[dict[str, Any]] = []
        for raw_spec in service_specs:
            try:
                service_seed_name, service_seed_count = _parse_seed_selection_spec(
                    raw_spec,
                    option_name='--seed-service',
                )
            except ValueError as exc:
                _emit_phase_json(
                    {
                        'ok': False,
                        'phase': 'new',
                        'xml_path': xml_path,
                        'scenario': scenario_name,
                        'error': str(exc),
                    },
                    output_path=args.plan_output,
                    stream=sys.stderr,
                )
                return 1
            service_name = service_seed_name
            if callable(normalize_service):
                try:
                    service_name = normalize_service(service_seed_name) or service_seed_name
                except Exception:
                    pass
            if service_seed_count == 0:
                continue
            service_item: dict[str, Any] = {'selected': service_name, 'factor': 1.0}
            if service_seed_count is not None:
                service_item['v_metric'] = 'Count'
                service_item['v_count'] = service_seed_count
            service_items_seeded.append(service_item)
        if service_items_seeded:
            _equalize_density_item_factors(service_items_seeded)
            service_section = sections.get('Services') if isinstance(sections.get('Services'), dict) else {}
            service_section['density'] = float(getattr(args, 'seed_service_density', 0.5) or 0.5)
            service_section['items'] = service_items_seeded
            sections['Services'] = service_section
            seeded_any = True

    segmentation_specs = list(getattr(args, 'seed_segmentation_specs', None) or [])
    if segmentation_specs:
        normalize_segmentation = getattr(backend, '_normalize_segmentation_item_selection', None)
        segmentation_items_seeded: list[dict[str, Any]] = []
        for raw_spec in segmentation_specs:
            try:
                segmentation_seed_name, segmentation_seed_count = _parse_seed_selection_spec(
                    raw_spec,
                    option_name='--seed-segmentation',
                )
            except ValueError as exc:
                _emit_phase_json(
                    {
                        'ok': False,
                        'phase': 'new',
                        'xml_path': xml_path,
                        'scenario': scenario_name,
                        'error': str(exc),
                    },
                    output_path=args.plan_output,
                    stream=sys.stderr,
                )
                return 1
            segmentation_name = segmentation_seed_name
            if callable(normalize_segmentation):
                try:
                    segmentation_name = normalize_segmentation(segmentation_seed_name) or segmentation_seed_name
                except Exception:
                    pass
            if segmentation_seed_count == 0:
                continue
            segmentation_item: dict[str, Any] = {'selected': segmentation_name, 'factor': 1.0}
            if segmentation_seed_count is not None:
                segmentation_item['v_metric'] = 'Count'
                segmentation_item['v_count'] = segmentation_seed_count
            segmentation_items_seeded.append(segmentation_item)
        if segmentation_items_seeded:
            _equalize_density_item_factors(segmentation_items_seeded)
            segmentation_section = sections.get('Segmentation') if isinstance(sections.get('Segmentation'), dict) else {}
            segmentation_section['density'] = float(getattr(args, 'seed_segmentation_density', 0.5) or 0.5)
            segmentation_section['items'] = segmentation_items_seeded
            sections['Segmentation'] = segmentation_section
            seeded_any = True

    vulnerability_specs = list(getattr(args, 'seed_vulnerabilities', None) or [])
    if vulnerability_specs:
        try:
            catalog_items = backend._load_backend_vuln_catalog_items()
        except Exception:
            catalog_items = []
        if not isinstance(catalog_items, list):
            catalog_items = []

        vulnerability_items: list[dict[str, Any]] = []
        for raw_spec in vulnerability_specs:
            try:
                vuln_seed_name, vuln_seed_count = _parse_seed_selection_spec(
                    raw_spec,
                    option_name='--seed-vulnerability',
                )
            except ValueError as exc:
                _emit_phase_json(
                    {
                        'ok': False,
                        'phase': 'new',
                        'xml_path': xml_path,
                        'scenario': scenario_name,
                        'error': str(exc),
                    },
                    output_path=args.plan_output,
                    stream=sys.stderr,
                )
                return 1
            if vuln_seed_count == 0:
                continue

            resolved = resolve_vulnerability_catalog_entry(
                catalog_items,
                v_name=vuln_seed_name,
                v_path=vuln_seed_name,
            )
            if not resolved:
                _emit_phase_json(
                    {
                        'ok': False,
                        'phase': 'new',
                        'xml_path': xml_path,
                        'scenario': scenario_name,
                        'error': f'Invalid --seed-vulnerability value: {str(raw_spec)!r}. Specific vulnerability must match an enabled catalog entry by v_path or v_name.',
                    },
                    output_path=args.plan_output,
                    stream=sys.stderr,
                )
                return 1

            vuln_item: dict[str, Any] = {
                'selected': 'Specific',
                'factor': 1.0,
                'v_name': str(resolved.get('name') or '').strip(),
                'v_path': str(resolved.get('path') or '').strip(),
            }
            if vuln_seed_count is not None:
                vuln_item['v_metric'] = 'Count'
                vuln_item['v_count'] = vuln_seed_count
            vulnerability_items.append(vuln_item)

        if vulnerability_items:
            _equalize_density_item_factors(vulnerability_items)
            vuln_section = sections.get('Vulnerabilities') if isinstance(sections.get('Vulnerabilities'), dict) else {}
            vuln_items_existing = list(vuln_section.get('items') or []) if isinstance(vuln_section.get('items'), list) else []
            vuln_section['density'] = float(getattr(args, 'seed_vulnerability_density', 0.5) or 0.5)
            vuln_section['flag_type'] = str(vuln_section.get('flag_type') or 'text')
            vuln_section['items'] = [*vuln_items_existing, *vulnerability_items]
            sections['Vulnerabilities'] = vuln_section
            seeded_any = True

    random_vuln_count = int(getattr(args, 'seed_random_vulnerability_count', 0) or 0)
    if random_vuln_count > 0:
        vuln_section = sections.get('Vulnerabilities') if isinstance(sections.get('Vulnerabilities'), dict) else {}
        if 'density' not in vuln_section:
            vuln_section['density'] = 0.0
        vuln_section['flag_type'] = str(vuln_section.get('flag_type') or 'text')
        vuln_items_existing = list(vuln_section.get('items') or []) if isinstance(vuln_section.get('items'), list) else []
        vuln_section['items'] = [*vuln_items_existing, {
            'selected': 'Random',
            'factor': 1.0,
            'v_metric': 'Count',
            'v_count': random_vuln_count,
        }]
        sections['Vulnerabilities'] = vuln_section
        seeded_any = True

    if seeded_any:
        try:
            scenario_payload['sections'] = sections
            concretized = backend._concretize_scenarios_for_save([scenario_payload], seed=args.seed)
            if isinstance(concretized, list) and concretized:
                payload['scenarios'][0] = concretized[0]
                scenario_payload = payload['scenarios'][0]
        except Exception:
            pass

    core_override: dict[str, Any] = {}
    if _cli_option_provided('--host'):
        core_override['host'] = args.host
        core_override['grpc_host'] = args.host
    if _cli_option_provided('--port'):
        core_override['port'] = args.port
        core_override['grpc_port'] = args.port
    if _cli_option_provided('--ssh-host'):
        core_override['ssh_host'] = args.ssh_host
    if _cli_option_provided('--ssh-port'):
        core_override['ssh_port'] = args.ssh_port
    if _cli_option_provided('--ssh-username'):
        core_override['ssh_username'] = args.ssh_username
    if _cli_option_provided('--ssh-password'):
        core_override['ssh_password'] = args.ssh_password
    if _cli_option_provided('--venv-bin'):
        core_override['venv_bin'] = args.venv_bin

    if core_override and not _cli_option_provided('--host') and str(core_override.get('ssh_host') or '').strip() and _cli_runtime_mode(backend) == 'vm':
        core_override.setdefault('host', core_override.get('ssh_host'))
        core_override.setdefault('grpc_host', core_override.get('ssh_host'))

    if core_override:
        try:
            payload['core'] = backend._merge_core_configs(payload.get('core'), core_override, include_password=True)
        except Exception:
            merged_core = dict(payload.get('core') or {})
            merged_core.update(core_override)
            payload['core'] = merged_core

    if _cli_runtime_mode(backend) == 'vm':
        try:
            core_cfg_with_password = backend._core_backend_defaults(include_password=True)
            if core_override:
                core_cfg_with_password = backend._merge_core_configs(core_cfg_with_password, core_override, include_password=True)
            core_cfg_xml = backend._normalize_core_config(core_cfg_with_password, include_password=True)
        except Exception:
            core_cfg_with_password = dict(core_override)
            core_cfg_xml = dict(core_override)

        vm_mode_issues = _cli_vm_mode_config_issues(
            backend,
            phase='new',
            core_cfg=core_cfg_with_password if isinstance(core_cfg_with_password, dict) else {},
            has_saved_core_source=False,
            hitl_config=None,
        )
        if vm_mode_issues:
            return _emit_vm_mode_cli_error(
                phase='new',
                xml_path=xml_path,
                scenario_name=scenario_name,
                issues=vm_mode_issues,
                output_path=args.plan_output,
                json_output=True,
            )

        payload['core'] = core_cfg_xml
        try:
            vm_defaults = backend._webui_vm_mode_defaults(include_password=False)
        except Exception:
            vm_defaults = {}
        scenario_hitl = deepcopy((vm_defaults.get('hitl') if isinstance(vm_defaults, dict) else {}) or {})
        if not isinstance(scenario_hitl, dict):
            scenario_hitl = {}
        scenario_hitl['core'] = deepcopy(core_cfg_xml)
        scenario_payload['hitl'] = scenario_hitl

    try:
        tree = backend._build_scenarios_xml(payload)
        try:
            from lxml import etree as LET  # type: ignore

            raw = ET.tostring(tree.getroot(), encoding='utf-8')
            lroot = LET.fromstring(raw)
            pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
            with open(xml_path, 'wb') as handle:
                handle.write(pretty)
        except Exception:
            tree.write(xml_path, encoding='utf-8', xml_declaration=True)
    except Exception as exc:
        _emit_phase_json(
            {
                'ok': False,
                'phase': 'new',
                'xml_path': xml_path,
                'scenario': scenario_name,
                'error': f'Failed to create starter XML: {exc}',
            },
            output_path=args.plan_output,
            stream=sys.stderr,
        )
        return 1

    effective_scenario_name = scenario_name
    try:
        parsed_root = ET.parse(xml_path).getroot()
        parsed_scenario = parsed_root.find('Scenario')
        parsed_name = str(parsed_scenario.get('name') or '').strip() if parsed_scenario is not None else ''
        if parsed_name:
            effective_scenario_name = parsed_name
    except Exception:
        pass

    _emit_phase_json(
        {
            'ok': True,
            'phase': 'new',
            'xml_path': xml_path,
            'scenario': effective_scenario_name,
            'overwritten': bool(getattr(args, 'force', False) and existed_before),
            'next_steps': [
                'Edit the scenario sections in the Web UI or by hand.',
                'Run preview-plan to persist PlanPreview.',
                'Run flag-sequencing if you want Flow state embedded.',
                'Run topo or execute against the same XML.',
            ],
        },
        output_path=args.plan_output,
    )
    return 0


def _run_flag_sequencing_phase(args: Any) -> int:
    backend = _load_web_backend_module()
    xml_path = os.path.abspath(args.xml)
    scenario_name = _cli_phase_scenario(args, backend=backend)
    if not scenario_name:
        _emit_phase_json(
            {
                'ok': False,
                'phase': 'flag-sequencing',
                'xml_path': xml_path,
                'error': 'No scenario specified.',
            },
            output_path=args.plan_output,
            stream=sys.stderr,
        )
        return 1

    try:
        backend._planner_persist_flow_plan(
            xml_path=xml_path,
            scenario=scenario_name,
            seed=args.seed,
            persist_plan_file=False,
        )
    except Exception as exc:
        _emit_phase_json(
            {
                'ok': False,
                'phase': 'flag-sequencing',
                'xml_path': xml_path,
                'scenario': scenario_name,
                'error': f'Failed to prepare preview plan: {exc}',
            },
            output_path=args.plan_output,
            stream=sys.stderr,
        )
        return 1

    payload: dict[str, Any] = {
        'scenario': scenario_name,
        'preview_plan': xml_path,
        'mode': args.flow_mode,
        'length': int(args.flow_length),
        'best_effort': bool(args.flow_best_effort),
        'allow_node_duplicates': bool(args.flow_allow_node_duplicates),
        'cleanup_generated_artifacts': bool(args.flow_cleanup_generated_artifacts),
        'dependency_level': int(args.flow_dependency_level),
    }
    chain_ids = _cli_phase_chain_ids(args)
    if chain_ids:
        payload['chain_ids'] = chain_ids
    preset = str(args.flow_preset or '').strip()
    if preset:
        payload['preset'] = preset
    if args.flow_timeout_s is not None:
        payload['timeout_s'] = int(args.flow_timeout_s)
    if args.flow_run_remote:
        payload['run_remote'] = True
    if args.flow_run_local:
        payload['run_local'] = True

    scenario_norm, resolved_core_cfg, has_saved_core_source = _resolve_cli_core_context(
        args,
        backend=backend,
        scenario_name=scenario_name,
    )
    vm_mode_issues = _cli_vm_mode_config_issues(
        backend,
        phase='flag-sequencing',
        core_cfg=resolved_core_cfg,
        has_saved_core_source=has_saved_core_source,
        hitl_config=None,
    )
    if vm_mode_issues:
        return _emit_vm_mode_cli_error(
            phase='flag-sequencing',
            xml_path=xml_path,
            scenario_name=scenario_name,
            issues=vm_mode_issues,
            output_path=args.plan_output,
            json_output=True,
        )
    env_remote_source = _cli_has_env_remote_source(backend, resolved_core_cfg)
    flow_backend: Any = backend
    if (has_saved_core_source or env_remote_source) and isinstance(resolved_core_cfg, dict) and resolved_core_cfg:
        flow_backend = _BackendProxy(
            backend,
            _core_config_from_xml_path=lambda *_a, **_k: dict(resolved_core_cfg),
        )
        flow_mode_norm = str(args.flow_mode or '').strip().lower()
        generators_expected = flow_mode_norm in {'resolve', 'resolve_hints', 'hint', 'hint_only'}
        remote_execution_expected = _cli_should_delegate_remote(resolved_core_cfg) or env_remote_source
        if generators_expected and remote_execution_expected and (not args.flow_run_local) and ('run_remote' not in payload):
            payload['run_remote'] = True

    try:
        _best_effort_cli_flag_sequencing_cleanup(
            args,
            backend=backend,
            core_cfg=resolved_core_cfg if isinstance(resolved_core_cfg, dict) else None,
            scenario_name=scenario_name,
            run_remote=bool(payload.get('run_remote')),
        )
    except Exception as cleanup_exc:
        logging.warning('Flow cleanup failed: %s', cleanup_exc)

    from webapp import flow_prepare_preview_execute as _flow_prepare_preview_execute

    sequence_payload = {
        'scenario': scenario_name,
        'preview_plan': xml_path,
        'length': int(args.flow_length),
        'best_effort': bool(args.flow_best_effort),
        'allow_node_duplicates': bool(args.flow_allow_node_duplicates),
        'dependency_level': int(args.flow_dependency_level),
    }
    if preset:
        sequence_payload['preset'] = preset
    if chain_ids:
        sequence_payload['chain_ids'] = chain_ids

    sequence_view = None
    try:
        sequence_view = backend.app.view_functions.get('api_flow_sequence_preview_plan')
    except Exception:
        sequence_view = None
    if sequence_view is None:
        _emit_phase_json(
            {
                'ok': False,
                'phase': 'flag-sequencing',
                'xml_path': xml_path,
                'scenario': scenario_name,
                'error': 'Flag sequencing sequence_preview_plan route is not registered.',
            },
            output_path=args.plan_output,
            stream=sys.stderr,
        )
        return 1

    with backend.app.test_request_context(
        '/api/flag-sequencing/sequence_preview_plan',
        method='POST',
        json=sequence_payload,
    ):
        sequence_http_response = sequence_view()
    sequence_status, sequence_payload_out = _response_payload_and_status(sequence_http_response)
    if sequence_status >= 400:
        if not isinstance(sequence_payload_out, dict):
            sequence_payload_out = {'ok': False, 'status': sequence_status, 'payload': sequence_payload_out}
        sequence_payload_out.setdefault('phase', 'flag-sequencing')
        sequence_payload_out.setdefault('xml_path', xml_path)
        sequence_payload_out.setdefault('scenario', scenario_name)
        _emit_phase_json(sequence_payload_out, output_path=args.plan_output, stream=sys.stderr)
        return 1

    if isinstance(sequence_payload_out, dict):
        seq_chain_ids = [
            str(node.get('id') or '').strip()
            for node in (sequence_payload_out.get('chain') or [])
            if isinstance(node, dict) and str(node.get('id') or '').strip()
        ]
        if seq_chain_ids:
            payload['chain_ids'] = seq_chain_ids
        if sequence_payload_out.get('preview_plan_path'):
            payload['preview_plan'] = str(sequence_payload_out.get('preview_plan_path'))

    with backend.app.test_request_context(
        '/api/flag-sequencing/prepare_preview_for_execute',
        method='POST',
        json=payload,
    ):
        response = _flow_prepare_preview_execute.execute(backend=flow_backend)
    status_code, response_payload = _response_payload_and_status(response)
    if not isinstance(response_payload, dict):
        response_payload = {'ok': status_code < 400, 'status': status_code, 'payload': response_payload}
    response_payload.setdefault('phase', 'flag-sequencing')
    response_payload.setdefault('xml_path', xml_path)
    response_payload.setdefault('scenario', scenario_name)
    if str(args.flow_mode or '').strip().lower() in {'resolve', 'resolve_hints', 'hint', 'hint_only'}:
        response_payload.setdefault('generator_execution_requested', True)
        response_payload.setdefault('generator_execution_mode', 'remote' if bool(payload.get('run_remote')) else 'local')
    _emit_phase_json(
        response_payload,
        output_path=args.plan_output,
        stream=(sys.stdout if status_code < 400 else sys.stderr),
    )
    return 0 if status_code < 400 else 1


CLI_PHASES = ('execute', 'new', 'preview-plan', 'flag-sequencing', 'topo')


class _CliHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    def _get_help_string(self, action: argparse.Action) -> str:
        help_text = action.help or ''
        if not help_text:
            return help_text
        if '%(default)' in help_text or 'default:' in help_text.lower():
            return help_text
        default = action.default
        if default in (None, '', False, argparse.SUPPRESS):
            return help_text
        if isinstance(action, argparse._StoreTrueAction):
            return help_text
        return f'{help_text} (default: %(default)s)'


def _cli_help_requested(argv: list[str]) -> bool:
    return any(token in {'-h', '--help'} for token in (argv or []))


def _cli_phase_token(argv: list[str]) -> str | None:
    if not argv:
        return None
    token = str(argv[0] or '').strip()
    return token if token in CLI_PHASES else None


def _add_cli_phase_arg(container: Any) -> None:
    container.add_argument(
        'phase',
        nargs='?',
        choices=list(CLI_PHASES),
        default='execute',
        help='Phase to run: execute, new, preview-plan, flag-sequencing, or topo',
    )


def _add_cli_common_args(container: Any) -> None:
    container.add_argument('--xml', required=True, help='Path to XML scenario file')
    container.add_argument('--scenario', default=None, help='Scenario name to use (defaults to the first scenario; execute/topo forward the resolved value during remote delegation)')
    container.add_argument('--verbose', action='store_true', help='Enable debug logging')
    container.add_argument('--plan-output', help='Path to write computed phase JSON output (preview, topo, flow, or build)')
    container.add_argument('--seed', type=int, default=None, help='Optional RNG seed for reproducible planning/build randomness. Reuse the same value across preview-plan, flag-sequencing, topo, and execute when you want repeatable results; explicit --preview-plan can also supply a saved seed when --seed is omitted')


def _cli_core_argument_defaults() -> dict[str, Any]:
    defaults: dict[str, Any] = {
        'host': str(os.environ.get('CORE_HOST') or 'localhost'),
        'port': 50051,
        'ssh_host': str(os.environ.get('CORE_SSH_HOST') or ''),
        'ssh_port': 22,
        'ssh_username': str(os.environ.get('CORE_SSH_USERNAME') or ''),
        'venv_bin': str(os.environ.get('CORE_VENV_BIN') or ''),
    }
    try:
        defaults['port'] = int(str(os.environ.get('CORE_PORT') or '50051').strip() or 50051)
    except Exception:
        defaults['port'] = 50051
    try:
        defaults['ssh_port'] = int(str(os.environ.get('CORE_SSH_PORT') or '22').strip() or 22)
    except Exception:
        defaults['ssh_port'] = 22

    try:
        backend = _load_web_backend_module()
    except Exception:
        backend = None
    if backend is not None:
        try:
            core_cfg = backend._default_core_dict()
            normalized = backend._normalize_core_config(core_cfg, include_password=False)
            host = str(normalized.get('host') or defaults['host']).strip()
            defaults['host'] = host or defaults['host']
            defaults['port'] = int(normalized.get('port') or defaults['port'])
            ssh_host = str(normalized.get('ssh_host') or '').strip()
            if ssh_host:
                defaults['ssh_host'] = ssh_host
            defaults['ssh_port'] = int(normalized.get('ssh_port') or defaults['ssh_port'])
            ssh_username = str(normalized.get('ssh_username') or '').strip()
            if ssh_username:
                defaults['ssh_username'] = ssh_username
            venv_bin = str(normalized.get('venv_bin') or '').strip()
            if venv_bin:
                defaults['venv_bin'] = venv_bin
        except Exception:
            pass
    return defaults


def _cli_new_argument_defaults() -> dict[str, Any]:
    defaults = {
        'density_count': 10,
        'seed_routing_density': 0.5,
        'seed_service_density': 0.5,
        'seed_traffic_density': 0.5,
        'seed_segmentation_density': 0.5,
        'seed_vulnerability_density': 0.5,
    }
    try:
        backend = _load_web_backend_module()
    except Exception:
        backend = None
    if backend is not None:
        try:
            payload = backend._default_scenarios_payload_for_names(['Scenario 1'])
            scenarios = payload.get('scenarios') if isinstance(payload, dict) else None
            scenario = scenarios[0] if isinstance(scenarios, list) and scenarios else None
            if isinstance(scenario, dict):
                if scenario.get('density_count') is not None:
                    defaults['density_count'] = int(scenario.get('density_count'))
                sections = scenario.get('sections') if isinstance(scenario.get('sections'), dict) else {}

                def _density(section_name: str, fallback: float) -> float:
                    try:
                        section = sections.get(section_name) if isinstance(sections, dict) else None
                        if isinstance(section, dict) and section.get('density') is not None:
                            return float(section.get('density'))
                    except Exception:
                        pass
                    return fallback

                defaults['seed_routing_density'] = _density('Routing', defaults['seed_routing_density'])
                defaults['seed_service_density'] = _density('Services', defaults['seed_service_density'])
                defaults['seed_traffic_density'] = _density('Traffic', defaults['seed_traffic_density'])
                defaults['seed_segmentation_density'] = _density('Segmentation', defaults['seed_segmentation_density'])
                defaults['seed_vulnerability_density'] = _density('Vulnerabilities', defaults['seed_vulnerability_density'])
        except Exception:
            pass
    return defaults


def _add_cli_core_connection_args(container: Any) -> None:
    defaults = _cli_core_argument_defaults()
    container.add_argument('--host', default=defaults['host'], help='core-daemon gRPC host')
    container.add_argument('--port', type=int, default=defaults['port'], help='core-daemon gRPC port')
    container.add_argument('--ssh-host', default=defaults['ssh_host'], help='CORE SSH host to persist in XML or override at runtime')
    container.add_argument('--ssh-port', type=int, default=defaults['ssh_port'], help='CORE SSH port to persist in XML or override at runtime')
    container.add_argument('--ssh-username', default=defaults['ssh_username'], help='CORE SSH username to persist in XML or override at runtime')
    container.add_argument('--ssh-password', default='', help='CORE SSH password to persist in XML or override at runtime')
    container.add_argument('--venv-bin', default=defaults['venv_bin'], help='Remote CORE Python venv/bin path to persist in XML or override at runtime')


def _add_cli_new_args(container: Any) -> None:
    defaults = _cli_new_argument_defaults()
    container.add_argument('--force', action='store_true', help='Overwrite an existing XML file when used with the new phase')
    container.add_argument('--density-count', type=int, default=defaults['density_count'], help='Scenario-level Count for Density base host pool for density-based planning in the new phase')
    container.add_argument('--seed-role', dest='seed_roles', action='append', help='Seed a Node Information count row as ROLE=COUNT for the new phase (repeatable)')
    container.add_argument('--seed-routing', dest='seed_routing_specs', action='append', help='Seed a Routing row for the new phase (repeatable; density rows are equal-weighted, for example OSPFv2, BGP=density, or OSPFv2=3)')
    container.add_argument('--seed-routing-density', type=float, default=defaults['seed_routing_density'], help='Routing density to use with --seed-routing')
    container.add_argument('--seed-service', dest='seed_service_specs', action='append', help='Seed a Services row for the new phase (repeatable; density rows are equal-weighted, for example SSH, HTTP=density, or SSH=4)')
    container.add_argument('--seed-service-density', type=float, default=defaults['seed_service_density'], help='Services density to use with --seed-service')
    container.add_argument('--seed-traffic', dest='seed_traffic_specs', action='append', help='Seed a Traffic row for the new phase (repeatable; density rows are equal-weighted, for example TCP, UDP=density, or TCP=10)')
    container.add_argument('--seed-traffic-density', type=float, default=defaults['seed_traffic_density'], help='Traffic density to use with --seed-traffic')
    container.add_argument('--seed-segmentation', dest='seed_segmentation_specs', action='append', help='Seed a Segmentation row for the new phase (repeatable; density rows are equal-weighted, for example Firewall, NAT=density, or Firewall=2)')
    container.add_argument('--seed-segmentation-density', type=float, default=defaults['seed_segmentation_density'], help='Segmentation density to use with --seed-segmentation')
    container.add_argument('--seed-vulnerability', dest='seed_vulnerabilities', action='append', help='Seed a specific Vulnerabilities row for the new phase using an active catalog entry name or path (repeatable; density rows are equal-weighted, for example jboss/CVE-2017-12149, weblogic/CVE-2017-10271=density, or jboss/CVE-2017-12149=2)')
    container.add_argument('--seed-vulnerability-density', type=float, default=defaults['seed_vulnerability_density'], help='Vulnerabilities density to use with --seed-vulnerability when count is omitted or set to density')
    container.add_argument('--seed-random-vulnerability-count', type=int, default=0, help='Seed this many random vulnerability targets for the new phase')


def _add_cli_preview_plan_args(container: Any) -> None:
    return None


def _add_cli_flag_sequencing_args(container: Any) -> None:
    container.add_argument(
        '--flow-mode',
        choices=['resolve', 'resolve_hints', 'hint', 'hint_only'],
        default='resolve',
        help='Flag-sequencing mode for the flag-sequencing phase (default: resolve)',
    )
    container.add_argument('--flow-length', type=int, default=5, help='Requested chain length for the flag-sequencing phase')
    container.add_argument('--flow-preset', default='', help='Optional flow preset name for the flag-sequencing phase')
    container.add_argument('--flow-chain-id', dest='flow_chain_ids', action='append', help='Explicit flow chain node id (repeatable)')
    container.add_argument('--flow-chain-ids', dest='flow_chain_ids_csv', default='', help='Comma-separated explicit flow chain node ids')
    container.add_argument('--flow-best-effort', action='store_true', help='Allow the flag-sequencing phase to clamp to available eligible nodes')
    container.add_argument('--flow-allow-node-duplicates', action='store_true', help='Allow duplicate nodes in the flag-sequencing chain')
    container.add_argument('--flow-timeout-s', type=int, default=None, help='Optional total timeout in seconds for the flag-sequencing phase')
    container.add_argument('--flow-run-remote', action='store_true', help='Force remote flag-sequencing generator execution when CORE SSH config is available')
    container.add_argument('--flow-run-local', action='store_true', help='Force local flag-sequencing generator execution even when CORE SSH config exists')
    container.add_argument(
        '--flow-cleanup-before-run',
        dest='flow_cleanup_before_run',
        action='store_true',
        default=True,
        help='Best-effort cleanup of stale generator Docker state and flow artifacts before resolve (default: on)',
    )
    container.add_argument(
        '--no-flow-cleanup-before-run',
        dest='flow_cleanup_before_run',
        action='store_false',
        help='Disable pre-run cleanup before flag-sequencing resolve',
    )
    container.add_argument('--flow-cleanup-generated-artifacts', action='store_true', help='Delete temporary flag-sequencing generator run directories after completion')
    container.add_argument('--flow-dependency-level', type=int, default=3, help='Flag-sequencing dependency strictness level (1-5)')


def _add_cli_execute_topo_args(container: Any) -> None:
    container.add_argument('--prefix', default='10.0.0.0/24', help='IPv4 prefix for auto-assigned addresses')
    container.add_argument(
        '--ip-mode',
        choices=['private', 'mixed', 'public'],
        default='private',
        help='IP address pool mode: private (RFC1918), mixed (private+public), or public',
    )
    container.add_argument(
        '--ip-region',
        choices=['all', 'na', 'eu', 'apac', 'latam', 'africa', 'middle-east'],
        default='all',
        help='Region for public pools when ip-mode is mixed/public (default: all)',
    )
    container.add_argument('--max-nodes', type=int, default=None, help='Optional cap on hosts to create')
    container.add_argument(
        '--start-timeout-s',
        type=float,
        default=None,
        help='Max seconds to wait for CORE session to reach RUNTIME (default: 120; env: CORETG_CORE_START_TIMEOUT_S)',
    )
    container.add_argument(
        '--docker-wait-s',
        type=float,
        default=None,
        help='Max seconds to wait for Docker containers to become running (default: 45; env: CORETG_DOCKER_WAIT_RUNNING_S)',
    )
    container.add_argument('--preview', action='store_true', help='Parse and plan only; output plan summary JSON and exit 0')
    container.add_argument('--preview-full', action='store_true', help='Generate a full dry-run plan (routers, hosts, IPs, services, vulnerabilities, segmentation) without contacting CORE; implies --preview style output')
    container.add_argument('--preview-plan', help='Optional persisted preview source (JSON or XML with embedded PlanPreview). If omitted, execute/topo reuse PlanPreview embedded in --xml when available')
    container.add_argument(
        '--router-mesh',
        choices=['full', 'ring', 'tree'],
        default='full',
        help='Protocol adjacency mesh style among routers sharing a protocol: full (complete), ring (cycle), tree (chain)',
    )
    container.add_argument(
        '--layout-density',
        choices=['compact', 'normal', 'spacious'],
        default='normal',
        help='Layout spacing for visual clarity (affects node positions)',
    )
    container.add_argument('--traffic-pattern', choices=['continuous', 'burst', 'periodic', 'poisson', 'ramp'], help='Override traffic pattern for all items')
    container.add_argument('--traffic-rate', type=float, help='Override traffic rate for all items (KB/s)')
    container.add_argument('--traffic-period', type=float, help='Override traffic period for all items (seconds)')
    container.add_argument('--traffic-jitter', type=float, help='Override traffic jitter for all items (percent 0-100)')
    container.add_argument(
        '--traffic-content',
        choices=['text', 'photo', 'audio', 'video'],
        help='Override traffic content type for all items (text/photo/audio/video)',
    )
    container.add_argument(
        '--allow-src-subnet-prob',
        type=float,
        default=0.3,
        help='Probability [0..1] to widen firewall allow rules to the source subnet',
    )
    container.add_argument(
        '--allow-dst-subnet-prob',
        type=float,
        default=0.3,
        help='Probability [0..1] to widen firewall allow rules to the destination subnet',
    )
    container.add_argument(
        '--nat-mode',
        choices=['SNAT', 'MASQUERADE'],
        default='SNAT',
        help='NAT mode when segmentation selects NAT (routers): SNAT or MASQUERADE',
    )
    container.add_argument(
        '--dnat-prob',
        type=float,
        default=0.0,
        help='Probability [0..1] to create DNAT (port-forward) on routers for generated flows',
    )
    container.add_argument(
        '--seg-include-hosts',
        action='store_true',
        help='Include host nodes as candidates for segmentation placement (default: routers only)',
    )
    container.add_argument(
        '--seg-allow-docker-ports',
        action='store_true',
        help='Allow docker-compose container ports through host INPUT chains when segmentation enforces default-deny',
    )
    container.add_argument(
        '--docker-check-conflicts',
        action='store_true',
        default=True,
        help='Check for existing Docker containers/images that could conflict with compose-based Docker nodes (default: on)',
    )
    container.add_argument(
        '--no-docker-check-conflicts',
        dest='docker_check_conflicts',
        action='store_false',
        help='Disable Docker conflict checks',
    )
    container.add_argument(
        '--docker-remove-conflicts',
        action='store_true',
        default=True,
        help='Automatically remove conflicting Docker containers/images before execute (default: on)',
    )
    container.add_argument(
        '--no-docker-remove-conflicts',
        dest='docker_remove_conflicts',
        action='store_false',
        help='Disable automatic Docker conflict removal during execute',
    )
    container.add_argument(
        '--core-cleanup-before-run',
        dest='core_cleanup_before_run',
        action='store_true',
        default=True,
        help='Run core-cleanup and stale CORE runtime cleanup before execute (default: on)',
    )
    container.add_argument(
        '--no-core-cleanup-before-run',
        dest='core_cleanup_before_run',
        action='store_false',
        help='Disable core-cleanup and stale CORE runtime cleanup before execute',
    )
    container.add_argument(
        '--docker-cleanup-before-run',
        dest='docker_cleanup_before_run',
        action='store_true',
        default=True,
        help='Prune Docker artifacts and stale /tmp/vulns files before execute (default: on)',
    )
    container.add_argument(
        '--no-docker-cleanup-before-run',
        dest='docker_cleanup_before_run',
        action='store_false',
        help='Disable Docker prune and stale /tmp/vulns cleanup before execute',
    )
    container.add_argument(
        '--overwrite-existing-images',
        dest='overwrite_existing_images',
        action='store_true',
        default=True,
        help='Remove wrapper/generator images before execute when cleaning up (default: on)',
    )
    container.add_argument(
        '--no-overwrite-existing-images',
        dest='overwrite_existing_images',
        action='store_false',
        help='Disable wrapper/generator image removal before execute',
    )
    container.add_argument(
        '--docker-remove-all-containers',
        action='store_true',
        default=False,
        help='Remove all non-essential Docker containers/images before execute (default: off)',
    )
    container.add_argument(
        '-post-execution-validation',
        '--post-execution-validation',
        dest='post_execution_validation',
        action='store_true',
        help='After execute, export the CORE session and run WebUI-equivalent node, Docker, Flow, and inject validation',
    )


def _build_cli_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(formatter_class=_CliHelpFormatter)
    _add_cli_phase_arg(ap)
    _add_cli_common_args(ap)
    _add_cli_new_args(ap)
    _add_cli_core_connection_args(ap)
    _add_cli_execute_topo_args(ap)
    _add_cli_flag_sequencing_args(ap)
    return ap


def _build_cli_help_parser(phase: str | None) -> argparse.ArgumentParser:
    if phase is None:
        ap = argparse.ArgumentParser(
            formatter_class=_CliHelpFormatter,
            description='ScenarioForge CLI. Omit phase to run execute.',
            epilog='Use "cli.py <phase> --help" to view phase-specific options.',
        )
        _add_cli_phase_arg(ap)
        _add_cli_common_args(ap)
        return ap

    ap = argparse.ArgumentParser(
        prog=f'cli.py {phase}',
        formatter_class=_CliHelpFormatter,
        description=f'ScenarioForge CLI help for the {phase} phase.',
    )
    _add_cli_common_args(ap)
    if phase == 'new':
        _add_cli_new_args(ap)
        _add_cli_core_connection_args(ap)
    elif phase == 'preview-plan':
        _add_cli_preview_plan_args(ap)
    elif phase == 'flag-sequencing':
        _add_cli_core_connection_args(ap)
        _add_cli_flag_sequencing_args(ap)
    elif phase in {'execute', 'topo'}:
        _add_cli_core_connection_args(ap)
        _add_cli_execute_topo_args(ap)
    return ap


def main():
    argv = sys.argv[1:]
    if _cli_help_requested(argv):
        help_phase = _cli_phase_token(argv)
        help_parser = _build_cli_help_parser(help_phase)
        help_parser.print_help()
        return 0

    ap = _build_cli_parser()
    args = ap.parse_args()

    # Remote SSH runner may provide sudo password on stdin; make it available to
    # docker-invoking subprocesses (e.g. flag-node-generators) via env.
    _maybe_seed_docker_sudo_password_from_stdin()

    backend_for_cli = None
    try:
        backend_for_cli = _load_web_backend_module()
    except Exception:
        backend_for_cli = None

    remote_delegated_cli = str(os.environ.get('CORETG_CLI_REMOTE_DELEGATED') or '').strip().lower() in {'1', 'true', 'yes', 'y', 'on'}

    if backend_for_cli is not None:
        try:
            resolved_scenario_name = _cli_phase_scenario(args, backend=backend_for_cli)
            if resolved_scenario_name and not args.scenario:
                args.scenario = resolved_scenario_name
        except Exception:
            resolved_scenario_name = args.scenario
        if not remote_delegated_cli:
            try:
                _resolve_cli_authoritative_xml_path(args, backend=backend_for_cli)
            except Exception:
                pass
        try:
            resolved_scenario_name = _cli_phase_scenario(args, backend=backend_for_cli)
            if resolved_scenario_name and not args.scenario:
                args.scenario = resolved_scenario_name
        except Exception:
            resolved_scenario_name = args.scenario
    else:
        resolved_scenario_name = args.scenario

    execute_preflight_source_xml = ''
    execute_tmp_preview_source = False
    if str(args.phase or '').strip().lower() == 'execute':
        try:
            execute_preflight_source_xml = os.path.abspath(str(getattr(args, 'xml', '') or '').strip())
        except Exception:
            execute_preflight_source_xml = str(getattr(args, 'xml', '') or '').strip()
        execute_tmp_preview_source = _is_temporary_preview_xml_path(execute_preflight_source_xml)

    execute_hitl_errors: list[str] = []
    execute_hitl_changes: list[dict[str, Any]] = []
    if backend_for_cli is not None and str(args.phase or '').strip().lower() == 'execute' and not remote_delegated_cli:
        try:
            execute_hitl_errors, execute_hitl_changes = _maybe_prepare_cli_execute_hitl_xml(
                args,
                backend=backend_for_cli,
                scenario_name=resolved_scenario_name,
            )
        except Exception as exc:
            execute_hitl_errors = [f'Failed to validate HITL interface names before execute: {exc}']

    preview_payload: Dict[str, Any] | None = None
    preview_full: Dict[str, Any] | None = None
    preview_plan_path: str | None = None
    if args.preview_plan:
        preview_plan_path = os.path.abspath(args.preview_plan)
        try:
            preview_payload, preview_full = _load_preview_plan(preview_plan_path, args.scenario)
            logging.getLogger(__name__).info("Loaded preview plan from %s", preview_plan_path)
            try:
                setattr(args, '_resolved_preview_plan_path', preview_plan_path)
            except Exception:
                pass
        except Exception as e:
            logging.getLogger(__name__).error("Failed loading preview plan %s: %s", preview_plan_path, e)
            raise SystemExit(1)
        if args.seed is None:
            try:
                seed_candidate = preview_payload.get('metadata', {}).get('seed') if isinstance(preview_payload, dict) else None
            except Exception:
                seed_candidate = None
            if seed_candidate is None and isinstance(preview_full, dict):
                seed_candidate = preview_full.get('seed')
            if isinstance(seed_candidate, int):
                args.seed = seed_candidate
    else:
        # Web runs typically pass only --xml; when that XML embeds PlanPreview,
        # use it as the preview source so runtime slot/vulnerability mapping stays
        # aligned with the persisted scenario plan.
        try:
            preview_payload, preview_full = _load_preview_plan(args.xml, args.scenario)
            preview_plan_path = os.path.abspath(args.xml)
            try:
                setattr(args, '_resolved_preview_plan_path', preview_plan_path)
            except Exception:
                pass
        except Exception:
            preview_payload, preview_full = None, None

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    if execute_hitl_errors:
        logging.error('HITL interface validation failed before execute.')
        for detail in execute_hitl_errors:
            logging.error('%s', detail)
        return 1
    if execute_hitl_changes:
        try:
            mappings = ', '.join(
                f"{entry.get('from')}->{entry.get('to')}"
                for entry in execute_hitl_changes
                if entry.get('from') and entry.get('to')
            )
            if mappings:
                logging.info('Resolved HITL interface selectors for execute: %s', mappings)
        except Exception:
            pass

    prefetched_hitl_config: dict[str, Any] | None = None
    if args.phase in {'execute', 'topo'}:
        try:
            prefetched_hitl_config = parse_hitl_info(args.xml, args.scenario) or {"enabled": False, "interfaces": []}
        except Exception:
            prefetched_hitl_config = {"enabled": False, "interfaces": []}
        if backend_for_cli is not None:
            try:
                xml_basename = os.path.basename(os.path.abspath(args.xml))
            except Exception:
                xml_basename = os.path.basename(args.xml)
            try:
                prefetched_hitl_config = backend_for_cli._sanitize_hitl_config(prefetched_hitl_config, args.scenario, xml_basename)
            except Exception:
                pass
        try:
            setattr(args, '_prefetched_hitl_config', prefetched_hitl_config)
        except Exception:
            pass

    if backend_for_cli is not None:
        delegated_exit_code = _maybe_delegate_cli_to_remote(
            args,
            backend=backend_for_cli,
            scenario_name=resolved_scenario_name,
        )
        if delegated_exit_code is not None:
            return delegated_exit_code

    if args.phase == 'preview-plan':
        return _run_preview_plan_phase(args)
    if args.phase == 'new':
        return _run_new_phase(args)
    if args.phase == 'flag-sequencing':
        return _run_flag_sequencing_phase(args)

    # Expose FlowState assignments so compose prep can overlay flow artifacts.
    try:
        _export_flow_assignments_to_env(args.xml, args.scenario)
    except Exception:
        pass

    if args.seed is not None:
        random.seed(args.seed)
        try:
            from .builders.topology import set_global_random_seed
            set_global_random_seed(args.seed)
        except Exception:
            pass

    # Single-pass planning/build
    logging.info("PHASE: Parse scenario inputs")

    # Unified planning via orchestrator (still parse node_info early for some legacy metadata requirements)
    density_base, weight_items, count_items, services = parse_node_info(args.xml, args.scenario)
    # Optional additive planning metadata (if XML produced by enhanced web UI)
    planning_meta = {}
    try:
        planning_meta = parse_planning_metadata(args.xml, args.scenario) or {}
    except Exception:
        planning_meta = {}
    try:
        if prefetched_hitl_config is not None:
            hitl_config = prefetched_hitl_config
        else:
            hitl_config = parse_hitl_info(args.xml, args.scenario) or {"enabled": False, "interfaces": []}
    except Exception:
        hitl_config = {"enabled": False, "interfaces": []}
    if backend_for_cli is not None:
        if prefetched_hitl_config is not None:
            pass
        else:
            try:
                xml_basename = os.path.basename(os.path.abspath(args.xml))
            except Exception:
                xml_basename = os.path.basename(args.xml)
            try:
                hitl_config = backend_for_cli._sanitize_hitl_config(hitl_config, args.scenario, xml_basename)
            except Exception:
                pass
    scenario_key = args.scenario
    if not scenario_key:
        try:
            scenario_key = os.path.splitext(os.path.basename(args.xml))[0]
        except Exception:
            scenario_key = "__default__"
    hitl_config.setdefault("scenario_key", scenario_key)
    # First allocate weight-based roles across density base
    base_total = density_base
    if args.max_nodes is not None and args.max_nodes > 0:
        base_total = min(base_total, args.max_nodes)
    role_counts = compute_role_counts(base_total, [(r, f) for r, f in weight_items]) if base_total > 0 else {}
    # Add absolute count rows (subject to max cap)
    additive_total = sum(c for _, c in count_items)
    if args.max_nodes is not None and args.max_nodes > 0:
        remaining = max(0, args.max_nodes - sum(role_counts.values()))
    else:
        remaining = additive_total
    for role, c in count_items:
        to_add = c if args.max_nodes is None else min(c, remaining)
        if to_add <= 0:
            continue
        role_counts[role] = role_counts.get(role, 0) + to_add
        if args.max_nodes is not None:
            remaining -= to_add
            if remaining <= 0:
                break
    effective_total = sum(role_counts.values())
    logging.info("PHASE: Role counts computed (hosts=%d)", effective_total)
    routing_density, routing_items = parse_routing_info(args.xml, args.scenario)
    # Derive R2R / R2S policy directly from the first routing item with a mode (no averaging)
    r2r_policy_plan = None
    r2s_policy_plan = None
    if routing_items:
        try:
            first_r2r = next((ri for ri in routing_items if getattr(ri,'r2r_mode',None)), None)
            if first_r2r:
                m = getattr(first_r2r, 'r2r_mode', '')
                if m == 'Exact' and getattr(first_r2r, 'r2r_edges', 0) > 0:
                    r2r_policy_plan = { 'mode': 'Exact', 'target_degree': int(getattr(first_r2r,'r2r_edges',0)) }
                elif m:
                    r2r_policy_plan = { 'mode': m }
            first_r2s = next((ri for ri in routing_items if getattr(ri,'r2s_mode',None)), None)
            if first_r2s:
                m2_raw = getattr(first_r2s, 'r2s_mode', '') or ''
                m2 = m2_raw.strip()
                m2_norm = m2.lower()
                edges_raw = getattr(first_r2s,'r2s_edges',0)
                try: edges_val = int(edges_raw)
                except Exception: edges_val = 0
                if m2_norm == 'exact' and edges_val > 0:
                    r2s_policy_plan = { 'mode': 'Exact', 'target_per_router': edges_val }
                elif m2:
                    r2s_policy_plan = { 'mode': m2 }
        except Exception:
            pass

    preview_router_count: int | None = None
    if preview_full:
        try:
            hosts_preview = preview_full.get('hosts') or []
            if isinstance(hosts_preview, list):
                preview_role_counts: Dict[str, int] = {}
                for h in hosts_preview:
                    role = (h.get('role') if isinstance(h, dict) else None) or 'Host'
                    preview_role_counts[role] = preview_role_counts.get(role, 0) + 1
                if preview_role_counts:
                    role_counts = preview_role_counts
                    effective_total = sum(preview_role_counts.values())
        except Exception as e_rc:
            logging.getLogger(__name__).warning("Preview plan role expansion failed: %s", e_rc)
        try:
            routers_preview = preview_full.get('routers') or []
            if isinstance(routers_preview, list):
                preview_router_count = len(routers_preview)
        except Exception:
            preview_router_count = None

    # Orchestrator full plan (centralized)
    logging.info("PHASE: Planning topology")
    from .planning.orchestrator import compute_full_plan
    orchestrated_plan = compute_full_plan(args.xml, scenario=args.scenario, seed=args.seed, include_breakdowns=True)
    if not args.scenario and isinstance(orchestrated_plan, dict):
        derived_key = orchestrated_plan.get("scenario_name") or orchestrated_plan.get("scenario_key")
        if derived_key:
            hitl_config["scenario_key"] = derived_key
    try:
        hitl_preview_reservations = collect_hitl_preview_ip_reservations(hitl_config)
    except Exception:
        hitl_preview_reservations = {"ip_addresses": set(), "network_cidrs": set()}
    prelim_router_count = orchestrated_plan['routers_planned']
    if preview_router_count is not None and preview_router_count > 0:
        prelim_router_count = preview_router_count
        orchestrated_plan['routers_planned'] = preview_router_count
    service_plan = orchestrated_plan.get('service_plan') or {}
    vulnerabilities_plan = orchestrated_plan.get('vulnerability_plan')
    routing_plan = orchestrated_plan.get('breakdowns', {}).get('router', {}).get('simple_plan', {})
    router_plan_breakdown = orchestrated_plan.get('breakdowns', {}).get('router', {})
    seg_breakdown = orchestrated_plan.get('breakdowns', {}).get('segmentation', {}) if orchestrated_plan else {}
    seg_density_plan = seg_breakdown.get('density') if isinstance(seg_breakdown, dict) else None
    seg_items_serialized = seg_breakdown.get('raw_items_serialized') if isinstance(seg_breakdown, dict) else None
    traffic_plan_preview = orchestrated_plan.get('traffic_plan') if isinstance(orchestrated_plan, dict) else None
    flow_state = _flow_state_from_xml(args.xml, args.scenario)

    flow_execute_active = _flow_state_requires_cli_execute_runtime(flow_state)
    flow_remote_expected = False
    if args.phase == 'execute' and backend_for_cli is not None:
        try:
            _scenario_norm, flow_core_cfg, _has_saved_core_source = _resolve_cli_core_context(
                args,
                backend=backend_for_cli,
                scenario_name=resolved_scenario_name,
            )
            if isinstance(flow_core_cfg, dict):
                coerce_bool = getattr(backend_for_cli, '_coerce_bool', lambda value: bool(value))
                flow_remote_expected = bool(coerce_bool(flow_core_cfg.get('ssh_enabled')))
        except Exception:
            flow_remote_expected = False

    if flow_execute_active:
        flow_ok, flow_error, flow_details = _validate_flow_state_for_cli_execute(
            flow_state,
            remote_execution_expected=flow_remote_expected,
            require_local_runtime_paths=execute_tmp_preview_source,
        )
        if not flow_ok:
            if execute_tmp_preview_source and any(
                isinstance(detail, dict)
                and str(detail.get('reason') or '').strip() in {'missing artifacts_dir', 'missing inject_source'}
                for detail in (flow_details or [])
            ):
                flow_error = (
                    'Execute was given a temporary preview XML whose Flow artifacts are no longer present. '
                    'Use the saved scenario XML under outputs/scenarios-* or rerun Generate (resolve) and Save before executing via CLI.'
                )
            logging.error("%s", flow_error)
            if execute_tmp_preview_source and execute_preflight_source_xml:
                logging.error('Temporary preview XML source: %s', execute_preflight_source_xml)
            if flow_details:
                logging.error(
                    "FLOW_EXECUTE_PREFLIGHT_DETAILS: %s",
                    json.dumps(flow_details, indent=2, sort_keys=True),
                )
            return 1
    elif isinstance(flow_state, dict) and list(flow_state.get('flag_assignments') or []):
        logging.info(
            "FlowState present in XML but the current XML-derived plan has no Docker or vulnerability targets; skipping Flow execute preflight"
        )

    if flow_execute_active and not _plan_supports_flow(orchestrated_plan.get('role_counts') or {}, vulnerabilities_plan):
        logging.info(
            "FlowState runtime values were validated, but the current XML-derived plan has no Docker or vulnerability targets; downstream Flow-specific execution behavior may be skipped"
        )

    if preview_full is not None and flow_execute_active:
        try:
            preview_summary = _plan_summary_from_full_preview(preview_full)
            current_summary = _current_plan_summary_for_execute(
                orchestrated_plan=orchestrated_plan,
                r2r_policy=r2r_policy_plan,
                r2s_policy=r2s_policy_plan,
                routing_items=routing_items,
                routing_plan=routing_plan,
                segmentation_density=seg_density_plan,
                segmentation_items=seg_items_serialized,
                traffic_plan=traffic_plan_preview,
                seed=args.seed,
                ip4_prefix=args.prefix,
                ip_mode=args.ip_mode,
                ip_region=args.ip_region,
                hitl_preview_reservations=hitl_preview_reservations,
            )
            diffs = _diff_plan_summaries(preview_summary, current_summary)
            if diffs:
                logging.error(
                    "Saved PlanPreview does not match the current XML-derived plan. Regenerate preview metadata and save the XML before executing via CLI."
                )
                for entry in diffs:
                    logging.error(
                        "PlanPreview mismatch: %s flow=%s xml=%s",
                        entry.get('field'),
                        json.dumps(_json_ready(entry.get('flow')), sort_keys=True),
                        json.dumps(_json_ready(entry.get('xml')), sort_keys=True),
                    )
                return 1
        except Exception as exc:
            logging.warning("Failed validating saved PlanPreview against the current XML: %s", exc)

    if preview_full is None:
        try:
            preview_full = build_full_preview(
                role_counts=role_counts,
                routers_planned=prelim_router_count,
                services_plan=service_plan,
                vulnerabilities_plan=vulnerabilities_plan,
                r2r_policy=r2r_policy_plan,
                r2s_policy=r2s_policy_plan,
                routing_items=routing_items,
                routing_plan=routing_plan,
                segmentation_density=seg_density_plan,
                segmentation_items=seg_items_serialized,
                traffic_plan=traffic_plan_preview,
                seed=args.seed,
                ip4_prefix=args.prefix,
                ip_mode=args.ip_mode,
                ip_region=args.ip_region,
                base_scenario=orchestrated_plan.get('base_scenario'),
                reserved_ipv4_addrs=sorted(hitl_preview_reservations.get('ip_addresses') or []),
                reserved_ipv4_networks=sorted(hitl_preview_reservations.get('network_cidrs') or []),
            )
        except Exception as auto_prev_exc:
            logging.getLogger(__name__).warning("Failed to generate automatic full preview: %s", auto_prev_exc)
    if preview_full and isinstance(router_plan_breakdown, dict):
        preview_full.setdefault('router_plan', router_plan_breakdown)
    logging.info(
        "PHASE: Planning complete (routers=%s hosts=%s)",
        prelim_router_count,
        effective_total,
    )
    try:
        from .planning.plan_builder import build_initial_pool
        from .planning.constraints import validate_pool_final
        # Vulnerabilities: reuse earlier parsing if available in generation_meta (planning_meta done above). We recompute minimally.
        try:
            from .parsers.vulnerabilities import parse_vulnerabilities_info
            from .planning.vulnerability_plan import VulnerabilityItem, compute_vulnerability_plan
            vuln_density, vuln_items_xml, _vuln_flag_type = parse_vulnerabilities_info(args.xml, args.scenario)
            vuln_items: list[VulnerabilityItem] = []
            for it in (vuln_items_xml or []):
                name = (it.get('selected') or '').strip() or 'Item'
                vm_raw = (it.get('v_metric') or '').strip()
                vm = vm_raw or ('Count' if (it.get('selected') or '').strip() == 'Specific' and (it.get('v_count') or '').strip() else 'Weight')
                abs_count = 0
                if vm.lower() == 'count':
                    try:
                        abs_count = int(it.get('v_count') or 0)
                    except Exception:
                        abs_count = 0
                try:
                    factor_val = float(it.get('factor') or 0.0)
                except Exception:
                    factor_val = 0.0
                kind = (it.get('selected') or name)
                vuln_items.append(VulnerabilityItem(name=name, density=vuln_density, abs_count=abs_count, kind=kind, factor=factor_val, metric=vm))
            vplan, vbreak = compute_vulnerability_plan(base_total, vuln_density, vuln_items)
            if vplan:
                vulnerabilities_plan = vplan
        except Exception:
            pass
        pool = build_initial_pool(role_counts, prelim_router_count, service_plan, routing_plan, router_breakdown=router_plan_breakdown, r2r_policy=r2r_policy_plan, vulnerabilities_plan=vulnerabilities_plan)
        if preview_full:
            try:
                pool.full_preview = preview_full
            except Exception:
                pass
        if args.preview or args.preview_full:
            summary = pool.summarize()
            # Provide r2s/r2r placeholders if not yet populated by builders so UI/report
            # can render consistent sections.
            if 'r2r_policy' in summary and summary['r2r_policy'] is None:
                summary['r2r_policy'] = r2r_policy_plan
            if 'r2s_policy' not in summary or summary['r2s_policy'] is None:
                summary['r2s_policy'] = r2s_policy_plan
            # Resolved expansions (already added in summarize) but ensure deterministic ordering
            try:
                if isinstance(summary.get('role_assignment_preview'), list):
                    summary['role_assignment_preview'] = list(summary['role_assignment_preview'])
            except Exception:
                pass
            violations = validate_pool_final(summary)
            # Attach orchestrator plan for parity with web preview
            out = {"plan": summary, "violations": violations, "orchestrator_plan": orchestrated_plan}
            if args.preview_full:
                try:
                    if preview_full:
                        full_prev = preview_full
                    else:
                        # Derive r2s policy summary (mirror earlier plan pass) for preview fidelity
                        r2s_policy_plan = None
                        try:
                            first_r2s = next((ri for ri in routing_items if getattr(ri,'r2s_mode',None)), None)
                            if first_r2s:
                                m2_raw = getattr(first_r2s, 'r2s_mode', '') or ''
                                m2 = m2_raw.strip()
                                m2_norm = m2.lower()
                                edges_raw = getattr(first_r2s,'r2s_edges',0)
                                try: edges_val = int(edges_raw)
                                except Exception: edges_val = 0
                                if m2_norm == 'exact' and edges_val > 0:
                                    r2s_policy_plan = { 'mode': 'Exact', 'target_per_router': edges_val }
                                elif m2:
                                    r2s_policy_plan = { 'mode': m2 }
                        except Exception:
                            pass
                        full_prev = build_full_preview(
                            role_counts=role_counts,
                            routers_planned=prelim_router_count,
                            services_plan=service_plan,
                            vulnerabilities_plan=vulnerabilities_plan,
                            r2r_policy=r2r_policy_plan,
                            r2s_policy=r2s_policy_plan,
                            routing_items=routing_items,
                            routing_plan=routing_plan,
                            segmentation_density=orchestrated_plan.get('breakdowns', {}).get('segmentation', {}).get('density'),
                            segmentation_items=orchestrated_plan.get('breakdowns', {}).get('segmentation', {}).get('raw_items_serialized'),
                            seed=args.seed,
                            ip4_prefix=args.prefix,
                            ip_mode=args.ip_mode,
                            ip_region=args.ip_region,
                            base_scenario=orchestrated_plan.get('base_scenario'),
                            reserved_ipv4_addrs=sorted(hitl_preview_reservations.get('ip_addresses') or []),
                            reserved_ipv4_networks=sorted(hitl_preview_reservations.get('network_cidrs') or []),
                        )
                    full_prev['router_plan'] = router_plan_breakdown
                    out['full_preview'] = full_prev
                except Exception as e:
                    out['full_preview_error'] = str(e)
            print(json.dumps(out, indent=2, sort_keys=True))
            if args.plan_output:
                try:
                    with open(args.plan_output, 'w', encoding='utf-8') as wf:
                        json.dump(out, wf, indent=2, sort_keys=True)
                except Exception as e:
                    print(f"WARN: failed to write plan file {args.plan_output}: {e}", file=sys.stderr)
            return
        else:
            if args.plan_output:
                try:
                    with open(args.plan_output, 'w', encoding='utf-8') as wf:
                        json.dump({"plan": pool.summarize()}, wf, indent=2, sort_keys=True)
                except Exception:
                    pass
    except Exception:
        pass

    scenario_name = args.scenario
    generation_meta = {
        "host": args.host,
        "port": args.port,
        "ip_prefix": args.prefix,
        "ip_mode": args.ip_mode,
        "ip_region": args.ip_region,
        "layout_density": args.layout_density,
        "seed": args.seed,
        "router_mesh_style": args.router_mesh,
    "density_base_count": density_base,
    "count_rows_additive_total": sum(c for _, c in count_items),
    "effective_total_nodes": effective_total,
        "count_rows_breakdown": {r: c for r, c in count_items},
        "weight_rows": {r: f for r, f in weight_items},
        "role_counts": role_counts,
        "hitl_enabled": bool(hitl_config.get("enabled")),
        "hitl_interface_count": len(hitl_config.get("interfaces") or []),
    }
    if preview_full:
        try:
            generation_meta['preview_router_count'] = len(preview_full.get('routers') or [])
            generation_meta['preview_host_total'] = len(preview_full.get('hosts') or [])
        except Exception:
            pass
    if preview_plan_path:
        generation_meta['preview_plan_path'] = preview_plan_path
    # Merge in planning metadata namespaced to avoid collision
    try:
        if planning_meta:
            if 'node_info' in planning_meta:
                ni = planning_meta['node_info']
                generation_meta.update({
                    'plan_node_base_nodes': ni.get('base_nodes'),
                    'plan_node_additive_nodes': ni.get('additive_nodes'),
                    'plan_node_combined_nodes': ni.get('combined_nodes'),
                    'plan_node_weight_rows': ni.get('weight_rows'),
                    'plan_node_count_rows': ni.get('count_rows'),
                    'plan_node_weight_sum': ni.get('weight_sum'),
                })
            if 'routing' in planning_meta:
                ro = planning_meta['routing']
                generation_meta.update({
                    'plan_routing_explicit': ro.get('explicit_count'),
                    'plan_routing_derived': ro.get('derived_count'),
                    'plan_routing_total': ro.get('total_planned'),
                    'plan_routing_weight_rows': ro.get('weight_rows'),
                    'plan_routing_count_rows': ro.get('count_rows'),
                    'plan_routing_weight_sum': ro.get('weight_sum'),
                })
            if 'vulnerabilities' in planning_meta:
                vu = planning_meta['vulnerabilities']
                generation_meta.update({
                    'plan_vuln_explicit': vu.get('explicit_count'),
                    'plan_vuln_derived': vu.get('derived_count'),
                    'plan_vuln_total': vu.get('total_planned'),
                    'plan_vuln_weight_rows': vu.get('weight_rows'),
                    'plan_vuln_count_rows': vu.get('count_rows'),
                    'plan_vuln_weight_sum': vu.get('weight_sum'),
                })
    except Exception:
        pass

    if not CORE_GRPC_AVAILABLE:
        if args.phase in {'execute', 'topo'} and str(
            os.environ.get('CORETG_CLI_ALLOW_OFFLINE_REPORT') or ''
        ).strip().lower() not in {'1', 'true', 'yes', 'y', 'on'}:
            logging.error(
                "The %s phase requires CORE gRPC availability or successful remote delegation; "
                "no CORE session was started.",
                args.phase,
            )
            return 1
        return _run_offline_report(
            args,
            role_counts,
            routing_items,
            services,
            orchestrated_plan,
            generation_meta,
        )

    core = client.CoreGrpcClient(address=f"{args.host}:{args.port}")
    # Wrap with retry proxy to handle transient GOAWAY/ping_timeout errors
    try:
        from .utils.grpc_retry import wrap_core_client as wrap_core_client_retry
        core = wrap_core_client_retry(core, logging.getLogger("scenarioforge.grpc"))
    except Exception:
        pass
    logging.info("[grpc] CoreGrpcClient.connect() -> %s:%s", args.host, args.port)
    core.connect()
    reconnect_after_cleanup = False
    try:
        reconnect_after_cleanup = _best_effort_cli_execute_cleanup(args, core)
    except Exception as cleanup_exc:
        logging.warning('Execute cleanup failed: %s', cleanup_exc)
    if reconnect_after_cleanup:
        try:
            core.connect()
        except Exception as reconnect_exc:
            logging.warning('Reconnect after execute cleanup failed: %s', reconnect_exc)
    try:
        from .utils.grpc_helpers import start_grpc_keepalive
        # IMPORTANT: start keepalive before applying any gRPC logging proxy.
        # The keepalive pings call get_sessions() on an interval (default 20s).
        # If we wrap the client with a logging proxy at INFO, that turns into
        # repetitive INFO log spam even after the scenario is running.
        start_grpc_keepalive(core)
    except Exception:
        pass
    # Optional: wrap with a logging proxy to trace all gRPC calls.
    # Default OFF unless explicitly enabled (or logger already in DEBUG).
    try:
        enable_trace = False
        try:
            v = os.getenv('CORETG_GRPC_CALL_TRACE')
            if v is None:
                enable_trace = False
            else:
                enable_trace = str(v).strip().lower() not in ('0', 'false', 'no', 'off', '')
        except Exception:
            enable_trace = False
        try:
            if logging.getLogger('scenarioforge.grpc').isEnabledFor(logging.DEBUG):
                enable_trace = True
        except Exception:
            pass
        if enable_trace:
            from .utils.grpc_logging import wrap_core_client as wrap_core_client_logging
            core = wrap_core_client_logging(core, logging.getLogger("scenarioforge.grpc"))
    except Exception:
        pass
    # Pre-parse vulnerabilities to plan docker-compose assignments mapped to host slots (reuse orchestrator raw)
    docker_slot_plan: dict | None = None
    preview_vuln_slots: list[str] = []
    try:
        pivot_density, pivot_items = parse_pivoting_info(args.xml, args.scenario)
    except Exception:
        pivot_density, pivot_items = 0.0, []
    if pivot_items:
        generation_meta['pivoting_items'] = [
            {
                'name': getattr(item, 'name', ''),
                'factor': getattr(item, 'factor', 0.0),
                'pivot_node': getattr(item, 'pivot_node', ''),
                'pivot_role': getattr(item, 'pivot_role', ''),
                'target_node': getattr(item, 'target_node', ''),
                'target_role': getattr(item, 'target_role', ''),
                'target_ports': getattr(item, 'target_ports', ''),
                'target_protocols': getattr(item, 'target_protocols', ''),
                'exposure': getattr(item, 'exposure', ''),
                'source_scope': getattr(item, 'source_scope', ''),
                'access_provider': getattr(item, 'access_provider', ''),
            }
            for item in (pivot_items or [])
        ]
    seed_for_vuln = args.seed
    try:
        if seed_for_vuln is None and isinstance(preview_full, dict):
            seed_raw = preview_full.get('seed')
            if seed_raw is not None:
                seed_for_vuln = int(seed_raw)
    except Exception:
        seed_for_vuln = args.seed
    try:
        if isinstance(preview_full, dict):
            vbn = preview_full.get('vulnerabilities_by_node') or preview_full.get('vulnerabilities_preview') or {}
            host_ids: list[int] = []
            if isinstance(vbn, dict):
                for key in vbn.keys():
                    try:
                        host_ids.append(int(key))
                    except Exception:
                        continue
            if host_ids:
                hosts_preview = preview_full.get('hosts') or []
                if isinstance(hosts_preview, list):
                    ordered_hosts = sorted(hosts_preview, key=lambda h: (h.get('node_id', 0) if isinstance(h, dict) else 0))
                    slot_map: dict[int, str] = {}
                    for idx, h in enumerate(ordered_hosts):
                        try:
                            hid = int(h.get('node_id'))
                        except Exception:
                            continue
                        slot_map[hid] = f"slot-{idx+1}"
                    for hid in host_ids:
                        slot = slot_map.get(hid)
                        if slot:
                            preview_vuln_slots.append(slot)
    except Exception:
        preview_vuln_slots = []
    try:
        vuln_density = None
        vuln_items = []
        try:
            vuln_density = orchestrated_plan.get('breakdowns', {}).get('vulnerabilities', {}).get('density_input')
        except Exception:
            pass
        if not vuln_items:
            vuln_items = orchestrated_plan.get('vulnerability_items_raw') or []
        if not vuln_density:
            # fallback legacy parse
            vuln_density, vuln_items, vuln_flag_type = parse_vulnerabilities_info(args.xml, args.scenario)
        catalog = load_vuln_catalog(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        total_hosts = sum(role_counts.values())  # total allocated hosts (base + additive)
        slot_names = [f"slot-{i+1}" for i in range(total_hosts)]
        if preview_vuln_slots:
            seen = set()
            ordered_slots: list[str] = []
            for slot in preview_vuln_slots:
                if slot in slot_names and slot not in seen:
                    ordered_slots.append(slot)
                    seen.add(slot)
            for slot in slot_names:
                if slot not in seen:
                    ordered_slots.append(slot)
            slot_names = ordered_slots
            logging.info("Using preview vulnerability slot ordering (%d slots prioritized)", len(preview_vuln_slots))
        flow_slots = _slot_names_for_flow_nodes(
            flow_state=flow_state,
            preview_full=preview_full,
            slot_names=slot_names,
        )
        if flow_slots:
            slot_names = flow_slots
            logging.info(
                "Restricting vulnerability docker assignments to %d Flow-selected slots",
                len(slot_names),
            )
        elif _flow_assignment_node_ids(flow_state):
            slot_names = []
            logging.info(
                "Flow assignments detected but no preview slot mapping resolved; skipping vulnerability docker assignments",
            )
        logging.info("Vulnerabilities config: density=%.3f, items=%d (total_hosts=%d)", float(vuln_density or 0.0), len(vuln_items or []), total_hosts)
        assignments_slots = {}
        if slot_names:
            assignments_slots = assign_compose_to_nodes(
                slot_names,
                vuln_density or 0.0,
                vuln_items or [],
                catalog,
                out_base="/tmp/vulns",
                require_pulled=False,
                base_host_pool=density_base,
                seed=seed_for_vuln,
                shuffle_nodes=not bool(preview_vuln_slots),
            )

        # Preview parity: if the preview plan has explicit vulnerabilities_by_node,
        # force those vulnerability names onto the corresponding slots. This prevents
        # silently falling back to the standard docker compose template for vuln nodes.
        try:
            overrides = _preview_vuln_slot_overrides(
                preview_full,
                vuln_items=vuln_items or [],
                catalog=catalog or [],
                slot_names=slot_names,
            )
        except Exception:
            overrides = {}
        if overrides:
            before_len = len(assignments_slots) if isinstance(assignments_slots, dict) else 0
            assignments_slots = _merge_vuln_slot_assignments_with_preview(
                assignments_slots,
                overrides=overrides,
                preview_full=preview_full,
            )
            after_len = len(assignments_slots) if isinstance(assignments_slots, dict) else 0
            logging.info(
                "Applied %d preview-based vulnerability slot overrides (%d -> %d total assignments)",
                int(len(overrides or {})),
                int(before_len),
                int(after_len),
            )
        if assignments_slots:
            docker_slot_plan = assignments_slots
            logging.info("Planned %d docker-compose assignments over %d host slots", len(assignments_slots), len(slot_names))
            try:
                logging.debug("Docker slot keys: %s", ", ".join(sorted(assignments_slots.keys())))
            except Exception:
                pass
        else:
            cnt_items = [it for it in (vuln_items or []) if (it.get('v_metric') == 'Count') or (it.get('selected') == 'Specific' and it.get('v_count'))]
            w_items = [it for it in (vuln_items or []) if it not in cnt_items]
            logging.info("No docker-compose assignments planned (density=%.3f, count_items=%d, weight_items=%d, catalog=%d)", float(vuln_density or 0.0), len(cnt_items), len(w_items), len(catalog or []))
        # Stats
        try:
            cnt_total = 0
            for it in (vuln_items or []):
                if (it.get('v_metric') == 'Count') or (it.get('selected') == 'Specific' and it.get('v_count')):
                    try:
                        vc = int(it.get('v_count') or 0)
                    except Exception:
                        vc = 0
                    if vc > 0:
                        cnt_total += vc
            generation_meta["vuln_density_fraction"] = float(vuln_density or 0.0)
            try:
                import math as _math
                generation_meta["vuln_density_target"] = int(_math.floor((vuln_density or 0.0) * (density_base or 0) + 1e-9))
            except Exception:
                generation_meta["vuln_density_target"] = int(round((vuln_density or 0.0) * density_base))  # fallback
            generation_meta["vuln_count_items_total"] = cnt_total
            generation_meta["vuln_total_planned_additive"] = generation_meta["vuln_density_target"] + cnt_total
            generation_meta["vuln_docker_assignments"] = len(assignments_slots or {})
        except Exception:
            pass
    except Exception as e:
        logging.exception("Vulnerability planning skipped or failed: %s", e)

    # Log DOCKER availability in this CORE wrapper
    try:
        from core.api.grpc.wrappers import NodeType as _NT  # type: ignore
        logging.info("CORE Docker node type available: %s", hasattr(_NT, 'DOCKER'))
    except Exception:
        pass
    # If any routing item carries abs_count>0, we should build a segmented topology even if density==0
    has_routing_counts = any(getattr(ri, 'abs_count', 0) and int(getattr(ri, 'abs_count', 0)) > 0 for ri in (routing_items or []))
    # Always build directly from current scenario plan (phased path removed)
    logging.info("PHASE: Building topology")
    routers = []
    switches = []
    hosts = []
    service_assignments = {}
    router_protocols = {}
    docker_by_name = {}
    if (routing_density and routing_density > 0) or has_routing_counts:
        session, routers, hosts, service_assignments, router_protocols, docker_by_name = build_segmented_topology(
            core,
            role_counts,
            routing_density=routing_density,
            routing_items=routing_items,
            base_host_pool=density_base,
            services=services,
            ip4_prefix=args.prefix,
            ip_mode=args.ip_mode,
            ip_region=args.ip_region,
            layout_density=args.layout_density,
            docker_slot_plan=docker_slot_plan,
            router_mesh_style=args.router_mesh,
            preview_plan=preview_full,
        )
        # Preview parity signal (authoritative when preview_full was provided)
        try:
            ts = getattr(session, 'topo_stats', None)
            realized = bool(ts.get('preview_realized')) if isinstance(ts, dict) else False
            logging.info("Preview parity: preview_attached=%s preview_realized=%s", bool(preview_full), realized)
            try:
                generation_meta['preview_attached'] = bool(preview_full)
                generation_meta['preview_realized'] = realized
            except Exception:
                pass
        except Exception:
            pass
        # Merge topo stats if present
        try:
            ts = getattr(session, 'topo_stats', None)
            if isinstance(ts, dict):
                generation_meta.update(ts)
        except Exception:
            pass
    else:
        # Pure host topology (no routers requested)
        session, switches, hosts, service_assignments, docker_by_name = build_star_from_roles(
            core,
            role_counts,
            services=services,
            ip4_prefix=args.prefix,
            ip_mode=args.ip_mode,
            ip_region=args.ip_region,
            layout_density=args.layout_density,
            docker_slot_plan=docker_slot_plan,
            preview_plan=preview_full,
        )
        # Star topologies don't use preview realization, but log for consistency.
        try:
            logging.info("Preview parity: preview_attached=%s preview_realized=%s", bool(preview_full), False)
            try:
                generation_meta['preview_attached'] = bool(preview_full)
                generation_meta['preview_realized'] = False
            except Exception:
                pass
        except Exception:
            pass
        # Align function return signature with segmented path
        router_protocols = {}
        routers = []

    try:
        logging.info("PHASE: Topology built (routers=%d hosts=%d)", len(routers or []), len(hosts or []))
    except Exception:
        pass

    # Log which docker nodes were actually created by the builders
    try:
        if docker_by_name:
            logging.info("Docker nodes created: %d -> %s", len(docker_by_name), ", ".join(sorted(docker_by_name.keys())))
        else:
            logging.info("No docker nodes created by topology builders (either no assignments or NodeType.DOCKER unavailable)")
    except Exception:
        pass

    try:
        if pivot_items and docker_by_name:
            pivot_summary = _apply_pivoting_to_docker_nodes(
                session=session,
                hosts=hosts,
                docker_nodes=docker_by_name,
                pivot_items=pivot_items,
            )
            generation_meta['pivoting'] = pivot_summary
            applied_count = len(pivot_summary.get('rules') or []) if isinstance(pivot_summary, dict) else 0
            warning_count = len(pivot_summary.get('warnings') or []) if isinstance(pivot_summary, dict) else 0
            logging.info("Applied pivot exposure metadata: targets=%d warnings=%d", applied_count, warning_count)
            for warning in (pivot_summary.get('warnings') or [])[:10]:
                logging.warning("Pivoting: %s", warning)
    except Exception as e_pivot:
        logging.warning("Pivoting metadata application failed: %s", e_pivot)

    try:
        preview_hitl_router_ids = []
        if isinstance(preview_full, dict):
            raw_hitl_ids = preview_full.get("hitl_router_ids") or []
            if isinstance(raw_hitl_ids, list):
                preview_hitl_router_ids = [item for item in raw_hitl_ids if item is not None]
        if bool(hitl_config.get("enabled")) and preview_hitl_router_ids:
            raw_settle = os.getenv("CORETG_HITL_PREVIEW_SETTLE_SECONDS", "0.35")
            settle_seconds = max(0.0, min(5.0, float(raw_settle)))
            if settle_seconds > 0:
                logging.info("HITL: waiting %.2fs for preview router links to settle", settle_seconds)
                time.sleep(settle_seconds)
    except Exception:
        pass

    try:
        logging.info("PHASE: HITL attachment")
        hitl_summary = attach_hitl_rj45_nodes(session, routers, hosts, hitl_config)
        generation_meta["hitl_attachment"] = hitl_summary
        if hitl_summary.get("interfaces"):
            logging.info(
                "HITL: attached %d RJ45 node(s) to session", len(hitl_summary.get("interfaces", []))
            )
        elif hitl_summary.get("enabled"):
            logging.info("HITL: enabled but no RJ45 nodes created (see hitl_attachment metadata)")
    except Exception as exc:
        logging.warning("HITL attachment failed: %s", exc)

    if args.phase == 'topo':
        topo_summary = {
            'ok': True,
            'phase': 'topo',
            'xml_path': os.path.abspath(args.xml),
            'scenario': scenario_name,
            'preview_plan_path': preview_plan_path,
            'core': {'host': args.host, 'port': args.port},
            'session_id': _core_session_id(session),
            'session_started': False,
            'routers_count': len(routers or []),
            'hosts_count': len(hosts or []),
            'switches_count': len(switches or []),
            'docker_nodes': sorted(docker_by_name.keys()) if isinstance(docker_by_name, dict) else [],
            'service_assignment_count': len(service_assignments or {}),
            'preview_attached': bool(preview_full),
            'preview_realized': bool(generation_meta.get('preview_realized')),
            'pivoting': generation_meta.get('pivoting'),
            'hitl_attachment': generation_meta.get('hitl_attachment'),
        }
        _emit_phase_json(topo_summary, output_path=args.plan_output)
        return 0

    # Parse segmentation config OR fallback to preview segmentation if available
    seg_summary = None
    try:
        logging.info("PHASE: Segmentation")
        seg_density = orchestrated_plan.get('breakdowns', {}).get('segmentation', {}).get('density')
        seg_items = orchestrated_plan.get('segmentation_items_raw')
        if seg_density is None:
            seg_density, seg_items = parse_segmentation_info(args.xml, args.scenario)
        logging.info("Segmentation config: density=%.3f, items=%d", float(seg_density or 0.0), len(seg_items or []))
        if seg_density and seg_density > 0 and seg_items:
            try:
                from .utils.segmentation import plan_and_apply_segmentation
                seg_summary = plan_and_apply_segmentation(
                    session,
                    routers if 'routers' in locals() else [],
                    hosts,
                    seg_density,
                    seg_items,
                    nat_mode=str(getattr(args, 'nat_mode', 'SNAT')).upper(),
                    include_hosts=bool(getattr(args, 'seg_include_hosts', False)),
                    allow_docker_ports=bool(getattr(args, 'seg_allow_docker_ports', False)),
                    docker_nodes=docker_by_name if isinstance(docker_by_name, dict) else None,
                )
                logging.info("Applied segmentation rules: %d", len(seg_summary.get("rules", [])))
            except Exception as e:
                logging.warning("Failed applying segmentation: %s", e)
        else:
            # Attempt preview injection if present
            logging.info("Segmentation disabled or unspecified; skipping")
    except Exception as e:
        logging.warning("Segmentation parse/apply error: %s", e)

    # Parse traffic and generate scripts for non-router hosts
    logging.info("PHASE: Traffic")
    traffic_density, traffic_items = parse_traffic_info(args.xml, args.scenario)
    logging.info(
        "Traffic config: density=%.3f, items=%d",
        float(traffic_density or 0.0),
        len(traffic_items or []),
    )
    traffic_out_dir = "/tmp/traffic"
    traffic_map = {}
    if traffic_density and traffic_density > 0:
        try:
            # apply CLI overrides, if provided
            if traffic_items:
                for i in range(len(traffic_items)):
                    ti = traffic_items[i]
                    if args.traffic_pattern:
                        ti.pattern = args.traffic_pattern
                    if args.traffic_rate is not None:
                        ti.rate_kbps = max(0.0, float(args.traffic_rate))
                    if args.traffic_period is not None:
                        ti.period_s = max(0.0, float(args.traffic_period)) if float(args.traffic_period) > 0 else 10.0
                    if args.traffic_jitter is not None:
                        ti.jitter_pct = max(0.0, min(100.0, float(args.traffic_jitter)))
                    if args.traffic_content:
                        ti.content_type = args.traffic_content
            traffic_map = generate_traffic_scripts(hosts, traffic_density, traffic_items, out_dir=traffic_out_dir)
            if not traffic_map:
                logging.info("No hosts selected for traffic after generation (density too low or no eligible hosts)")
            # Enable 'Traffic' service on all nodes that have traffic (additive)
            for node_id in traffic_map.keys():
                logging.info("Enabling Traffic service on node %s", node_id)
                ok = False
                try:
                    # try with node_obj if available for broader compatibility
                    node_obj = None
                    try:
                        if hasattr(session, "get_node"):
                            node_obj = session.get_node(node_id)
                    except Exception:
                        node_obj = None
                    ok = ensure_service(session, node_id, "Traffic", node_obj=node_obj)
                except Exception as e:
                    logging.warning("Error enabling Traffic service on node %s: %s", node_id, e)
                if ok:
                    logging.info("Traffic service enabled on node %s", node_id)
                else:
                    logging.warning("Unable to add 'Traffic' service on node %s (service may not be installed in CORE)", node_id)
            # Ensure firewall allows the generated traffic
            try:
                from .utils.segmentation import write_allow_rules_for_flows, write_dnat_for_flows
                write_allow_rules_for_flows(
                    session,
                    routers if 'routers' in locals() else [],
                    hosts,
                    os.path.join(traffic_out_dir, "traffic_summary.json"),
                    out_dir="/tmp/segmentation",
                    src_subnet_prob=max(0.0, min(1.0, float(getattr(args, 'allow_src_subnet_prob', 0.3)))),
                    dst_subnet_prob=max(0.0, min(1.0, float(getattr(args, 'allow_dst_subnet_prob', 0.3)))),
                    include_hosts=bool(getattr(args, 'seg_include_hosts', False)),
                )
                logging.info("Inserted allow rules for generated traffic")
                # Flow verification artifact
                try:
                    from .utils.segmentation import verify_flows_allowed
                    verification = verify_flows_allowed(
                        os.path.join(traffic_out_dir, "traffic_summary.json"),
                        segmentation_summary_path="/tmp/segmentation/segmentation_summary.json",
                        out_path="/tmp/segmentation/allow_verification.json",
                    )
                    if verification.get('blocked_count'):
                        logging.warning("Flow verification: %d blocked flows remain", verification.get('blocked_count'))
                    else:
                        logging.info("Flow verification: all %d flows allowed", verification.get('flows_total', 0))
                except Exception as e_vf:
                    logging.warning("Flow verification failed: %s", e_vf)
                # Optional DNAT port-forwarding
                dnat_p = max(0.0, min(1.0, float(getattr(args, 'dnat_prob', 0.0))))
                if dnat_p > 0:
                    write_dnat_for_flows(
                        session,
                        routers if 'routers' in locals() else [],
                        hosts,
                        os.path.join(traffic_out_dir, "traffic_summary.json"),
                        out_dir="/tmp/segmentation",
                        dnat_prob=dnat_p,
                    )
                    logging.info("Inserted DNAT rules for some flows (prob=%.2f)", dnat_p)
            except Exception as e:
                logging.warning("Failed to insert allow rules for traffic: %s", e)

            # Summarize traffic scripts (receivers/senders)
            total_r = 0
            total_s = 0
            nodes_with_r = 0
            nodes_with_s = 0
            for nid, paths in traffic_map.items():
                r = s = 0
                for p in paths:
                    b = os.path.basename(p)
                    stem = b.rsplit(".", 1)[0]
                    suffix = stem.split("_")[-1]
                    if suffix.startswith("r"):
                        r += 1
                    elif suffix.startswith("s"):
                        s += 1
                total_r += r
                total_s += s
                if r:
                    nodes_with_r += 1
                if s:
                    nodes_with_s += 1
                logging.debug("Node %s traffic scripts: receivers=%d, senders=%d", nid, r, s)
            logging.info(
                "Traffic scripts written to /tmp/traffic (receivers=%d on %d nodes; senders=%d on %d nodes; up to %.0f%% of hosts)",
                total_r,
                nodes_with_r,
                total_s,
                nodes_with_s,
                traffic_density * 100,
            )
        except Exception as e:
            # Log full traceback for diagnostics and attempt a safe fallback
            logging.exception("Failed generating traffic scripts: %s", e)
            try:
                # Map unknown kinds to TCP to avoid legacy KeyErrors; keep TCP/UDP/RANDOM/CUSTOM as-is
                safe_items = []
                for ti in (traffic_items or []):
                    kind_u = (ti.kind or "").upper()
                    if kind_u not in ("TCP", "UDP", "RANDOM", "CUSTOM"):
                        kind_u = "TCP"
                    # create a shallow clone with adjusted kind
                    from .types import TrafficInfo as _TI
                    safe_items.append(_TI(
                        kind=kind_u,
                        factor=ti.factor,
                        pattern=ti.pattern,
                        rate_kbps=ti.rate_kbps,
                        period_s=ti.period_s,
                        jitter_pct=ti.jitter_pct,
                        content_type=ti.content_type,
                    ))
                traffic_map = generate_traffic_scripts(hosts, traffic_density, safe_items, out_dir=traffic_out_dir)
                logging.warning("Traffic generation succeeded after fallback to safe kinds (unknown kinds -> TCP)")
            except Exception as e2:
                logging.warning("Fallback traffic generation also failed: %s", e2)
    else:
        logging.info("Traffic disabled or density is 0; skipping traffic generation and service enablement")

    # Write scenario report (Markdown) under ./reports/
    try:
        import time as _time
        from datetime import datetime as _dt
        # Always write reports under the repository root's ./reports directory
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        report_dir = os.path.join(repo_root, "reports")
        os.makedirs(report_dir, exist_ok=True)
        traffic_summary_path = os.path.join(traffic_out_dir, "traffic_summary.json")
        # Use a high-resolution timestamp to avoid same-second filename collisions across runs
        _ts = _dt.now().strftime("%m-%d-%y-%H-%M-%S-%f")
        report_path = os.path.join(report_dir, f"scenario_report_{_ts}.md")
        routing_cfg = {
            "density": routing_density,
            "items": [{"protocol": i.protocol, "factor": i.factor} for i in (routing_items or [])],
        }
        traffic_cfg = {
            "density": traffic_density,
            "items": [{
                "kind": i.kind,
                "factor": i.factor,
                "pattern": i.pattern,
                "rate_kbps": i.rate_kbps,
                "period_s": i.period_s,
                "jitter_pct": i.jitter_pct,
                "content_type": i.content_type,
            } for i in (traffic_items or [])],
        }
        services_cfg = [{"name": s.name, "factor": s.factor, "density": s.density} for s in (services or [])]
        # Vulnerabilities (load catalog locally to avoid dependency on earlier planning block)
        logging.info("PHASE: Vulnerabilities")
        try:
            vuln_density = orchestrated_plan.get('breakdowns', {}).get('vulnerabilities', {}).get('density_input')
        except Exception:
            vuln_density = None
        vuln_items = orchestrated_plan.get('vulnerability_items_raw')
        if vuln_density is None or vuln_items is None:
            vuln_density_fallback, vuln_items_fallback, _vuln_flag_type_fb = parse_vulnerabilities_info(args.xml, args.scenario)
            if vuln_density is None:
                vuln_density = vuln_density_fallback
            if vuln_items is None:
                vuln_items = vuln_items_fallback
        vulnerabilities_cfg = {"density": vuln_density, "items": vuln_items or [], "flag_type": vuln_flag_type}
        try:
            _repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            catalog_local = load_vuln_catalog(_repo_root)
            selected_vulns = select_vulnerabilities(vuln_density or 0.0, vuln_items or [], catalog_local)
            if selected_vulns:
                logging.info("Selected %d vulnerabilities based on criteria", len(selected_vulns))
                results = process_vulnerabilities(selected_vulns, out_dir="/tmp/vulns")
                ok_count = sum(1 for _rec, _act, ok, _dir in results if ok)
                logging.info("Vulnerability processing done: %d/%d ok", ok_count, len(results))
                # Prepare per-node docker-compose files matching docker nodes created (by name)
                try:
                    # Collect mapping name->rec of docker nodes actually created by builders
                    name_to_vuln = {}
                    try:
                        # Prefer function returns when available via locals
                        if 'docker_by_name' in locals() and isinstance(docker_by_name, dict):
                            name_to_vuln.update(docker_by_name)
                    except Exception:
                        pass
                    # Fallback: reconstruct from slot plan and current session nodes order if needed
                    if not name_to_vuln and docker_slot_plan:
                        try:
                            # Iterate session nodes in creation order if possible
                            # Note: this is best-effort and may not exactly match slot numbering
                            idx = 0
                            for ni in hosts:
                                try:
                                    node_obj = session.get_node(ni.node_id)
                                    nm = getattr(node_obj, 'name', None)
                                except Exception:
                                    nm = None
                                if nm:
                                    slot_key = f"slot-{idx+1}"
                                    if slot_key in docker_slot_plan:
                                        name_to_vuln[nm] = docker_slot_plan[slot_key]
                                    idx += 1
                        except Exception:
                            pass
                    if name_to_vuln:
                        prepared_name_to_vuln = {}
                        for _node_name, _rec in name_to_vuln.items():
                            try:
                                rec_copy = dict(_rec or {})
                            except Exception:
                                rec_copy = {}
                            rec_copy['CoreTGVulnAssignment'] = '1'
                            if vuln_flag_type:
                                rec_copy['FlagType'] = str(vuln_flag_type)
                            prepared_name_to_vuln[_node_name] = rec_copy

                        created = prepare_compose_for_assignments(prepared_name_to_vuln, out_base="/tmp/vulns")
                        logging.info("Prepared per-node compose files: %d for %d docker nodes", len(created), len(name_to_vuln))
                        # Do not start compose stacks here; CORE will start docker nodes during session start
                        # This avoids container name conflicts when CORE brings up containers automatically.
                        # Write a small summary for web/ops
                        try:
                            _write_compose_assignments_summary(
                                prepared_name_to_vuln,
                                created,
                                out_base='/tmp/vulns',
                            )
                            logging.info("Compose assignments prepared for %d docker nodes; startup deferred to CORE session", len(created))
                        except Exception:
                            pass

                        # Ensure CORE docker nodes point at the per-node sanitized compose output.
                        # Without this, a node may still reference a downloaded compose (which can
                        # contain `${...}` and trigger Mako NameError in core-daemon).
                        try:
                            for ni in (hosts or []):
                                try:
                                    node_obj = session.get_node(ni.node_id)
                                    nm = getattr(node_obj, 'name', None)
                                except Exception:
                                    nm = None
                                if nm and nm in name_to_vuln:
                                    try:
                                        _apply_docker_compose_meta(node_obj, prepared_name_to_vuln[nm], session=session)
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                    else:
                        logging.info("No docker nodes present after build; skipping compose prep")
                except Exception as e2:
                    logging.debug("Per-node compose prepare/assign skipped or failed: %s", e2)
            else:
                logging.info("No vulnerabilities selected (empty catalog or criteria)")
        except Exception as e:
            logging.warning("Vulnerability processing failed: %s", e)

        # Also prepare compose files for explicitly-added Docker role nodes (standard template).
        # These nodes are not tied to vulnerability selection and should still get the same docker-compose
        # sanitation + iproute2/ethtool wrapper workflow.
        try:
            repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            standard_compose = os.path.join(repo_root, 'scripts', 'standard-ubuntu-docker-core', 'docker-compose.yml')
            standard_compose = os.path.abspath(standard_compose)
            standard_nodes = {}
            try:
                if 'docker_by_name' in locals() and isinstance(docker_by_name, dict):
                    for nm, rec in docker_by_name.items():
                        if not isinstance(rec, dict):
                            continue
                        if (rec.get('Type') or '').strip().lower() != 'docker-compose':
                            continue
                        path_val = os.path.abspath(str(rec.get('Path') or '')) if rec.get('Path') else ''
                        name_val = str(rec.get('Name') or '')
                        if name_val == 'standard-ubuntu-docker-core' or (path_val and path_val == standard_compose):
                            standard_nodes[nm] = rec
            except Exception:
                standard_nodes = {}

            def _load_enabled_flag_node_generators(repo_root_path: str) -> list[dict]:
                """Load enabled flag-node-generators from YAML manifests.

                Best-effort behavior:
                  - discovers manifests in repo + outputs/installed_generators
                  - filters out disabled installed generators when _packs_state.json is present
                """
                try:
                    from scenarioforge.generator_manifests import discover_generator_manifests

                    gens, _plugins_by_id, errs = discover_generator_manifests(repo_root=repo_root_path, kind='flag-node-generator')
                    try:
                        if errs:
                            logging.debug("flag-node-generator manifest warnings: %d", len(errs))
                    except Exception:
                        pass

                    # Load disable map from installed generator packs state.
                    disabled: dict[tuple[str, str], bool] = {}
                    try:
                        installed_root = str(os.environ.get('CORETG_INSTALLED_GENERATORS_DIR') or '').strip()
                        if installed_root:
                            installed_root = os.path.abspath(os.path.expanduser(installed_root))
                        else:
                            installed_root = os.path.abspath(os.path.join(repo_root_path, 'outputs', 'installed_generators'))
                        state_path = os.path.join(installed_root, '_packs_state.json')
                        if os.path.exists(state_path):
                            with open(state_path, 'r', encoding='utf-8') as fh:
                                st = json.load(fh) or {}
                            packs = st.get('packs') if isinstance(st, dict) else None
                            if not isinstance(packs, list):
                                packs = []
                            for p in packs:
                                if not isinstance(p, dict):
                                    continue
                                pack_disabled = bool(p.get('disabled') is True)
                                for it in (p.get('installed') or []):
                                    if not isinstance(it, dict):
                                        continue
                                    gid = str(it.get('id') or '').strip()
                                    kind = str(it.get('kind') or '').strip()
                                    if not gid or not kind:
                                        continue
                                    item_disabled = bool(it.get('disabled') is True)
                                    disabled[(kind, gid)] = bool(pack_disabled or item_disabled)
                    except Exception:
                        disabled = {}

                    # Filter out disabled installed generators; keep non-installed generators.
                    out: list[dict] = []
                    for g in (gens or []):
                        if not isinstance(g, dict):
                            continue
                        gid = str(g.get('id') or '').strip()
                        if not gid:
                            continue
                        # Best-effort installed check: manifest path under installed_root.
                        is_installed = False
                        try:
                            mp = str(g.get('_source_path') or '').strip()
                            if mp and 'installed_root' in locals():
                                is_installed = os.path.commonpath([os.path.abspath(installed_root), os.path.abspath(mp)]) == os.path.abspath(installed_root)
                        except Exception:
                            is_installed = False
                        if is_installed and disabled.get(('flag-node-generator', gid)):
                            continue
                        out.append(g)
                    return out
                except Exception:
                    return []

            def _run_flag_node_generator(generator_id: str, *, out_dir: str, config: dict) -> tuple[bool, str]:
                """Best-effort run of scripts/run_flag_generator.py for flag-node-generators (manifest-based)."""
                try:
                    runner_path = os.path.join(repo_root, 'scripts', 'run_flag_generator.py')
                    if not os.path.exists(runner_path):
                        return False, 'runner script not found'
                    try:
                        docker_ok = bool(shutil.which('docker'))
                    except Exception:
                        docker_ok = False
                    if not docker_ok:
                        for cand in ('/usr/bin/docker', '/usr/local/bin/docker', '/bin/docker', '/snap/bin/docker'):
                            try:
                                if os.path.exists(cand) and os.access(cand, os.X_OK):
                                    docker_ok = True
                                    break
                            except Exception:
                                continue
                    if not docker_ok:
                        return False, 'docker not found'
                    cmd = [
                        sys.executable or 'python',
                        runner_path,
                        '--kind',
                        'flag-node-generator',
                        '--generator-id',
                        generator_id,
                        '--out-dir',
                        out_dir,
                        '--config',
                        json.dumps(config, ensure_ascii=False),
                        '--repo-root',
                        repo_root,
                    ]
                    p = subprocess.run(
                        cmd,
                        cwd=repo_root,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if p.returncode != 0:
                        err = (p.stderr or p.stdout or '').strip()
                        if err:
                            err = err[-800:]
                        return False, f'generator failed (rc={p.returncode}): {err}'
                    return True, 'ok'
                except subprocess.TimeoutExpired:
                    return False, 'generator timed out'
                except Exception as exc:
                    try:
                        import traceback
                        tb = traceback.format_exc(limit=6)
                        return False, f'generator exception: {exc}; traceback={tb[-1200:]}'
                    except Exception:
                        return False, f'generator exception: {exc}'

            if standard_nodes:
                # Optional: auto-run flag-node-generators for explicit Docker role nodes.
                # Default OFF because it overrides per-node plan intent (e.g., Flow chains where only
                # a single node should get a node-generator compose).
                try:
                    auto_nodegen = str(os.getenv('CORETG_CLI_AUTO_FLAG_NODEGEN', '0') or '0').strip().lower() in ('1', 'true', 'yes', 'y', 'on')
                except Exception:
                    auto_nodegen = False

                if auto_nodegen:
                    # If any flag-node-generators are enabled, use them to generate per-node docker-compose
                    # for the explicit Docker role nodes (these are DOCKER-type nodes, not vulnerability nodes).
                    node_gens = _load_enabled_flag_node_generators(repo_root)
                    usable = [g for g in (node_gens or []) if isinstance(g.get('compose'), dict)]

                    if usable:
                        # Round-robin generator assignment across standard docker nodes.
                        usable.sort(key=lambda g: str(g.get('id') or ''))
                        try:
                            base_seed = int(getattr(args, 'seed', 0) or 0)
                        except Exception:
                            base_seed = 0
                        scenario_tag = str(os.getenv('CORETG_SCENARIO_TAG') or '').strip()
                        if not scenario_tag:
                            scenario_tag = str(getattr(args, 'scenario', '') or 'scenario').strip() or 'scenario'
                        scenario_tag = ''.join([c for c in scenario_tag if c.isalnum() or c in ('-', '_')])[:40] or 'scenario'

                        updated = {}
                        for idx, (nm, _rec) in enumerate(sorted(standard_nodes.items(), key=lambda x: str(x[0]))):
                            gen = usable[idx % max(1, len(usable))]
                            gen_id = str(gen.get('id') or '').strip()
                            if not gen_id:
                                continue
                            out_dir = os.path.join('/tmp/vulns', 'flag_node_generators_runs', f"cli-{scenario_tag}-{nm}")
                            try:
                                if os.path.exists(out_dir):
                                    import shutil
                                    shutil.rmtree(out_dir)
                                os.makedirs(out_dir, exist_ok=True)
                            except Exception:
                                pass
                            cfg = {
                                'seed': f"{base_seed}:{scenario_tag}:{nm}:{gen_id}",
                                'node_name': nm,
                            }
                            ok_run, note = _run_flag_node_generator(gen_id, out_dir=out_dir, config=cfg)
                            compose_src = os.path.join(out_dir, 'docker-compose.yml')
                            if ok_run and os.path.exists(compose_src):
                                updated[nm] = {
                                    'Type': 'docker-compose',
                                    'Name': str(gen.get('name') or gen_id),
                                    'Path': compose_src,
                                    'Vector': 'flag-nodegen',
                                    'ScenarioTag': scenario_tag,
                                }
                            else:
                                logging.warning("Flag-node-generator failed for node=%s gen=%s: %s", nm, gen_id, note)

                        if updated:
                            # Replace the standard compose records for those nodes so compose prep uses the generated templates.
                            for nm, rec in updated.items():
                                standard_nodes[nm] = rec
                                try:
                                    if 'docker_by_name' in locals() and isinstance(docker_by_name, dict):
                                        docker_by_name[nm] = rec
                                except Exception:
                                    pass
                else:
                    logging.info('Auto flag-node-generator assignment disabled (set CORETG_CLI_AUTO_FLAG_NODEGEN=1 to enable)')

                # Ensure ScenarioTag is present so wrapper images are scoped.
                try:
                    for _nm, _rec in (standard_nodes or {}).items():
                        if isinstance(_rec, dict):
                            _rec.setdefault('ScenarioTag', scenario_tag)
                except Exception:
                    pass
                created = prepare_compose_for_assignments(standard_nodes, out_base="/tmp/vulns")
                logging.info("Prepared docker compose files for explicit Docker role nodes: %d for %d docker nodes", len(created), len(standard_nodes))

                # Best-effort: update compose_name on CORE nodes to reflect the record name.
                try:
                    for ni in (hosts or []):
                        try:
                            node_obj = session.get_node(ni.node_id)
                            nm = getattr(node_obj, 'name', None)
                        except Exception:
                            nm = None
                        if nm and nm in standard_nodes:
                            try:
                                _apply_docker_compose_meta(node_obj, standard_nodes[nm], session=session)
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception as e2:
            logging.debug("Standard docker compose prepare skipped or failed: %s", e2)

        # Finally, ensure docker-compose prep runs for any remaining docker nodes (e.g., Flow-injected flag packages).
        # This is safe to run even if some nodes were already prepared earlier.
        try:
            all_docker_nodes = {}
            if 'docker_by_name' in locals() and isinstance(docker_by_name, dict):
                for nm, rec in docker_by_name.items():
                    if not isinstance(rec, dict):
                        continue
                    if (rec.get('Type') or '').strip().lower() != 'docker-compose':
                        continue
                    all_docker_nodes[nm] = rec
            if all_docker_nodes:
                segmentation_active = os.path.exists('/tmp/segmentation/segmentation_summary.json')
                # Ensure ScenarioTag is present so wrapper images are scoped.
                try:
                    _scenario_tag = str(os.getenv('CORETG_SCENARIO_TAG') or '').strip()
                    if not _scenario_tag:
                        _scenario_tag = str(getattr(args, 'scenario', '') or 'scenario').strip() or 'scenario'
                    _scenario_tag = ''.join([c for c in _scenario_tag if c.isalnum() or c in ('-', '_')])[:40] or 'scenario'
                    for _nm, _rec in all_docker_nodes.items():
                        if isinstance(_rec, dict):
                            _rec.setdefault('ScenarioTag', _scenario_tag)
                            if segmentation_active:
                                _rec.setdefault('EnableSegmentationMount', 'true')
                except Exception:
                    pass
                created = prepare_compose_for_assignments(all_docker_nodes, out_base="/tmp/vulns")
                logging.info("Prepared docker compose files (all docker nodes): %d for %d docker nodes", len(created), len(all_docker_nodes))
                try:
                    _write_compose_assignments_summary(
                        all_docker_nodes,
                        created,
                        out_base='/tmp/vulns',
                    )
                    logging.info(
                        "Compose assignments summary written for %d docker nodes",
                        len(all_docker_nodes),
                    )
                except Exception as e_summary:
                    logging.warning("Failed writing compose assignments summary: %s", e_summary)

                if segmentation_active:
                    try:
                        from .utils.segmentation import write_allow_rules_for_compose_ports

                        compose_allow = write_allow_rules_for_compose_ports(
                            session,
                            routers if 'routers' in locals() else [],
                            hosts,
                            all_docker_nodes,
                            out_dir="/tmp/segmentation",
                        )
                        compose_allow_count = len(compose_allow.get('rules', []) if isinstance(compose_allow, dict) else [])
                        generation_meta['compose_port_allow_rules'] = compose_allow_count
                        logging.info("Inserted compose port allow rules for docker service ports: %d", compose_allow_count)
                    except Exception as e_allow:
                        logging.warning("Failed to insert compose port allow rules: %s", e_allow)

                # Sanity logging: show final per-node compose inputs and output file.
                # Keep detail at DEBUG to avoid noisy logs by default.
                try:
                    for nm, rec in sorted(all_docker_nodes.items(), key=lambda x: str(x[0])):
                        out_path = _docker_node_compose_path(nm)
                        logging.debug(
                            "Docker node compose assignment node=%s Name=%s Path=%s Vector=%s out=%s exists=%s",
                            nm,
                            rec.get('Name'),
                            rec.get('Path'),
                            rec.get('Vector'),
                            out_path,
                            os.path.exists(out_path),
                        )
                except Exception:
                    pass
        except Exception as e2:
            logging.debug("All docker compose prepare skipped or failed: %s", e2)
        seg_out_dir = "/tmp/segmentation"
        seg_summary_path = os.path.join(seg_out_dir, "segmentation_summary.json")
        segmentation_cfg = {
            "density": seg_density if 'seg_density' in locals() else None,
            "items": [{"name": i.name, "factor": i.factor} for i in (seg_items or [])] if 'seg_items' in locals() and seg_items else [],
        }
        pivoting_cfg = {
            "density": pivot_density if 'pivot_density' in locals() else None,
            "items": [
                {
                    "name": getattr(item, 'name', ''),
                    "factor": getattr(item, 'factor', 0.0),
                    "pivot_node": getattr(item, 'pivot_node', ''),
                    "pivot_role": getattr(item, 'pivot_role', ''),
                    "target_node": getattr(item, 'target_node', ''),
                    "target_role": getattr(item, 'target_role', ''),
                    "target_ports": getattr(item, 'target_ports', ''),
                    "target_protocols": getattr(item, 'target_protocols', ''),
                    "exposure": getattr(item, 'exposure', ''),
                    "source_scope": getattr(item, 'source_scope', ''),
                    "access_provider": getattr(item, 'access_provider', ''),
                }
                for item in (pivot_items or [])
            ] if 'pivot_items' in locals() and pivot_items else [],
        }
        logging.info("PHASE: Report")
        if routing_density and routing_density > 0:
            # Inject XML/source classification metadata if available
            try:
                xml_path_meta = os.path.abspath(args.xml)
                generation_meta.setdefault('xml_path', xml_path_meta)
                # classification flags may have been computed upstream; if not, attempt lightweight detection
                if 'xml_schema_classification' not in generation_meta:
                    try:
                        import xml.etree.ElementTree as _ET
                        rt = _ET.parse(xml_path_meta).getroot()
                        tagl = rt.tag.lower()
                        if 'scenarios' in tagl:
                            generation_meta['xml_schema_classification'] = 'scenario'
                        elif 'session' in tagl:
                            generation_meta['xml_schema_classification'] = 'session'
                        else:
                            generation_meta['xml_schema_classification'] = 'unknown'
                        if rt.find('.//container') is not None:
                            generation_meta['xml_container_flag'] = True
                    except Exception:
                        pass
            except Exception:
                pass
            report_path, summary_path = write_report(
                report_path,
                scenario_name,
                routers=routers,
                router_protocols=router_protocols,
                switches=[],
                hosts=hosts,
                service_assignments=service_assignments,
                traffic_summary_path=traffic_summary_path if os.path.exists(traffic_summary_path) else None,
                segmentation_summary_path=seg_summary_path if os.path.exists(seg_summary_path) else None,
                metadata=generation_meta,
                routing_cfg=routing_cfg,
                traffic_cfg=traffic_cfg,
                services_cfg=services_cfg,
                segmentation_cfg=segmentation_cfg,
                vulnerabilities_cfg=vulnerabilities_cfg,
                pivoting_cfg=pivoting_cfg if 'pivoting_cfg' in locals() else None,
            )
        else:
            try:
                xml_path_meta = os.path.abspath(args.xml)
                generation_meta.setdefault('xml_path', xml_path_meta)
                if 'xml_schema_classification' not in generation_meta:
                    try:
                        import xml.etree.ElementTree as _ET
                        rt = _ET.parse(xml_path_meta).getroot()
                        tagl = rt.tag.lower()
                        if 'scenarios' in tagl:
                            generation_meta['xml_schema_classification'] = 'scenario'
                        elif 'session' in tagl:
                            generation_meta['xml_schema_classification'] = 'session'
                        else:
                            generation_meta['xml_schema_classification'] = 'unknown'
                        if rt.find('.//container') is not None:
                            generation_meta['xml_container_flag'] = True
                    except Exception:
                        pass
            except Exception:
                pass
            report_path, summary_path = write_report(
                report_path,
                scenario_name,
                routers=[],
                router_protocols={},
                switches=switches,
                hosts=hosts,
                service_assignments=service_assignments,
                traffic_summary_path=traffic_summary_path if os.path.exists(traffic_summary_path) else None,
                segmentation_summary_path=seg_summary_path if os.path.exists(seg_summary_path) else None,
                metadata=generation_meta,
                routing_cfg=routing_cfg,
                traffic_cfg=traffic_cfg,
                services_cfg=services_cfg,
                segmentation_cfg=segmentation_cfg,
                vulnerabilities_cfg=vulnerabilities_cfg,
                pivoting_cfg=pivoting_cfg if 'pivoting_cfg' in locals() else None,
            )
        logging.info("Scenario report written to %s", report_path)
        # Also emit a plain stdout line for robust parsing by web frontends
        try:
            print(f"Scenario report written to {report_path}", flush=True)
        except Exception:
            pass
        if summary_path:
            logging.info("Scenario summary written to %s", summary_path)
            try:
                print(f"Scenario summary written to {summary_path}", flush=True)
            except Exception:
                pass
    except Exception as e:
        logging.exception("Failed to write scenario report: %s", e)

    # Start the CORE session only after all services (including Traffic) are applied.
    start_ok = True
    session_id: int | None = None
    session_state = ''
    docker_runtime: dict[str, Any] | None = None
    start_error: str | None = None
    core_daemon_journal_started_at: float | None = None
    core_daemon_journal_tail: str | None = None
    core_daemon_boot_error: str | None = None
    core_daemon_runtime_hint: str | None = None

    # Timeouts: allow overrides for slow CORE startups / slow docker pulls.
    try:
        core_start_timeout_s = float(
            args.start_timeout_s
            if getattr(args, 'start_timeout_s', None) is not None
            else (os.getenv('CORETG_CORE_START_TIMEOUT_S') or 120.0)
        )
    except Exception:
        core_start_timeout_s = 120.0
    try:
        docker_wait_s = float(
            args.docker_wait_s
            if getattr(args, 'docker_wait_s', None) is not None
            else (os.getenv('CORETG_DOCKER_WAIT_RUNNING_S') or 45.0)
        )
    except Exception:
        docker_wait_s = 45.0
    core_start_timeout_s = max(5.0, min(core_start_timeout_s, 600.0))
    docker_wait_s = max(5.0, min(docker_wait_s, 600.0))
    try:
        logging.info("PHASE: Start CORE session")
        # Preflight: check for conflicting Docker containers/images for any compose-based Docker nodes.
        # This prevents hard-to-debug failures when CORE attempts to start docker-compose nodes.
        try:
            if getattr(args, 'docker_check_conflicts', True):
                docker_names = []
                try:
                    if 'docker_by_name' in locals() and isinstance(docker_by_name, dict):
                        for nm, rec in docker_by_name.items():
                            if not isinstance(rec, dict):
                                continue
                            if (rec.get('Type') or '').strip().lower() != 'docker-compose':
                                continue
                            docker_names.append(str(nm))
                except Exception:
                    docker_names = []
                docker_names = sorted(set([n for n in docker_names if n]))
                if docker_names:
                    compose_paths = [_docker_node_compose_path(nm) for nm in docker_names]
                    compose_paths = [p for p in compose_paths if p and os.path.exists(p)]
                    # Detect conflicts from compose files (if present) AND from existing containers
                    # that match the docker node names themselves (CORE uses node name as container name).
                    conflicts: Dict[str, Any] = {'containers': [], 'images': []}
                    if compose_paths:
                        try:
                            conflicts = detect_docker_conflicts_for_compose_files(compose_paths)
                        except Exception:
                            conflicts = {'containers': [], 'images': []}
                    try:
                        if shutil.which('docker'):
                            existing_named: list[str] = []
                            for nm in docker_names:
                                try:
                                    p2 = subprocess.run(
                                        ['docker', 'container', 'inspect', str(nm)],
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL,
                                    )
                                    if p2.returncode == 0:
                                        existing_named.append(str(nm))
                                except Exception:
                                    continue
                            if existing_named:
                                cur = conflicts.get('containers') if isinstance(conflicts, dict) else []
                                if not isinstance(cur, list):
                                    cur = []
                                conflicts['containers'] = list(dict.fromkeys([*cur, *existing_named]))
                    except Exception:
                        pass

                    # Also include any generic CORE-style host containers (hN) currently present
                    try:
                        import re as _re
                        import subprocess as _sp
                        if shutil.which('docker'):
                            p = _sp.run(['docker', 'ps', '-a', '--format', '{{.Names}}'], stdout=_sp.PIPE, stderr=_sp.DEVNULL, text=True)
                            if p.returncode == 0:
                                names = [ln.strip() for ln in (p.stdout or '').splitlines() if ln.strip()]
                                pat = _re.compile(r'^(?i:h)\d+$')
                                generic = [n for n in names if pat.match(n)]
                                if generic:
                                    cur = conflicts.get('containers') if isinstance(conflicts, dict) else []
                                    if not isinstance(cur, list):
                                        cur = []
                                    conflicts['containers'] = list(dict.fromkeys([*cur, *generic]))
                    except Exception:
                        pass

                    c_cont = conflicts.get('containers') or []
                    c_imgs = conflicts.get('images') or []
                    if c_cont or c_imgs:
                        # Emit a machine-readable marker for web frontends to parse.
                        try:
                            print(f"DOCKER_CONFLICTS_JSON: {json.dumps({'containers': list(c_cont), 'images': list(c_imgs)})}", flush=True)
                        except Exception:
                            pass
                        logging.warning(
                            "Detected potential Docker conflicts: containers=%d images=%d",
                            len(c_cont),
                            len(c_imgs),
                        )
                        if getattr(args, 'docker_remove_conflicts', False):
                            rr = remove_docker_conflicts(conflicts)
                            logging.info(
                                "Removed Docker conflicts (best-effort): containers=%d images=%d",
                                len(rr.get('removed_containers') or []),
                                len(rr.get('removed_images') or []),
                            )
                        else:
                            import sys as _sys
                            if _sys.stdin.isatty():
                                try:
                                    print("\nDocker conflicts detected for compose-based Docker nodes:")
                                    if c_cont:
                                        print("- Existing containers:")
                                        for x in c_cont:
                                            print(f"  - {x}")
                                    if c_imgs:
                                        print("- Existing images:")
                                        for x in c_imgs:
                                            print(f"  - {x}")
                                    ans = input("Remove these now? [y/N] ").strip().lower()
                                except Exception:
                                    ans = ''
                                if ans in {'y', 'yes'}:
                                    rr = remove_docker_conflicts(conflicts)
                                    logging.info(
                                        "Removed Docker conflicts (best-effort): containers=%d images=%d",
                                        len(rr.get('removed_containers') or []),
                                        len(rr.get('removed_images') or []),
                                    )
                                else:
                                    start_ok = False
                                    start_error = 'Docker conflicts not removed'
                            else:
                                start_ok = False
                                start_error = (
                                    'Docker conflicts detected but cannot prompt (non-interactive). '
                                    'Rerun with --docker-remove-conflicts or clean up Docker resources.'
                                )
        except Exception as _dock_exc:
            logging.debug("Docker conflict preflight skipped/failed: %s", _dock_exc)

        session_id = _core_session_id(session)
        if session_id is not None:
            logging.info("CORE_SESSION_ID: %s", session_id)

        if start_ok:
            # CORE client expects the session object (uses session.to_proto()).
            core_daemon_journal_started_at = time.time()
            core.start_session(session)
            logging.info("CORE session start requested")

        docker_names2 = _docker_compose_node_names(docker_by_name)
        configuration_state_pending_docker_validation = False

        # Validate that CORE reaches runtime.
        if start_ok and session_id is not None:
            ok_runtime, st = _wait_for_core_runtime(core, int(session_id), timeout_s=core_start_timeout_s, poll_s=0.5)
            session_state = st
            if not ok_runtime:
                _st_text = str(st or 'unknown').strip().lower()
                if _is_configuration_state(_st_text) and docker_names2:
                    configuration_state_pending_docker_validation = True
                    logging.warning(
                        'CORE session stayed in configuration; deferring failure pending docker-compose runtime validation for nodes: %s',
                        ', '.join(docker_names2),
                    )
                elif _is_configuration_state(_st_text):
                    start_ok = False
                    start_error = 'CORE session stayed in "configuration"'
                else:
                    start_ok = False
                    start_error = f"CORE session did not reach runtime (state={st or 'unknown'})"

        # Validate docker-compose nodes are actually running (not merely created in config).
        if start_ok or configuration_state_pending_docker_validation:
            if docker_names2:
                docker_runtime = _wait_for_docker_running(docker_names2, timeout_s=docker_wait_s, poll_s=0.5)
                if docker_runtime.get('not_running'):
                    start_ok = False
                    configuration_state_pending_docker_validation = False
                    start_error = f"Docker node(s) not running: {', '.join(docker_runtime.get('not_running') or [])}"

            # Strict: ensure docker-compose nodes are running the intended compose service/image.
            # This prevents intermittent outcomes where CORE starts the default "sleep" container before we swap
            # in the generated compose metadata.
            if (start_ok or configuration_state_pending_docker_validation) and docker_names2:
                try:
                    mismatches: list[dict[str, Any]] = []
                    for nm in docker_names2:
                        # Generated per-node compose path (CORE host path).
                        compose_path = _docker_node_compose_path(nm)
                        expected = _expected_container_config_from_compose(compose_path, service=str(nm))
                        actual = _docker_container_config(nm)
                        if expected is None:
                            # If we can't read compose locally, don't block (best-effort).
                            continue
                        exp_img = str(expected.get('image') or '').strip()
                        act_img = str(actual.get('image') or '').strip()
                        if exp_img and act_img and exp_img != act_img:
                            mismatches.append({'name': nm, 'expected': expected, 'actual': actual})
                            continue
                        # If compose sets an explicit command/entrypoint, ensure it matches.
                        if 'command' in expected and expected.get('command') is not None:
                            if actual.get('cmd') is not None and expected.get('command') != actual.get('cmd'):
                                mismatches.append({'name': nm, 'expected': expected, 'actual': actual})
                                continue
                        if 'entrypoint' in expected and expected.get('entrypoint') is not None:
                            if actual.get('entrypoint') is not None and expected.get('entrypoint') != actual.get('entrypoint'):
                                mismatches.append({'name': nm, 'expected': expected, 'actual': actual})
                                continue
                    if mismatches:
                        # Best-effort recovery: re-run docker compose up for the affected services.
                        # This helps CORE versions that auto-start docker nodes during add_node()
                        # (and do not support start=False).
                        try:
                            val = os.getenv('CORETG_DOCKER_RESTART_ON_COMPOSE_MISMATCH')
                            restart_enabled = True if val is None else (str(val).strip().lower() not in ('0', 'false', 'no', 'off', ''))
                        except Exception:
                            restart_enabled = True

                        restart_results: list[dict[str, Any]] = []
                        if restart_enabled and shutil.which('docker'):
                            for m in mismatches:
                                nm = str(m.get('name') or '').strip()
                                if not nm:
                                    continue
                                compose_path = _docker_node_compose_path(nm)
                                rr = _docker_compose_restart_service(compose_path, nm, timeout_s=float(os.getenv('CORETG_DOCKER_RESTART_TIMEOUT_S') or 120))
                                rr['node'] = nm
                                restart_results.append(rr)
                                try:
                                    if rr.get('ok'):
                                        logging.info("Restarted docker compose node=%s via %s", nm, compose_path)
                                    else:
                                        logging.warning("Failed restarting docker compose node=%s via %s: %s", nm, compose_path, rr.get('error'))
                                except Exception:
                                    pass

                        # Re-check after restarts.
                        if restart_results and any(bool(r.get('ok')) for r in restart_results):
                            try:
                                time.sleep(1.0)
                            except Exception:
                                pass
                            fixed: list[dict[str, Any]] = []
                            still_bad: list[dict[str, Any]] = []
                            for m in mismatches:
                                nm = str(m.get('name') or '').strip()
                                if not nm:
                                    continue
                                compose_path = _docker_node_compose_path(nm)
                                expected2 = _expected_container_config_from_compose(compose_path, service=str(nm))
                                actual2 = _docker_container_config(nm)
                                if expected2 is None:
                                    # Can't validate, treat as fixed (best-effort).
                                    fixed.append({'name': nm, 'expected': None, 'actual': actual2})
                                    continue
                                exp_img2 = str(expected2.get('image') or '').strip()
                                act_img2 = str(actual2.get('image') or '').strip()
                                ok2 = True
                                if exp_img2 and act_img2 and exp_img2 != act_img2:
                                    ok2 = False
                                if ok2 and 'command' in expected2 and expected2.get('command') is not None:
                                    if actual2.get('cmd') is not None and expected2.get('command') != actual2.get('cmd'):
                                        ok2 = False
                                if ok2 and 'entrypoint' in expected2 and expected2.get('entrypoint') is not None:
                                    if actual2.get('entrypoint') is not None and expected2.get('entrypoint') != actual2.get('entrypoint'):
                                        ok2 = False
                                if ok2:
                                    fixed.append({'name': nm, 'expected': expected2, 'actual': actual2})
                                else:
                                    still_bad.append({'name': nm, 'expected': expected2, 'actual': actual2})

                            if still_bad:
                                # Persist diagnostics and fail.
                                start_ok = False
                                configuration_state_pending_docker_validation = False
                                generation_meta.setdefault('docker_nodes_config_mismatch', still_bad)  # type: ignore[arg-type]
                                generation_meta.setdefault('docker_nodes_restart_attempts', restart_results)  # type: ignore[arg-type]
                                bad = ', '.join([m.get('name') for m in still_bad if m.get('name')])
                                start_error = (
                                    'Docker node(s) running unexpected config (likely started before compose override was applied): '
                                    + bad
                                )
                            else:
                                # Recovery succeeded: keep going.
                                generation_meta.setdefault('docker_nodes_restart_attempts', restart_results)  # type: ignore[arg-type]
                                try:
                                    logging.info("Recovered docker-compose node config mismatch via restart: %s", ', '.join([f.get('name') for f in fixed if f.get('name')]))
                                except Exception:
                                    pass
                        else:
                            # No successful restarts: fail as before.
                            start_ok = False
                            configuration_state_pending_docker_validation = False
                            generation_meta.setdefault('docker_nodes_config_mismatch', mismatches)  # type: ignore[arg-type]
                            if restart_results:
                                generation_meta.setdefault('docker_nodes_restart_attempts', restart_results)  # type: ignore[arg-type]
                            bad = ', '.join([m.get('name') for m in mismatches if m.get('name')])
                            start_error = (
                                'Docker node(s) running unexpected config (likely started before compose override was applied): '
                                + bad
                            )
                except Exception:
                    pass

            if configuration_state_pending_docker_validation and start_ok:
                if _should_tolerate_configuration_state_for_docker(session_state, docker_names2, docker_runtime):
                    configuration_state_pending_docker_validation = False
                    start_error = None
                    try:
                        generation_meta.setdefault('warnings', [])
                        if isinstance(generation_meta.get('warnings'), list):
                            generation_meta['warnings'].append(
                                'CORE session remained in configuration, but docker-compose node runtime validation passed.'
                            )
                    except Exception:
                        pass
                    logging.warning(
                        'Accepting CORE session in configuration because docker-compose runtime validation passed for nodes: %s',
                        ', '.join(docker_names2),
                    )
                else:
                    start_ok = False
                    configuration_state_pending_docker_validation = False
                    start_error = 'CORE session stayed in "configuration"'

        # CORE can swallow per-node boot exceptions from its thread pool while the
        # session or Docker containers still appear to be running. Inspect only the
        # journal entries emitted after this start_session() request so CLI and WebUI
        # report the same daemon-side failure.
        if core_daemon_journal_started_at is not None:
            try:
                core_daemon_journal_tail = _tail_core_daemon_journal(
                    lines=300,
                    since_epoch=core_daemon_journal_started_at,
                )
                if core_daemon_journal_tail:
                    core_daemon_boot_error = _extract_core_daemon_boot_error(core_daemon_journal_tail)
                if core_daemon_boot_error:
                    start_ok = False
                    start_error = f"core-daemon node boot failure: {core_daemon_boot_error}"
                    logging.error("CORE daemon node boot failure: %s", core_daemon_boot_error)
                elif core_daemon_journal_tail and not start_ok:
                    core_daemon_runtime_hint = _extract_core_daemon_runtime_hint(
                        core_daemon_journal_tail
                    )
                    if core_daemon_runtime_hint:
                        logging.error(
                            "CORE daemon runtime hint: %s",
                            core_daemon_runtime_hint,
                        )
            except Exception:
                pass
    except Exception as e:
        start_ok = False
        start_error = f"{e.__class__.__name__}: {e}"
        logging.exception("Failed to start/validate CORE session: %s", e)

    # Record runtime status into the report metadata so the UI doesn't claim success when CORE stayed in config.
    try:
        if isinstance(generation_meta, dict):
            generation_meta.setdefault('errors', [])
            if (not start_ok) and start_error:
                try:
                    if isinstance(generation_meta.get('errors'), list):
                        generation_meta['errors'].append(str(start_error))
                except Exception:
                    pass
            generation_meta['core_session'] = {
                'id': session_id,
                'state': session_state,
                'runtime_ok': bool(_is_runtime_state(session_state)),
                'validation_ok': bool(start_ok),
                'validation_error': str(start_error) if ((not start_ok) and start_error) else None,
                'runtime_timeout_s': core_start_timeout_s,
            }
            if docker_runtime is not None:
                generation_meta['docker_nodes_runtime'] = docker_runtime
            generation_meta['docker_nodes_runtime_timeout_s'] = docker_wait_s
            if core_daemon_journal_tail:
                generation_meta['core_daemon_journal_tail'] = core_daemon_journal_tail
            if core_daemon_boot_error:
                generation_meta['core_daemon_runtime_hint'] = core_daemon_boot_error
            elif core_daemon_runtime_hint:
                generation_meta['core_daemon_runtime_hint'] = core_daemon_runtime_hint

            # Diagnostics: if runtime validation failed, include recent core-daemon logs when available.
            try:
                if (
                    (not core_daemon_journal_tail)
                    and (not start_ok)
                    and _should_collect_core_daemon_runtime_diag(start_error)
                ):
                    tail = _tail_core_daemon_journal(lines=200, since_seconds=int(core_start_timeout_s) + 60)
                    if tail:
                        generation_meta['core_daemon_journal_tail'] = tail
                        hint = _extract_core_daemon_runtime_hint(tail)
                        if hint:
                            generation_meta['core_daemon_runtime_hint'] = hint
                            core_daemon_runtime_hint = hint
                            logging.error("CORE daemon runtime hint: %s", hint)
            except Exception:
                pass
    except Exception:
        pass

    # Rewrite report+summary to include the post-start runtime validation data.
    try:
        if 'report_path' in locals() and report_path:
            _routers = routers if ('routers' in locals() and isinstance(routers, list)) else []
            _router_protocols = router_protocols if ('router_protocols' in locals() and isinstance(router_protocols, dict)) else {}
            _switches = [] if _routers else (switches if ('switches' in locals() and isinstance(switches, list)) else [])
            _hosts = hosts if ('hosts' in locals() and isinstance(hosts, list)) else []
            _service_assignments = service_assignments if ('service_assignments' in locals() and isinstance(service_assignments, dict)) else {}
            report_path, summary_path = write_report(
                report_path,
                scenario_name,
                routers=_routers,
                router_protocols=_router_protocols,
                switches=_switches,
                hosts=_hosts,
                service_assignments=_service_assignments,
                traffic_summary_path=traffic_summary_path if ('traffic_summary_path' in locals() and traffic_summary_path and os.path.exists(traffic_summary_path)) else None,
                segmentation_summary_path=seg_summary_path if ('seg_summary_path' in locals() and seg_summary_path and os.path.exists(seg_summary_path)) else None,
                metadata=generation_meta,
                routing_cfg=routing_cfg if 'routing_cfg' in locals() else None,
                traffic_cfg=traffic_cfg if 'traffic_cfg' in locals() else None,
                services_cfg=services_cfg if 'services_cfg' in locals() else None,
                segmentation_cfg=segmentation_cfg if 'segmentation_cfg' in locals() else None,
                vulnerabilities_cfg=vulnerabilities_cfg if 'vulnerabilities_cfg' in locals() else None,
                pivoting_cfg=pivoting_cfg if 'pivoting_cfg' in locals() else None,
            )
    except Exception:
        # Keep exit code semantics even if report rewrite fails.
        logging.exception("Failed to rewrite scenario report with runtime status")

    if not start_ok:
        if start_error:
            logging.error("Start validation failed: %s", start_error)
        if (
            args.phase == 'execute'
            and bool(getattr(args, 'post_execution_validation', False))
        ):
            details = []
            if core_daemon_runtime_hint:
                details.append(core_daemon_runtime_hint)
            elif core_daemon_boot_error:
                details.append(core_daemon_boot_error)
            _print_post_execution_validation_unavailable(
                start_error or 'CORE session start validation failed',
                session_id=session_id,
                details=details,
            )
        return 1

    logging.info("CORE session started and validated")
    configuration_tolerated = bool(
        start_ok
        and not _is_runtime_state(session_state)
        and _is_configuration_state(session_state)
    )
    print(
        'CORE_SESSION_VALIDATION_JSON: '
        + json.dumps(
            {
                'session_id': session_id,
                'state': session_state,
                'runtime_ok': bool(_is_runtime_state(session_state)),
                'validation_ok': True,
                'configuration_tolerated': configuration_tolerated,
            },
            sort_keys=True,
            separators=(',', ':'),
            default=str,
        ),
        flush=True,
    )
    if (
        args.phase == 'execute'
        and bool(getattr(args, 'post_execution_validation', False))
        and session_id is not None
    ):
        if backend_for_cli is None:
            _print_post_execution_validation_summary(
                {
                    'ok': False,
                    'error': 'WebUI validation backend is unavailable',
                    'validation_unavailable': True,
                    'session_id': int(session_id),
                }
            )
            return 1
        try:
            _scenario_norm, validation_core_cfg, _has_saved_core_source = _resolve_cli_core_context(
                args,
                backend=backend_for_cli,
                scenario_name=args.scenario,
            )
        except Exception as exc:
            _print_post_execution_validation_summary(
                {
                    'ok': False,
                    'error': f'failed resolving CORE validation connection: {exc}',
                    'validation_unavailable': True,
                    'session_id': int(session_id),
                }
            )
            return 1
        validation_ok = _run_cli_post_execution_validation(
            backend=backend_for_cli,
            args=args,
            core_cfg=validation_core_cfg,
            session_id=int(session_id),
        )
        if not validation_ok:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
