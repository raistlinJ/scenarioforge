"""Tracks scenarioforge.cli subprocesses so a run can be force-stopped on
demand (the dashboard's Stop button) and so residual ones left behind by a
previous exec-sim process — one that exited without cleaning up after
itself, e.g. killed rather than shut down cleanly — get caught too. An
in-memory registry alone wouldn't survive a process restart; PIDs are
persisted to a file next to the run's other artifacts so a fresh process can
still find and kill them.
"""

from __future__ import annotations

import json
import os
import signal
import time

_PID_FILE_NAME = ".scenarioforge_running_pids.json"


def _pid_file_path(output_dir: str) -> str:
    return os.path.join(output_dir, _PID_FILE_NAME)


def _read_entries(output_dir: str) -> list:
    try:
        with open(_pid_file_path(output_dir)) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _write_entries(output_dir: str, entries: list) -> None:
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(_pid_file_path(output_dir), "w") as f:
            json.dump(entries, f)
    except Exception:
        pass


def register_process(output_dir: str, proc, label: str = "") -> None:
    """Record a just-started subprocess. It must have been started with
    start_new_session=True (its own process-group leader), so the whole
    group — e.g. `uv run`'s own child, the actual scenarioforge.cli process —
    can be cleaned up together, not just the immediate child."""
    entries = _read_entries(output_dir)
    entries.append({"pid": proc.pid, "label": label, "started_at": time.time()})
    _write_entries(output_dir, entries)


def unregister_process(output_dir: str, proc) -> None:
    entries = [e for e in _read_entries(output_dir) if e.get("pid") != proc.pid]
    _write_entries(output_dir, entries)


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
    except Exception:
        return False


def _send_signal(pid: int, sig: int) -> None:
    # start_new_session=True has the child call setsid() itself, right
    # before it execs — from the parent's side, there's a narrow window
    # right after fork() where the child hasn't made that call yet, so
    # os.killpg(pid, ...) can target a process-group id that doesn't exist
    # yet and silently reach nobody. os.kill(pid, ...) (a direct PID signal,
    # not a group one) always resolves regardless of that timing, so send
    # both — a process already dead from the first just makes the second a
    # harmless no-op.
    for sender in (lambda: os.killpg(pid, sig), lambda: os.kill(pid, sig)):
        try:
            sender()
        except ProcessLookupError:
            pass
        except Exception:
            pass


def kill_process_group(pid: int) -> None:
    """Send SIGTERM to pid (and its process group), escalating to SIGKILL if
    it's still alive shortly after. Safe to call on an already-dead pid."""
    _send_signal(pid, signal.SIGTERM)
    deadline = time.monotonic() + 2.0
    while _is_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    if _is_alive(pid):
        _send_signal(pid, signal.SIGKILL)
        deadline = time.monotonic() + 1.0
        while _is_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.05)


def stop_all(output_dir: str) -> list[int]:
    """Kill every subprocess ever registered under output_dir and not yet
    cleaned up — including ones left running by a previous exec-sim process.
    Returns the PIDs it found alive and attempted to stop."""
    entries = _read_entries(output_dir)
    stopped = []
    for entry in entries:
        pid = entry.get("pid")
        if not isinstance(pid, int):
            continue
        if _is_alive(pid):
            kill_process_group(pid)
            stopped.append(pid)
    _write_entries(output_dir, [])
    return stopped
