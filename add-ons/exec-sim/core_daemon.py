"""Check whether CORE's gRPC daemon is reachable, and start it over SSH if not.

Mirrors the SSH probe/start commands ScenarioForge's own webapp uses
(`webapp/app_backend.py`: `_collect_remote_core_daemon_pids`,
`_start_remote_core_daemon`) so exec-sim's diagnosis matches what the CORE VM
actually expects, without depending on the webapp process being up.
"""

from __future__ import annotations

import socket
from typing import Any


def scrub_password_echo(text: str, password: str | None) -> str:
    """Strip a sudo password a PTY may have echoed back into captured output."""
    pw = str(password or "").strip()
    if not pw or not text:
        return text
    kept = [line for line in str(text).splitlines(keepends=True) if line.strip() != pw]
    return "".join(kept).replace(pw, "[REDACTED]")


def tcp_port_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def open_ssh_client(ssh_host: str, ssh_port: int, username: str, password: str) -> Any:
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=ssh_host,
        port=int(ssh_port),
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15.0,
        banner_timeout=15.0,
        auth_timeout=15.0,
    )
    return client


def collect_remote_core_daemon_pids(client: Any) -> list[int]:
    command = "sh -c 'timeout 5s pgrep -x core-daemon 2>/dev/null || true'"
    stdin, stdout, stderr = client.exec_command(command, timeout=8.0)
    out = stdout.read()
    stderr.read()
    stdin.close()
    exit_code = stdout.channel.recv_exit_status() if hasattr(stdout, "channel") else 0
    if exit_code not in (0, 1):
        return []
    text = out.decode("utf-8", "ignore") if isinstance(out, (bytes, bytearray)) else str(out or "")
    pids = []
    for token in text.strip().split():
        try:
            pids.append(int(token))
        except ValueError:
            continue
    return pids


def start_remote_core_daemon(client: Any, sudo_password: str | None) -> tuple[int, str, str]:
    if sudo_password:
        sudo_cmd = "sudo -S -p '' sh -c 'timeout 20s systemctl start core-daemon'"
    else:
        sudo_cmd = "sudo -n sh -c 'timeout 20s systemctl start core-daemon'"
    stdin, stdout, stderr = client.exec_command(sudo_cmd, timeout=25.0, get_pty=True)
    if sudo_password:
        try:
            stdin.write(str(sudo_password) + "\n")
            stdin.flush()
        except Exception:
            pass
    out = stdout.read()
    err = stderr.read()
    stdin.close()
    exit_code = stdout.channel.recv_exit_status() if hasattr(stdout, "channel") else 0
    out_text = scrub_password_echo(
        out.decode("utf-8", "ignore") if isinstance(out, (bytes, bytearray)) else str(out or ""), sudo_password
    )
    err_text = scrub_password_echo(
        err.decode("utf-8", "ignore") if isinstance(err, (bytes, bytearray)) else str(err or ""), sudo_password
    )
    return exit_code, out_text, err_text


def check_core_daemon(grpc_host: str, grpc_port: int, ssh_host: str, ssh_port: int,
                       username: str, password: str, timeout: float = 5.0) -> dict:
    """Diagnose why `grpc_host:grpc_port` isn't reachable, when it isn't.

    Returns a dict always containing "reachable". When not reachable, it also
    distinguishes "daemon is down on the CORE VM" (offer to start it) from
    "daemon is already up but this host can't reach the gRPC port" (an SSH
    tunnel or CORE_HOST value problem, not something a restart fixes).
    """
    if tcp_port_reachable(grpc_host, grpc_port, timeout=timeout):
        return {"reachable": True}

    if not ssh_host or not username:
        return {
            "reachable": False,
            "ssh_ok": None,
            "can_start": False,
            "message": (
                f"{grpc_host}:{grpc_port} is not reachable and no CORE SSH host/username is "
                "configured to check further."
            ),
        }

    try:
        client = open_ssh_client(ssh_host, ssh_port, username, password)
    except Exception as exc:
        return {
            "reachable": False,
            "ssh_ok": False,
            "can_start": False,
            "message": f"SSH connect to {ssh_host}:{ssh_port} failed: {exc}",
        }

    try:
        pids = collect_remote_core_daemon_pids(client)
    finally:
        try:
            client.close()
        except Exception:
            pass

    if pids:
        return {
            "reachable": False,
            "ssh_ok": True,
            "daemon_running_remotely": True,
            "daemon_pids": pids,
            "can_start": False,
            "message": (
                f"core-daemon is already running on {ssh_host} (pid {', '.join(map(str, pids))}), "
                f"but {grpc_host}:{grpc_port} isn't reachable from here. This usually means "
                "core-daemon only listens on the VM's loopback interface — open an SSH tunnel "
                f"(e.g. `ssh -N -L {grpc_port}:127.0.0.1:{grpc_port} {username}@{ssh_host}`) rather "
                "than restarting the daemon."
            ),
        }

    return {
        "reachable": False,
        "ssh_ok": True,
        "daemon_running_remotely": False,
        "can_start": True,
        "message": f"core-daemon is not running on {ssh_host}.",
    }


def start_core_daemon(ssh_host: str, ssh_port: int, username: str, password: str) -> dict:
    try:
        client = open_ssh_client(ssh_host, ssh_port, username, password)
    except Exception as exc:
        return {"ok": False, "message": f"SSH connect to {ssh_host}:{ssh_port} failed: {exc}"}

    try:
        exit_code, _out, err = start_remote_core_daemon(client, password)
        if exit_code != 0:
            return {"ok": False, "message": f"Failed to start core-daemon (exit {exit_code}): {err.strip()}"}
        pids = collect_remote_core_daemon_pids(client)
        if not pids:
            return {
                "ok": False,
                "message": "systemctl start reported success but core-daemon is still not detected.",
            }
        return {"ok": True, "daemon_pids": pids, "message": f"core-daemon started on {ssh_host} (pid {', '.join(map(str, pids))})."}
    finally:
        try:
            client.close()
        except Exception:
            pass
