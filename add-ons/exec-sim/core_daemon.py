"""Check whether CORE's gRPC daemon is reachable, and start it over SSH if not.

Mirrors the SSH probe/start commands ScenarioForge's own webapp uses
(`webapp/app_backend.py`: `_collect_remote_core_daemon_pids`,
`_start_remote_core_daemon`) so exec-sim's diagnosis matches what the CORE VM
actually expects, without depending on the webapp process being up.
"""

from __future__ import annotations

import select
import socket
import socketserver
import threading
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
            "can_tunnel": True,
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


class _ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _make_forward_handler(transport: Any, remote_host: str, remote_port: int):
    """Proxy each accepted local connection through an SSH `direct-tcpip`
    channel to remote_host:remote_port, as resolved by the far end (sshd on
    the CORE VM) — the same mechanism `ssh -L` uses under the hood."""

    class _ForwardHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            try:
                if transport is None or not transport.is_active():
                    self.request.close()
                    return
                chan = transport.open_channel(
                    kind="direct-tcpip",
                    dest_addr=(remote_host, remote_port),
                    src_addr=self.request.getpeername(),
                )
            except Exception:
                try:
                    self.request.close()
                except Exception:
                    pass
                return
            if chan is None:
                try:
                    self.request.close()
                except Exception:
                    pass
                return
            try:
                while True:
                    rlist, _, _ = select.select([self.request, chan], [], [])
                    if self.request in rlist:
                        data = self.request.recv(4096)
                        if not data:
                            break
                        chan.sendall(data)
                    if chan in rlist:
                        data = chan.recv(4096)
                        if not data:
                            break
                        self.request.sendall(data)
            finally:
                try:
                    chan.close()
                except Exception:
                    pass
                try:
                    self.request.close()
                except Exception:
                    pass

    return _ForwardHandler


class LocalForward:
    """A local TCP listener that proxies to remote_host:remote_port over SSH,
    equivalent to `ssh -N -L local_port:remote_host:remote_port ssh_host`.

    Any local process — including a `scenarioforge.cli` subprocess we spawn
    afterward — that connects to local_host:local_port transparently rides
    this tunnel; nothing in the connecting process needs to know it exists.
    """

    def __init__(self, *, ssh_host: str, ssh_port: int, username: str, password: str,
                 remote_host: str = "127.0.0.1", remote_port: int,
                 local_host: str = "127.0.0.1", local_port: int | None = None):
        self.ssh_host = ssh_host
        self.ssh_port = int(ssh_port)
        self.username = username
        self.password = password or ""
        self.remote_host = remote_host
        self.remote_port = int(remote_port)
        self.local_host = local_host
        self.local_port = int(local_port if local_port is not None else remote_port)
        self.client: Any | None = None
        self.server: _ForwardServer | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> tuple[str, int]:
        client = open_ssh_client(self.ssh_host, self.ssh_port, self.username, self.password)
        self.client = client
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            self.close()
            raise RuntimeError("SSH transport unavailable after connect")
        try:
            transport.set_keepalive(30)
        except Exception:
            pass
        handler = _make_forward_handler(transport, self.remote_host, self.remote_port)
        try:
            self.server = _ForwardServer((self.local_host, self.local_port), handler)
        except OSError as exc:
            self.close()
            raise RuntimeError(
                f"Could not bind local forward on {self.local_host}:{self.local_port}: {exc}"
            ) from exc
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.server.server_address

    def close(self) -> None:
        if self.server is not None:
            try:
                self.server.shutdown()
            except Exception:
                pass
            try:
                self.server.server_close()
            except Exception:
                pass
            self.server = None
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None


def open_local_forward(grpc_host: str, grpc_port: int, ssh_host: str, ssh_port: int,
                        username: str, password: str) -> dict:
    """Start a LocalForward exposing the CORE VM's daemon at grpc_host:grpc_port.

    Returns {"ok": True, "forward": LocalForward} on success, keeping the
    forward alive so the caller can hold a reference for the run's lifetime;
    {"ok": False, "message": ...} otherwise.
    """
    forward = LocalForward(
        ssh_host=ssh_host, ssh_port=ssh_port, username=username, password=password,
        remote_host="127.0.0.1", remote_port=grpc_port,
        local_host=grpc_host, local_port=grpc_port,
    )
    try:
        forward.start()
    except Exception as exc:
        return {"ok": False, "message": f"Failed to open SSH tunnel to {ssh_host}: {exc}"}
    return {
        "ok": True,
        "forward": forward,
        "message": f"SSH tunnel open: {grpc_host}:{grpc_port} -> {ssh_host} -> 127.0.0.1:{grpc_port}.",
    }
