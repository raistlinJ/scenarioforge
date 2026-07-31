"""Fast, accurate feedback when the CORE VM cannot be reached.

Paramiko spends its full connect/banner/auth budget before reporting an
unreachable host, and the caller then phrases the failure in terms of the gRPC
target it was ultimately after. That target is a loopback address reached
*through* the SSH hop, so an unreachable VM surfaced as

    CORE connection failed to localhost:50051: timed out

naming a host that was never the problem, after a long wait. A short TCP probe
first fails in seconds and names the endpoint actually dialled.
"""

from __future__ import annotations

import socket

import pytest

from webapp import app_backend as backend


def _listening_port() -> tuple[socket.socket, int]:
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    return srv, srv.getsockname()[1]


def _closed_port() -> int:
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_reachable_endpoint_reports_no_problem():
    srv, port = _listening_port()
    try:
        assert backend._core_ssh_endpoint_reachable('127.0.0.1', port, timeout=2.0) == ''
    finally:
        srv.close()


def test_refused_endpoint_says_nothing_is_listening():
    port = _closed_port()
    message = backend._core_ssh_endpoint_reachable('127.0.0.1', port, timeout=2.0)
    assert 'refused' in message
    assert str(port) in message


def test_unresolvable_host_is_named():
    message = backend._core_ssh_endpoint_reachable('no-such-host.invalid', 22, timeout=2.0)
    assert 'does not resolve' in message
    assert 'no-such-host.invalid' in message


def test_timeout_names_the_endpoint_and_suggests_why(monkeypatch):
    def _timeout(*_args, **_kwargs):
        raise socket.timeout()

    monkeypatch.setattr(backend, 'socket', socket, raising=False)
    monkeypatch.setattr(socket, 'create_connection', _timeout)

    message = backend._core_ssh_endpoint_reachable('core-vm.example', 2222, timeout=3.0)
    assert 'core-vm.example:2222' in message
    assert 'powered off' in message or 'cannot currently reach' in message


def test_missing_ssh_host_is_reported_rather_than_dialled():
    assert backend._core_ssh_endpoint_reachable('', 22) == 'no SSH host configured'


def test_daemon_check_fails_fast_and_names_the_ssh_endpoint(monkeypatch):
    """The message must name the SSH hop, not the gRPC target behind it."""
    monkeypatch.setattr(
        backend, '_core_ssh_endpoint_reachable',
        lambda host, port, **_kw: f'no response from {host}:{port} within 3s',
    )
    # Would otherwise require paramiko and a real connection.
    monkeypatch.setattr(backend, '_ensure_paramiko_available', lambda: None)

    cfg = {
        'host': 'localhost', 'port': 50051,
        'ssh_host': 'old-lab.example.edu', 'ssh_port': 10006,
        'ssh_username': 'corevm', 'ssh_password': 'x', 'ssh_enabled': True,
    }
    with pytest.raises(RuntimeError) as excinfo:
        backend._ensure_core_daemon_listening(cfg, timeout=5.0)

    text = str(excinfo.value)
    assert 'old-lab.example.edu:10006' in text
    assert 'Cannot reach the CORE VM over SSH' in text


class _FakeStdout:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self):
        return self._payload


class _FakeClient:
    def __init__(self, payload: bytes | None = None, raises: bool = False):
        self._payload = payload or b''
        self._raises = raises

    def exec_command(self, _command, timeout=None):
        if self._raises:
            raise RuntimeError('ssh channel closed')
        return None, _FakeStdout(self._payload), None


def test_daemon_failure_carries_the_daemon_log():
    client = _FakeClient(b'line one\nline two\n')
    suffix = backend._core_daemon_journal_suffix(client)
    assert 'Recent core-daemon log:' in suffix
    assert 'line two' in suffix


def test_daemon_log_suffix_is_empty_when_unavailable():
    """Callers append unconditionally, so failure here must not add noise."""
    assert backend._core_daemon_journal_suffix(_FakeClient(raises=True)) == ''
    assert backend._core_daemon_journal_suffix(_FakeClient(b'   \n  \n')) == ''
