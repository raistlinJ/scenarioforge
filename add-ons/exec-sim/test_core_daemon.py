import socket
import socketserver
import threading
import unittest
from unittest.mock import MagicMock, patch

import core_daemon
import dashboard


def _fake_exec_command_result(exit_code, stdout_text="", stderr_text=""):
    stdout = MagicMock()
    stdout.read.return_value = stdout_text.encode("utf-8")
    stdout.channel.recv_exit_status.return_value = exit_code
    stderr = MagicMock()
    stderr.read.return_value = stderr_text.encode("utf-8")
    stdin = MagicMock()
    return stdin, stdout, stderr


class CoreDaemonHelperTests(unittest.TestCase):
    def test_collect_remote_core_daemon_pids_parses_pgrep_output(self):
        client = MagicMock()
        client.exec_command.return_value = _fake_exec_command_result(0, "123\n456\n")
        self.assertEqual(core_daemon.collect_remote_core_daemon_pids(client), [123, 456])

    def test_collect_remote_core_daemon_pids_empty_when_not_running(self):
        client = MagicMock()
        client.exec_command.return_value = _fake_exec_command_result(1, "")
        self.assertEqual(core_daemon.collect_remote_core_daemon_pids(client), [])

    def test_start_remote_core_daemon_scrubs_password_from_output(self):
        client = MagicMock()
        client.exec_command.return_value = _fake_exec_command_result(
            0, "hunter2\nsudo: Password: hunter2 accepted\nStarted core-daemon\n"
        )
        exit_code, out, _err = core_daemon.start_remote_core_daemon(client, "hunter2")
        self.assertEqual(exit_code, 0)
        self.assertNotIn("hunter2", out)
        self.assertIn("[REDACTED]", out)

    def test_check_core_daemon_reachable_short_circuits_ssh(self):
        with patch.object(core_daemon, "tcp_port_reachable", return_value=True), \
             patch.object(core_daemon, "open_ssh_client") as ssh_mock:
            status = core_daemon.check_core_daemon("127.0.0.1", 50051, "12.0.0.100", 22, "user", "pass")
        self.assertTrue(status["reachable"])
        ssh_mock.assert_not_called()

    def test_check_core_daemon_reports_daemon_running_remotely_needs_tunnel(self):
        with patch.object(core_daemon, "tcp_port_reachable", return_value=False), \
             patch.object(core_daemon, "open_ssh_client", return_value=MagicMock()), \
             patch.object(core_daemon, "collect_remote_core_daemon_pids", return_value=[123]):
            status = core_daemon.check_core_daemon("127.0.0.1", 50051, "12.0.0.100", 22, "user", "pass")
        self.assertFalse(status["reachable"])
        self.assertTrue(status["daemon_running_remotely"])
        self.assertFalse(status["can_start"])
        self.assertIn("tunnel", status["message"])

    def test_check_core_daemon_offers_to_start_when_not_running(self):
        with patch.object(core_daemon, "tcp_port_reachable", return_value=False), \
             patch.object(core_daemon, "open_ssh_client", return_value=MagicMock()), \
             patch.object(core_daemon, "collect_remote_core_daemon_pids", return_value=[]):
            status = core_daemon.check_core_daemon("127.0.0.1", 50051, "12.0.0.100", 22, "user", "pass")
        self.assertFalse(status["reachable"])
        self.assertTrue(status["can_start"])

    def test_check_core_daemon_reports_ssh_failure(self):
        with patch.object(core_daemon, "tcp_port_reachable", return_value=False), \
             patch.object(core_daemon, "open_ssh_client", side_effect=RuntimeError("auth failed")):
            status = core_daemon.check_core_daemon("127.0.0.1", 50051, "12.0.0.100", 22, "user", "pass")
        self.assertFalse(status["reachable"])
        self.assertFalse(status["ssh_ok"])
        self.assertFalse(status["can_start"])

    def test_start_core_daemon_success(self):
        with patch.object(core_daemon, "open_ssh_client", return_value=MagicMock()), \
             patch.object(core_daemon, "start_remote_core_daemon", return_value=(0, "", "")), \
             patch.object(core_daemon, "collect_remote_core_daemon_pids", return_value=[789]):
            result = core_daemon.start_core_daemon("12.0.0.100", 22, "user", "pass")
        self.assertTrue(result["ok"])
        self.assertEqual(result["daemon_pids"], [789])

    def test_start_core_daemon_reports_nonzero_exit(self):
        with patch.object(core_daemon, "open_ssh_client", return_value=MagicMock()), \
             patch.object(core_daemon, "start_remote_core_daemon", return_value=(1, "", "permission denied")):
            result = core_daemon.start_core_daemon("12.0.0.100", 22, "user", "pass")
        self.assertFalse(result["ok"])
        self.assertIn("permission denied", result["message"])

    def test_check_core_daemon_running_remotely_offers_tunnel_not_start(self):
        with patch.object(core_daemon, "tcp_port_reachable", return_value=False), \
             patch.object(core_daemon, "open_ssh_client", return_value=MagicMock()), \
             patch.object(core_daemon, "collect_remote_core_daemon_pids", return_value=[609]):
            status = core_daemon.check_core_daemon("127.0.0.1", 50051, "12.0.0.100", 22, "user", "pass")
        self.assertTrue(status["can_tunnel"])
        self.assertFalse(status["can_start"])


class _EchoTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(4096)
            if not data:
                break
            self.request.sendall(data)


class LocalForwardProxyTests(unittest.TestCase):
    """Exercises the real byte-forwarding path (_make_forward_handler) without
    a real SSH server: the "SSH channel" a fake transport hands back is just a
    plain socket connected to a local echo server."""

    def test_local_forward_proxies_bytes_end_to_end(self):
        echo_server = _EchoTCPServer(("127.0.0.1", 0), _EchoHandler)
        echo_thread = threading.Thread(target=echo_server.serve_forever, daemon=True)
        echo_thread.start()
        echo_host, echo_port = echo_server.server_address

        class _FakeTransport:
            def is_active(self):
                return True

            def open_channel(self, kind, dest_addr, src_addr):
                return socket.create_connection((echo_host, echo_port), timeout=5.0)

        handler = core_daemon._make_forward_handler(_FakeTransport(), echo_host, echo_port)
        forward_server = core_daemon._ForwardServer(("127.0.0.1", 0), handler)
        forward_thread = threading.Thread(target=forward_server.serve_forever, daemon=True)
        forward_thread.start()
        local_host, local_port = forward_server.server_address

        try:
            client = socket.create_connection((local_host, local_port), timeout=5.0)
            try:
                client.sendall(b"hello through the tunnel")
                received = client.recv(4096)
                self.assertEqual(received, b"hello through the tunnel")
            finally:
                client.close()
        finally:
            forward_server.shutdown()
            forward_server.server_close()
            echo_server.shutdown()
            echo_server.server_close()

    def test_local_forward_start_raises_when_transport_inactive(self):
        fake_client = MagicMock()
        fake_transport = MagicMock()
        fake_transport.is_active.return_value = False
        fake_client.get_transport.return_value = fake_transport
        with patch.object(core_daemon, "open_ssh_client", return_value=fake_client):
            forward = core_daemon.LocalForward(
                ssh_host="12.0.0.100", ssh_port=22, username="user", password="pass",
                remote_port=50051, local_port=0,
            )
            with self.assertRaises(RuntimeError):
                forward.start()

    def test_open_local_forward_reports_failure_message(self):
        with patch.object(core_daemon, "open_ssh_client", side_effect=RuntimeError("auth failed")):
            result = core_daemon.open_local_forward("127.0.0.1", 50051, "12.0.0.100", 22, "user", "pass")
        self.assertFalse(result["ok"])
        self.assertIn("auth failed", result["message"])

    def test_open_local_forward_returns_forward_handle_on_success(self):
        fake_forward = MagicMock()
        fake_forward.start.return_value = ("127.0.0.1", 50051)
        with patch.object(core_daemon, "LocalForward", return_value=fake_forward):
            result = core_daemon.open_local_forward("127.0.0.1", 50051, "12.0.0.100", 22, "user", "pass")
        self.assertTrue(result["ok"])
        self.assertIs(result["forward"], fake_forward)


class DashboardValidateCoreTests(unittest.TestCase):
    def test_validate_core_connection_raises_daemon_not_reachable_with_details(self):
        details = {"reachable": False, "can_start": True, "message": "core-daemon is not running on 12.0.0.100."}
        with patch.object(dashboard.core_daemon, "tcp_port_reachable", return_value=False), \
             patch.object(dashboard.core_daemon, "check_core_daemon", return_value=details):
            with self.assertRaises(dashboard.CoreDaemonNotReachable) as ctx:
                dashboard._validate_core_connection(
                    "127.0.0.1", 50051, "12.0.0.100", 22, "user", "pass",
                )
        self.assertEqual(ctx.exception.details, details)


if __name__ == "__main__":
    unittest.main()
