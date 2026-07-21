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
