import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import process_registry


class RegisterUnregisterTests(unittest.TestCase):
    def test_register_then_unregister_leaves_no_entries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_proc = type("P", (), {"pid": 12345})()
            process_registry.register_process(temp_dir, fake_proc, label="new")
            entries = json.loads(Path(process_registry._pid_file_path(temp_dir)).read_text())
            self.assertEqual(entries, [{"pid": 12345, "label": "new", "started_at": entries[0]["started_at"]}])

            process_registry.unregister_process(temp_dir, fake_proc)
            entries = json.loads(Path(process_registry._pid_file_path(temp_dir)).read_text())
            self.assertEqual(entries, [])

    def test_missing_pid_file_reads_as_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertEqual(process_registry._read_entries(temp_dir), [])


class StopAllTests(unittest.TestCase):
    """Uses a real long-lived subprocess (its own process group) to verify
    stop_all actually terminates it — not just that it manipulates the PID
    file — since that's the entire point of the feature."""

    def _spawn_sleeper(self):
        return subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True,
        )

    def _is_alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def test_stop_all_kills_a_registered_running_process(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            proc = self._spawn_sleeper()
            try:
                process_registry.register_process(temp_dir, proc, label="sleeper")
                self.assertTrue(self._is_alive(proc.pid))

                stopped = process_registry.stop_all(temp_dir)

                self.assertIn(proc.pid, stopped)
                # Reap via the Popen object we own, rather than polling
                # os.kill(pid, 0): a killed-but-unreaped child is a zombie,
                # which still holds a process-table entry (so a raw signal-0
                # check reports it as "alive") until something calls wait()
                # on it — which is exactly what a real caller (whichever
                # thread/process owns the Popen, or init for a truly
                # orphaned residual process) does shortly after.
                exit_code = proc.wait(timeout=5)
                self.assertLess(exit_code, 0)  # negative == killed by signal
                self.assertEqual(process_registry._read_entries(temp_dir), [])
            finally:
                if self._is_alive(proc.pid):
                    proc.kill()
                proc.wait(timeout=5)

    def test_stop_all_skips_already_dead_pids_without_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            proc = self._spawn_sleeper()
            proc.kill()
            proc.wait(timeout=5)
            process_registry.register_process(temp_dir, proc, label="already-dead")

            stopped = process_registry.stop_all(temp_dir)

            self.assertEqual(stopped, [])
            self.assertEqual(process_registry._read_entries(temp_dir), [])

    def test_stop_all_with_no_entries_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertEqual(process_registry.stop_all(temp_dir), [])


if __name__ == "__main__":
    unittest.main()
