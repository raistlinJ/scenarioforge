import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import dashboard


class DashboardLogTeeTests(unittest.TestCase):
    def test_write_forwards_to_the_original_stream(self):
        original = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            tee = dashboard.DashboardLogTee(original, temp_dir)
            tee.write("hello\n")
        self.assertEqual(original.getvalue(), "hello\n")

    def test_write_splits_lines_into_the_dashboard_log(self):
        original = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            tee = dashboard.DashboardLogTee(original, temp_dir)
            tee.write("first line\nsecond line\n")
            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
        self.assertEqual(state["log"], ["first line", "second line"])

    def test_partial_line_is_buffered_until_newline_arrives(self):
        original = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            tee = dashboard.DashboardLogTee(original, temp_dir)
            tee.write("no newline yet")
            state_path = Path(temp_dir) / "dashboard_state.json"
            self.assertFalse(state_path.is_file())
            tee.write(" — now complete\n")
            state = json.loads(state_path.read_text())
        self.assertEqual(state["log"], ["no newline yet — now complete"])

    def test_log_is_capped_at_max_lines(self):
        original = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            tee = dashboard.DashboardLogTee(original, temp_dir)
            for i in range(dashboard._MAX_LOG_LINES + 50):
                tee.write(f"line {i}\n")
            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
        self.assertEqual(len(state["log"]), dashboard._MAX_LOG_LINES)
        self.assertEqual(state["log"][-1], f"line {dashboard._MAX_LOG_LINES + 49}")


class ResetDashboardRunTests(unittest.TestCase):
    def test_reset_clears_stale_error_and_iterations(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard.write_dashboard_error("old failure", temp_dir, iteration=1)
            dashboard.reset_dashboard_run(temp_dir)
            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
        self.assertEqual(state, {"iterations": [], "log": [], "status": "running"})


class SetDashboardStatusTests(unittest.TestCase):
    def test_sets_status_without_disturbing_other_fields(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard.update_dashboard_js({"iteration": 1}, temp_dir)
            dashboard.set_dashboard_status("stopped", temp_dir)
            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
        self.assertEqual(state["status"], "stopped")
        self.assertEqual(len(state["iterations"]), 1)


class MirrorStdoutToDashboardTests(unittest.TestCase):
    def test_prints_inside_the_block_are_captured_and_stdout_is_restored(self):
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        with tempfile.TemporaryDirectory() as temp_dir:
            with dashboard.mirror_stdout_to_dashboard(temp_dir):
                self.assertIsNot(sys.stdout, original_stdout)
                print("hello from the run")
            self.assertIs(sys.stdout, original_stdout)
            self.assertIs(sys.stderr, original_stderr)
            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
        self.assertIn("hello from the run", state["log"])

    def test_status_is_running_during_the_block_and_stopped_after(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with dashboard.mirror_stdout_to_dashboard(temp_dir):
                mid_run_state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
            after_run_state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
        self.assertEqual(mid_run_state["status"], "running")
        self.assertEqual(after_run_state["status"], "stopped")

    def test_status_becomes_stopped_even_if_the_block_raises(self):
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                with dashboard.mirror_stdout_to_dashboard(temp_dir):
                    raise ValueError("boom")
            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
        self.assertIs(sys.stdout, original_stdout)
        self.assertIs(sys.stderr, original_stderr)
        self.assertEqual(state["status"], "stopped")

    def test_run_generate_callback_with_log_captures_callback_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            def callback(params):
                print(f"generating with {params['difficulty']}")

            dashboard.run_generate_callback_with_log(callback, {"difficulty": "easy"}, temp_dir)
            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
        self.assertIn("generating with easy", state["log"])

    def test_residual_processes_are_stopped_before_a_new_run_starts(self):
        """"if running when we start, stop them" — any process left over
        from a previous, uncleanly-ended run must be killed before this run
        begins, not left to keep running alongside it."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(dashboard.process_registry, "stop_all", return_value=[4321]) as stop_all_mock:
                with dashboard.mirror_stdout_to_dashboard(temp_dir):
                    pass
            stop_all_mock.assert_called_once_with(temp_dir)
            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
            self.assertTrue(any("4321" in line for line in state["log"]))


class WriteScenarioParamsTests(unittest.TestCase):
    """Params are known as soon as generation succeeds, well before any
    solver has run — they must reach the dashboard immediately rather than
    waiting for iterations, which only gets its first entry once an entire
    solve finishes."""

    def test_params_are_written_as_a_top_level_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard.write_scenario_params({"chain_length": 3, "routing_protocol": "RIP"}, temp_dir)
            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
        self.assertEqual(state["params"], {"chain_length": 3, "routing_protocol": "RIP"})

    def test_does_not_clobber_other_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard.update_dashboard_js({"iteration": 1}, temp_dir)
            dashboard.write_scenario_params({"chain_length": 2}, temp_dir)
            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
        self.assertEqual(len(state["iterations"]), 1)
        self.assertEqual(state["params"], {"chain_length": 2})

    def test_later_call_overwrites_earlier_one(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard.write_scenario_params({"chain_length": 2}, temp_dir)
            dashboard.write_scenario_params({"chain_length": 5}, temp_dir)
            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
        self.assertEqual(state["params"], {"chain_length": 5})


if __name__ == "__main__":
    unittest.main()
