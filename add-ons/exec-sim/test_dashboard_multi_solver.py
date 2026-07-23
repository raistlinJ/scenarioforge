import json
import os
import tempfile
import unittest
from unittest.mock import patch

import config
import dashboard
import main


class DashboardMultiSolverTests(unittest.TestCase):
    def test_run_modal_options_update_runtime_configuration(self):
        old_turns = config.MAX_TURNS
        old_threshold = config.PASS_THRESHOLD
        old_output = config.OUTPUT_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                prefix = main.apply_dashboard_run_options({
                    "max_turns": 7,
                    "pass_threshold": 65,
                    "base_dir": temp_dir,
                    "challenge_name": "regression run",
                })
                self.assertEqual(prefix, "regression run")
                self.assertEqual(config.MAX_TURNS, 7)
                self.assertEqual(config.PASS_THRESHOLD, 65)
                self.assertEqual(config.OUTPUT_DIR, temp_dir)
            finally:
                config.MAX_TURNS = old_turns
                config.PASS_THRESHOLD = old_threshold
                config.OUTPUT_DIR = old_output

    def test_first_solver_generates_and_all_solvers_evaluate(self):
        first = {"id": "first", "provider": "ollama", "label": "Solver 1"}
        second = {"id": "second", "provider": "ollama", "label": "Solver 2"}
        result = {
            "pct": 100,
            "matched": [],
            "nodes_visited": [],
            "attack_steps": [],
            "chain_labels": [],
            "error": "",
            "flags_found": [],
            "turns": 1,
            "elapsed_s": 0.1,
            "missed": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir, \
             patch.object(config, "OUTPUT_DIR", temp_dir), \
             patch.object(main, "load_attack_graph", return_value={}), \
             patch.object(main, "parse_reference_graph", return_value=([], [], None)), \
             patch.object(main, "score_challenge_from_graph", return_value=([], 1.0)), \
             patch.object(main, "hypothesize_why_obvious", return_value=""), \
             patch.object(main, "build_claude_nodes", return_value=[]), \
             patch.object(main, "make_dashboard_data", return_value={}), \
             patch.object(main, "update_dashboard_js"), \
             patch.object(main, "solve_challenge_with_model", return_value=result) as solve_mock:

            def generate(_iteration, _difficulty, override_name, gen_model_cfg):
                self.assertIs(gen_model_cfg, first)
                with open(os.path.join(temp_dir, f"{override_name}.xml"), "w") as handle:
                    handle.write("<scenario />")
                with open(os.path.join(temp_dir, f"{override_name}_meta.json"), "w") as handle:
                    json.dump({"params": {}}, handle)
                with open(os.path.join(temp_dir, f"{override_name}_solution.json"), "w") as handle:
                    json.dump({}, handle)
                return True

            with patch.object(main, "generate_one_challenge", side_effect=generate):
                main.run_generate_and_solve("easy", [first, second])

        self.assertEqual([call.args[2] for call in solve_mock.call_args_list], [first, second])

    def test_params_reach_the_dashboard_before_any_solver_runs(self):
        """Params are known as soon as generation succeeds — they must be
        pushed to the dashboard right then, not only after solving (which
        can take a while, or fail/hang) finishes for the first solver."""
        solver = {"id": "m", "provider": "ollama", "label": "Solver 1"}
        result = {
            "pct": 0, "matched": [], "nodes_visited": [], "attack_steps": [],
            "chain_labels": [], "error": "", "flags_found": [], "turns": 0,
            "elapsed_s": 0.0, "missed": [],
        }
        call_order = []

        with tempfile.TemporaryDirectory() as temp_dir, \
             patch.object(config, "OUTPUT_DIR", temp_dir), \
             patch.object(main, "load_attack_graph", return_value={}), \
             patch.object(main, "parse_reference_graph", return_value=([], [], None)), \
             patch.object(main, "score_challenge_from_graph", return_value=([], 1.0)), \
             patch.object(main, "hypothesize_why_obvious", return_value=""), \
             patch.object(main, "build_claude_nodes", return_value=[]), \
             patch.object(main, "make_dashboard_data", return_value={}), \
             patch.object(main, "update_dashboard_js"), \
             patch.object(dashboard, "write_scenario_params",
                          side_effect=lambda params, _dir: call_order.append(("params", params))) as write_params_mock, \
             patch.object(main, "solve_challenge_with_model",
                          side_effect=lambda *a, **k: call_order.append(("solve",)) or result):

            def generate(_iteration, _difficulty, override_name, gen_model_cfg):
                with open(os.path.join(temp_dir, f"{override_name}.xml"), "w") as handle:
                    handle.write("<scenario />")
                with open(os.path.join(temp_dir, f"{override_name}_meta.json"), "w") as handle:
                    json.dump({"params": {"chain_length": 3}}, handle)
                with open(os.path.join(temp_dir, f"{override_name}_solution.json"), "w") as handle:
                    json.dump({}, handle)
                return True

            with patch.object(main, "generate_one_challenge", side_effect=generate):
                main.run_generate_and_solve("easy", [solver])

        write_params_mock.assert_called_once_with({"chain_length": 3}, config.DASHBOARD_DIR)
        self.assertEqual(call_order, [("params", {"chain_length": 3}), ("solve",)])


class StartDashboardServerTests(unittest.TestCase):
    def test_generate_callback_is_wired_to_the_module_global(self):
        """Regression test: start_dashboard_server previously accepted a
        generate_callback argument but never assigned it to the module-level
        _generate_callback the request handler actually reads, so clicking
        "Start Run" silently did nothing — the thread never started, but the
        handler still returned 200 "started"."""
        old_started = dashboard._dashboard_server_started
        old_callback = dashboard._generate_callback
        old_dashboard_dir = config.DASHBOARD_DIR
        dashboard._dashboard_server_started = False
        dashboard._generate_callback = None
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                config.DASHBOARD_DIR = temp_dir
                sentinel_callback = lambda params: None
                with patch("http.server.ThreadingHTTPServer"):
                    dashboard.start_dashboard_server(sentinel_callback)
            self.assertIs(dashboard._generate_callback, sentinel_callback)
        finally:
            dashboard._dashboard_server_started = old_started
            dashboard._generate_callback = old_callback
            config.DASHBOARD_DIR = old_dashboard_dir


class ChallengeNameSanitizationTests(unittest.TestCase):
    """ScenarioForge's own XML writer (_sanitize_scenario_name_strict) strips
    every non-alphanumeric character from a scenario name before storing it,
    but later phases look it back up using the original, unstripped name —
    any punctuation here makes that lookup silently fail downstream with
    "ScenarioEditor not found". Generated challenge/scenario names must stay
    purely alphanumeric to avoid that write/read mismatch."""

    def test_generated_challenge_name_has_no_punctuation(self):
        solver = {"id": "m", "provider": "dummy", "label": "Solver"}
        captured = []

        def fake_generate(_iteration, _difficulty, override_name, gen_model_cfg):
            captured.append(override_name)
            return False  # short-circuit; we only care about the name passed in

        with patch.object(main, "generate_one_challenge", side_effect=fake_generate):
            main.run_generate_and_solve(
                "easy", [solver], loop=1, challenge_prefix="My_Custom Prefix!",
            )

        self.assertEqual(len(captured), 1)
        self.assertRegex(captured[0], r"^[A-Za-z0-9]+$")
        self.assertTrue(captured[0].startswith("MyCustomPrefix"))

    def test_empty_or_fully_punctuation_prefix_falls_back_to_generated(self):
        solver = {"id": "m", "provider": "dummy", "label": "Solver"}
        captured = []

        def fake_generate(_iteration, _difficulty, override_name, gen_model_cfg):
            captured.append(override_name)
            return False

        with patch.object(main, "generate_one_challenge", side_effect=fake_generate):
            main.run_generate_and_solve("easy", [solver], loop=1, challenge_prefix="___---")

        self.assertTrue(captured[0].startswith("Generated"))
        self.assertRegex(captured[0], r"^[A-Za-z0-9]+$")


if __name__ == "__main__":
    unittest.main()
