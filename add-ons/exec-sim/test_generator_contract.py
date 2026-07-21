import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config
import dashboard
import generator


def _graph():
    return {
        "schema_version": 2,
        "scenario": "contract",
        "chain_order": ["entry", "target"],
        "assignment_order": ["target"],
        "nodes": [
            {"id": "entry", "sequence_index": 1, "label": "Entry", "type": "Docker", "is_vuln": False, "ipv4": "10.0.0.10", "generator": None},
            {
                "id": "target", "sequence_index": 2, "label": "Target", "type": "Docker", "is_vuln": True, "ipv4": "10.0.0.20",
                "generator": {
                    "id": "target-gen", "name": "Target", "kind": "flag-generator", "source": "test", "catalog": "test",
                    "sequence_index": 2, "resolved_inputs": {}, "resolved_outputs": {"Flag(flag_id)": "FLAG{target}"}, "flag_value": "FLAG{target}",
                },
            },
        ],
        "edges": [{"sequence_index": 1, "source": "entry", "target": "target", "relationship": "sequence", "facts": [], "artifacts": [], "artifacts_resolved": {}, "artifacts_resolved_kv": []}],
        "stages": [{"stage": 0, "indices": [0]}, {"stage": 1, "indices": [1]}],
        "fact_dependencies": [],
    }


class GeneratorContractTests(unittest.TestCase):
    def test_generation_uses_seeded_pipeline_and_requires_execute_validation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_output_dir = config.OUTPUT_DIR
            config.OUTPUT_DIR = temp_dir
            commands = []

            def fake_phase(name, command, *, cwd, log_path, timeout_s=generator.SCENARIOFORGE_PHASE_TIMEOUT_S, allow_failure=False):
                commands.append(command)
                Path(log_path).write_text(f"{name}\n", encoding="utf-8")
                output_path = Path(command[command.index("--plan-output") + 1])
                if name == "new":
                    xml_path = Path(command[command.index("--xml") + 1])
                    xml_path.write_text(
                        "<Scenarios><Scenario name='contract'><ScenarioEditor>"
                        "<section name='Services'><item selected='SSH'/></section>"
                        "</ScenarioEditor></Scenario></Scenarios>", encoding="utf-8",
                    )
                if name == "flag-sequencing":
                    output_path.write_text(json.dumps({"attack_graph": _graph()}), encoding="utf-8")
                else:
                    output_path.write_text("{}", encoding="utf-8")
                output = 'CORE_SESSION_ID: 123\nVALIDATION_SUMMARY_JSON: {"ok": true}' if name == "execute" else ""
                return (0, output) if allow_failure else output

            try:
                with patch.object(generator, "_run_scenarioforge_phase", side_effect=fake_phase):
                    ok = generator.generate_one_challenge(
                        1, "easy", override_name="contract", gen_model_cfg={"provider": "dummy"},
                    )
            finally:
                config.OUTPUT_DIR = old_output_dir

            self.assertTrue(ok)
            self.assertEqual([command[5] for command in commands], ["new", "preview-plan", "flag-sequencing", "execute"])
            seeds = [command[command.index("--seed") + 1] for command in commands]
            self.assertEqual(len(set(seeds)), 1)
            self.assertIn("--post-execution-validation", commands[-1])
            self.assertIn("--flow-best-effort", commands[2])
            self.assertNotIn("--flow-run-local", commands[2])
            self.assertTrue((Path(temp_dir) / "contract_execute-validation.json").is_file())
            self.assertTrue((Path(temp_dir) / "contract_solution.json").is_file())

    def test_core_connection_is_scoped_to_the_four_cli_phases_only(self):
        """The SSH tunnel (if any) must open right before 'new' and close
        right after 'execute' — never held open during planning, which also
        needs the LAN for its own LLM call."""
        with tempfile.TemporaryDirectory() as temp_dir:
            old_output_dir = config.OUTPUT_DIR
            config.OUTPUT_DIR = temp_dir
            events = []

            def fake_phase(name, command, *, cwd, log_path, timeout_s=generator.SCENARIOFORGE_PHASE_TIMEOUT_S, allow_failure=False):
                events.append(("phase", name))
                Path(log_path).write_text(f"{name}\n", encoding="utf-8")
                output_path = Path(command[command.index("--plan-output") + 1])
                if name == "new":
                    xml_path = Path(command[command.index("--xml") + 1])
                    xml_path.write_text(
                        "<Scenarios><Scenario name='contract'><ScenarioEditor>"
                        "<section name='Services'><item selected='SSH'/></section>"
                        "</ScenarioEditor></Scenario></Scenarios>", encoding="utf-8",
                    )
                if name == "flag-sequencing":
                    output_path.write_text(json.dumps({"attack_graph": _graph()}), encoding="utf-8")
                else:
                    output_path.write_text("{}", encoding="utf-8")
                output = 'CORE_SESSION_ID: 123\nVALIDATION_SUMMARY_JSON: {"ok": true}' if name == "execute" else ""
                return (0, output) if allow_failure else output

            @contextlib.contextmanager
            def fake_core_connection(*args, **kwargs):
                events.append(("tunnel", "open"))
                try:
                    yield None
                finally:
                    events.append(("tunnel", "close"))

            try:
                with patch.object(generator, "_run_scenarioforge_phase", side_effect=fake_phase), \
                     patch.object(generator.core_daemon, "core_connection", side_effect=fake_core_connection):
                    ok = generator.generate_one_challenge(
                        1, "easy", override_name="contract", gen_model_cfg={"provider": "dummy"},
                    )
            finally:
                config.OUTPUT_DIR = old_output_dir

            self.assertTrue(ok)
            self.assertEqual(events, [
                ("tunnel", "open"),
                ("phase", "new"),
                ("phase", "preview-plan"),
                ("phase", "flag-sequencing"),
                ("phase", "execute"),
                ("tunnel", "close"),
            ])

    def test_generation_failure_is_surfaced_to_the_dashboard_state_file(self):
        """dashboard_state.json only gets written after a successful solve
        (main.py's run_generate_and_solve), so without this a failed
        generation would leave the Web UI's terminal panel frozen forever
        with nothing to show — this writes the failure into the same file
        the browser already polls."""
        with tempfile.TemporaryDirectory() as temp_dir:
            old_output_dir = config.OUTPUT_DIR
            old_dashboard_dir = config.DASHBOARD_DIR
            config.OUTPUT_DIR = temp_dir
            config.DASHBOARD_DIR = temp_dir
            try:
                with patch.object(generator, "plan_scenario",
                                   side_effect=RuntimeError("[planner] Generator model returned empty response")):
                    ok = generator.generate_one_challenge(
                        3, "easy", override_name="contract", gen_model_cfg={"provider": "openai-compatible"},
                    )
            finally:
                config.OUTPUT_DIR = old_output_dir
                config.DASHBOARD_DIR = old_dashboard_dir

            self.assertFalse(ok)
            state_path = Path(temp_dir) / "dashboard_state.json"
            self.assertTrue(state_path.is_file())
            state = json.loads(state_path.read_text())
            self.assertIn("Generator model returned empty response", state["error"])
            self.assertEqual(state["error_iteration"], 3)

    def test_successful_run_clears_a_stale_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard.write_dashboard_error("stale failure", temp_dir, iteration=1)
            self.assertIn("error", json.loads((Path(temp_dir) / "dashboard_state.json").read_text()))

            dashboard.update_dashboard_js({"iteration": 2}, temp_dir)

            state = json.loads((Path(temp_dir) / "dashboard_state.json").read_text())
            self.assertNotIn("error", state)
            self.assertNotIn("error_iteration", state)

    def test_relative_output_dir_resolves_to_the_same_absolute_path_the_cli_subprocess_sees(self):
        """The scenarioforge.cli subprocess runs with cwd=cli_cwd (the
        scenarioforge repo root), a different directory than this process's
        own cwd. A relative OUTPUT_DIR would have each side resolve --xml/
        --plan-output to two different locations — this pins that every path
        handed to the subprocess is absolute, so both sides agree."""
        old_output_dir = config.OUTPUT_DIR
        old_cwd = os.getcwd()
        commands = []

        def fake_phase(name, command, *, cwd, log_path, timeout_s=generator.SCENARIOFORGE_PHASE_TIMEOUT_S, allow_failure=False):
            commands.append(command)
            self.assertTrue(os.path.isabs(log_path), f"log_path not absolute: {log_path}")
            output_path = Path(command[command.index("--plan-output") + 1])
            if name == "new":
                xml_path = Path(command[command.index("--xml") + 1])
                self.assertTrue(xml_path.is_absolute(), f"--xml not absolute: {xml_path}")
                xml_path.write_text(
                    "<Scenarios><Scenario name='contract'><ScenarioEditor>"
                    "<section name='Services'><item selected='SSH'/></section>"
                    "</ScenarioEditor></Scenario></Scenarios>", encoding="utf-8",
                )
            if name == "flag-sequencing":
                output_path.write_text(json.dumps({"attack_graph": _graph()}), encoding="utf-8")
            else:
                output_path.write_text("{}", encoding="utf-8")
            output = 'CORE_SESSION_ID: 123\nVALIDATION_SUMMARY_JSON: {"ok": true}' if name == "execute" else ""
            return (0, output) if allow_failure else output

        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                os.chdir(temp_dir)
                os.makedirs("relative_output", exist_ok=True)
                config.OUTPUT_DIR = "./relative_output"
                with patch.object(generator, "_run_scenarioforge_phase", side_effect=fake_phase):
                    ok = generator.generate_one_challenge(
                        1, "easy", override_name="contract", gen_model_cfg={"provider": "dummy"},
                    )
            finally:
                os.chdir(old_cwd)
                config.OUTPUT_DIR = old_output_dir

        self.assertTrue(ok)
        for command in commands:
            for flag in ("--xml", "--plan-output"):
                if flag in command:
                    self.assertTrue(os.path.isabs(command[command.index(flag) + 1]))


class RunScenarioforgePhaseOutputTests(unittest.TestCase):
    """The scenarioforge.cli subprocess's own stdout/stderr was previously
    only written to a per-phase .log file and never shown anywhere live —
    when a phase "succeeds" (exit 0) but didn't actually do what's needed
    (e.g. an unresolved flow), that captured output is the only diagnostic
    explaining why. It must be printed so it flows into both the real
    terminal and the dashboard's mirrored log."""

    def test_captured_subprocess_output_is_printed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = os.path.join(temp_dir, "phase.log")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                generator._run_scenarioforge_phase(
                    "new",
                    [sys.executable, "-c", "print('hello from the cli subprocess')"],
                    cwd=temp_dir, log_path=log_path,
                )
            self.assertIn("hello from the cli subprocess", buffer.getvalue())
            self.assertIn("scenarioforge.cli new output", buffer.getvalue())

    def test_captured_output_is_printed_even_on_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = os.path.join(temp_dir, "phase.log")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                with self.assertRaises(RuntimeError):
                    generator._run_scenarioforge_phase(
                        "flag-sequencing",
                        [sys.executable, "-c",
                         "import sys; print('partial resolution, 1 of 3 steps unresolved'); sys.exit(1)"],
                        cwd=temp_dir, log_path=log_path,
                    )
            self.assertIn("partial resolution, 1 of 3 steps unresolved", buffer.getvalue())


class AttackGraphFromFlowArtifactsDiagnosticsTests(unittest.TestCase):
    """When flag-sequencing exits 0 but its output has no attack_graph (e.g.
    a best-effort resolution that didn't actually resolve anything), the only
    explanation is inside that JSON's own ok/error fields — this must be
    printed before silently falling back to XML parsing, or the real cause
    is lost and only a generic 'No <FlowState> block found' error remains."""

    def test_prints_payload_diagnostics_before_falling_back_to_xml(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            xml_path = os.path.join(temp_dir, "scenario.xml")
            flow_path = os.path.join(temp_dir, "scenario_flag-sequencing.json")
            Path(xml_path).write_text(
                "<Scenarios><Scenario name='contract'><ScenarioEditor>"
                "<section name='Services'><item selected='SSH'/></section>"
                "</ScenarioEditor></Scenario></Scenarios>", encoding="utf-8",
            )
            Path(flow_path).write_text(json.dumps({
                "ok": False, "error": "best-effort resolution stalled: 0 of 2 steps resolved",
                "phase": "flag-sequencing",
            }), encoding="utf-8")

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                with self.assertRaises(ValueError):
                    generator._attack_graph_from_flow_artifacts(xml_path, flow_path)

            output = buffer.getvalue()
            self.assertIn("had no attack_graph", output)
            self.assertIn("best-effort resolution stalled: 0 of 2 steps resolved", output)

    def test_no_diagnostic_noise_when_attack_graph_is_present(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            xml_path = os.path.join(temp_dir, "scenario.xml")
            flow_path = os.path.join(temp_dir, "scenario_flag-sequencing.json")
            Path(flow_path).write_text(json.dumps({"attack_graph": _graph()}), encoding="utf-8")

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                graph, _graph_path = generator._attack_graph_from_flow_artifacts(xml_path, flow_path)

            self.assertNotIn("had no attack_graph", buffer.getvalue())
            self.assertEqual(graph["scenario"], "contract")


if __name__ == "__main__":
    unittest.main()
