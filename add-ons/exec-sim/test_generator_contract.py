import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config
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


if __name__ == "__main__":
    unittest.main()
