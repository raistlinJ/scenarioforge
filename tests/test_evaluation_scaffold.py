import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from scenarioforge.evaluation.scaffold import draft_tasks, graph_from_flow
from scenarioforge.evaluation.challenge_plan import validate_plan
from scenarioforge.evaluation.export import export_package


def fixture():
    flow = dict(
        chain=[
            dict(id="entry", name="Entry", ipv4="192.0.2.10"),
            dict(id="target", name="Target", ipv4="192.0.2.11"),
        ],
        flag_assignments=[
            dict(
                node_id="entry",
                flag_value="FLAG_ONE",
                resolved_outputs={"Credential(password)": "PASSWORD_ONE"},
            ),
            dict(
                node_id="target",
                flag_value="FLAG_TWO",
                requires=["Credential(password)"],
            ),
        ],
    )
    graph = graph_from_flow(flow, "Lab")
    return flow, graph


def test_draft_separates_private_references_and_maps_dependencies():
    flow, graph = fixture()
    tasks = draft_tasks(
        flow,
        graph,
        rendered_hints=[
            dict(node_id="entry", text="Inspect the login page."),
            dict(node_id="target", text="Use the credential."),
        ],
        rendered_solutions=[
            dict(node_id="entry", text="Recover FLAG_ONE. Future flag FLAG_TWO."),
            dict(node_id="target", text="Recover FLAG_TWO."),
        ],
    )
    task = tasks[0]
    assert (
        task["verification_mode"] == "judge"
        and "verifier" not in task
        and "flag_nodes" not in task
    )
    public = json.dumps(
        dict(
            prompt=task["prompt"],
            criteria=[
                {k: v for k, v in c.items() if k != "private_reference"}
                for c in task["rubric"]["criteria"]
            ],
        )
    )
    assert all(s not in public for s in ["FLAG_ONE", "FLAG_TWO", "PASSWORD_ONE"])
    steps = task["challenge_plan"]["steps"]
    assert steps[1]["requires"] == [steps[0]["id"]]
    assert "FLAG_ONE" in steps[0]["solution"] and "FLAG_TWO" not in steps[0]["solution"]
    assert "FLAG_TWO" in task["rubric"]["criteria"][1]["private_reference"]
    validate_plan(task["challenge_plan"], task["rubric"])


def test_native_export_preserves_scaffold_privately_and_each_solution(tmp_path):
    flow, graph = fixture()
    tasks = draft_tasks(flow, graph)
    xml = tmp_path / "scenario.xml"
    xml.write_text('<Scenarios><Scenario name="Lab"/></Scenarios>')
    export_package(
        xml_path=xml,
        graph=graph,
        definitions=tasks,
        output=tmp_path / "package",
        suite_id="draft-lab",
    )
    public = (tmp_path / "package/participant/tasks.json").read_text()
    assert (
        "FLAG_ONE" not in public
        and "FLAG_TWO" not in public
        and "challenge_plan" not in public
    )
    metadata = json.loads(
        (tmp_path / "package/evaluator/task-metadata.json").read_text()
    )["solve-scenario"]
    assert len(metadata["challenge_plan"]["steps"]) == 2
    solutions = metadata["challenge_solutions"]
    assert (
        len(solutions) == 2
        and "FLAG_ONE" in solutions[0]["text"]
        and "FLAG_TWO" not in solutions[0]["text"]
    )
    assert "FLAG_TWO" in solutions[1]["text"] and "FLAG_ONE" not in solutions[1]["text"]


def test_standalone_cli_scaffold(tmp_path, monkeypatch, capsys):
    from scenarioforge import cli

    flow, graph = fixture()
    xml = tmp_path / "lab.xml"
    xml.write_text('<Scenarios><Scenario name="Lab"/></Scenarios>')
    monkeypatch.setattr(
        cli,
        "_load_web_backend_module",
        lambda: SimpleNamespace(_attack_graph_for_chain=lambda **kw: graph),
    )
    monkeypatch.setattr(cli, "_cli_phase_scenario", lambda *a, **k: "Lab")
    monkeypatch.setattr(cli, "_flow_state_from_xml", lambda *a: flow)
    args = cli._build_cli_parser().parse_args(
        [
            "evaluation-scaffold",
            "--xml",
            str(xml),
            "--output-dir",
            str(tmp_path / "draft"),
        ]
    )
    assert cli._run_evaluation_scaffold_phase(args) == 0
    assert (
        json.loads((tmp_path / "draft/evaluation-tasks.json").read_text())[0][
            "verification_mode"
        ]
        == "judge"
    )
    assert (
        cli._run_evaluation_scaffold_phase(args) == 1
    )  # Never replace an authored draft.


def test_plan_contract_is_independent_and_identical():
    evaluator = (
        Path(__file__).resolve().parents[2]
        / "cyber-agent-flow-eval/cyber_agent_flow_eval/challenge_plan.py"
    )
    if evaluator.exists():
        assert (
            evaluator.read_bytes()
            == (
                Path(__file__).resolve().parents[1]
                / "scenarioforge/evaluation/challenge_plan.py"
            ).read_bytes()
        )


@pytest.mark.parametrize("change", ["cycle", "duplicate", "missing", "unknown"])
def test_invalid_milestone_mapping(change):
    flow, graph = fixture()
    task = draft_tasks(flow, graph, rendered_hints=[], rendered_solutions=[])[0]
    plan = task["challenge_plan"]
    if change == "cycle":
        plan["steps"][0]["requires"] = ["step-002"]
    elif change == "duplicate":
        plan["steps"][1]["criterion_ids"] = plan["steps"][0]["criterion_ids"]
    elif change == "missing":
        plan["steps"].pop()
    else:
        plan["steps"][0]["arbitrary_command"] = "whoami"
    with pytest.raises(ValueError):
        validate_plan(plan, task["rubric"])


def test_saved_guide_sections_are_scoped_and_unscoped_multi_step_guides_are_not_guessed():
    from scenarioforge.evaluation.scaffold import solutions_from_guide

    markdown = "## Step 1: Entry\nRead the entry.\n## Step 2: Target\nRead the target."
    rows = solutions_from_guide(markdown, ["entry", "target"])
    assert len(rows) == 2 and "Read the target" not in rows[0]["text"]
    html = "<html><body><script>PRIVATE_OTHER_ANSWER</script><details><summary>Step 1: Entry</summary><p>Read entry.</p></details><details><summary>Step 2: Target</summary><p>Read target.</p></details></body></html>"
    rows = solutions_from_guide(html, ["entry", "target"])
    assert (
        len(rows) == 2
        and "PRIVATE_OTHER_ANSWER" not in str(rows)
        and "Read target" not in rows[0]["text"]
    )
    assert solutions_from_guide("One whole unscoped guide", ["entry", "target"]) == []


def test_future_non_flag_answers_are_withheld_from_current_walkthrough():
    from scenarioforge.evaluation.hints import solutions_for_plan

    flow, graph = fixture()
    graph["nodes"][1]["generator"]["resolved_outputs"] = {
        "Token(value)": "FUTURE_TOKEN"
    }
    guides = [
        dict(node_id="entry", text="Recover FLAG_ONE. Next answer FUTURE_TOKEN."),
        dict(node_id="target", text="Recover FUTURE_TOKEN."),
    ]
    task = draft_tasks(flow, graph, rendered_hints=[], rendered_solutions=guides)[0]
    assert "FUTURE_TOKEN" not in task["challenge_plan"]["steps"][0]["solution"]
    solutions = solutions_for_plan(
        guides, graph, task["challenge_plan"], task["rubric"]
    )
    assert (
        "FUTURE_TOKEN" not in solutions[0]["text"]
        and "FUTURE_TOKEN" in solutions[1]["text"]
    )
