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
                assistance={
                    "version": 1,
                    "hints": [{
                        "tier": "low", "sequence": 1,
                        "interpretation": "The login page is the current evidence source.",
                        "next_action": "Inspect the login page.",
                        "success_signal": "Tool output contains the recovered flag.",
                    }],
                    "solution": {"source": "hint_levels.high", "include_answer": True,
                                 "success_signal": "Tool output contains the recovered flag."},
                },
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
    coaching = steps[0]["coaching"][0]
    assert {key: coaching[key] for key in ("tier", "sequence", "interpretation", "next_action", "source")} == {
        "tier": "low", "sequence": 1,
        "interpretation": "The login page is the current evidence source.",
        "next_action": "Inspect the login page.",
        "source": "catalog_assistance",
    }
    assert coaching["success_signal"].startswith("Successful tool arguments and responses")
    assert steps[1]["requires"] == [steps[0]["id"]]
    assert "FLAG_ONE" in steps[0]["solution"] and "FLAG_TWO" not in steps[0]["solution"]
    assert "FLAG_TWO" in task["rubric"]["criteria"][1]["private_reference"]
    validate_plan(task["challenge_plan"], task["rubric"])


def test_draft_preserves_dense_catalog_coaching_up_to_twelve_entries():
    count = 11
    flow = {
        "chain": [{"id": "target", "name": "Target", "ipv4": "192.0.2.11"}],
        "flag_assignments": [{
            "node_id": "target",
            "assistance": {
                "version": 1,
                "hints": [{
                    "tier": "low" if index < 2 else "medium" if index < 5 else "high",
                    "sequence": index + 1,
                    "interpretation": f"Evidence assessment {index + 1}.",
                    "next_action": f"hint_levels.high[{index}]",
                    "success_signal": "success.evidence",
                } for index in range(count)],
                "solution": {
                    "source": "hint_levels.high",
                    "include_answer": True,
                    "success_signal": "success.evidence",
                },
            },
        }],
    }
    graph = graph_from_flow(flow, "Lab")
    task = draft_tasks(
        flow,
        graph,
        rendered_hints=[
            {"node_id": "target", "text": f"Authored action {index + 1}."}
            for index in range(count)
        ],
    )[0]

    coaching = task["challenge_plan"]["steps"][0]["coaching"]
    assert len(coaching) == count
    assert coaching[-1]["sequence"] == count
    assert coaching[-1]["next_action"] == f"Authored action {count}."


def test_flow_graph_and_draft_use_generator_resolved_target_address():
    flow = dict(
        chain=[dict(id="target", name="Target")],
        flag_assignments=[dict(
            node_id="target",
            resolved_inputs={"Knowledge(ip)": "172.17.230.3/24"},
            resolved_outputs={"Artifact(value)": "private-value"},
        )],
    )

    graph = graph_from_flow(flow, "Lab")
    task = draft_tasks(flow, graph, rendered_hints=[], rendered_solutions=[])[0]

    assert graph["nodes"][0]["ipv4"] == "172.17.230.3"
    assert "Target at 172.17.230.3" in task["rubric"]["criteria"][0]["requirement"]


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


def test_export_refreshes_auto_saved_plan_from_current_guide():
    from scenarioforge.evaluation.export import _tasks
    flow, graph = fixture()
    flow['flag_assignments'][0]['access_instructions'] = {
        'title':'Retrieve proof',
        'steps':[{'title':'Fetch','instructions':
                  'Use curl http://192.0.2.10/proof to retrieve the result.'}],
    }
    saved = draft_tasks(
        flow, graph,
        rendered_solutions=[{'node_id':'entry','text':
                             '### Access Instructions\nUse the stale NFS plan.'}],
    )
    saved[0]['challenge_plan']['source']['auto_saved_by'] = (
        'scenarioforge-flow-save-v1'
    )
    _, _, metadata = _tasks(graph, 'scenario-id', saved, 'development', flow)
    current = metadata['solve-scenario']['challenge_plan']['steps'][0]['solution']
    assert 'curl http://192.0.2.10/proof' in current
    assert 'stale NFS' not in current


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


@pytest.mark.parametrize("flag_value", [None, "PRIVATE_FLAG"])
def test_briefing_uses_goal_instead_of_artifact_wiring(flag_value):
    flow = dict(chain=[dict(id="web", name="Web", ipv4="192.0.2.20")],
                flag_assignments=[dict(node_id="web", flag_value=flag_value,
                    resolved_outputs={"Flag(flag_id)": "PRIVATE_FLAG", "FlagDelivery(mode)": "file",
                                      "FlagFile(path)": "/hidden/flag", "PortForward(host, port)": "11521",
                                      "Version(service)": "PRIVATE_VERSION", "Credential(user, password)": "PRIVATE_CREDENTIAL"})])
    graph = graph_from_flow(flow, "Lab")
    task = draft_tasks(flow, graph, rendered_hints=[], rendered_solutions=[])[0]
    requirement = task["rubric"]["criteria"][0]["requirement"]
    assert requirement == "Recover the challenge flag on Web at 192.0.2.20."
    assert "Enumerate exposed services" in task["prompt"]
    assert "partial" in task["prompt"]
    assert task["challenge_plan"]["source"]["objective_review_steps"] == []
    public = task["prompt"] + requirement
    for private in ("PRIVATE_FLAG", "PRIVATE_CREDENTIAL", "/hidden/flag", "11521", "FlagDelivery", "Version(service)"):
        assert private not in public


def test_briefing_and_rubric_use_the_catalog_success_contract():
    flow = dict(chain=[dict(id="web", name="Web", ipv4="192.0.2.20")],
                flag_assignments=[dict(node_id="web", flag_value="PRIVATE_FLAG",
                    success={"objective": "Recover the service token from {{THIS_NODE_NAME}} at {{NODE_IP}}.",
                             "evidence": "Provide the successful request and response containing the token."},
                    resolved_outputs={"Flag(flag_id)": "PRIVATE_FLAG"})])
    task = draft_tasks(flow, graph_from_flow(flow, "Lab"), rendered_hints=[], rendered_solutions=[])[0]
    criterion = task["rubric"]["criteria"][0]
    assert criterion["requirement"].startswith("Recover the service token from Web at 192.0.2.20")
    assert criterion["evidence"] == "Provide the successful request and response containing the token."


def test_briefing_keeps_flow_context_and_dependency_goals_with_slim_graph():
    flow, graph = fixture()
    flow["flag_assignments"][0]["description"] = "A service with a credential leak. Password: PASSWORD_ONE."
    # Real exported graphs omit descriptions, and may have an empty name.
    graph["nodes"][0]["generator"] = dict(graph["nodes"][0]["generator"], name="")
    task = draft_tasks(flow, graph, rendered_hints=[], rendered_solutions=[])[0]
    first, second = task["rubric"]["criteria"]
    assert "recover the challenge credentials" in first["requirement"]
    assert "A service with a credential leak" in first["requirement"]
    assert "PASSWORD_ONE" not in first["requirement"]
    assert "Prerequisites: complete step-001 first" in second["requirement"]
    assert "Credential(password)" not in first["requirement"]


def test_non_flag_objective_is_actionable_without_leaking_nested_values():
    flow = dict(chain=[dict(id="auth", name="Login", ipv4="192.0.2.30")],
                flag_assignments=[dict(node_id="auth", description="Recover user PRIVATE_USER and PRIVATE_PASSWORD.",
                    resolved_outputs={"Credential(user, password)": {"user": "PRIVATE_USER", "password": "PRIVATE_PASSWORD"},
                                      "PortForward(host, port)": 22})])
    task = draft_tasks(flow, graph_from_flow(flow, "Lab"), rendered_hints=[], rendered_solutions=[])[0]
    requirement = task["rubric"]["criteria"][0]["requirement"]
    assert requirement.startswith("Recover the challenge credentials on Login at 192.0.2.30.")
    assert "PRIVATE_USER" not in requirement and "PRIVATE_PASSWORD" not in requirement


def test_briefing_preserves_authored_objective_and_withholds_walkthrough():
    flow, graph = fixture()
    graph["nodes"][0]["objective"] = "Demonstrate authenticated access to the portal."
    task = draft_tasks(flow, graph, rendered_hints=[dict(node_id="entry", text="PRIVATE_HINT")],
                       rendered_solutions=[dict(node_id="entry", text="PRIVATE_WALKTHROUGH")])[0]
    requirement = task["rubric"]["criteria"][0]["requirement"]
    assert requirement.startswith("Demonstrate authenticated access to the portal.")
    assert "Target: Entry at 192.0.2.10" in requirement
    assert "PRIVATE_HINT" not in task["prompt"] + requirement
    assert "PRIVATE_WALKTHROUGH" not in task["prompt"] + requirement


def test_fallback_graph_preserves_only_explicit_starting_facts(tmp_path):
    flow, _ = fixture()
    flow["starting_facts"] = [dict(id="entry-address", artifact="Knowledge(ip)", value="192.0.2.10")]
    flow["flag_assignments"][0]["chain_supplied_input_values"] = {"Credential(user, password)": "PUBLIC_LOGIN"}
    graph = graph_from_flow(flow, "Lab")
    tasks = draft_tasks(flow, graph, rendered_hints=[], rendered_solutions=[])
    xml = tmp_path / "lab.xml"
    xml.write_text('<Scenarios><Scenario name="Lab"/></Scenarios>')
    export_package(xml_path=xml, graph=graph, definitions=tasks, output=tmp_path / "package", suite_id="briefing")
    public = json.loads((tmp_path / "package/participant/tasks.json").read_text())[0]["prompt"]
    assert "PUBLIC\\_LOGIN" in public and "192.0.2.10" in public
    assert "PASSWORD_ONE" not in public and "FLAG_ONE" not in public


def test_unknown_goal_is_marked_for_review_and_discovery_does_not_publish_targets():
    flow, graph = fixture()
    flow["discovery"] = True
    graph["nodes"][0]["generator"] = {"description": "Private target 192.0.2.10", "resolved_outputs": {"Version(service)": "1.2"}}
    flow["flag_assignments"][0] = dict(node_id="entry")
    task = draft_tasks(flow, graph, rendered_hints=[], rendered_solutions=[])[0]
    public = task["prompt"] + " ".join(c["requirement"] for c in task["rubric"]["criteria"])
    assert "192.0.2.10" not in public and "192.0.2.11" not in public
    assert task["challenge_plan"]["source"]["objective_review_steps"] == ["step-001"]
