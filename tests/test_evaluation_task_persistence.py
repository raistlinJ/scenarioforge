import json

from scenarioforge.evaluation.task_persistence import (
    AUTO_SAVE_MARKER,
    apply_default_tasks,
    auto_saved,
)


def resolved_flow(secret="first-secret"):
    return {
        "flow_enabled": True,
        "topology_dirty": False,
        "chain_ids": ["node-1"],
        "chain": [{"id": "node-1", "name": "target"}],
        "flag_assignments": [
            {
                "node_id": "node-1",
                "id": "generator-1",
                "inject_files": ["proof.txt -> /tmp"],
                "produces": ["Pivot(node)"],
                "resolved_inputs": {"Knowledge(ip)": "10.77.0.10"},
                "resolved_outputs": {"Token(service)": secret},
            }
        ],
    }


def test_resolved_flow_gets_refreshable_saved_evaluation_task():
    saved, result = apply_default_tasks(resolved_flow(), "Training")
    assert result == {"status": "generated", "count": 1}
    assert auto_saved(saved["evaluation_tasks"])
    task = saved["evaluation_tasks"][0]
    assert task["challenge_plan"]["source"]["auto_saved_by"] == AUTO_SAVE_MARKER
    assert task["required_checks"] == [
        "containers",
        "services",
        "ports",
        "injects",
        "flow_pivot",
    ]
    assert "10.77.0.10" in task["rubric"]["criteria"][0]["requirement"]

    refreshed, result = apply_default_tasks(
        resolved_flow("replacement-secret"),
        "Training",
        existing_tasks=task and saved["evaluation_tasks"],
    )
    assert result["status"] == "generated"
    encoded = json.dumps(refreshed["evaluation_tasks"])
    assert "replacement-secret" in encoded and "first-secret" not in encoded


def test_authored_or_explicit_tasks_are_never_replaced():
    authored = [{"id": "reviewed", "prompt": "Perform the reviewed objective."}]
    preserved, result = apply_default_tasks(
        resolved_flow(), "Training", existing_tasks=authored
    )
    assert result == {"status": "preserved-authored", "count": 1}
    assert preserved["evaluation_tasks"] == authored

    explicit = resolved_flow()
    explicit["evaluation_tasks"] = []
    cleared, result = apply_default_tasks(
        explicit, "Training", existing_tasks=authored, explicit=True
    )
    assert result == {"status": "explicit", "count": 0}
    assert cleared["evaluation_tasks"] == []


def test_unresolved_flow_removes_only_previous_generated_tasks():
    saved, _ = apply_default_tasks(resolved_flow(), "Training")
    dirty = resolved_flow()
    dirty["topology_dirty"] = True
    updated, result = apply_default_tasks(
        dirty, "Training", existing_tasks=saved["evaluation_tasks"]
    )
    assert result == {"status": "not-resolved", "count": 0}
    assert "evaluation_tasks" not in updated

    unresolved = resolved_flow()
    unresolved["flag_assignments"] = [{"node_id": "node-1", "id": "generator-1"}]
    updated, result = apply_default_tasks(unresolved, "Training")
    assert result == {"status": "not-resolved", "count": 0}
    assert "evaluation_tasks" not in updated
