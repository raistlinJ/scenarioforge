"""Persist a reproducible default evaluation contract with a saved Flow."""

from copy import deepcopy

from .scaffold import draft_tasks, graph_from_flow


AUTO_SAVE_MARKER = "scenarioforge-flow-save-v1"


def auto_saved(tasks):
    """Return whether every task belongs to the Flow-save generated contract."""
    return bool(tasks) and all(
        isinstance(task, dict)
        and isinstance(task.get("challenge_plan"), dict)
        and isinstance(task["challenge_plan"].get("source"), dict)
        and task["challenge_plan"]["source"].get("auto_saved_by")
        == AUTO_SAVE_MARKER
        for task in tasks
    )


def readiness_checks(flow):
    checks = ["containers", "services", "ports"]
    assignments = [
        item
        for item in flow.get("flag_assignments", [])
        if isinstance(item, dict)
    ]
    if any(item.get("inject_files") for item in assignments):
        checks.append("injects")
    if any(
        any(
            str(value or "").startswith(("Pivot(", "pivot("))
            for value in list(item.get("produces") or [])
            + list(item.get("outputs") or [])
        )
        for item in assignments
    ):
        checks.append("flow_pivot")
    return checks


def _has_resolved_runtime(flow):
    assignments = flow.get("flag_assignments")
    if not isinstance(assignments, list) or not assignments:
        return False
    for assignment in assignments:
        if not isinstance(assignment, dict):
            continue
        outputs = assignment.get("resolved_outputs")
        if str(assignment.get("flag_value") or "").strip():
            return True
        if isinstance(outputs, dict) and outputs:
            return True
        if str(assignment.get("artifacts_dir") or assignment.get("run_dir") or "").strip():
            return True
    return False


def apply_default_tasks(flow, scenario, *, existing_tasks=None, explicit=False):
    """Attach or refresh generated tasks while preserving authored definitions.

    An explicit ``evaluation_tasks`` field always wins, including an empty list.
    Persisted definitions without our marker are considered authored. Generated
    definitions are removed when the Flow becomes unresolved and regenerated on
    the next resolved save.
    """
    result = deepcopy(flow)
    if explicit:
        return result, {"status": "explicit", "count": len(result.get("evaluation_tasks") or [])}
    if isinstance(existing_tasks, list) and existing_tasks and not auto_saved(existing_tasks):
        result["evaluation_tasks"] = deepcopy(existing_tasks)
        return result, {"status": "preserved-authored", "count": len(existing_tasks)}

    result.pop("evaluation_tasks", None)
    chain = result.get("chain")
    if (
        result.get("flow_enabled") is False
        or result.get("topology_dirty") is True
        or not isinstance(chain, list)
        or not chain
        or not _has_resolved_runtime(result)
    ):
        return result, {"status": "not-resolved", "count": 0}

    graph = graph_from_flow(result, scenario)
    tasks = draft_tasks(result, graph, checks=readiness_checks(result))
    for task in tasks:
        task["challenge_plan"]["source"]["auto_saved_by"] = AUTO_SAVE_MARKER
    result["evaluation_tasks"] = tasks
    return result, {"status": "generated", "count": len(tasks)}
