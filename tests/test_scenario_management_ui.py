from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_scenario_add_uses_next_available_scenario_number() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const candidate = `Scenario${candidateNumber}`;",
        "const newScenarioName = nextAvailableScenarioName(state.scenarios);",
        "const newScenario = defaultScenario(newScenarioName);",
        "const finalName = normalizeScenarioName(trimmed || `Scenario${sidx + 1}`);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing ScenarioN naming snippets: " + "; ".join(missing)


def test_snapshot_merge_appends_snapshot_only_scenarios() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const mergedKeys = new Set(",
        "snapScenarios.forEach((snapScen) => {",
        "state.scenarios.push(snapScen);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing snapshot-only scenario merge snippets: " + "; ".join(missing)
