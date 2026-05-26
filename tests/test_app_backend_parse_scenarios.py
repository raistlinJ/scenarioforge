from pathlib import Path

from webapp import app_backend as backend


def test_parse_sample_xml_summary_counts():
    """The canonical Web UI parser can read the checked-in example XML."""
    sample_path = Path(__file__).resolve().parent.parent / "examples" / "sample.xml"
    result = backend._parse_scenarios_xml(str(sample_path))

    scenarios = result.get("scenarios") if isinstance(result, dict) else None
    assert isinstance(scenarios, list) and len(scenarios) == 1
    scenario = scenarios[0]
    assert scenario.get("name") == "Sample Scenario"
    assert scenario.get("scenario_total_nodes") == 0

    sections = scenario.get("sections") if isinstance(scenario, dict) else None
    assert isinstance(sections, dict)
    assert set(sections) >= {"Node Information", "Routing", "Services", "Traffic", "Segmentation"}
    assert all((section.get("items") or []) == [] for section in sections.values() if isinstance(section, dict))
