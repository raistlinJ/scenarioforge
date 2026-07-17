from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_scenario_editor_cards_use_a_stable_requested_order() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_order = [
        "'Node Information'",
        "'Services'",
        "'Routing'",
        "'Traffic'",
        "'Segmentation'",
        "'Flag Node Generators'",
        "'Vulnerabilities'",
    ]
    start = text.index("const scenarioEditorSectionOrder = [")
    end = text.index("];", start)
    order_block = text[start:end]
    positions = [order_block.index(name) for name in expected_order]

    assert positions == sorted(positions)
    assert ".filter(name => !scenarioEditorSectionOrder.includes(name))" in text
