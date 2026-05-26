from scenarioforge.utils.report import write_report


def test_report_includes_preview_parity_when_present(tmp_path):
    out = tmp_path / "rep.md"
    write_report(
        out_path=str(out),
        scenario_name="scen",
        routers=[],
        hosts=[],
        switches=[],
        router_protocols={},
        service_assignments={},
        metadata={"preview_attached": True, "preview_realized": True},
    )

    txt = out.read_text(encoding="utf-8")
    assert "Preview parity: attached=True realized=True" in txt


def test_report_uses_embedded_xml_as_preview_plan_reference(tmp_path):
    out = tmp_path / "rep.md"
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text('<Scenarios><Scenario name="scen"><ScenarioEditor /></Scenario></Scenarios>', encoding="utf-8")

    write_report(
        out_path=str(out),
        scenario_name="scen",
        routers=[],
        hosts=[],
        switches=[],
        router_protocols={},
        service_assignments={},
        metadata={"xml_path": str(xml_path), "preview_host_total": 1},
    )

    txt = out.read_text(encoding="utf-8")
    assert "| XML Path | Flow/Preview Plan |" in txt
    assert f"| {xml_path} | {xml_path} |" in txt
    assert f"| {xml_path} | n/a |" not in txt
