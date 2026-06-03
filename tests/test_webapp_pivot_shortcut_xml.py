import xml.etree.ElementTree as ET

from scenarioforge.parsers.pivoting import parse_pivoting_info
from scenarioforge.planning.orchestrator import compute_full_plan
from webapp import app_backend as backend


def test_webapp_round_trips_segmentation_pivot_shortcut(tmp_path):
    payload = {
        "scenarios": [
            {
                "name": "Pivot Demo",
                "density_count": 2,
                "sections": {
                    "Node Information": {
                        "items": [{"selected": "PC", "factor": 1.0, "v_metric": "Count", "v_count": 2}],
                    },
                    "Segmentation": {
                        "density": 1.0,
                        "items": [
                            {
                                "selected": "Firewall",
                                "factor": 1.0,
                                "v_metric": "Count",
                                "v_count": 1,
                                "pivot_enabled": True,
                                "pivot_provider": "random",
                                "pivot_node": "jump-web",
                                "target_node": "internal-db",
                                "target_ports": "5432",
                                "target_protocols": "tcp",
                                "target_exposure": "pivot-only",
                                "source_scope": "host",
                            }
                        ],
                    },
                },
            }
        ]
    }

    tree = backend._build_scenarios_xml(payload)
    xml_path = tmp_path / "scenario.xml"
    tree.write(xml_path, encoding="utf-8", xml_declaration=True)

    root = ET.parse(xml_path).getroot()
    item = root.find(".//section[@name='Segmentation']/item")
    assert item is not None
    assert item.get("pivot_enabled") == "true"
    assert item.get("pivot_provider") == "random"
    assert item.get("pivot_node") is None
    assert item.get("target_node") is None
    assert item.get("target_ports") is None
    assert item.get("target_protocols") is None
    assert item.get("target_exposure") is None
    assert item.get("source_scope") is None

    parsed = backend._parse_scenarios_xml(str(xml_path))
    seg_item = parsed["scenarios"][0]["sections"]["Segmentation"]["items"][0]
    assert seg_item["pivot_enabled"] is True
    assert seg_item["pivot_provider"] == "random"
    assert "pivot_node" not in seg_item
    assert "target_node" not in seg_item
    assert "target_ports" not in seg_item

    density, pivot_items = parse_pivoting_info(str(xml_path), "Pivot Demo")
    assert density == 1.0
    assert len(pivot_items) == 1
    assert pivot_items[0].access_provider == "random"
    assert pivot_items[0].pivot_node == ""
    assert pivot_items[0].target_node == ""

    plan = compute_full_plan(str(xml_path), scenario="Pivot Demo", seed=123)
    pivoting = ((plan.get("breakdowns") or {}).get("pivoting") or {})
    assert pivoting.get("items_count") == 1
    raw_items = pivoting.get("raw_items_serialized") or []
    assert raw_items[0].get("access_provider") == "random"
    assert raw_items[0].get("pivot_node") == ""
    assert raw_items[0].get("target_node") == ""