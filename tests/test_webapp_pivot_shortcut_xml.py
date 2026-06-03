import xml.etree.ElementTree as ET

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
                                "pivot_provider": "ssh-fallback",
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
    assert item.get("pivot_provider") == "ssh-fallback"
    assert item.get("pivot_node") == "jump-web"
    assert item.get("target_node") == "internal-db"
    assert item.get("target_ports") == "5432"

    parsed = backend._parse_scenarios_xml(str(xml_path))
    seg_item = parsed["scenarios"][0]["sections"]["Segmentation"]["items"][0]
    assert seg_item["pivot_enabled"] is True
    assert seg_item["pivot_provider"] == "ssh-fallback"
    assert seg_item["pivot_node"] == "jump-web"
    assert seg_item["target_node"] == "internal-db"
    assert seg_item["target_ports"] == "5432"