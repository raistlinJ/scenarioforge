from pathlib import Path
import xml.etree.ElementTree as ET

from webapp import app_backend as backend


def test_preexecute_xml_resolution_preserves_explicit_selected_xml(tmp_path, monkeypatch):
    selected = tmp_path / 'selected.xml'
    newer_same_name = tmp_path / 'newer.xml'
    selected.write_text('<Scenarios />', encoding='utf-8')
    newer_same_name.write_text('<Scenarios />', encoding='utf-8')
    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(newer_same_name))

    resolved = backend._resolve_preexecute_xml_path(str(selected), 'Scenario1')

    assert resolved == str(selected.resolve())


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


def test_build_and_parse_xml_round_trips_core_password_fields(tmp_path):
    payload = {
        'core': {
            'host': '10.0.0.10',
            'port': 50051,
            'ssh_host': '10.0.0.11',
            'ssh_port': 22,
            'ssh_username': 'corevm',
            'ssh_password': 'pw123',
            'venv_bin': '/opt/core/venv/bin',
        },
        'scenarios': [
            {
                'name': 'Scenario 1',
                'hitl': {
                    'enabled': True,
                    'interfaces': [{'name': 'ens19', 'attachment': 'existing_router'}],
                    'core': {
                        'host': '10.0.0.10',
                        'port': 50051,
                        'ssh_host': '10.0.0.11',
                        'ssh_port': 22,
                        'ssh_username': 'corevm',
                        'ssh_password': 'pw123',
                    },
                },
                'sections': {
                    'Node Information': {'total_nodes': 1, 'items': []},
                    'Routing': {'density': 0.0, 'items': []},
                    'Services': {'density': 0.0, 'items': []},
                    'Traffic': {'density': 0.0, 'items': []},
                    'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
                    'Segmentation': {'density': 0.0, 'items': []},
                },
            }
        ],
    }

    xml_path = tmp_path / 'scenario.xml'
    tree = backend._build_scenarios_xml(payload)
    tree.write(xml_path, encoding='utf-8', xml_declaration=True)

    raw_root = ET.parse(xml_path).getroot()
    top_core = raw_root.find('CoreConnection')
    assert top_core is not None
    assert top_core.get('ssh_password') == 'pw123'
    hitl_core = raw_root.find('.//HardwareInLoop/CoreConnection')
    assert hitl_core is not None
    assert hitl_core.get('ssh_password') == 'pw123'

    parsed = backend._parse_scenarios_xml(str(xml_path))
    assert parsed['core']['ssh_password'] == 'pw123'
    hitl = parsed['scenarios'][0]['hitl']
    assert hitl['core']['ssh_password'] == 'pw123'
