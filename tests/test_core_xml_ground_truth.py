import xml.etree.ElementTree as ET

from webapp import app_backend


def test_update_core_config_in_xml_replaces_global_and_scenario_targets(tmp_path):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text(
        '''<?xml version="1.0"?>
<Scenarios>
  <CoreConnection host="127.0.0.1" port="50051" ssh_enabled="true"
                  ssh_host="old.example" ssh_port="9001" ssh_username="core"/>
  <Scenario name="Scenario One">
    <ScenarioEditor>
      <BaseScenario filepath="/tmp/base.xml"/>
      <HardwareInLoop enabled="true">
        <CoreConnection host="localhost" port="50051" ssh_enabled="true"
                        ssh_host="old.example" ssh_port="9001" ssh_username="core"
                        core_secret_id="old-secret" vm_key="old::1"/>
        <Interface name="ens19"/>
      </HardwareInLoop>
      <PlanPreview>{"keep":true}</PlanPreview>
    </ScenarioEditor>
  </Scenario>
</Scenarios>
''',
        encoding='utf-8',
    )

    ok, message = app_backend._update_core_config_in_xml(
        str(xml_path),
        'Scenario One',
        {
            'host': 'localhost',
            'port': 50051,
            'ssh_enabled': True,
            'ssh_host': 'new.example',
            'ssh_port': 9012,
            'ssh_username': 'corevm',
            'ssh_password': 'embedded-password',
            'core_secret_id': 'scenario-one-secret',
            'vm_key': 'node::722986',
            'vm_name': 'scenarioforge-core-test-2',
            'validated': True,
            'proxmox_target': {'node': 'node', 'vmid': 722986},
        },
    )

    assert ok is True, message
    root = ET.parse(xml_path).getroot()
    global_core = root.find('CoreConnection')
    scenario_core = root.find('./Scenario/ScenarioEditor/HardwareInLoop/CoreConnection')
    assert global_core is not None
    assert scenario_core is not None
    for core_el in (global_core, scenario_core):
        assert core_el.get('ssh_host') == 'new.example'
        assert core_el.get('ssh_port') == '9012'
        assert core_el.get('ssh_username') == 'corevm'
        assert core_el.get('core_secret_id') == 'scenario-one-secret'
        assert core_el.get('vm_key') == 'node::722986'
        assert core_el.get('validated') == 'true'
        assert core_el.get('ssh_password') == 'embedded-password'
    assert root.find('./Scenario/ScenarioEditor/HardwareInLoop/Interface').get('name') == 'ens19'
    assert root.find('./Scenario/ScenarioEditor/PlanPreview').text == '{"keep":true}'
    assert xml_path.stat().st_mode & 0o777 == 0o600


def test_fill_matching_core_credentials_never_changes_xml_identity():
    xml_cfg = {
        'ssh_host': 'core.example',
        'ssh_port': 9001,
        'ssh_username': 'corevm',
        'core_secret_id': 'secret-1',
        'vm_key': 'node::1',
    }
    matching_secret = {
        'ssh_host': 'other.example',
        'ssh_port': 9012,
        'ssh_username': 'different',
        'ssh_password': 'pw',
        'core_secret_id': 'secret-1',
        'vm_key': 'node::2',
    }

    result = app_backend._fill_matching_core_credentials(xml_cfg, matching_secret)

    assert result['ssh_password'] == 'pw'
    assert result['ssh_host'] == 'core.example'
    assert result['ssh_port'] == 9001
    assert result['ssh_username'] == 'corevm'
    assert result['vm_key'] == 'node::1'


def test_fill_matching_core_credentials_rejects_unrelated_saved_target():
    xml_cfg = {
        'ssh_host': 'core-a.example',
        'ssh_port': 9001,
        'ssh_username': 'corevm',
        'core_secret_id': 'secret-a',
    }
    unrelated = {
        'ssh_host': 'core-b.example',
        'ssh_port': 9012,
        'ssh_username': 'corevm',
        'ssh_password': 'wrong-target-password',
        'core_secret_id': 'secret-b',
    }

    result = app_backend._fill_matching_core_credentials(xml_cfg, unrelated)

    assert result == xml_cfg
    assert 'ssh_password' not in result
