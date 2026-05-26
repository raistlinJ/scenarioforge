from webapp import app_backend as backend


def test_collect_scenario_catalog_discovers_display_named_saved_xml(monkeypatch, tmp_path):
    outdir = tmp_path / 'outputs'
    scen_dir_one = outdir / 'scenarios-01'
    scen_dir_two = outdir / 'scenarios-02'
    scen_dir_one.mkdir(parents=True, exist_ok=True)
    scen_dir_two.mkdir(parents=True, exist_ok=True)

    scenario1_xml = scen_dir_one / 'Scenario1.xml'
    scenario2_xml = scen_dir_two / 'NewScenario2.xml'
    scenario1_xml.write_text(
        '<Scenarios><Scenario name="Scenario1"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )
    scenario2_xml.write_text(
        '<Scenarios><Scenario name="NewScenario2"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )
    (outdir / 'scenario_catalog.json').write_text(
        '{"names":["NewScenario2"],"sources":{"NewScenario2":"' + str(scenario2_xml) + '"}}',
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, '_load_run_history', lambda: [])

    names, paths, _hints = backend._scenario_catalog_for_user(None, user=None)

    assert set(names) == {'Scenario1', 'NewScenario2'}
    assert str(scenario1_xml) in paths.get('scenario1', set())
    assert str(scenario2_xml) in paths.get('newscenario2', set())


def test_deleted_scenario_tombstone_blocks_rediscovered_saved_xml(monkeypatch, tmp_path):
    outdir = tmp_path / 'outputs'
    snapdir = outdir / 'editor_snapshots'
    scen_dir = outdir / 'scenarios-01'
    snapdir.mkdir(parents=True, exist_ok=True)
    scen_dir.mkdir(parents=True, exist_ok=True)

    scenario3_xml = scen_dir / 'Scenario3-2.xml'
    scenario3_xml.write_text(
        '<Scenarios><Scenario name="Scenario3"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )
    new_scenario_xml = scen_dir / 'NewScenario2.xml'
    new_scenario_xml.write_text(
        '<Scenarios><Scenario name="NewScenario2"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )
    (outdir / 'scenario_catalog.json').write_text(
        '{"names":["NewScenario2"],"sources":{"NewScenario2":"' + str(new_scenario_xml) + '"}}',
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))
    monkeypatch.setattr(backend, '_editor_state_snapshot_dir', lambda: str(snapdir))
    monkeypatch.setattr(backend, '_load_run_history', lambda: [])

    names_before, _paths_before, _hints_before = backend._scenario_catalog_for_user(None, user=None)
    assert set(names_before) == {'Scenario3', 'NewScenario2'}

    result = backend._remove_scenarios_from_catalog(['Scenario3'])
    assert result['remaining'] == 1

    names_after, paths_after, _hints_after = backend._scenario_catalog_for_user(None, user=None)
    assert names_after == ['NewScenario2']
    assert str(new_scenario_xml) in paths_after.get('newscenario2', set())
    assert scenario3_xml.exists()


def test_delete_saved_scenario_xml_artifacts_removes_display_derived_suffix(monkeypatch, tmp_path):
    outdir = tmp_path / 'outputs'
    scen_dir = outdir / 'scenarios-01'
    scen_dir.mkdir(parents=True, exist_ok=True)
    scenario3_xml = scen_dir / 'Scenario3-2.xml'
    scenario3_xml.write_text(
        '<Scenarios><Scenario name="Scenario3"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )

    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    result = backend._delete_saved_scenario_xml_artifacts(['Scenario3'])

    assert result['artifacts_removed'] == 1
    assert not scenario3_xml.exists()


def test_merge_catalog_scenario_stubs_filters_deleted_payload_entries(monkeypatch, tmp_path):
    outdir = tmp_path / 'outputs'
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / 'scenario_catalog.json').write_text(
        '{"names":["NewScenario2"],"deleted_name_keys":["scenario3"]}',
        encoding='utf-8',
    )
    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(outdir))

    payload = {
        '_filter_deleted_scenarios': True,
        'scenario_catalog_names': ['NewScenario2', 'Scenario3'],
        'scenarios': [
            {'name': 'NewScenario2', 'sections': {'Node Information': {'items': []}}, 'density_count': 10},
            {'name': 'Scenario3', 'sections': {'Node Information': {'items': []}}, 'density_count': 10},
        ],
    }

    out = backend._merge_catalog_scenario_stubs_into_payload(payload)
    names = [str((s or {}).get('name') or '') for s in (out.get('scenarios') or []) if isinstance(s, dict)]

    assert names == ['NewScenario2']
    assert out.get('scenario_catalog_names') == ['NewScenario2']


def test_prepare_payload_includes_catalog_scenario_stubs(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda history, user=None: (
            ['NewScenario1', 'NewScenario12'],
            {'newscenario1': {'/tmp/NewScenario1.xml'}, 'newscenario12': {'/tmp/NewScenario12.xml'}},
            {},
        ),
    )

    payload = {
        'scenarios': [
            {
                'name': 'NewScenario1',
                'sections': {
                    'Node Information': {'items': []},
                },
                'density_count': 10,
            }
        ]
    }

    out = backend._prepare_payload_for_index(payload, user=None)
    names = [str((s or {}).get('name') or '') for s in (out.get('scenarios') or []) if isinstance(s, dict)]

    assert 'NewScenario1' in names
    assert 'NewScenario12' in names


def test_merge_catalog_scenario_stubs_into_payload_adds_missing_names():
    payload = {
        'scenario_catalog_names': ['NewScenario1', 'NewScenario12'],
        'scenarios': [
            {
                'name': 'NewScenario1',
                'sections': {'Node Information': {'items': []}},
                'density_count': 10,
            }
        ],
    }

    out = backend._merge_catalog_scenario_stubs_into_payload(payload)
    names = [str((s or {}).get('name') or '') for s in (out.get('scenarios') or []) if isinstance(s, dict)]

    assert 'NewScenario1' in names
    assert 'NewScenario12' in names


def test_normalize_scenario_names_strict_uses_next_available_scenario_number():
    scenarios = [
        {'name': 'Scenario1'},
        {'name': 'Scenario2'},
        {'name': 'Scenario2'},
    ]

    backend._normalize_scenario_names_strict(scenarios)

    assert [s['name'] for s in scenarios] == ['Scenario1', 'Scenario2', 'Scenario3']


def test_sort_scenario_display_names_uses_natural_scenario_order():
    names = ['Scenario10', 'Scenario2', 'Scenario1', 'Scenario2']

    assert backend._sort_scenario_display_names(names) == ['Scenario1', 'Scenario2', 'Scenario10']


def test_prepare_payload_orders_scenarios_with_sorted_catalog(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda history, user=None: (
            ['Scenario10', 'Scenario2', 'Scenario1'],
            {'scenario10': set(), 'scenario2': set(), 'scenario1': set()},
            {},
        ),
    )

    payload = {
        'scenarios': [
            {'name': 'Scenario10', 'sections': {'Node Information': {'items': []}}, 'density_count': 10},
            {'name': 'Scenario1', 'sections': {'Node Information': {'items': []}}, 'density_count': 10},
            {'name': 'Scenario2', 'sections': {'Node Information': {'items': []}}, 'density_count': 10},
        ],
    }

    out = backend._prepare_payload_for_index(payload, user=None)
    names = [str((s or {}).get('name') or '') for s in (out.get('scenarios') or []) if isinstance(s, dict)]

    assert names == ['Scenario1', 'Scenario2', 'Scenario10']


def test_prepare_payload_preserves_hitl_proxmox_validation_state(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda history, user=None: (
            ['Anatest'],
            {'anatest': {'/tmp/Anatest.xml'}},
            {},
        ),
    )

    payload = {
        'scenarios': [
            {
                'name': 'Anatest',
                'density_count': 10,
                'sections': {'Node Information': {'items': []}},
                'hitl': {
                    'enabled': True,
                    'proxmox': {
                        'url': 'https://proxmox.local',
                        'port': 8006,
                        'verify_ssl': False,
                        'secret_id': 'prox-secret-1',
                        'validated': True,
                        'last_validated_at': '2026-03-03T00:00:00',
                    },
                },
            }
        ]
    }

    out = backend._prepare_payload_for_index(payload, user=None)
    scenarios = out.get('scenarios') if isinstance(out.get('scenarios'), list) else []
    anatest = next((s for s in scenarios if isinstance(s, dict) and str(s.get('name') or '') == 'Anatest'), {})
    hitl = anatest.get('hitl') if isinstance(anatest.get('hitl'), dict) else {}
    prox = hitl.get('proxmox') if isinstance(hitl.get('proxmox'), dict) else {}

    assert prox.get('secret_id') == 'prox-secret-1'
    assert prox.get('validated') is True
    assert prox.get('url') == 'https://proxmox.local'


def test_prepare_payload_admin_merges_hitl_hints_when_scenario_missing_fields(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_scenario_catalog_for_user',
        lambda history, user=None: (
            ['Anatest'],
            {'anatest': {'/tmp/Anatest.xml'}},
            {},
        ),
    )
    monkeypatch.setattr(
        backend,
        '_load_scenario_hitl_validation_from_disk',
        lambda: {
            'anatest': {
                'proxmox': {'secret_id': 'prox-secret-1', 'validated': True},
                'core': {'core_secret_id': 'core-secret-1', 'validated': True, 'vm_key': 'pve::101'},
            }
        },
    )
    monkeypatch.setattr(backend, '_load_scenario_hitl_config_from_disk', lambda: {})

    payload = {
        'scenarios': [
            {
                'name': 'Anatest',
                'sections': {'Node Information': {'items': []}},
                'density_count': 10,
                'hitl': {'enabled': True},
            }
        ]
    }

    out = backend._prepare_payload_for_index(payload, user=None)
    scenarios = out.get('scenarios') if isinstance(out.get('scenarios'), list) else []
    anatest = next((s for s in scenarios if isinstance(s, dict) and str(s.get('name') or '') == 'Anatest'), {})
    hitl = anatest.get('hitl') if isinstance(anatest.get('hitl'), dict) else {}
    prox = hitl.get('proxmox') if isinstance(hitl.get('proxmox'), dict) else {}
    core = hitl.get('core') if isinstance(hitl.get('core'), dict) else {}

    assert prox.get('secret_id') == 'prox-secret-1'
    assert prox.get('validated') is True
    assert core.get('core_secret_id') == 'core-secret-1'
    assert core.get('validated') is True


def test_sanitize_hitl_config_hint_preserves_external_interface_metadata():
    hint = backend._sanitize_hitl_config_hint({
        'enabled': True,
        'participant_proxmox_url': 'https://participant.local:8006',
        'interfaces': [
            {
                'name': 'eth1',
                'attachment': 'proxmox_vm',
                'external_vm': {
                    'vm_key': 'pve1::202',
                    'vmid': '202',
                    'vm_node': 'pve1',
                    'vm_name': 'External',
                    'status': 'running',
                    'interface_id': 'net1',
                    'interface_bridge': 'vmbr0',
                    'interface_mac': 'aa:bb:cc:dd:ee:ff',
                    'interface_model': 'virtio',
                },
                'proxmox_target': {
                    'node': 'pve1',
                    'vmid': '101',
                    'interface_id': 'net0',
                    'vm_name': 'CORE-VM',
                    'label': 'CORE-VM',
                    'macaddr': '11:22:33:44:55:66',
                    'bridge': 'vmbr1',
                    'model': 'virtio',
                },
            }
        ],
    })

    assert isinstance(hint, dict)
    interfaces = hint.get('interfaces') if isinstance(hint.get('interfaces'), list) else []
    assert len(interfaces) == 1
    ext = interfaces[0].get('external_vm') if isinstance(interfaces[0].get('external_vm'), dict) else {}
    assert ext.get('status') == 'running'
    assert ext.get('interface_bridge') == 'vmbr0'
    assert ext.get('interface_mac') == 'aa:bb:cc:dd:ee:ff'
    assert ext.get('interface_model') == 'virtio'
    prox_target = interfaces[0].get('proxmox_target') if isinstance(interfaces[0].get('proxmox_target'), dict) else {}
    assert prox_target.get('label') == 'CORE-VM'
