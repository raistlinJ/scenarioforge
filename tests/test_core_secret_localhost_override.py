from webapp import app_backend


def test_apply_core_secret_to_config_overrides_localhost_placeholders(monkeypatch):
    cfg = {
        'host': 'localhost',
        'port': 50051,
        'ssh_host': 'localhost',
        'ssh_port': 22,
        'ssh_username': 'coreadmin',
        'core_secret_id': 'secret-1',
    }

    monkeypatch.setattr(
        app_backend,
        '_select_latest_core_secret_record',
        lambda *_a, **_k: {
            'identifier': 'secret-1',
            'host': '10.10.10.20',
            'port': 50051,
            'ssh_host': '10.10.10.20',
            'ssh_port': 22,
            'ssh_username': 'coreadmin',
            'ssh_password_plain': 'pw',
            'validated': True,
            'last_tested_status': 'success',
        },
    )

    out = app_backend._apply_core_secret_to_config(cfg, 'ScenarioX')

    assert str(out.get('host')) == '10.10.10.20'
    assert str(out.get('ssh_host')) == '10.10.10.20'
    assert str(out.get('ssh_username')) == 'coreadmin'
    assert str(out.get('ssh_password') or '') == 'pw'


def test_apply_core_secret_to_config_keeps_explicit_non_local_hosts(monkeypatch):
    cfg = {
        'host': '192.168.56.99',
        'port': 50051,
        'ssh_host': '192.168.56.99',
        'ssh_port': 22,
        'ssh_username': 'coreadmin',
        'core_secret_id': 'secret-1',
    }

    monkeypatch.setattr(
        app_backend,
        '_select_latest_core_secret_record',
        lambda *_a, **_k: {
            'identifier': 'secret-1',
            'host': '10.10.10.20',
            'port': 50051,
            'ssh_host': '10.10.10.20',
            'ssh_port': 22,
            'ssh_username': 'coreadmin',
            'ssh_password_plain': 'pw',
            'validated': True,
            'last_tested_status': 'success',
        },
    )

    out = app_backend._apply_core_secret_to_config(cfg, 'ScenarioX')

    assert str(out.get('host')) == '192.168.56.99'
    assert str(out.get('ssh_host')) == '192.168.56.99'
    assert str(out.get('ssh_password') or '') == 'pw'


def test_apply_core_secret_to_config_prefers_configured_secret_id(monkeypatch):
    cfg = {
        'host': 'localhost',
        'port': 50051,
        'ssh_host': 'localhost',
        'ssh_port': 22,
        'ssh_username': 'coreadmin',
        'core_secret_id': 'secret-specific',
    }

    monkeypatch.setattr(
        app_backend,
        '_select_latest_core_secret_record',
        lambda *_a, **_k: {
            'identifier': 'secret-latest',
            'host': '10.0.0.99',
            'ssh_host': '10.0.0.99',
            'ssh_username': 'wrong-user',
            'ssh_password_plain': 'wrong-pass',
        },
    )

    monkeypatch.setattr(
        app_backend,
        '_load_core_credentials',
        lambda sid: {
            'identifier': sid,
            'host': '10.0.0.10',
            'port': 50051,
            'ssh_host': '10.0.0.10',
            'ssh_port': 22,
            'ssh_username': 'right-user',
            'ssh_password_plain': 'right-pass',
            'validated': True,
            'last_tested_status': 'success',
        } if sid == 'secret-specific' else None,
    )

    out = app_backend._apply_core_secret_to_config(cfg, 'ScenarioX')

    assert str(out.get('host')) == '10.0.0.10'
    assert str(out.get('ssh_host')) == '10.0.0.10'
    assert str(out.get('ssh_username')) == 'right-user'
    assert str(out.get('ssh_password') or '') == 'right-pass'


def test_select_latest_core_secret_record_matches_forgiving_scenario_name(tmp_path, monkeypatch):
    secret_dir = tmp_path / 'core-secrets'
    secret_dir.mkdir()
    (secret_dir / 'secret-old.json').write_text('{}', encoding='utf-8')
    (secret_dir / 'secret-match.json').write_text('{}', encoding='utf-8')

    records = {
        'secret-old': {
            'identifier': 'secret-old',
            'scenario_name': 'Other Scenario',
            'stored_at': '2026-05-10T10:00:00+00:00',
        },
        'secret-match': {
            'identifier': 'secret-match',
            'scenario_name': 'Scenario 1',
            'stored_at': '2026-05-12T10:00:00+00:00',
        },
    }

    monkeypatch.setattr(app_backend, '_core_secret_dir', lambda: str(secret_dir))
    monkeypatch.setattr(app_backend, '_load_core_credentials', lambda identifier: records.get(identifier))

    out = app_backend._select_latest_core_secret_record('scenario1')

    assert out is not None
    assert out.get('identifier') == 'secret-match'


def test_select_core_config_for_page_repairs_stale_hitl_secret_reference(monkeypatch):
    monkeypatch.setattr(
        app_backend,
        '_load_scenario_hitl_config_from_disk',
        lambda: {
            'scenario1': {
                'core': {
                    'grpc_host': 'localhost',
                    'grpc_port': 50051,
                    'ssh_host': 'core-vm.example.test',
                    'ssh_port': 10000,
                    'core_secret_id': 'stale-secret',
                    'validated': True,
                    'vm_key': 'pve-node-a::149',
                    'vm_name': 'test-scenarioforge',
                    'vm_node': 'pve-node-a',
                }
            }
        },
    )
    monkeypatch.setattr(app_backend, '_load_scenario_hitl_validation_from_disk', lambda: {})
    monkeypatch.setattr(app_backend, '_load_core_credentials', lambda identifier: None if identifier == 'stale-secret' else None)
    monkeypatch.setattr(
        app_backend,
        '_select_latest_core_secret_record',
        lambda scenario_norm=None: {
            'identifier': 'secret-match',
            'scenario_name': 'Scenario 1',
            'host': '10.10.10.20',
            'port': 50051,
            'ssh_host': '10.10.10.20',
            'ssh_port': 22,
            'ssh_username': 'sampleuser',
            'ssh_password_plain': 'pw',
            'vm_key': 'pve-node-a::149',
            'vm_name': 'test-scenarioforge',
            'vm_node': 'pve-node-a',
        },
    )

    out = app_backend._select_core_config_for_page('scenario1', history=[], include_password=True)

    assert str(out.get('host')) == '10.10.10.20'
    assert str(out.get('ssh_host')) == 'core-vm.example.test'
    assert str(out.get('ssh_username')) == 'sampleuser'
    assert str(out.get('ssh_password') or '') == 'pw'
    assert str(out.get('core_secret_id') or '') == 'secret-match'
    assert str(out.get('vm_key') or '') == 'pve-node-a::149'
    assert str(out.get('vm_name') or '') == 'test-scenarioforge'
    assert str(out.get('vm_node') or '') == 'pve-node-a'


def test_select_core_config_for_page_uses_vm_mode_defaults_without_scenario_secret(monkeypatch):
    monkeypatch.setattr(app_backend, '_webui_runtime_mode', lambda: 'vm')
    monkeypatch.setattr(app_backend, '_load_scenario_hitl_config_from_disk', lambda: {})
    monkeypatch.setattr(app_backend, '_load_scenario_hitl_validation_from_disk', lambda: {})
    monkeypatch.setattr(app_backend, '_load_run_history', lambda: [])
    monkeypatch.setattr(app_backend, '_select_latest_core_secret_record', lambda scenario_norm=None: None)
    monkeypatch.setattr(app_backend, '_augment_core_config_from_secret', lambda cfg: dict(cfg))
    monkeypatch.setattr(app_backend, '_ensure_core_vm_metadata', lambda core_cfg: dict(core_cfg))
    monkeypatch.setattr(
        app_backend,
        '_core_backend_defaults',
        lambda include_password=True: {
            'host': '12.0.0.100',
            'grpc_host': '12.0.0.100',
            'port': 50051,
            'grpc_port': 50051,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'sampleuser',
            'ssh_password': 'pw' if include_password else '',
            'ssh_enabled': True,
            'venv_bin': '/opt/core/venv/bin',
        },
    )

    out = app_backend._select_core_config_for_page('scenario1', history=None, include_password=True)

    assert str(out.get('host') or '') == '12.0.0.100'
    assert str(out.get('ssh_host') or '') == '12.0.0.100'
    assert str(out.get('ssh_username') or '') == 'sampleuser'
    assert str(out.get('ssh_password') or '') == 'pw'


def test_build_core_vm_summary_accepts_runtime_managed_vm_defaults(monkeypatch):
    monkeypatch.setattr(app_backend, '_webui_runtime_mode', lambda: 'vm')
    monkeypatch.setattr(app_backend, '_ensure_core_vm_metadata', lambda core_cfg: dict(core_cfg))

    configured, summary = app_backend._build_core_vm_summary(
        {
            'host': '12.0.0.100',
            'grpc_host': '12.0.0.100',
            'port': 50051,
            'grpc_port': 50051,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'sampleuser',
        }
    )

    assert configured is True
    assert summary is not None
    assert summary.get('label') == 'runtime-managed'
    assert summary.get('runtime_managed_vm_mode') is True
    assert summary.get('ssh_username') == 'sampleuser'
