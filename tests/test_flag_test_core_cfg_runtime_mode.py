import json

from webapp import app_backend


def test_parse_flag_test_core_cfg_native_mode_prefers_ssh_host_when_not_explicit(monkeypatch):
    monkeypatch.setattr(app_backend, '_webui_runtime_mode', lambda: 'native')
    monkeypatch.setattr(
        app_backend,
        '_merge_core_configs',
        lambda *_args, **_kwargs: {
            'host': 'configured-core-host',
            'grpc_host': 'configured-core-host',
            'port': 50051,
            'ssh_host': 'vm-node-host',
            'ssh_port': 22,
            'ssh_username': 'sampleuser',
            'ssh_password': 'pw',
        },
    )
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)

    cfg = app_backend._parse_flag_test_core_cfg_from_form({'core': json.dumps({'ssh_host': 'vm-node-host'})})

    assert isinstance(cfg, dict)
    assert cfg.get('host') == 'vm-node-host'
    assert cfg.get('grpc_host') == 'vm-node-host'
    assert cfg.get('ssh_host') == 'vm-node-host'


def test_parse_flag_test_core_cfg_native_mode_keeps_explicit_core_host(monkeypatch):
    monkeypatch.setattr(app_backend, '_webui_runtime_mode', lambda: 'native')
    monkeypatch.setattr(
        app_backend,
        '_merge_core_configs',
        lambda *_args, **_kwargs: {
            'host': 'configured-core-host',
            'grpc_host': 'configured-core-host',
            'port': 50051,
            'ssh_host': 'vm-node-host',
            'ssh_port': 22,
            'ssh_username': 'sampleuser',
            'ssh_password': 'pw',
        },
    )
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)

    cfg = app_backend._parse_flag_test_core_cfg_from_form({
        'core': json.dumps({'host': 'configured-core-host', 'ssh_host': 'vm-node-host'})
    })

    assert isinstance(cfg, dict)
    assert cfg.get('host') == 'configured-core-host'
    assert cfg.get('grpc_host') == 'configured-core-host'
    assert cfg.get('ssh_host') == 'vm-node-host'


def test_parse_flag_test_core_cfg_vm_mode_prefers_ssh_host_when_not_explicit(monkeypatch):
    monkeypatch.setattr(app_backend, '_webui_runtime_mode', lambda: 'vm')
    monkeypatch.setattr(
        app_backend,
        '_merge_core_configs',
        lambda *_args, **_kwargs: {
            'host': 'host.docker.internal',
            'grpc_host': 'host.docker.internal',
            'port': 50051,
            'ssh_host': 'vm-node-host',
            'ssh_port': 22,
            'ssh_username': 'sampleuser',
            'ssh_password': 'pw',
        },
    )
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)

    cfg = app_backend._parse_flag_test_core_cfg_from_form({'core': json.dumps({'ssh_host': 'vm-node-host'})})

    assert isinstance(cfg, dict)
    assert cfg.get('host') == 'vm-node-host'
    assert cfg.get('grpc_host') == 'vm-node-host'


def test_parse_flag_test_core_cfg_vm_mode_uses_env_defaults_without_form_payload(monkeypatch):
    monkeypatch.setattr(app_backend, '_webui_runtime_mode', lambda: 'vm')
    monkeypatch.setattr(
        app_backend,
        '_core_backend_defaults',
        lambda **_kwargs: {
            'host': '127.0.0.1',
            'grpc_host': '127.0.0.1',
            'port': 50051,
            'ssh_host': 'corevm.example.test',
            'ssh_port': 22,
            'ssh_username': 'corevm',
            'ssh_password': 'from-scenarioforge-env',
        },
    )
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)

    cfg = app_backend._parse_flag_test_core_cfg_from_form({})

    assert isinstance(cfg, dict)
    assert cfg.get('host') == 'corevm.example.test'
    assert cfg.get('grpc_host') == 'corevm.example.test'
    assert cfg.get('ssh_host') == 'corevm.example.test'
    assert cfg.get('ssh_username') == 'corevm'
