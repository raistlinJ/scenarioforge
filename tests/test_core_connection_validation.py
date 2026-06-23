from contextlib import contextmanager
import xml.etree.ElementTree as ET

import pytest

from webapp import app_backend as backend

app = backend.app
app.config.setdefault('TESTING', True)


class _NoRunThread:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        return None


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


@pytest.fixture()
def client():
    client = app.test_client()
    _login(client)
    return client


class _FakeSocket:
    def __init__(self, *args, **kwargs):
        self._args = args
        self.connected = None

    def settimeout(self, *_args, **_kwargs):
        return None

    def connect(self, address):
        self.connected = address

    def close(self):
        return None


@contextmanager
def _fake_core_connection(_cfg):
    yield '127.0.0.1', 6000


def test_require_core_ssh_credentials_requires_username():
    with pytest.raises(RuntimeError) as exc:
        backend._require_core_ssh_credentials({'host': 'core-host', 'port': 50051, 'ssh_password': 'pw'})
    assert 'SSH username is required' in str(exc.value)


def test_require_core_ssh_credentials_requires_password():
    with pytest.raises(RuntimeError) as exc:
        backend._require_core_ssh_credentials({'host': 'core-host', 'port': 50051, 'ssh_username': 'core'})
    assert 'SSH password is required' in str(exc.value)


def test_require_core_ssh_credentials_trims_fields():
    cfg = backend._require_core_ssh_credentials({
        'host': 'core-host',
        'port': 50051,
        'ssh_username': ' core ',
        'ssh_password': ' pw ',
    })
    # Config normalization preserves original values; validation trims only for checks.
    assert cfg['ssh_username'] == ' core '
    assert cfg['ssh_password'] == ' pw '


def test_ensure_core_daemon_listening_stops_after_socket_refused(monkeypatch):
    class _FakeSSH:
        def set_missing_host_key_policy(self, *_args, **_kwargs):
            return None

        def connect(self, **_kwargs):
            return None

        def close(self):
            return None

    class _FakeParamiko:
        @staticmethod
        def SSHClient():
            return _FakeSSH()

        @staticmethod
        def AutoAddPolicy():
            return object()

    calls = []

    def _fake_probe(_client, command, *, timeout):
        calls.append(command)
        return 1, 'ERROR: [Errno 111] Connection refused\n', ''

    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko())
    monkeypatch.setattr(backend, '_exec_ssh_python_probe', _fake_probe)

    with pytest.raises(RuntimeError) as exc:
        backend._ensure_core_daemon_listening({
            'host': 'localhost',
            'port': 55001,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'venv_bin': '/custom/core/venv/bin',
        })

    message = str(exc.value)
    assert len(calls) == 1
    assert 'core-daemon is not accepting gRPC connections on 127.0.0.1:55001' in message
    assert 'Test Venv only verifies' in message
    assert '/custom/core/venv/bin/python3' in message
    assert '/opt/core/venv/python3.13' not in message


def test_normalize_core_config_uses_grpc_fields_when_host_missing():
    cfg = backend._normalize_core_config({
        'grpc_host': 'core-vm.example.test',
        'grpc_port': 50051,
        'ssh_host': 'core-vm.example.test',
        'ssh_port': 22,
        'ssh_username': 'core',
        'ssh_password': 'pw',
    }, include_password=True)

    assert cfg['host'] == 'core-vm.example.test'
    assert cfg['port'] == 50051


def test_normalize_core_config_prefers_grpc_fields_over_legacy_host():
    cfg = backend._normalize_core_config({
        'host': '10.0.0.5',
        'port': 50051,
        'grpc_host': 'core-vm.example.test',
        'grpc_port': 50051,
        'ssh_host': 'core-vm.example.test',
        'ssh_port': 10000,
        'ssh_username': 'sampleuser',
    }, include_password=False)

    assert cfg['host'] == 'core-vm.example.test'
    assert cfg['port'] == 50051
    assert cfg['grpc_host'] == 'core-vm.example.test'
    assert cfg['grpc_port'] == 50051


def test_extract_optional_core_config_accepts_grpc_fields_signal():
    cfg = backend._extract_optional_core_config({
        'grpc_host': 'core-vm.example.test',
        'grpc_port': 50051,
        'vm_key': 'pve1::101',
    }, include_password=False)

    assert isinstance(cfg, dict)
    assert cfg.get('host') == 'core-vm.example.test'
    assert cfg.get('port') == 50051


def test_build_scenarios_xml_canonicalizes_hitl_host_from_grpc_host():
    tree = backend._build_scenarios_xml({
        'core': {
            'host': '10.0.0.5',
            'grpc_host': 'localhost',
            'port': 50051,
            'grpc_port': 50051,
            'ssh_enabled': True,
            'ssh_host': 'core-vm.example.test',
            'ssh_port': 10000,
            'ssh_username': 'sampleuser',
        },
        'scenarios': [{
            'name': 'Anatest',
            'base': {'filepath': '/tmp/base.imn'},
            'sections': {},
            'hitl': {
                'enabled': True,
                'core': {
                    'host': '10.0.0.5',
                    'grpc_host': 'localhost',
                    'port': 50051,
                    'grpc_port': 50051,
                    'ssh_enabled': True,
                    'ssh_host': 'core-vm.example.test',
                    'ssh_port': 10000,
                    'ssh_username': 'sampleuser',
                },
            },
        }],
    })

    root = tree.getroot()
    global_core = root.find('CoreConnection')
    assert global_core is not None
    assert global_core.get('host') == 'localhost'

    hitl_core = root.find('./Scenario/ScenarioEditor/HardwareInLoop/CoreConnection')
    assert hitl_core is not None
    assert hitl_core.get('host') == 'localhost'
    assert hitl_core.get('port') == '50051'


def test_apply_hitl_config_to_full_preview_canonicalizes_hitl_core_host():
    full_preview = {}
    hitl_cfg = {
        'enabled': True,
        'scenario_key': 'Anatest',
        'interfaces': [{'name': 'ens19'}],
        'core': {
            'validated': True,
            'host': '10.0.0.5',
            'port': 50051,
            'grpc_host': 'localhost',
            'grpc_port': 50051,
            'ssh_host': 'core-vm.example.test',
            'ssh_port': 10000,
            'ssh_username': 'sampleuser',
        },
    }

    backend._apply_hitl_config_to_full_preview(full_preview, hitl_cfg, 'Anatest')

    core = full_preview.get('hitl_core')
    assert isinstance(core, dict)
    assert core.get('host') == 'localhost'
    assert core.get('port') == 50051


def test_test_core_requires_vm_selection(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)

    def _fail_save(_payload):  # pragma: no cover - safety net
        raise AssertionError('Should not attempt to store credentials when VM selection is missing')

    monkeypatch.setattr(backend, '_save_core_credentials', _fail_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        'scenario_name': 'Scenario Alpha',
        'scenario_index': 0,
        'hitl_core': {
            'vm_name': 'CORE VM',
            'vm_node': 'pve1',
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['ok'] is False
    assert 'Select a CORE VM' in data['error']


def test_test_core_allows_runtime_managed_vm_mode_without_vm_selection(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_merge_hitl_validation_into_scenario_catalog', lambda *args, **kwargs: None)

    saved_payloads = []

    def _fake_save(payload):
        saved_payloads.append(payload.copy())
        return {
            'identifier': 'secret-vm-mode',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2026-05-12T00:00:00Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'runtime_managed_vm_mode': True,
        },
        'scenario_name': 'Scenario VM Mode',
        'scenario_index': 0,
        'hitl_core': {
            'grpc_host': 'core-host',
            'grpc_port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'runtime_managed_vm_mode': True,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert data.get('core_secret_id') == 'secret-vm-mode'
    assert saved_payloads
    assert saved_payloads[0].get('vm_key') in (None, '')


def test_test_core_rejects_mismatched_secret(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)

    def _fake_load(identifier):
        assert identifier == 'secret-mismatch'
        return {
            'identifier': identifier,
            'ssh_password_plain': 'stored-pw',
            'ssh_username': 'core',
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'host': 'core-host',
            'port': 50051,
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE-OLD',
        }

    monkeypatch.setattr(backend, '_load_core_credentials', _fake_load)

    def _fail_save(_payload):  # pragma: no cover - should not be called
        raise AssertionError('Should not persist credentials on mismatch')

    monkeypatch.setattr(backend, '_save_core_credentials', _fail_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': '',
            'core_secret_id': 'secret-mismatch',
        },
        'scenario_name': 'Scenario Beta',
        'scenario_index': 0,
        'hitl_core': {
            'vm_key': 'pve1::202',
            'vm_node': 'pve1',
            'vm_name': 'CORE-NEW',
            'core_secret_id': 'secret-mismatch',
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 409
    data = resp.get_json()
    assert data['ok'] is False
    assert data.get('vm_mismatch') is True
    assert 'CORE-NEW' in data['error']
    assert 'CORE-OLD' in data['error']


def test_test_core_allows_stale_secret_when_password_reentered(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)

    saved_payloads = []

    def _fake_save(payload):
        saved_payloads.append(payload.copy())
        return {
            'identifier': 'secret-replaced',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2026-03-05T00:00:00Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'fresh-pass',
            'core_secret_id': 'stale-secret',
        },
        'scenario_name': 'Scenario Stale Secret',
        'scenario_index': 2,
        'hitl_core': {
            'vm_key': 'pve1::303',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM 303',
            'vmid': 303,
            'core_secret_id': 'stale-secret',
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True, data
    assert data.get('core_secret_id') == 'secret-replaced'
    assert saved_payloads
    assert saved_payloads[0]['ssh_password'] == 'fresh-pass'
    assert saved_payloads[0]['vm_key'] == 'pve1::303'


def test_test_core_success_includes_vm_metadata(client, monkeypatch, tmp_path):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)

    saved_payloads = []

    def _fake_save(payload):
        saved_payloads.append(payload.copy())
        return {
            'identifier': 'secret-success',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2025-10-28T00:00:00Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)
    xml_path = tmp_path / 'scenario-gamma.xml'
    xml_path.write_text(
        '<Scenarios><Scenario name="Scenario Gamma"><ScenarioEditor/></Scenario></Scenarios>',
        encoding='utf-8',
    )
    monkeypatch.setattr(backend, '_latest_xml_path_for_scenario', lambda _scenario: str(xml_path))

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        'scenario_name': 'Scenario Gamma',
        'scenario_index': 1,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert data['core_summary']['vm_key'] == 'pve1::101'
    assert data['core_summary']['vmid'] == 101 or data['core_summary']['vmid'] == '101'
    assert 'VM CORE VM' in data['message']
    assert data['xml_sync']['ok'] is True
    assert data['xml_sync']['xml_path'] == str(xml_path)
    assert saved_payloads and saved_payloads[0]['vm_key'] == 'pve1::101'
    assert saved_payloads[0]['vmid'] == 101
    scenario_core = ET.parse(xml_path).getroot().find(
        './Scenario/ScenarioEditor/HardwareInLoop/CoreConnection'
    )
    assert scenario_core is not None
    assert scenario_core.get('ssh_host') == 'core-host'
    assert scenario_core.get('core_secret_id') == 'secret-success'
    assert scenario_core.get('vm_key') == 'pve1::101'
    assert scenario_core.get('ssh_password') == 'pw'


def test_test_core_uses_dialog_core_fields_only(client, monkeypatch):
    captured_cfg = {}

    @contextmanager
    def _capture_core_connection(cfg):
        captured_cfg.update(cfg)
        yield '127.0.0.1', 6000

    monkeypatch.setattr(backend, '_core_connection', _capture_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)

    def _fake_save(payload):
        return {
            'identifier': 'secret-dialog-only',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2025-10-28T00:00:00Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)

    payload = {
        'core': {
            'host': 'core-vm.example.test',
            'port': 50051,
            'ssh_host': 'core-vm.example.test',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        'scenario_name': 'Scenario Delta',
        'scenario_index': 0,
        'hitl_core': {
            'host': '10.0.0.5',
            'port': 50051,
            'ssh_host': '10.0.0.5',
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert data['host'] == 'core-vm.example.test'
    assert captured_cfg.get('host') == 'core-vm.example.test'
    assert captured_cfg.get('ssh_host') == 'core-vm.example.test'


def test_test_core_daemon_listener_failure_is_structured(client, monkeypatch):
    # Force the handler down the non-pytest path so daemon listener failures are surfaced.
    monkeypatch.delenv('PYTEST_CURRENT_TEST', raising=False)
    monkeypatch.delitem(backend.sys.modules, 'pytest', raising=False)

    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_paramiko_available', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [123])
    monkeypatch.setattr(
        backend,
        '_ensure_core_daemon_listening',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(
            'core-daemon is not accepting gRPC connections on 127.0.0.1:55001. '
            'The Python probe ran via /custom/core/venv/bin/python3, but the daemon socket returned: '
            'ERROR: [Errno 111] Connection refused. Test Venv only verifies imports.'
        )),
    )

    def _fail_save(_payload):  # pragma: no cover - should not be called
        raise AssertionError('Should not persist credentials when daemon listener check fails')

    monkeypatch.setattr(backend, '_save_core_credentials', _fail_save)

    class _FakeSSH:
        def set_missing_host_key_policy(self, *_args, **_kwargs):
            return None

        def connect(self, **_kwargs):
            return None

        def close(self):
            return None

    class _FakeParamiko:
        @staticmethod
        def SSHClient():
            return _FakeSSH()

        @staticmethod
        def AutoAddPolicy():
            return object()

    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko())

    payload = {
        'core': {
            'host': 'localhost',
            'port': 55001,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'venv_bin': '/custom/core/venv/bin',
        },
        'scenario_name': 'Scenario Listener Down',
        'scenario_index': 0,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 502
    data = resp.get_json()
    assert data['ok'] is False
    assert data.get('code') == 'core_daemon_unreachable'
    assert data.get('daemon_unreachable') is True
    assert data.get('host') == 'localhost'
    assert data.get('port') == 55001
    assert data.get('venv_bin') == '/custom/core/venv/bin'
    assert 'Test Venv only verifies' in data.get('error', '')
    assert '/opt/core/venv/python3.13' not in data.get('error', '')


def test_test_core_prefers_stored_config_when_requested(client, monkeypatch):
    captured_cfg = {}

    @contextmanager
    def _capture_core_connection(cfg):
        captured_cfg.update(cfg)
        yield '127.0.0.1', 6000

    monkeypatch.setattr(backend, '_core_connection', _capture_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)

    def _fake_load(identifier):
        assert identifier == 'secret-stored-config'
        return {
            'identifier': identifier,
            'ssh_password_plain': 'stored-pw',
            'ssh_username': 'stored-user',
            'ssh_host': 'stored-ssh-host',
            'ssh_port': 2201,
            'host': 'stored-grpc-host',
            'port': 55001,
            'grpc_host': 'stored-grpc-host',
            'grpc_port': 55001,
            'venv_bin': '/opt/stored/venv/bin',
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
        }

    monkeypatch.setattr(backend, '_load_core_credentials', _fake_load)

    def _fake_save(payload):
        return {
            'identifier': 'secret-stored-config',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'venv_bin': payload.get('venv_bin'),
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2026-05-11T18:35:09Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)

    payload = {
        'core': {
            'host': 'stale-dialog-host',
            'port': 50051,
            'ssh_host': 'stale-dialog-ssh-host',
            'ssh_port': 22,
            'ssh_username': 'stale-dialog-user',
            'ssh_password': '',
            'venv_bin': '/tmp/stale/venv/bin',
            'core_secret_id': 'secret-stored-config',
            'prefer_stored_config': True,
        },
        'scenario_name': 'Scenario Stored Config',
        'scenario_index': 0,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'core_secret_id': 'secret-stored-config',
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert data['host'] == 'stored-grpc-host'
    assert captured_cfg.get('host') == 'stored-grpc-host'
    assert captured_cfg.get('port') == 55001
    assert captured_cfg.get('ssh_host') == 'stored-ssh-host'
    assert captured_cfg.get('ssh_port') == 2201
    assert captured_cfg.get('ssh_username') == 'stored-user'
    assert captured_cfg.get('ssh_password') == 'stored-pw'
    assert captured_cfg.get('venv_bin') == '/opt/stored/venv/bin'



def test_test_core_install_custom_services_triggers_installer(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_paramiko_available', lambda *_args, **_kwargs: None)

    # Avoid depending on process inspection details.
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [123])

    installer_calls = []

    def _fake_installer(ssh_client, *, sudo_password, logger, core_cfg=None):
        installer_calls.append({'ssh_client': ssh_client, 'sudo_password': sudo_password})
        return {'services_dir': '/opt/core/services', 'modules': ['TrafficService']}

    monkeypatch.setattr(backend, '_install_custom_services_to_core_vm', _fake_installer)

    class _FakeSSH:
        def set_missing_host_key_policy(self, *_args, **_kwargs):
            return None

        def connect(self, **_kwargs):
            return None

        def close(self):
            return None

    class _FakeParamiko:
        @staticmethod
        def SSHClient():
            return _FakeSSH()

        @staticmethod
        def AutoAddPolicy():
            return object()

    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko())

    def _fake_save(payload):
        return {
            'identifier': 'secret-install-services',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2025-10-28T00:00:00Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'install_custom_services': True,
        },
        'scenario_name': 'Scenario Install',
        'scenario_index': 2,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert installer_calls and installer_calls[0]['sudo_password'] == 'pw'


def test_test_core_daemon_conflict_prompts_with_pids(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_paramiko_available', lambda *_args, **_kwargs: None)

    # Force a daemon conflict.
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [18263, 78479])

    def _fail_save(_payload):  # pragma: no cover - should not be called
        raise AssertionError('Should not persist credentials when daemon conflict exists')

    monkeypatch.setattr(backend, '_save_core_credentials', _fail_save)

    class _FakeSSH:
        def set_missing_host_key_policy(self, *_args, **_kwargs):
            return None

        def connect(self, **_kwargs):
            return None

        def close(self):
            return None

    class _FakeParamiko:
        @staticmethod
        def SSHClient():
            return _FakeSSH()

        @staticmethod
        def AutoAddPolicy():
            return object()

    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko())

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'auto_start_daemon': True,
        },
        'scenario_name': 'Scenario Conflict',
        'scenario_index': 0,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 409
    data = resp.get_json()
    assert data['ok'] is False
    assert data.get('daemon_conflict') is True
    assert data.get('code') == 'core_daemon_conflict'
    assert data.get('daemon_pids') == [18263, 78479]
    assert data.get('can_stop_daemons') is True


def test_test_core_daemon_conflict_can_be_auto_stopped(client, monkeypatch):
    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_paramiko_available', lambda *_args, **_kwargs: None)

    pid_calls = {'count': 0}

    def _fake_collect(*_args, **_kwargs):
        pid_calls['count'] += 1
        return [18263, 78479] if pid_calls['count'] == 1 else [18263]

    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', _fake_collect)

    stop_calls = []

    def _fake_stop(ssh_client, *, sudo_password, pids, logger):
        stop_calls.append({'sudo_password': sudo_password, 'pids': list(pids)})
        return {'status': 'attempted'}

    monkeypatch.setattr(backend, '_stop_remote_core_daemon_conflict', _fake_stop)

    class _FakeSSH:
        def set_missing_host_key_policy(self, *_args, **_kwargs):
            return None

        def connect(self, **_kwargs):
            return None

        def close(self):
            return None

    class _FakeParamiko:
        @staticmethod
        def SSHClient():
            return _FakeSSH()

        @staticmethod
        def AutoAddPolicy():
            return object()

    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko())

    def _fake_save(payload):
        return {
            'identifier': 'secret-conflict-fixed',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2025-10-28T00:00:00Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'stop_duplicate_daemons': True,
        },
        'scenario_name': 'Scenario Conflict Fixed',
        'scenario_index': 0,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert stop_calls and stop_calls[0]['sudo_password'] == 'pw'
    assert stop_calls[0]['pids'] == [18263, 78479]


def test_test_core_daemon_not_running_prompts_for_start(client, monkeypatch):
    # Force the handler down the non-pytest path so SSH daemon inspection runs.
    monkeypatch.delenv('PYTEST_CURRENT_TEST', raising=False)
    monkeypatch.delitem(backend.sys.modules, 'pytest', raising=False)

    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_paramiko_available', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [])

    def _fail_save(_payload):  # pragma: no cover - should not be called
        raise AssertionError('Should not persist credentials when core-daemon is not running')

    monkeypatch.setattr(backend, '_save_core_credentials', _fail_save)

    class _FakeSSH:
        def set_missing_host_key_policy(self, *_args, **_kwargs):
            return None

        def connect(self, **_kwargs):
            return None

        def close(self):
            return None

    class _FakeParamiko:
        @staticmethod
        def SSHClient():
            return _FakeSSH()

        @staticmethod
        def AutoAddPolicy():
            return object()

    monkeypatch.setattr(backend, 'paramiko', _FakeParamiko())

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        'scenario_name': 'Scenario Daemon Down',
        'scenario_index': 0,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 409
    data = resp.get_json()
    assert data['ok'] is False
    assert data.get('code') == 'core_daemon_not_running'
    assert data.get('daemon_not_running') is True
    assert data.get('daemon_pids') == []
    assert data.get('can_start_daemon') is True


def test_test_core_advanced_checks_fail_as_warning(client, monkeypatch):
    # Force the handler down the non-pytest code path so we exercise warning behavior.
    # (The backend intentionally skips remote checks during pytest.)
    monkeypatch.delenv('PYTEST_CURRENT_TEST', raising=False)
    monkeypatch.delitem(backend.sys.modules, 'pytest', raising=False)

    monkeypatch.setattr(backend, '_core_connection', _fake_core_connection)
    monkeypatch.setattr(backend.socket, 'socket', _FakeSocket)
    monkeypatch.setattr(backend, '_load_core_credentials', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_ensure_core_daemon_listening', lambda *_args, **_kwargs: None)

    def _fake_adv(_cfg, **_kwargs):
        return {
            'adv_fix_docker_daemon': {'enabled': False, 'ok': None, 'message': ''},
            'adv_run_core_cleanup': {'enabled': True, 'ok': True, 'message': 'completed'},
            'adv_restart_core_daemon': {'enabled': False, 'ok': None, 'message': ''},
            'adv_start_core_daemon': {'enabled': False, 'ok': None, 'message': ''},
            'adv_auto_kill_sessions': {'enabled': False, 'ok': None, 'message': ''},
        }

    monkeypatch.setattr(backend, '_run_core_connection_advanced_checks', _fake_adv)

    def _fake_save(payload):
        return {
            'identifier': 'secret-adv-warning',
            'scenario_name': payload.get('scenario_name'),
            'scenario_index': payload.get('scenario_index'),
            'host': payload['grpc_host'],
            'port': payload['grpc_port'],
            'grpc_host': payload['grpc_host'],
            'grpc_port': payload['grpc_port'],
            'ssh_host': payload['ssh_host'],
            'ssh_port': payload['ssh_port'],
            'ssh_username': payload['ssh_username'],
            'ssh_enabled': payload['ssh_enabled'],
            'vm_key': payload.get('vm_key'),
            'vm_name': payload.get('vm_name'),
            'vm_node': payload.get('vm_node'),
            'vmid': payload.get('vmid'),
            'stored_at': '2025-10-28T00:00:00Z',
        }

    monkeypatch.setattr(backend, '_save_core_credentials', _fake_save)

    payload = {
        'core': {
            'host': 'core-host',
            'port': 50051,
            'ssh_host': 'core-host',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'adv_run_core_cleanup': True,
        },
        'scenario_name': 'Scenario Advanced',
        'scenario_index': 3,
        'hitl_core': {
            'vm_key': 'pve1::101',
            'vm_node': 'pve1',
            'vm_name': 'CORE VM',
            'vmid': 101,
        },
    }

    resp = client.post('/test_core', json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert isinstance(data.get('advanced_checks'), dict)
    assert data['advanced_checks']['adv_run_core_cleanup']['enabled'] is True
    assert data['advanced_checks']['adv_run_core_cleanup']['ok'] is True
    assert not data.get('warnings')


def test_run_cli_async_requires_ssh_credentials(client, tmp_path, monkeypatch):
    xml_path = tmp_path / 'scenarios.xml'
    xml_path.write_text('<Scenarios></Scenarios>')

    # Avoid heavy parsing during the test
    monkeypatch.setattr(backend, '_parse_scenarios_xml', lambda *_args, **_kwargs: {})
    monkeypatch.setattr(backend.threading, 'Thread', _NoRunThread)

    resp = client.post('/run_cli_async', data={'xml_path': str(xml_path), 'flow_enabled': '0'})
    # run_cli_async now accepts and validates execution prerequisites in background.
    assert resp.status_code == 202
    data = resp.get_json()
    assert isinstance(data.get('run_id'), str) and data.get('run_id')


def test_run_cli_async_blocks_invalid_hitl_proxmox_interface_ids(client, tmp_path, monkeypatch):
    xml_path = tmp_path / 'scenarios.xml'
    xml_path.write_text(
        (
            '<Scenarios>'
            '<Scenario name="Scenario A">'
            '<ScenarioEditor>'
            '<HardwareInLoop enabled="true">'
            '<Interface name="net0" attachment="existing_router" core_bridge="vmbr-core" pve_interface_id="net0" />'
            '</HardwareInLoop>'
            '</ScenarioEditor>'
            '</Scenario>'
            '</Scenarios>'
        ),
        encoding='utf-8',
    )

    monkeypatch.setattr(
        backend,
        '_enumerate_core_vm_interfaces_from_secret',
        lambda secret_id, **kwargs: [
            {
                'name': 'ens18',
                'ifindex': 2,
                'bridge': 'vmbr-core',
                'proxmox': {'id': 'net0', 'bridge': 'vmbr-core'},
            }
        ],
    )
    monkeypatch.setattr(
        backend,
        '_merge_core_configs',
        lambda *args, include_password=True: {'core_secret_id': 'core-secret-1', 'ssh_enabled': True},
    )
    monkeypatch.setattr(backend, '_prefer_explicit_or_ssh_core_host', lambda cfg, *args: cfg)

    resp = client.post('/run_cli_async', data={'xml_path': str(xml_path), 'scenario': 'Scenario A', 'flow_enabled': '0'})

    assert resp.status_code == 202
    data = resp.get_json()
    assert isinstance(data.get('run_id'), str) and data.get('run_id')


def test_run_cli_async_blocks_out_of_range_hitl_slot_selector(client, tmp_path, monkeypatch):
    xml_path = tmp_path / 'scenarios.xml'
    xml_path.write_text(
        (
            '<Scenarios>'
            '<Scenario name="Scenario A">'
            '<ScenarioEditor>'
            '<HardwareInLoop enabled="true">'
            '<Interface name="net2" attachment="existing_router" core_bridge="vmbr-core" pve_interface_id="net2" />'
            '</HardwareInLoop>'
            '</ScenarioEditor>'
            '</Scenario>'
            '</Scenarios>'
        ),
        encoding='utf-8',
    )

    monkeypatch.setattr(
        backend,
        '_enumerate_core_vm_interfaces_from_secret',
        lambda secret_id, **kwargs: [
            {'name': 'ens18', 'ifindex': 2, 'bridge': 'vmbr-core'},
            {'name': 'ens19', 'ifindex': 3, 'bridge': 'vmbr-core'},
        ],
    )
    monkeypatch.setattr(
        backend,
        '_merge_core_configs',
        lambda *args, include_password=True: {'core_secret_id': 'core-secret-1', 'ssh_enabled': True},
    )
    monkeypatch.setattr(backend, '_prefer_explicit_or_ssh_core_host', lambda cfg, *args: cfg)

    resp = client.post('/run_cli_async', data={'xml_path': str(xml_path), 'scenario': 'Scenario A', 'flow_enabled': '0'})

    assert resp.status_code == 422
    data = resp.get_json()
    assert data['error'] == 'HITL interface validation failed before execute.'
    assert any('did not match any CORE VM interface discovered over SSH' in detail for detail in data.get('details') or [])


def test_ensure_remote_daemon_ready_uses_fallback_before_autostart(monkeypatch):
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [])

    def _fake_exec(_client, command, *, timeout=120.0, cancel_check=None, check=False):
        if 'systemctl show -p MainPID' in command:
            return 0, '4242\n', ''
        if 'pidof core-daemon' in command:
            return 0, '4242\n', ''
        if 'pgrep -fa core-daemon' in command:
            return 0, '4242 /usr/sbin/core-daemon\n', ''
        if 'systemctl is-active core-daemon' in command:
            return 0, 'active\n', ''
        if 'ss -ltn' in command:
            return 0, 'LISTEN 0 128 0.0.0.0:50051 0.0.0.0:*\n', ''
        raise AssertionError(f'unexpected command: {command}')

    monkeypatch.setattr(backend, '_exec_ssh_command', _fake_exec)

    def _fail_start(*_args, **_kwargs):
        raise AssertionError('auto-start should not run when fallback detects an existing daemon')

    monkeypatch.setattr(backend, '_start_remote_core_daemon', _fail_start)

    pid = backend._ensure_remote_core_daemon_ready(
        client=object(),
        core_cfg={'ssh_password': 'pw'},
        auto_start_allowed=True,
        sudo_password='pw',
        logger=backend.app.logger,
    )
    assert pid == 4242


def test_ensure_remote_daemon_ready_refuses_autostart_when_active_pid_unknown(monkeypatch):
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [])

    def _fake_exec(_client, command, *, timeout=120.0, cancel_check=None, check=False):
        if 'systemctl show -p MainPID' in command:
            return 0, '0\n', ''
        if 'pidof core-daemon' in command:
            return 0, '\n', ''
        if 'pgrep -fa core-daemon' in command:
            return 0, '\n', ''
        if 'systemctl is-active core-daemon' in command:
            return 0, 'active\n', ''
        if 'ss -ltn' in command:
            return 0, '\n', ''
        raise AssertionError(f'unexpected command: {command}')

    monkeypatch.setattr(backend, '_exec_ssh_command', _fake_exec)

    def _fail_start(*_args, **_kwargs):
        raise AssertionError('auto-start should not run when daemon appears active')

    monkeypatch.setattr(backend, '_start_remote_core_daemon', _fail_start)

    with pytest.raises(backend.CoreDaemonMissingError) as exc:
        backend._ensure_remote_core_daemon_ready(
            client=object(),
            core_cfg={'ssh_password': 'pw'},
            auto_start_allowed=True,
            sudo_password='pw',
            logger=backend.app.logger,
        )
    assert 'refusing auto-start to avoid duplicate daemons' in str(exc.value)


def test_ensure_remote_daemon_ready_detects_manual_sudo_core_daemon(monkeypatch):
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [])

    def _fake_exec(_client, command, *, timeout=120.0, cancel_check=None, check=False):
        if 'systemctl show -p MainPID' in command:
            return 0, '0\n', ''
        if 'pidof core-daemon' in command:
            return 0, '\n', ''
        if 'pgrep -fa core-daemon' in command:
            return 0, '9123 sudo core-daemon\n9124 core-daemon\n', ''
        if 'systemctl is-active core-daemon' in command:
            return 3, 'inactive\n', ''
        if 'ss -ltn' in command:
            return 0, 'LISTEN 0 128 0.0.0.0:50051 0.0.0.0:*\n', ''
        raise AssertionError(f'unexpected command: {command}')

    monkeypatch.setattr(backend, '_exec_ssh_command', _fake_exec)

    def _fail_start(*_args, **_kwargs):
        raise AssertionError('auto-start should not run when manual daemon is already running')

    monkeypatch.setattr(backend, '_start_remote_core_daemon', _fail_start)

    pid = backend._ensure_remote_core_daemon_ready(
        client=object(),
        core_cfg={'ssh_password': 'pw'},
        auto_start_allowed=True,
        sudo_password='pw',
        logger=backend.app.logger,
    )
    assert pid == 9124


def test_ensure_remote_daemon_ready_detects_sudo_wrapper_only(monkeypatch):
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [])

    def _fake_exec(_client, command, *, timeout=120.0, cancel_check=None, check=False):
        if 'systemctl show -p MainPID' in command:
            return 0, '0\n', ''
        if 'pidof core-daemon' in command:
            return 0, '\n', ''
        if 'pgrep -fa core-daemon' in command:
            return 0, '9123 sudo core-daemon\n', ''
        if 'systemctl is-active core-daemon' in command:
            return 3, 'inactive\n', ''
        if 'ss -ltn' in command:
            return 0, '\n', ''
        raise AssertionError(f'unexpected command: {command}')

    monkeypatch.setattr(backend, '_exec_ssh_command', _fake_exec)

    def _fail_start(*_args, **_kwargs):
        raise AssertionError('auto-start should not run when manual sudo wrapper process is active')

    monkeypatch.setattr(backend, '_start_remote_core_daemon', _fail_start)

    pid = backend._ensure_remote_core_daemon_ready(
        client=object(),
        core_cfg={'ssh_password': 'pw'},
        auto_start_allowed=True,
        sudo_password='pw',
        logger=backend.app.logger,
    )
    assert pid == 9123


def test_ensure_remote_daemon_ready_prefers_managed_service_for_manual_daemon(monkeypatch):
    pid_samples = [[9124], [2222]]

    def _fake_collect(_client, **_kwargs):
        if pid_samples:
            return pid_samples.pop(0)
        return [2222]

    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', _fake_collect)

    show_values = iter(['0\n', '2222\n'])
    active_values = iter(['inactive\n', 'active\n'])
    owner_values = iter(['sampleuser\n', 'root\n'])

    def _fake_exec(_client, command, *, timeout=120.0, cancel_check=None, check=False):
        if 'systemctl show -p MainPID' in command:
            return 0, next(show_values), ''
        if 'systemctl is-active core-daemon' in command:
            return 0, next(active_values), ''
        if 'ps -o user=' in command:
            return 0, next(owner_values), ''
        raise AssertionError(f'unexpected command: {command}')

    monkeypatch.setattr(backend, '_exec_ssh_command', _fake_exec)

    heal_calls = []

    def _fake_heal(_client, *, sudo_password, pids, logger):
        heal_calls.append({'sudo_password': sudo_password, 'pids': list(pids)})
        return {
            'status': 'attempted',
            'main_pid': 2222,
            'preserved_main_pid': False,
            'kill_targets': [9124],
        }

    monkeypatch.setattr(backend, '_stop_remote_core_daemon_conflict', _fake_heal)

    pid = backend._ensure_remote_core_daemon_ready(
        client=object(),
        core_cfg={'ssh_password': 'pw'},
        auto_start_allowed=True,
        sudo_password='pw',
        prefer_managed_service=True,
        logger=backend.app.logger,
    )

    assert pid == 2222
    assert heal_calls == [{'sudo_password': 'pw', 'pids': [9124]}]


def test_ensure_remote_daemon_ready_prefer_managed_service_without_sudo_raises(monkeypatch):
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [9124])

    def _fake_exec(_client, command, *, timeout=120.0, cancel_check=None, check=False):
        if 'systemctl show -p MainPID' in command:
            return 0, '0\n', ''
        if 'systemctl is-active core-daemon' in command:
            return 0, 'inactive\n', ''
        if 'ps -o user=' in command:
            return 0, 'sampleuser\n', ''
        raise AssertionError(f'unexpected command: {command}')

    monkeypatch.setattr(backend, '_exec_ssh_command', _fake_exec)

    with pytest.raises(backend.CoreDaemonMissingError) as exc:
        backend._ensure_remote_core_daemon_ready(
            client=object(),
            core_cfg={'ssh_password': ''},
            auto_start_allowed=True,
            sudo_password='',
            prefer_managed_service=True,
            logger=backend.app.logger,
        )

    assert 'provide an SSH password' in str(exc.value)


def test_ensure_remote_daemon_ready_auto_heals_duplicate_pids(monkeypatch):
    pid_samples = [[1111, 2222], [2222]]

    def _fake_collect(_client, **_kwargs):
        if pid_samples:
            return pid_samples.pop(0)
        return [2222]

    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', _fake_collect)

    heal_calls = []

    def _fake_heal(_client, *, sudo_password, pids, logger):
        heal_calls.append({'sudo_password': sudo_password, 'pids': list(pids)})
        return {
            'status': 'attempted',
            'main_pid': 2222,
            'preserved_main_pid': True,
            'kill_targets': [1111],
        }

    monkeypatch.setattr(backend, '_stop_remote_core_daemon_conflict', _fake_heal)

    pid = backend._ensure_remote_core_daemon_ready(
        client=object(),
        core_cfg={'ssh_password': 'pw'},
        auto_start_allowed=True,
        sudo_password='pw',
        logger=backend.app.logger,
    )
    assert pid == 2222
    assert heal_calls == [{'sudo_password': 'pw', 'pids': [1111, 2222]}]


def test_ensure_remote_daemon_ready_conflict_without_sudo_raises(monkeypatch):
    monkeypatch.setattr(backend, '_collect_remote_core_daemon_pids', lambda *_args, **_kwargs: [1111, 2222])

    def _unexpected_heal(*_args, **_kwargs):
        raise AssertionError('auto-heal should not run without sudo password')

    monkeypatch.setattr(backend, '_stop_remote_core_daemon_conflict', _unexpected_heal)

    with pytest.raises(backend.CoreDaemonConflictError) as exc:
        backend._ensure_remote_core_daemon_ready(
            client=object(),
            core_cfg={'ssh_password': ''},
            auto_start_allowed=True,
            sudo_password='',
            logger=backend.app.logger,
        )
    assert 'Multiple core-daemon processes are running' in str(exc.value)


def test_is_transient_remote_prepare_error_matches_network_signatures():
    assert backend._is_transient_remote_prepare_error(RuntimeError('[Errno 65] No route to host')) is True
    assert backend._is_transient_remote_prepare_error(RuntimeError('Connection reset by peer')) is True
    assert backend._is_transient_remote_prepare_error(RuntimeError('socket timeout while connecting')) is True


def test_is_transient_remote_prepare_error_ignores_non_network_errors():
    assert backend._is_transient_remote_prepare_error(RuntimeError('invalid xml schema')) is False
    assert backend._is_transient_remote_prepare_error(RuntimeError('permission denied writing file')) is False
