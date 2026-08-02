"""VM mode targets the CORE VM declared by the runtime environment.

`_select_core_config_for_page` falls back through stored credentials and run
history when a scenario has no explicit CORE config. Both are implicit and
machine-specific: after switching from a remote lab to a local CORE VM, a
credential stored during the earlier setup would still win, and every
connection went to an address the operator had already moved away from. The
symptom is a connect timeout surfaced as a generic "Failed to Start".

In VM mode the CORE VM comes from .scenarioforge.env, so those fallbacks are
skipped. Native mode still uses them.
"""

from __future__ import annotations

import pytest

from webapp import app_backend as backend


@pytest.fixture
def stale_secret(monkeypatch):
    """A stored credential pointing at a host the operator has left."""
    record = {
        'identifier': 'stale-record',
        'scenario_name': 'Scenario1',
        'host': 'localhost',
        'port': 50051,
        'ssh_host': 'old-lab.example.edu',
        'ssh_port': 10006,
        'ssh_username': 'corevm',
        'ssh_password_plain': 'stored-secret',
        'vm_key': 'oldlab::185',
    }
    monkeypatch.setattr(backend, '_select_latest_core_secret_record', lambda *_a, **_k: dict(record))
    monkeypatch.setattr(backend, '_load_scenario_hitl_config_from_disk', lambda: {})
    monkeypatch.setattr(backend, '_load_scenario_hitl_validation_from_disk', lambda: {})
    monkeypatch.setattr(backend, '_load_run_history', lambda: [])
    return record


def _use_env_vm(monkeypatch):
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'vm')
    monkeypatch.setenv('CORE_SSH_HOST', '12.0.0.100')
    monkeypatch.setenv('CORE_SSH_PORT', '22')
    monkeypatch.setenv('CORE_SSH_USERNAME', 'corevm')
    monkeypatch.setenv('CORE_SSH_PASSWORD', 'env-secret')


def test_vm_mode_uses_environment_not_a_stale_stored_credential(monkeypatch, stale_secret):
    _use_env_vm(monkeypatch)

    cfg = backend._select_core_config_for_page('Scenario1', include_password=False)

    assert cfg.get('ssh_host') == '12.0.0.100', cfg
    assert str(cfg.get('ssh_port')) == '22', cfg
    # The stale record must not leak any of its identity through either.
    assert cfg.get('core_secret_id') != 'stale-record'
    assert cfg.get('vm_key') != 'oldlab::185'


def test_vm_mode_is_consistent_across_scenarios(monkeypatch, stale_secret):
    """One CORE VM per deployment: a scenario without its own record must not
    inherit another scenario's stored credential."""
    _use_env_vm(monkeypatch)

    first = backend._select_core_config_for_page('Scenario1', include_password=False)
    second = backend._select_core_config_for_page('Scenario2', include_password=False)

    assert first.get('ssh_host') == second.get('ssh_host') == '12.0.0.100'
    assert str(first.get('ssh_port')) == str(second.get('ssh_port')) == '22'


def test_native_mode_still_prefers_the_stored_credential(monkeypatch, stale_secret):
    """The fallbacks exist for native mode, where CORE is not env-declared."""
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')
    monkeypatch.setenv('CORE_SSH_HOST', '12.0.0.100')
    monkeypatch.setenv('CORE_SSH_PORT', '22')

    cfg = backend._select_core_config_for_page('Scenario1', include_password=False)

    assert cfg.get('ssh_host') == 'old-lab.example.edu', cfg
    assert str(cfg.get('ssh_port')) == '10006', cfg


def test_vm_mode_keeps_an_explicit_per_scenario_config(monkeypatch, stale_secret):
    """An explicit config is a visible setting, unlike the implicit fallbacks."""
    _use_env_vm(monkeypatch)
    monkeypatch.setattr(
        backend, '_load_scenario_hitl_config_from_disk',
        lambda: {'scenario1': {'core': {
            'ssh_host': '10.9.9.9', 'ssh_port': 2222, 'ssh_username': 'corevm',
        }}},
    )

    cfg = backend._select_core_config_for_page('Scenario1', include_password=False)
    assert cfg.get('ssh_host') == '10.9.9.9', cfg


def _scenario_xml_with_core(tmp_path, ssh_host: str, ssh_port: int):
    xml = tmp_path / 'Scenario1.xml'
    xml.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Scenarios>\n'
        f'  <CoreConnection host="localhost" port="50051" ssh_enabled="true"\n'
        f'    ssh_host="{ssh_host}" ssh_port="{ssh_port}" ssh_username="corevm"\n'
        '    core_secret_id="stale-record" vm_key="oldlab::185" />\n'
        '  <Scenario name="Scenario1" density_count="4" />\n'
        '</Scenarios>\n',
        encoding='utf-8',
    )
    return str(xml)


def test_vm_mode_ignores_the_core_endpoint_recorded_in_a_scenario(monkeypatch, tmp_path):
    """A scenario records the CORE endpoint it was last saved against.

    Callers merge that over the resolved config, so without this a scenario
    saved against a previous CORE VM drags every connection back to it -- which
    surfaces as `CORE connection failed to localhost:50051: timed out`, naming
    the gRPC target rather than the SSH host actually being dialled.
    """
    _use_env_vm(monkeypatch)
    path = _scenario_xml_with_core(tmp_path, 'old-lab.example.edu', 10006)

    cfg = backend._core_config_from_xml_path(path, 'Scenario1', include_password=True) or {}

    for key in ('host', 'port', 'ssh_host', 'ssh_port', 'ssh_username'):
        assert not cfg.get(key), f'{key} survived: {cfg.get(key)!r}'
    # The stored credential id would refill the transport from the same record.
    assert not cfg.get('core_secret_id')


def test_native_mode_still_honors_the_scenario_core_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')
    path = _scenario_xml_with_core(tmp_path, 'old-lab.example.edu', 10006)

    cfg = backend._core_config_from_xml_path(path, 'Scenario1', include_password=True) or {}

    assert cfg.get('ssh_host') == 'old-lab.example.edu'
    assert str(cfg.get('ssh_port')) == '10006'
