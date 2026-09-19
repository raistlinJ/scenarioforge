import importlib.util
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hitl_gateway', ROOT / 'scripts/provision/common/hitl_gateway.py')
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


@pytest.mark.parametrize('core,participant,override,expected', [
    ('10.254.200.3/24', '10.254.200.10/24', '', '10.254.200.1'),
    ('10.80.12.3/24', '10.80.12.10/24', '', '10.80.12.1'),
    ('10.80.12.1/24', '10.80.12.10/24', '', '10.80.12.2'),
    ('10.254.200.3/24', '10.254.200.10/24', '10.254.200.2', '10.254.200.2'),
])
def test_router_address_is_separate_from_interface(core, participant, override, expected):
    assert gateway.resolve(core, participant, override) == expected


@pytest.mark.parametrize('override', ['10.254.200.3', '10.254.200.10', '10.254.200.0', '10.254.200.255', '10.99.0.1', '::1', 'invalid'])
def test_invalid_gateway_rejected(override):
    with pytest.raises(ValueError):
        gateway.resolve('10.254.200.3/24', '10.254.200.10/24', override)


@pytest.mark.parametrize('platform', ['proxmox', 'vmware-workstation-linux', 'vmware-fusion-mac'])
@pytest.mark.parametrize('mode,expected', [('default', '10.254.200.1'), ('config', '10.254.200.2'), ('env', '10.254.200.4'), ('cli', '10.254.200.5')])
def test_shell_gateway_precedence(tmp_path, platform, mode, expected):
    config = tmp_path / 'lab.conf'
    config.write_text('participant_gateway=10.254.200.2\n')
    env = {key: value for key, value in os.environ.items() if not key.startswith('SF_')}
    args = [] if mode == 'default' else ['--config', str(config)]
    if mode in ('env', 'cli'):
        env['SF_PARTICIPANT_GATEWAY'] = '10.254.200.4'
    if mode == 'cli':
        args += ['--participant-gateway', expected]
    installer = ROOT / 'scripts/provision' / platform / 'install-scenarioforge-lab.sh'
    result = subprocess.run(['bash', '-c', 'source "$1"; shift; parse_args install "$@"; resolve_participant_gateway; printf "%s|%s|%s\\n" "$CORE_HITL_CIDR" "$PARTICIPANT_CIDR" "$PARTICIPANT_GATEWAY"', 'test', str(installer), *args],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == f'10.254.200.3/24|10.254.200.10/24|{expected}'


@pytest.mark.parametrize('attachment,router_key', [
    ('existing_router', 'existing_router_ip4'), ('new_router', 'new_router_ip4'),
])
@pytest.mark.parametrize('saved_gateway', ['10.254.200.1', '10.254.200.2', '10.254.200.20'])
def test_saved_runtime_env_controls_router_on_later_runs(tmp_path, monkeypatch, attachment, router_key, saved_gateway):
    from webapp.env_loader import load_runtime_env_files
    from scenarioforge.utils.hitl import preferred_hitl_link_ips

    values = dict(CORETG_HITL_CORE_IFX_IPV4='10.254.200.3/24',
                  CORETG_VM_MODE_HITL_CORE_IFX_NAME='ens19', CORETG_HITL_GATEWAY=saved_gateway)
    for key in values:
        monkeypatch.setenv(key, '')
    (tmp_path / '.scenarioforge.env').write_text(''.join(f'{k}={v}\n' for k, v in values.items()))
    load_runtime_env_files(base_dir=tmp_path, override=True)
    info = preferred_hitl_link_ips(dict(name='ens19', ipv4=['10.254.200.3/24'], attachment=attachment))
    assert info[router_key] == saved_gateway
    assert len({info['existing_router_ip4'], info['new_router_ip4'], info['rj45_ip4']}) == 3
    from webapp import app_backend
    preview = app_backend._sanitize_hitl_config(
        {'enabled': True, 'interfaces': [{'name': 'ens19', 'ipv4': ['10.254.200.3/24'], 'attachment': attachment}]},
        'Saved gateway', 'saved-gateway',
    )
    assert preview['interfaces'][0][router_key] == saved_gateway
    # A different interface or scenario-supplied subnet is not overridden.
    other = preferred_hitl_link_ips(dict(name='ens20', ipv4=['10.254.200.3/24']))
    assert other['existing_router_ip4'] == '10.254.200.1'
    other = preferred_hitl_link_ips(dict(name='ens19', ipv4=['192.0.2.3/24']))
    assert other['existing_router_ip4'] == '192.0.2.1'


@pytest.mark.parametrize('value', ['10.254.200.3', '10.254.200.0', '10.254.200.255', '10.99.0.1', 'invalid'])
def test_runtime_rejects_invalid_saved_gateway(monkeypatch, value):
    from scenarioforge.utils.hitl import preferred_hitl_link_ips

    monkeypatch.setenv('CORETG_HITL_CORE_IFX_IPV4', '10.254.200.3/24')
    monkeypatch.setenv('CORETG_VM_MODE_HITL_CORE_IFX_NAME', 'ens19')
    monkeypatch.setenv('CORETG_HITL_GATEWAY', value)
    with pytest.raises(ValueError):
        preferred_hitl_link_ips(dict(name='ens19', ipv4=['10.254.200.3/24']))
