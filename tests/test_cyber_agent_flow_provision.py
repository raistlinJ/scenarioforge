import importlib.util
import json
from pathlib import Path
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / 'scripts/provision/common/cyber_agent_flow.py'
spec = importlib.util.spec_from_file_location('caf_provision', COMMON)
caf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(caf)

@pytest.fixture
def config():
    return dict(cyber_agent_flow=True, participant_os='kali',
                llm_provider_address='203.0.113.20', llm_provider_url='http://203.0.113.20:11434',
                llm_interface_cidr='192.168.80.10/24', llm_gateway='192.168.80.2')

@pytest.mark.parametrize('key,value', [
    ('participant_os', 'debian'), ('llm_provider_address', '0.0.0.0/0'),
    ('llm_provider_address', '10.254.200.20'), ('llm_provider_url', 'http://wrong-host:11434'),
    ('llm_gateway', '192.168.90.1'), ('llm_interface_cidr', '10.254.200.10/24'),
    ('cyber_agent_flow_ref', '--evil'), ('cyber_agent_flow_url', 'file:///tmp/repo'),
    ('cyber_agent_flow', 'false'),
])
def test_invalid_config(config, key, value):
    config[key] = value
    with pytest.raises(ValueError):
        caf.validate(config)


def test_fixed_provider_route(config):
    nic = caf.interface(config, '00:50:56:01:02:03')
    assert nic['set-name'] == 'ens20'
    assert nic['routes'] == [{'to': '203.0.113.20/32', 'via': '192.168.80.2'}]
    assert nic['dhcp4'] is False and nic['dhcp6'] is False and nic['accept-ra'] is False
    config.update(llm_provider_address='192.168.80.20', llm_provider_url='http://192.168.80.20:11434')
    assert caf.interface(config, 'mac')['routes'] == [{'to': '192.168.80.20/32', 'scope': 'link'}]


def test_injected_install_precedes_readiness(config, tmp_path):
    script = '#!/bin/bash\ntouch /var/lib/scenarioforge/participant-ready\n'
    assert caf.inject(script, {}) == script
    generated = caf.inject(script, config)
    assert generated.index('install_prerequisites.sh') < generated.index('ip -4 route get') < generated.index('touch /var/lib/scenarioforge/participant-ready')
    assert 'cyber-agent-flow.git' in generated
    assert 'MCP_API_KEY' in generated
    path = tmp_path / 'bootstrap.sh'
    path.write_text(generated)
    subprocess.run(['bash', '-n', str(path)], check=True)

@pytest.mark.parametrize('platform,callback', [
    ('vmware-fusion-mac', 'apply_vmware_config_value'),
    ('proxmox', 'apply_proxmox_config_value'),
])
def test_shell_config_and_guest_generation(platform, callback, config, tmp_path):
    installer = ROOT / 'scripts/provision' / platform / 'install-scenarioforge-lab.sh'
    assignments = '\n'.join(f'{callback} {key} {shlex.quote(str(value).lower() if isinstance(value, bool) else value)}' for key, value in config.items())
    probe = f'''source {shlex.quote(str(installer))}
{assignments}
validate_caf
WORK_DIR={shlex.quote(str(tmp_path))}
write_guest_bootstraps
caf_generate inject "$WORK_DIR/participant-bootstrap.sh"
caf_generate network 00:50:56:01:02:03
'''
    result = subprocess.run(['bash', '-c', probe], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    network = json.loads(result.stdout.strip().removeprefix('llm: '))
    assert network['routes'][0]['to'] == '203.0.113.20/32'
    generated = (tmp_path / 'participant-bootstrap.sh').read_text()
    assert '/opt/cyber-agent-flow' in generated
    subprocess.run(['bash', '-n', str(tmp_path / 'participant-bootstrap.sh')], check=True)


def test_fusion_detach_keeps_dedicated_nic(tmp_path):
    installer = ROOT / 'scripts/provision/vmware-fusion-mac/install-scenarioforge-lab.sh'
    vmx = tmp_path / 'participant.vmx'
    vmx.write_text('ethernet0.present = "TRUE"\nethernet1.present = "TRUE"\nethernet1.connectionType = "nat"\nethernet2.present = "TRUE"\nethernet2.vnet = "vmnet8"\n')
    probe = f'''source {shlex.quote(str(installer))}
CYBER_AGENT_FLOW=1
PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=1
PARTICIPANT_VMX={shlex.quote(str(vmx))}
vm_running() {{ return 1; }}
vmrun() {{ if [[ "$*" == *deleteNetworkAdapter* ]]; then exit 93; fi; return 0; }}
write_state() {{ :; }}
start_vm() {{ :; }}
detach_participant_uplink
[[ "$PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED" == 0 ]]
'''
    result = subprocess.run(['bash', '-c', probe], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'ethernet1.' not in vmx.read_text()
    assert 'ethernet2.vnet = "vmnet8"' in vmx.read_text()


def test_proxmox_third_nic_attached(tmp_path):
    installer = ROOT / 'scripts/provision/proxmox/install-scenarioforge-lab.sh'
    # Exercise the actual create_vms function with qm and base VM construction mocked.
    probe = f'''source {shlex.quote(str(installer))}
CYBER_AGENT_FLOW=1
LLM_BRIDGE=vmbr9
PARTICIPANT_NET2_MAC=02:00:00:00:00:09
for name in CORE_NET0_MAC CORE_NET1_MAC CORE_NET2_MAC APP_NET0_MAC APP_NET1_MAC PARTICIPANT_NET0_MAC PARTICIPANT_NET1_MAC; do printf -v "$name" '%s' 02:00:00:00:00:01; done
DEBIAN_IMAGE=/tmp/debian
UBUNTU_IMAGE=/tmp/ubuntu
PARTICIPANT_IMAGE=/tmp/kali
create_vm() {{ :; }}
run() {{ printf '%s\\n' "$*"; }}
create_vms
'''
    result = subprocess.run(['bash', '-c', probe], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert '--net2 virtio=02:00:00:00:00:09,bridge=vmbr9' in result.stdout


def test_launcher_starts_web_mode(config, tmp_path):
    generated = caf.inject('touch /var/lib/scenarioforge/participant-ready\n', config)
    launcher = generated.split("<<'CAF_LAUNCH'\n", 1)[1].split('\nCAF_LAUNCH', 1)[0]
    (tmp_path / 'start_ws.sh').write_text('#!/bin/bash\nprintf "web mode:%s\\n" "$*"\n')
    path = tmp_path / 'launcher'
    path.write_text(launcher.replace('cd /opt/cyber-agent-flow', f'cd {shlex.quote(str(tmp_path))}'))
    result = subprocess.run(['bash', str(path), '--build'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'web mode:--build'


def test_web_defaults_patch_applies_and_is_idempotent(tmp_path):
    import ast
    patch = COMMON.with_name('cyber-agent-flow-web-defaults.patch')
    source = ROOT.parent / 'cyber-agent-flow'
    if not (source / '.git').exists():
        pytest.skip('Sibling checkout needed for upstream compatibility check')
    for name in ('app.py', 'static/js/main.js', 'templates/index.html'):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        content = subprocess.check_output(['git', '-C', str(source), 'show', f'HEAD:{name}'])
        target.write_bytes(content)
    subprocess.run(['git', '-C', str(tmp_path), 'apply', str(patch)], check=True)
    subprocess.run(['git', '-C', str(tmp_path), 'apply', '--reverse', '--check', str(patch)], check=True)
    tree = ast.parse((tmp_path / 'app.py').read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_web_cli_defaults')
    namespace = {'__file__': str(tmp_path / 'app.py'), 'json': json}
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<defaults>', 'exec'), namespace)
    load = namespace['_web_cli_defaults']
    assert load() == {}
    config = tmp_path / 'configs/cli.json'
    config.parent.mkdir()
    config.write_text(json.dumps(dict(provider='openai', url='http://192.0.2.1:8000/v1', model='example',
                                     ssl_verify=False, api_key='secret', api_key_env='SECRET', context_window=4096)))
    assert load() == dict(provider='openai', url='http://192.0.2.1:8000/v1', model='example', sslVerify=False, contextWindow=4096)
    config.write_text('{invalid')
    assert load() == {}
    config.write_text(json.dumps({'url': 'https://user:password@example.com', 'api_key': 'secret'}))
    assert load() == {}
