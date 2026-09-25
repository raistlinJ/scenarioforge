import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

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
    ('llm_provider_address', '10.254.200.20'), ('llm_provider_url', 'ftp://provider.example'),
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


def test_automatic_dhcp_ignores_general_routes_and_installs_route_service(config, tmp_path):
    config.update(llm_interface_cidr='', llm_gateway='')
    nic = caf.interface(config, 'mac')
    assert nic['dhcp4'] is True
    assert nic['dhcp-identifier'] == 'mac'
    assert nic['dhcp4-overrides']['use-routes'] is False
    assert nic['dhcp4-overrides']['use-dns'] is False
    assert 'routes' not in nic
    script = caf.inject('#!/bin/bash\ntouch /var/lib/scenarioforge/participant-ready\n', config)
    assert script.index('systemctl start scenarioforge-llm-route.service') < script.index('touch /var/lib/scenarioforge/participant-ready')
    path = tmp_path / 'auto.sh'
    path.write_text(script)
    subprocess.run(['bash', '-n', str(path)], check=True)


def test_automatic_route_uses_lease_and_rejects_protected_networks():
    spec = importlib.util.spec_from_file_location('llm_route', COMMON.with_name('llm_dhcp_route.py'))
    route = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(route)
    config = dict(provider='203.0.113.20', protected=['10.254.200.10/24', '172.31.250.3/24'])
    lease = dict(ADDRESS='192.168.20.100', NETMASK='255.255.255.0', ROUTER='192.168.20.2')
    args = route.route_arguments(config, lease)
    assert args == ['ip', '-4', 'route', 'replace', '203.0.113.20/32', 'via', '192.168.20.2', 'dev', 'ens20', 'src', '192.168.20.100']
    with pytest.raises(ValueError):
        route.route_arguments(config, dict(lease, ADDRESS='10.254.200.30'))
    with pytest.raises(ValueError):
        route.route_arguments(config, dict(lease, ROUTER='14.0.0.1'))
    config['provider'] = '192.168.20.50'
    assert 'via' not in route.route_arguments(config, lease)


def test_provider_hostname_and_gateway_cidr_are_accepted_and_normalized(config):
    config.update(llm_provider_url='https://provider.example:10101/v1', llm_gateway='192.168.80.2/24')
    normalized = caf.validate(config)
    assert normalized['llm_gateway'] == '192.168.80.2'
    assert caf.interface(normalized, 'mac')['routes'] == [{'to': '203.0.113.20/32', 'via': '192.168.80.2'}]


def test_injected_install_precedes_readiness(config, tmp_path):
    script = '#!/bin/bash\ntouch /var/lib/scenarioforge/participant-ready\n'
    assert caf.inject(script, {}) == script
    generated = caf.inject(script, config)
    assert generated.index('install_prerequisites.sh') < generated.index('ip -4 route get') < generated.index('touch /var/lib/scenarioforge/participant-ready')
    assert 'cyber-agent-flow.git' in generated
    assert 'MCP_API_KEY' in generated
    assert generated.index('bash /usr/local/sbin/scenarioforge-caf-runtime') < generated.index('if [[ ! -f /var/lib/scenarioforge/cyber-agent-flow-installed')
    assert 'SUDO_USER=participant bash /opt/cyber-agent-flow/install_prerequisites.sh' in generated
    assert 'sudo -H -u participant bash /opt/cyber-agent-flow/install_claude.sh --check' in generated
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
CORE_MANAGEMENT_CIDR=172.31.250.3/24
validate_caf >&2
WORK_DIR={shlex.quote(str(tmp_path))}
write_guest_bootstraps
caf_generate inject "$WORK_DIR/participant-bootstrap.sh"
caf_generate network 00:50:56:01:02:03
'''
    result = subprocess.run(['bash', '-c', probe], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    network = json.loads(result.stdout.strip().removeprefix('llm: '))
    assert network['routes'][0]['to'] == '203.0.113.20/32'
    assert network['match'] == {'macaddress': '00:50:56:01:02:03'}
    assert network['set-name'] == 'ens20'
    generated = (tmp_path / 'participant-bootstrap.sh').read_text()
    assert '/opt/cyber-agent-flow' in generated
    subprocess.run(['bash', '-n', str(tmp_path / 'participant-bootstrap.sh')], check=True)


def test_shell_option_selects_kali_after_default_debian_config(tmp_path):
    installer = ROOT / 'scripts/provision/vmware-fusion-mac/install-scenarioforge-lab.sh'
    probe = f'''source {shlex.quote(str(installer))}
PARTICIPANT_OS=debian
PARTICIPANT_DISK_GB=20
CORE_MANAGEMENT_CIDR=172.31.250.3/24
CYBER_AGENT_FLOW=1
LLM_PROVIDER_ADDRESS=203.0.113.20
LLM_PROVIDER_URL=https://provider.example:10101/v1
LLM_INTERFACE_CIDR=192.168.80.10/24
LLM_GATEWAY=192.168.80.2/24
validate_caf
printf '%s|%s|%s\\n' "$PARTICIPANT_OS" "$PARTICIPANT_DISK_GB" "$LLM_GATEWAY"
'''
    result = subprocess.run(['bash', '-c', probe], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.endswith('kali|80|192.168.80.2/24\n')


def test_fusion_detach_keeps_dedicated_nic(tmp_path):
    installer = ROOT / 'scripts/provision/vmware-fusion-mac/install-scenarioforge-lab.sh'
    vmx = tmp_path / 'participant.vmx'
    vmx.write_text('ethernet0.present = "TRUE"\nethernet1.present = "TRUE"\nethernet1.connectionType = "nat"\nethernet2.present = "TRUE"\nethernet2.vnet = "vmnet8"\n')
    probe = f'''source {shlex.quote(str(installer))}
CYBER_AGENT_FLOW=1
PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=1
PARTICIPANT_VMX={shlex.quote(str(vmx))}
vm_running() {{ return 1; }}
vmrun() {{
    if [[ "$*" == *deleteNetworkAdapter* ]]; then exit 93; fi
    if [[ "$*" == *listNetworkAdapters* ]]; then printf '0 custom vmnet3\\n1 custom vmnet8\\n'; fi
    return 0
}}
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
    (tmp_path / 'start_ws.sh').write_text('#!/bin/bash\n[[ "$VIRTUAL_ENV" == /opt/cyber-agent-flow/venv ]] || exit 91\n[[ "$PATH" == "$VIRTUAL_ENV/bin:"* ]] || exit 92\nprintf "web mode:%s\\n" "$*"\n')
    path = tmp_path / 'launcher'
    path.write_text(launcher.replace('cd /opt/cyber-agent-flow', f'cd {shlex.quote(str(tmp_path))}'))
    result = subprocess.run(['bash', str(path), '--build'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'web mode:--build'


def test_launcher_child_resolves_python_from_virtual_environment(config, tmp_path):
    generated = caf.inject('touch /var/lib/scenarioforge/participant-ready\n', config)
    launcher = generated.split("<<'CAF_LAUNCH'\n", 1)[1].split('\nCAF_LAUNCH', 1)[0]
    bindir = tmp_path / 'venv/bin'
    bindir.mkdir(parents=True)
    python = bindir / 'python3'
    python.write_text('#!/bin/bash\n[[ -z "${PYTHONHOME+x}" ]] || exit 93\necho venv-child\n')
    python.chmod(0o755)
    (tmp_path / 'start_ws.sh').write_text('#!/bin/bash\nbash -c "python3"\n')
    path = tmp_path / 'launcher'
    path.write_text(launcher.replace('/opt/cyber-agent-flow', str(tmp_path)))
    result = subprocess.run(['bash', str(path)], env={**os.environ, 'PYTHONHOME': '/invalid'},
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'venv-child'


def test_launcher_resolves_participant_claude(config, tmp_path):
    generated = caf.inject('touch /var/lib/scenarioforge/participant-ready\n', config)
    launcher = generated.split("<<'CAF_LAUNCH'\n", 1)[1].split('\nCAF_LAUNCH', 1)[0]
    bindir = tmp_path / '.local/bin'
    bindir.mkdir(parents=True)
    cli = bindir / 'claude'
    cli.write_text('#!/bin/bash\necho participant-claude\n')
    cli.chmod(0o755)
    (tmp_path / 'start_ws.sh').write_text('#!/bin/bash\nclaude --version\n')
    path = tmp_path / 'launcher'
    path.write_text(launcher.replace('/opt/cyber-agent-flow', str(tmp_path)))
    result = subprocess.run(['bash', str(path)], env={**os.environ, 'HOME': str(tmp_path)},
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'participant-claude'


@pytest.mark.parametrize('failure', ['', 'apt-get', 'systemctl', 'docker info', 'docker compose version', 'docker-compose version', 'curl', 'claude'])
def test_runtime_setup_checks_tools_as_participant_and_fails_closed(tmp_path, failure):
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    home = tmp_path / 'participant'
    home.mkdir()
    log = tmp_path / 'commands.jsonl'
    stub = bindir / 'stub'
    stub.write_text(f'#!{sys.executable}\n' + '''import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['COMMAND_LOG'], 'a') as stream:
    stream.write(json.dumps([name, args, os.environ.get('TEST_USER', 'root')]) + '\\n')
failure = os.environ['TEST_FAILURE']
if failure and (name == failure or ' '.join([name, *args]) == failure):
    sys.exit(42)
if name == 'sudo':
    assert args[:3] == ['-H', '-u', 'participant']
    os.execvpe(args[3], args[3:], dict(os.environ, HOME=os.environ['PARTICIPANT_HOME'], TEST_USER='participant'))
elif name == 'curl':
    assert os.environ['TEST_USER'] == 'participant'
    output = pathlib.Path(args[args.index('--output') + 1])
    output.write_text('mkdir -p "$HOME/.local/bin"\\ncp "$TEST_CLAUDE" "$HOME/.local/bin/claude"\\n')
''')
    stub.chmod(0o755)
    for command in ('apt-get', 'systemctl', 'usermod', 'sudo', 'docker', 'docker-compose', 'curl', 'claude'):
        (bindir / command).symlink_to(stub)
    env = {**os.environ, 'PATH': str(bindir) + ':' + os.environ['PATH'],
           'COMMAND_LOG': str(log), 'PARTICIPANT_HOME': str(home),
           'TEST_CLAUDE': str(bindir / 'claude'), 'TEST_FAILURE': failure}
    script = COMMON.with_name('cyber-agent-flow-runtime.sh')
    result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True)
    assert (result.returncode != 0) == bool(failure), result.stderr
    if failure:
        return
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    assert ['apt-get', ['install', '-y', 'docker.io', 'docker-compose', 'curl', 'ca-certificates'], 'root'] in commands
    assert ['systemctl', ['enable', '--now', 'docker.service'], 'root'] in commands
    assert ['usermod', ['-aG', 'docker', 'participant'], 'root'] in commands
    for command, args in [('docker', ['info']), ('docker', ['compose', 'version']),
                          ('docker-compose', ['version']), ('claude', ['--version'])]:
        assert [command, args, 'participant'] in commands
    # Re-running verifies the installed CLI without downloading it again.
    log.write_text('')
    result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    assert not any(command[0] == 'curl' for command in commands)
    assert ['claude', ['--version'], 'participant'] in commands
