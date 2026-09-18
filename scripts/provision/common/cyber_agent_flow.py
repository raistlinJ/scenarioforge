"""Shared opt-in Kali CyberAgentFlow provisioning and dedicated LLM routing."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
from urllib.parse import urlsplit

DEFAULTS = dict(cyber_agent_flow=False,
    cyber_agent_flow_url='https://github.com/raistlinJ/cyber-agent-flow.git',
    cyber_agent_flow_ref='main', llm_provider_address='', llm_provider_url='',
    llm_provider_type='ollama_direct', llm_model='', llm_interface_cidr='',
    llm_gateway='', llm_vmnet='vmnet8', llm_bridge='')

def validate(config):
    c = {**DEFAULTS, **config}
    if not isinstance(c['cyber_agent_flow'], bool):
        raise ValueError('cyber_agent_flow must be a boolean')
    if not c['cyber_agent_flow']:
        return c
    if c.get('participant_os') != 'kali':
        raise ValueError('cyber_agent_flow requires participant_os=kali')
    provider = ipaddress.IPv4Address(c['llm_provider_address'])
    automatic = not c['llm_interface_cidr'] and not c['llm_gateway']
    if bool(c['llm_interface_cidr']) != bool(c['llm_gateway']):
        raise ValueError('Set both llm_interface_cidr and llm_gateway, or omit both for automatic DHCP configuration')
    interface = None if automatic else ipaddress.IPv4Interface(c['llm_interface_cidr'])
    # Accept an accidental/pasted CIDR suffix on a gateway, but normalize it
    # before emitting Netplan's `via`, which accepts an address only.
    gateway = None if automatic else ipaddress.IPv4Interface(c['llm_gateway']).ip
    c['llm_gateway'] = '' if automatic else str(gateway)
    if provider.is_unspecified or provider.is_multicast or provider.is_loopback:
        raise ValueError('llm_provider_address must be a reachable unicast IPv4 address')
    if not automatic and (gateway not in interface.network or gateway == interface.ip or gateway in (interface.network.network_address, interface.network.broadcast_address)):
        raise ValueError('llm_gateway must be a different usable address in llm_interface_cidr')
    if not automatic and (interface.ip in (interface.network.network_address, interface.network.broadcast_address) or provider == interface.ip):
        raise ValueError('llm_interface_cidr must have a usable guest address distinct from the provider')
    for network in (c.get('participant_cidr', '10.254.200.10/24'), c.get('core_management_cidr', '172.31.250.3/24')):
        protected = ipaddress.ip_interface(network).network
        if (not automatic and interface.network.overlaps(protected)) or provider in protected:
            raise ValueError('LLM network/provider must not overlap HITL or management')
    endpoint = urlsplit(c['llm_provider_url'])
    if endpoint.scheme not in ('http', 'https') or not endpoint.hostname or endpoint.username or endpoint.password:
        raise ValueError('llm_provider_url must be an http(s) URL without credentials')
    if c['llm_provider_type'] not in ('ollama_direct', 'litellm', 'openai', 'claude'):
        raise ValueError('unsupported llm_provider_type')
    source = urlsplit(c['cyber_agent_flow_url'])
    if source.scheme != 'https' or not source.hostname or source.username or source.password:
        raise ValueError('cyber_agent_flow_url must be an HTTPS Git URL without credentials')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', c['cyber_agent_flow_ref']):
        raise ValueError('invalid cyber_agent_flow_ref')
    if not re.fullmatch(r'vmnet\d+', c['llm_vmnet']):
        raise ValueError('invalid llm_vmnet')
    if c['llm_bridge'] and not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]*', c['llm_bridge']):
        raise ValueError('invalid llm_bridge')
    return c

def interface(config, mac):
    c = validate(config)
    if not c['llm_interface_cidr']:
        return {'match': {'macaddress': mac}, 'set-name': 'ens20',
                'dhcp4': True, 'dhcp6': False, 'accept-ra': False, 'link-local': [],
                'dhcp4-overrides': {'use-routes': False, 'use-dns': False, 'use-domains': False,
                                    'use-ntp': False, 'use-hostname': False, 'send-hostname': False}}
    provider = ipaddress.IPv4Address(c['llm_provider_address'])
    subnet = ipaddress.IPv4Interface(c['llm_interface_cidr']).network
    route = {'to': f'{provider}/32'}
    if provider not in subnet:
        route['via'] = c['llm_gateway']
    else:
        route['scope'] = 'link'
    return {'match': {'macaddress': mac}, 'set-name': 'ens20',
            'addresses': [c['llm_interface_cidr']], 'dhcp4': False, 'dhcp6': False,
            'accept-ra': False, 'link-local': [], 'routes': [route]}

def inject(script, config):
    c = validate(config)
    if not c['cyber_agent_flow']:
        return script
    cli = dict(provider=c['llm_provider_type'], url=c['llm_provider_url'], model=c['llm_model'],
               api_key_env='MCP_API_KEY', ssl_verify=True, server_command='venv/bin/python mcp_kali.py',
               tools_config='kali_tools.json')
    q = shlex.quote
    automatic_setup = ''
    if not c['llm_interface_cidr']:
        route_config = json.dumps(dict(provider=c['llm_provider_address'], protected=[
            c.get('participant_cidr', '10.254.200.10/24'), c.get('core_management_cidr', '172.31.250.3/24')]))
        route_script = Path(__file__).with_name('llm_dhcp_route.py').read_text()
        automatic_setup = f'''
cat > /usr/local/sbin/scenarioforge-llm-route <<'CAF_ROUTE_SCRIPT'
{route_script}
CAF_ROUTE_SCRIPT
chmod 0755 /usr/local/sbin/scenarioforge-llm-route
cat > /etc/scenarioforge-llm-route.json <<'CAF_ROUTE_CONFIG'
{route_config}
CAF_ROUTE_CONFIG
cat > /etc/systemd/system/scenarioforge-llm-route.service <<'CAF_ROUTE_SERVICE'
[Unit]
Description=Route the LLM provider through the dedicated DHCP interface
After=systemd-networkd.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/scenarioforge-llm-route
CAF_ROUTE_SERVICE
cat > /etc/systemd/system/scenarioforge-llm-route.timer <<'CAF_ROUTE_TIMER'
[Unit]
Description=Refresh the LLM provider route after DHCP lease changes
[Timer]
OnBootSec=10s
OnUnitInactiveSec=15s
[Install]
WantedBy=timers.target
CAF_ROUTE_TIMER
systemctl daemon-reload
systemctl enable --now scenarioforge-llm-route.timer
llm_route_ready=0
for attempt in $(seq 1 30); do
    if systemctl start scenarioforge-llm-route.service; then llm_route_ready=1; break; fi
    sleep 2
done
[[ "$llm_route_ready" == 1 ]] || fail_bootstrap 'LLM DHCP lease/route unavailable; check DHCP on the selected vmnet/bridge or provide both static overrides'
'''
    addition = f'''
set_bootstrap_status 90 'installing CyberAgentFlow'
[[ "$ID" == kali ]] || fail_bootstrap 'CyberAgentFlow requires Kali'
apt-get install -y git ca-certificates python3-venv python3-dev python3-yaml build-essential xdotool x11-utils python3-psutil curl xdg-utils
cat > /usr/local/sbin/scenarioforge-caf-runtime <<'CAF_RUNTIME'
{Path(__file__).with_name('cyber-agent-flow-runtime.sh').read_text()}
CAF_RUNTIME
chmod 0755 /usr/local/sbin/scenarioforge-caf-runtime
bash /usr/local/sbin/scenarioforge-caf-runtime \\
    || fail_bootstrap 'CyberAgentFlow requires working Docker, Compose, and Claude CLI for participant; inspect the error above'
if [[ ! -f /var/lib/scenarioforge/cyber-agent-flow-installed ]]; then
    if [[ ! -f /var/lib/scenarioforge/cyber-agent-flow-source-ready ]]; then
        [[ ! -e /opt/cyber-agent-flow ]] || fail_bootstrap '/opt/cyber-agent-flow already exists; inspect the incomplete installation'
        git clone -- {q(c['cyber_agent_flow_url'])} /opt/cyber-agent-flow
        touch /var/lib/scenarioforge/cyber-agent-flow-source-ready
    fi
    git -C /opt/cyber-agent-flow fetch origin {q(c['cyber_agent_flow_ref'])}
    git -C /opt/cyber-agent-flow checkout --detach FETCH_HEAD
    # CyberAgentFlow uses the MCP v1 decorator API; v2 is incompatible.
    printf 'mcp>=1.28,<2\n' > /opt/cyber-agent-flow/scenarioforge-constraints.txt
    export PIP_CONSTRAINT=/opt/cyber-agent-flow/scenarioforge-constraints.txt
    SUDO_USER=participant bash /opt/cyber-agent-flow/install_prerequisites.sh
    # Do not trust prerequisite scripts that can warn and skip pip setup.
    /opt/cyber-agent-flow/venv/bin/python -m pip install -r /opt/cyber-agent-flow/requirements.txt
    /opt/cyber-agent-flow/venv/bin/python -m pip check
    /opt/cyber-agent-flow/venv/bin/python -c "from mcp.server import Server; assert callable(Server('provision-check').list_tools)"
    /opt/cyber-agent-flow/venv/bin/python -c "import flask, requests, mcp, ollama, importlib.util; assert importlib.util.find_spec('pynput'), 'pynput is missing'"
    cat > /opt/cyber-agent-flow/configs/cli.json <<'CAF_CONFIG'
{json.dumps(cli, indent=2)}
CAF_CONFIG
    chown -R participant:participant /opt/cyber-agent-flow
    chmod 0600 /opt/cyber-agent-flow/configs/cli.json
    touch /var/lib/scenarioforge/cyber-agent-flow-installed
fi
# Verify existing installations too, before declaring the participant ready.
if [[ -f /opt/cyber-agent-flow/install_claude.sh ]]; then
    sudo -H -u participant bash /opt/cyber-agent-flow/install_claude.sh --check \\
        || fail_bootstrap 'Claude CLI does not meet CyberAgentFlow requirements; run install_claude.sh as participant'
fi
/opt/cyber-agent-flow/venv/bin/python -c "from mcp.server import Server; assert callable(Server('provision-check').list_tools)" \\
    || fail_bootstrap 'CyberAgentFlow requires MCP v1; install mcp>=1.28,<2 in its virtual environment'
/opt/cyber-agent-flow/venv/bin/python -c "import flask, requests, mcp, ollama, importlib.util; assert importlib.util.find_spec('pynput'), 'pynput is missing'" \\
    || fail_bootstrap 'CyberAgentFlow dependency verification failed; inspect the Python error above'
cat > /usr/local/sbin/update-llm-destination <<'CAF_UPDATE_SCRIPT'
{Path(__file__).with_name('update-llm-destination.py').read_text()}
CAF_UPDATE_SCRIPT
chmod 0755 /usr/local/sbin/update-llm-destination
{automatic_setup}
provider_host={q(urlsplit(c['llm_provider_url']).hostname or '')}
if [[ "$provider_host" != {q(str(c['llm_provider_address']))} ]]; then
    getent ahostsv4 "$provider_host" | awk '{{print $1}}' | sort -u | grep -Fxq -- {q(str(c['llm_provider_address']))} \
        || fail_bootstrap 'LLM provider URL hostname does not resolve to llm_provider_address'
fi
ip -4 route get {q(c['llm_provider_address'])} | grep -Eq 'dev ens20( |$)' || fail_bootstrap 'LLM provider traffic is not routed through ens20'
/usr/local/sbin/update-llm-destination --sync-policy {q(c['llm_provider_address'])} || fail_bootstrap 'Could not exclude the LLM route gateway from CyberAgentFlow targets'
cat > /usr/local/bin/cyber-agent-flow <<'CAF_LAUNCH'
#!/bin/bash
set -e
cd /opt/cyber-agent-flow
# MCP children invoke Python through PATH, so export the environment to them.
unset PYTHONHOME
export VIRTUAL_ENV=/opt/cyber-agent-flow/venv
export PATH="$VIRTUAL_ENV/bin:$HOME/.local/bin:$PATH"
exec bash ./start_ws.sh "$@"
CAF_LAUNCH
chmod 0755 /usr/local/bin/cyber-agent-flow
cat > /usr/local/bin/cyber-agent-flow-desktop <<'CAF_DESKTOP_LAUNCH'
{Path(__file__).with_name('cyber-agent-flow-desktop.sh').read_text()}
CAF_DESKTOP_LAUNCH
chmod 0755 /usr/local/bin/cyber-agent-flow-desktop
install -d -o participant -g participant -m 0755 /home/participant/Desktop
cat > /home/participant/Desktop/cyber-agent-flow.desktop <<'CAF_DESKTOP'
[Desktop Entry]
Type=Application
Name=CyberAgentFlow Web
Comment=Start the CyberAgentFlow web server
Exec=/usr/local/bin/cyber-agent-flow-desktop
Path=/opt/cyber-agent-flow
Icon=utilities-terminal
Terminal=true
Categories=Development;Network;
StartupNotify=false
CAF_DESKTOP
chown participant:participant /home/participant/Desktop/cyber-agent-flow.desktop
chmod 0755 /home/participant/Desktop/cyber-agent-flow.desktop
install -m 0644 /home/participant/Desktop/cyber-agent-flow.desktop /usr/share/applications/cyber-agent-flow.desktop
cat > /home/participant/Desktop/update-llm-destination.desktop <<'CAF_UPDATE_DESKTOP'
[Desktop Entry]
Type=Application
Name=Update LLM Destination
Comment=Update CyberAgentFlow endpoint, dedicated route, and gateway exclusion
Exec=sudo /usr/local/sbin/update-llm-destination
Icon=network-wired
Terminal=true
Categories=Network;
CAF_UPDATE_DESKTOP
chown participant:participant /home/participant/Desktop/update-llm-destination.desktop
chmod 0755 /home/participant/Desktop/update-llm-destination.desktop
install -m 0644 /home/participant/Desktop/update-llm-destination.desktop /usr/share/applications/update-llm-destination.desktop
'''
    marker = 'touch /var/lib/scenarioforge/participant-ready'
    if script.count(marker) != 1:
        raise ValueError('participant readiness marker missing or ambiguous')
    return script.replace(marker, addition + '\n' + marker)

def from_environment():
    c = {key: os.environ.get('SF_CAF_' + key.upper(), value) for key, value in DEFAULTS.items()}
    c['cyber_agent_flow'] = str(c['cyber_agent_flow']).lower() in ('1', 'true')
    for key in ('participant_os', 'participant_cidr', 'core_management_cidr'):
        c[key] = os.environ['SF_CAF_' + key.upper()]
    return validate(c)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['validate', 'inject', 'network'])
    parser.add_argument('value', nargs='?')
    args = parser.parse_args()
    c = from_environment()
    if args.action == 'inject' and c['cyber_agent_flow']:
        path = Path(args.value)
        path.write_text(inject(path.read_text(), c))
    elif args.action == 'network' and c['cyber_agent_flow']:
        print('  llm: ' + json.dumps(interface(c, args.value)))
