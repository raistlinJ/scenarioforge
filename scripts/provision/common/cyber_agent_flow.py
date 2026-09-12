"""Shared opt-in Kali CyberAgentFlow provisioning and dedicated LLM routing."""
import argparse
import base64
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
    interface = ipaddress.IPv4Interface(c['llm_interface_cidr'])
    gateway = ipaddress.IPv4Address(c['llm_gateway'])
    if provider.is_unspecified or provider.is_multicast or provider.is_loopback:
        raise ValueError('llm_provider_address must be a reachable unicast IPv4 address')
    if gateway not in interface.network or gateway == interface.ip or gateway in (interface.network.network_address, interface.network.broadcast_address):
        raise ValueError('llm_gateway must be a different usable address in llm_interface_cidr')
    if interface.ip in (interface.network.network_address, interface.network.broadcast_address) or provider == interface.ip:
        raise ValueError('llm_interface_cidr must have a usable guest address distinct from the provider')
    for network in (c.get('participant_cidr', '10.254.200.10/24'), c.get('core_management_cidr', '172.31.250.3/24')):
        protected = ipaddress.ip_interface(network).network
        if interface.network.overlaps(protected) or provider in protected:
            raise ValueError('LLM network/provider must not overlap HITL or management')
    endpoint = urlsplit(c['llm_provider_url'])
    if endpoint.scheme not in ('http', 'https') or endpoint.hostname != str(provider) or endpoint.username or endpoint.password:
        raise ValueError('llm_provider_url must be an http(s) URL using llm_provider_address, without credentials')
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
    web_patch = base64.b64encode(Path(__file__).with_name('cyber-agent-flow-web-defaults.patch').read_bytes()).decode()
    addition = f'''
set_bootstrap_status 90 'installing CyberAgentFlow'
[[ "$ID" == kali ]] || fail_bootstrap 'CyberAgentFlow requires Kali'
apt-get install -y git ca-certificates python3-venv python3-dev build-essential xdotool x11-utils python3-psutil npm
if [[ ! -f /var/lib/scenarioforge/cyber-agent-flow-installed ]]; then
    if [[ ! -f /var/lib/scenarioforge/cyber-agent-flow-source-ready ]]; then
        [[ ! -e /opt/cyber-agent-flow ]] || fail_bootstrap '/opt/cyber-agent-flow already exists; inspect the incomplete installation'
        git clone -- {q(c['cyber_agent_flow_url'])} /opt/cyber-agent-flow
        touch /var/lib/scenarioforge/cyber-agent-flow-source-ready
    fi
    git -C /opt/cyber-agent-flow fetch origin {q(c['cyber_agent_flow_ref'])}
    git -C /opt/cyber-agent-flow checkout --detach FETCH_HEAD
    bash /opt/cyber-agent-flow/install_prerequisites.sh
    cat > /opt/cyber-agent-flow/configs/cli.json <<'CAF_CONFIG'
{json.dumps(cli, indent=2)}
CAF_CONFIG
    chown -R participant:participant /opt/cyber-agent-flow
    chmod 0600 /opt/cyber-agent-flow/configs/cli.json
    touch /var/lib/scenarioforge/cyber-agent-flow-installed
fi
printf '%s' '{web_patch}' | base64 -d > /var/lib/scenarioforge/cyber-agent-flow-web-defaults.patch
if ! git -c safe.directory=/opt/cyber-agent-flow -C /opt/cyber-agent-flow apply --reverse --check /var/lib/scenarioforge/cyber-agent-flow-web-defaults.patch 2>/dev/null; then
    git -c safe.directory=/opt/cyber-agent-flow -C /opt/cyber-agent-flow apply /var/lib/scenarioforge/cyber-agent-flow-web-defaults.patch
fi
ip -4 route get {q(c['llm_provider_address'])} | grep -Eq 'dev ens20( |$)' || fail_bootstrap 'LLM provider traffic is not routed through ens20'
cat > /usr/local/bin/cyber-agent-flow <<'CAF_LAUNCH'
#!/bin/bash
cd /opt/cyber-agent-flow
exec bash ./start_ws.sh "$@"
CAF_LAUNCH
chmod 0755 /usr/local/bin/cyber-agent-flow
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
