"""Read-only participant readiness contract shared by Proxmox and VMware."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit


def verify(helper, config, expected_hash, expected_interface=None):
    helper, config = Path(helper), Path(config)
    if helper.is_symlink() or not helper.is_file():
        raise ValueError('Participant routing helper is missing or is a symlink')
    actual = hashlib.sha256(helper.read_bytes()).hexdigest()
    if actual != expected_hash:
        raise ValueError('Participant routing helper differs from this provisioner; update/reprovision the guest helper before marking ready')
    result = subprocess.run([sys.executable, str(helper), '--help'], capture_output=True, text=True, timeout=15)
    if result.returncode or any(option not in result.stdout for option in ('--url', '--cli-config', '--json')):
        raise ValueError('Participant routing helper cannot provide the orchestrator CLI options; check its Python dependencies')
    if config.is_symlink() or not config.is_file():
        raise ValueError('Participant CAF model configuration is missing or is a symlink')
    data = json.loads(config.read_text())
    if not isinstance(data, dict):
        raise ValueError('Participant CAF configuration must be an object')
    model = data.get('model')
    if not isinstance(model, str) or not model.strip() or len(model)>2048 or any(ord(c)<32 for c in model):
        raise ValueError('Participant CAF model name is empty or invalid; set llm_model before provisioning')
    if data.get('provider') not in ('openai', 'litellm', 'ollama_direct', 'claude'):
        raise ValueError('Participant CAF provider is missing or invalid')
    endpoint=urlsplit(data.get('url',''))
    if endpoint.scheme not in ('http','https') or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError('Participant CAF endpoint is missing or invalid')
    if expected_interface is not None:
        import yaml
        definitions = []
        for path in Path('/etc/netplan').glob('*.yaml'):
            document = yaml.safe_load(path.read_text()) or {}
            nic = document.get('network', {}).get('ethernets', {}).get('llm')
            if nic is not None:
                definitions.append(nic)
        if len(definitions) != 1 or definitions[0].get('match') != {'name': expected_interface} or definitions[0].get('set-name'):
            raise ValueError('Proxmox LLM Netplan definition must match the guest interface name, never a template MAC')
        if not (Path('/sys/class/net') / expected_interface / 'ifindex').is_file():
            raise ValueError('Dedicated LLM NIC is missing: ' + expected_interface + '; retain the original NIC slots when cloning')
        if definitions[0].get('dhcp4'):
            route = json.loads(Path('/etc/scenarioforge-llm-route.json').read_text())
            if route.get('interface') != expected_interface:
                raise ValueError('LLM route service interface differs from Netplan')
    return dict(status='verified',helper_sha256=actual,model=model)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('helper')
    parser.add_argument('config')
    parser.add_argument('expected_hash')
    parser.add_argument('--expected-interface')
    args=parser.parse_args()
    try:
        print(json.dumps(verify(args.helper,args.config,args.expected_hash,args.expected_interface)))
    except Exception as error:
        raise SystemExit('CAF participant verification failed: '+str(error))
