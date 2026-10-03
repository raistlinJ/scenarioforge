#!/usr/bin/python3
"""Repair a Proxmox clone's legacy LLM NIC binding using an explicitly selected adapter's current MAC."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

import yaml


def repair_plan(mac, root=Path('/'), reuse_bootstrap_uplink=False):
    """Identify the explicitly selected adapter; never infer it from a default route."""
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
        raise ValueError('Supply the current Proxmox LLM adapter MAC address')
    names = [p.parent.name for p in (root/'sys/class/net').glob('*/address')
             if p.read_text().strip().lower() == mac.lower()]
    if len(names) != 1:
        raise ValueError('The selected Proxmox adapter MAC does not identify exactly one guest NIC')
    interface = names[0]
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface) or interface in ('lo', '.', '..'):
        raise ValueError('Invalid selected LLM interface')
    matches, documents, bootstrap = [], [], []
    for path in sorted((root/'etc/netplan').glob('*.yaml')):
        doc = yaml.safe_load(path.read_text()) or {}
        nics = doc.get('network', {}).get('ethernets', {})
        documents.append((path, doc))
        for name, nic in nics.items():
            if name == 'llm':
                matches.append((path, doc, nic))
            else:
                match = nic.get('match') or {}
                if (nic.get('set-name') == interface or match.get('name') == interface
                        or str(match.get('macaddress', '')).lower() == mac.lower()
                        or (not match and name == interface)):
                    if (reuse_bootstrap_uplink and name == 'bootstrap-uplink'
                            and nic.get('dhcp4') and not nic.get('addresses') and not nic.get('routes')):
                        bootstrap.append((path, doc, nics, name))
                    else:
                        raise ValueError('Selected adapter is already assigned to another Netplan role: ' + name)
    if reuse_bootstrap_uplink and len(bootstrap) != 1:
        raise ValueError('Reusing an uplink requires exactly one matching DHCP bootstrap-uplink role')
    if len(matches) != 1:
        raise ValueError('Expected exactly one LLM Netplan definition; no changes made')
    path, doc, nic = matches[0]
    if not nic.get('dhcp4'):
        raise ValueError('This repair supports DHCP LLM interfaces only; no changes made')
    route_path = root/'etc/scenarioforge-llm-route.json'
    route = json.loads(route_path.read_text())
    if not isinstance(route, dict) or not route.get('provider') or not isinstance(route.get('protected'), list):
        raise ValueError('Invalid LLM DHCP route configuration')
    nic['match'] = {'name': interface}
    nic.pop('set-name', None)
    nic.setdefault('dhcp4-overrides', {})['use-routes'] = False
    doc['network']['renderer'] = 'networkd'
    route['interface'] = interface
    for _, document, nics, name in bootstrap:
        del nics[name]
        document['network']['renderer'] = 'networkd'
    owned = {interface}
    for _, document in documents:
        for definition in document.get('network', {}).get('ethernets', {}).values():
            name = definition.get('set-name') or (definition.get('match') or {}).get('name')
            if name and re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', name) and (root/'sys/class/net'/name/'ifindex').is_file():
                owned.add(name)
    policy = ('[device-scenarioforge-netplan]\nmatch-device=' +
              ';'.join('interface-name:' + name for name in sorted(owned)) + '\nmanaged=0\n')
    changes = {path: yaml.safe_dump(doc, sort_keys=False),
               route_path: json.dumps(route, indent=2) + '\n',
               root/'etc/NetworkManager/conf.d/90-scenarioforge-netplan.conf': policy}
    for bootstrap_path, document, _, _ in bootstrap:
        changes[bootstrap_path] = yaml.safe_dump(document, sort_keys=False)
    for target in changes:
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError('Refusing unsafe configuration path: ' + str(target))
    return interface, sorted(owned), route['provider'], changes


def remove_llm_defaults(interface):
    # The selected adapter now serves only LLM egress. Remove DHCP defaults left
    # behind by its old bootstrap/NM role, preserving the provider host route.
    defaults = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'default'], text=True))
    for route in defaults:
        if route.get('dev') != interface:
            continue
        command = ['ip', '-4', 'route', 'del', 'default', 'dev', interface]
        if route.get('gateway'):
            command += ['via', route['gateway']]
        if 'metric' in route:
            command += ['metric', str(route['metric'])]
        subprocess.run(command, check=True, timeout=5)


def repair(mac, reuse_bootstrap_uplink=False):
    import os
    if os.geteuid() != 0:
        raise ValueError('Run the repair as root inside the participant guest')
    interface, owned, provider, changes = repair_plan(mac, reuse_bootstrap_uplink=reuse_bootstrap_uplink)
    backup = Path(tempfile.mkdtemp(prefix='scenarioforge-llm-repair-', dir='/root'))
    originals = {}
    for path in changes:
        originals[path] = path.read_bytes() if path.exists() else None
        if path.exists():
            shutil.copy2(path, backup/path.name)
    print('Selected LLM interface:', interface, flush=True)
    print('Backup:', backup, flush=True)
    for path, text in changes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o644 if path.suffix == '.conf' else 0o600)
    try:
        subprocess.run(['netplan', 'generate'], check=True, timeout=30)
    except Exception:
        for path, content in originals.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(content)
        raise
    subprocess.run(['systemctl', 'enable', '--now', 'systemd-networkd'], check=True, timeout=30)
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'NetworkManager']).returncode == 0:
        subprocess.run(['nmcli', 'general', 'reload'], check=True, timeout=15)
        for name in owned:
            subprocess.run(['nmcli', 'device', 'set', name, 'managed', 'no'], check=True, timeout=15)
    subprocess.run(['netplan', 'apply'], check=True, timeout=45)
    subprocess.run(['networkctl', 'reconfigure', *owned], check=True, timeout=15)
    index = (Path('/sys/class/net')/interface/'ifindex').read_text().strip()
    lease = Path('/run/systemd/netif/leases')/index
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            content = lease.read_text()
            if 'ADDRESS=' in content and 'NETMASK=' in content:
                break
        except FileNotFoundError:
            pass
        time.sleep(1)
    else:
        raise ValueError('No networkd DHCP lease on ' + interface + '; check the selected adapter bridge DHCP server. Corrected configuration and backups were retained')
    subprocess.run(['systemctl', 'restart', 'scenarioforge-llm-route.service'], check=True, timeout=60)
    routes = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'get', provider], text=True))
    if len(routes) != 1 or routes[0].get('dev') != interface:
        raise ValueError('Provider route verification failed on ' + interface)
    remove_llm_defaults(interface)
    print('LLM route repaired:', provider, 'via', interface)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--llm-mac', required=True, help='Current Proxmox LLM adapter MAC (normally net2)')
    parser.add_argument('--reuse-bootstrap-uplink', action='store_true', help='Explicitly migrate a legacy two-NIC DHCP bootstrap uplink to LLM-only egress')
    args = parser.parse_args()
    try:
        repair(args.llm_mac, args.reuse_bootstrap_uplink)
    except Exception as error:
        print('LLM interface repair failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
