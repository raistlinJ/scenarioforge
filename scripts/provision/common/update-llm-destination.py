#!/usr/bin/python3
"""Interactive participant utility: update the endpoint and persistent host route."""
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from urllib.parse import urlsplit

import yaml


def validate_destination(address, url, protected):
    ip = ipaddress.IPv4Address(address)
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip == ipaddress.IPv4Address('255.255.255.255'):
        raise ValueError('Enter a unicast IPv4 destination')
    if any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in protected):
        raise ValueError('The provider must be outside HITL and management networks')
    endpoint = urlsplit(url)
    if endpoint.scheme not in ('http', 'https') or not endpoint.hostname or endpoint.username or endpoint.password:
        raise ValueError('Enter an HTTP(S) URL without embedded credentials')
    resolved = {item[4][0] for item in socket.getaddrinfo(endpoint.hostname, endpoint.port or 443, socket.AF_INET)}
    if resolved != {str(ip)}:
        raise ValueError('URL hostname must resolve only to the destination IPv4 address')
    return str(ip)


def write_atomic(path, content):
    stat = path.stat()
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
        os.chmod(temporary, stat.st_mode & 0o777)
        os.chown(temporary, stat.st_uid, stat.st_gid)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    if os.geteuid() != 0:
        raise ValueError('Run this utility with sudo; routing changes require administrator access')
    cli_path = Path('/opt/cyber-agent-flow/configs/cli.json')
    cli = json.loads(cli_path.read_text())
    print('Current endpoint:', cli.get('url', ''))
    address = input('New LLM destination IPv4 address: ').strip()
    url = input('New LLM URL (including port and API path): ').strip()
    dhcp_path = Path('/etc/scenarioforge-llm-route.json')
    protected = []
    matches = []
    for path in sorted(Path('/etc/netplan').glob('*.yaml')):
        document = yaml.safe_load(path.read_text()) or {}
        for name, nic in document.get('network', {}).get('ethernets', {}).items():
            if nic.get('set-name', name) == 'ens20':
                matches.append((path, document, nic))
            else:
                protected.extend(nic.get('addresses', []))
    if len(matches) != 1:
        raise ValueError('Expected exactly one dedicated ens20 Netplan definition; no changes made')
    netplan_path, document, nic = matches[0]
    dynamic = bool(nic.get('dhcp4'))
    if dynamic:
        route_config = json.loads(dhcp_path.read_text())
        protected.extend(route_config['protected'])
    address = validate_destination(address, url, protected)
    if any(ipaddress.ip_interface(value).ip == ipaddress.ip_address(address) for value in nic.get('addresses', [])):
        raise ValueError('The provider cannot be the participant interface address')
    cli['url'] = url
    updates = {cli_path: (json.dumps(cli, indent=2) + '\n').encode()}
    if dynamic:
        old = route_config['provider']
        route_config['provider'] = address
        updates[dhcp_path] = (json.dumps(route_config, indent=2) + '\n').encode()
        apply = ['systemctl', 'start', 'scenarioforge-llm-route.service']
    else:
        routes = nic.get('routes', [])
        if len(routes) != 1 or not str(routes[0].get('to', '')).endswith('/32'):
            raise ValueError('Expected one provider host route on ens20; no changes made')
        old = str(ipaddress.ip_network(routes[0]['to']).network_address)
        subnet = ipaddress.ip_interface(nic['addresses'][0]).network
        gateway = routes[0].get('via')
        new = {'to': address + '/32'}
        if ipaddress.ip_address(address) in subnet:
            new['scope'] = 'link'
        else:
            if not gateway:
                gateway = input('ens20 gateway IPv4 address: ').strip()
            gateway_ip = ipaddress.IPv4Address(gateway)
            if gateway_ip not in subnet or gateway_ip in (subnet.network_address, subnet.broadcast_address, ipaddress.ip_interface(nic['addresses'][0]).ip):
                raise ValueError('Gateway must be a usable router address in the ens20 subnet')
            new['via'] = str(gateway_ip)
        nic['routes'] = [new]
        updates[netplan_path] = yaml.safe_dump(document, sort_keys=False).encode()
        apply = ['netplan', 'apply']
    backups = {path: path.read_bytes() for path in updates}
    print(f'Updating provider route on ens20: {old} -> {address}')
    try:
        for path, content in updates.items():
            write_atomic(path, content)
        subprocess.run(apply, check=True)
        result = subprocess.check_output(['ip', '-4', 'route', 'get', address], text=True)
        if 'dev ens20' not in result:
            raise ValueError('Destination is not routed through ens20')
    except Exception:
        for path, content in backups.items():
            write_atomic(path, content)
        subprocess.run(apply, check=False)
        if old != address:
            subprocess.run(['ip', '-4', 'route', 'del', address + '/32', 'dev', 'ens20'], check=False)
        raise
    if old != address:
        subprocess.run(['ip', '-4', 'route', 'del', old + '/32', 'dev', 'ens20'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('Updated configuration and persistent route. Restart CyberAgentFlow and update any browser-saved endpoint settings.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(f'LLM update failed: {error}')
