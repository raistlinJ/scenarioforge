#!/usr/bin/python3
"""Interactive participant utility: update the endpoint and persistent host route."""
import ipaddress
import argparse
import json
import contextlib
import io
import re
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


def sync_gateway_policy(cli_path, destination, interface='ens20'):
    """Exclude the LLM endpoint and next-hop without replacing user policy."""
    destination = str(ipaddress.IPv4Address(destination))
    routes = json.loads(subprocess.check_output(
        ['ip', '-j', '-4', 'route', 'get', destination], text=True))
    if len(routes) != 1 or routes[0].get('dev') != interface:
        raise ValueError('Destination is not routed through ' + interface)
    gateway = routes[0].get('gateway', '')
    if gateway:
        gateway = str(ipaddress.IPv4Address(gateway))
    cli = json.loads(cli_path.read_text())
    before = json.dumps(cli, sort_keys=True)
    policy = cli.setdefault('network_policy', {'allow': ['*'], 'disallow': []})
    denied = policy.setdefault('disallow', [])
    addresses = {'llm_route_gateway': gateway, 'llm_route_destination': destination}
    # Reconcile both addresses together: a provider can also be the gateway,
    # or a former gateway can become the new provider. Never drop an address
    # that is still needed, and only remove entries this utility added.
    managed = {cli[key] for key in addresses if cli.get(key) and cli.get(key + '_managed')}
    required = {address for address in addresses.values() if address}
    for previous in managed - required:
        if previous in denied:
            denied.remove(previous)
    managed.intersection_update(required)
    for address in addresses.values():
        if address and address not in denied:
            denied.append(address)
            managed.add(address)
    for key, address in addresses.items():
        cli[key] = address
        cli[key + '_managed'] = address in managed
    if json.dumps(cli, sort_keys=True) != before:
        write_atomic(cli_path, (json.dumps(cli, indent=2) + '\n').encode())


def configured_interface():
    config_path = Path('/etc/scenarioforge-llm-route.json')
    if config_path.exists():
        return json.loads(config_path.read_text()).get('interface', 'ens20')
    names = []
    for path in sorted(Path('/etc/netplan').glob('*.yaml')):
        document = yaml.safe_load(path.read_text()) or {}
        for name, nic in document.get('network', {}).get('ethernets', {}).items():
            interface = nic.get('set-name') or (nic.get('match') or {}).get('name') or name
            if name == 'llm' or interface == 'ens20':
                names.append(interface)
    if len(names) != 1:
        raise ValueError('Expected exactly one dedicated LLM Netplan interface')
    return names[0]


def update_route(address=None, url=None, cli_path=None, prompt=False):
    if os.geteuid() != 0:
        raise ValueError('Run this utility with sudo; routing changes require administrator access')
    cli_path = cli_path or Path('/opt/cyber-agent-flow/configs/cli.json')
    cli = json.loads(cli_path.read_text())
    print('Current endpoint:', cli.get('url', ''))
    interactive = prompt or url is None
    if url is None:
        address = input('New LLM destination IPv4 address: ').strip()
        url = input('New LLM URL (including port and API path): ').strip()
    elif address is None:
        endpoint = urlsplit(url)
        if endpoint.scheme not in ('http', 'https') or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
            raise ValueError('Enter an HTTP(S) URL without credentials, query or fragment')
        resolved = sorted({item[4][0] for item in socket.getaddrinfo(endpoint.hostname, endpoint.port or (443 if endpoint.scheme == 'https' else 80), socket.AF_INET)})
        if len(resolved) != 1:
            raise ValueError('Automatic routing currently requires a hostname resolving to one IPv4 address')
        address = resolved[0]
    dhcp_path = Path('/etc/scenarioforge-llm-route.json')
    protected = []
    matches = []
    for path in sorted(Path('/etc/netplan').glob('*.yaml')):
        document = yaml.safe_load(path.read_text()) or {}
        for name, nic in document.get('network', {}).get('ethernets', {}).items():
            interface = nic.get('set-name') or (nic.get('match') or {}).get('name') or name
            if name == 'llm' or interface == 'ens20':
                matches.append((path, document, nic, interface))
            else:
                protected.extend(nic.get('addresses', []))
    if len(matches) != 1:
        raise ValueError('Expected exactly one dedicated LLM Netplan definition; no changes made')
    netplan_path, document, nic, interface = matches[0]
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
        raise ValueError("Invalid LLM interface name")
    dynamic = bool(nic.get('dhcp4'))
    if dynamic:
        route_config = json.loads(dhcp_path.read_text())
        protected.extend(route_config['protected'])
        if route_config.get('interface', 'ens20') != interface:
            raise ValueError('DHCP route interface differs from the LLM Netplan interface')
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
                gateway = cli.get('llm_route_gateway')
                if not gateway:
                    if not interactive:
                        raise ValueError('No stored LLM gateway; configure it with the desktop utility first')
                    gateway = input(interface + ' gateway IPv4 address: ').strip()
            gateway_ip = ipaddress.IPv4Address(gateway)
            if gateway_ip not in subnet or gateway_ip in (subnet.network_address, subnet.broadcast_address, ipaddress.ip_interface(nic['addresses'][0]).ip):
                raise ValueError('Gateway must be a usable router address in the ens20 subnet')
            new['via'] = str(gateway_ip)
        nic['routes'] = [new]
        updates[netplan_path] = yaml.safe_dump(document, sort_keys=False).encode()
        apply = ['netplan', 'apply']
    backups = {path: path.read_bytes() for path in updates}
    print(f'Updating provider route on {interface}: {old} -> {address}')
    try:
        for path, content in updates.items():
            write_atomic(path, content)
        subprocess.run(apply, check=True, timeout=60, capture_output=True, text=True)
        result = subprocess.check_output(['ip', '-4', 'route', 'get', address], text=True)
        if 'dev ' + interface not in result:
            raise ValueError('Destination is not routed through ' + interface)
        sync_gateway_policy(cli_path, address, interface)
    except Exception:
        for path, content in backups.items():
            write_atomic(path, content)
        subprocess.run(apply, check=False, timeout=60, capture_output=True, text=True)
        if old != address:
            subprocess.run(['ip', '-4', 'route', 'del', address + '/32', 'dev', interface], check=False)
        raise
    if old != address:
        subprocess.run(['ip', '-4', 'route', 'del', old + '/32', 'dev', interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('Updated configuration, persistent route, and LLM endpoint/gateway deny entries. Reload CyberAgentFlow and update any browser-saved endpoint settings before starting a new session.')
    return dict(status='updated', destination=address, previous_destination=old, interface=interface,
                gateway=json.loads(cli_path.read_text()).get('llm_route_gateway', ''))


def main(address=None, url=None, cli_path=None):
    """Supply endpoint-specific DNS on the LLM NIC when its resolver is absent."""
    if os.geteuid()!=0:
        raise ValueError('Run this utility with sudo; routing changes require administrator access')
    interactive = url is None
    if interactive:
        cli_path = cli_path or Path('/opt/cyber-agent-flow/configs/cli.json')
        print('Current endpoint:', json.loads(cli_path.read_text()).get('url',''))
        address = input('New LLM destination IPv4 address: ').strip()
        url = input('New LLM URL (including port and API path): ').strip()
    def apply_route():
        return update_route(address,url,cli_path,prompt=True) if interactive else update_route(address,url,cli_path)
    endpoint = urlsplit(url)
    if endpoint.scheme not in ('http','https') or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError('Enter an HTTP(S) URL without credentials, query or fragment')
    try:
        literal=ipaddress.ip_address(endpoint.hostname)
    except ValueError:
        literal=None
    if literal is not None:
        return apply_route()
    # Respect working DNS. The provisioned DHCP/static LLM interface deliberately
    # has no default route; only this provider's DNS domain is routed to its NIC.
    try:
        socket.getaddrinfo(endpoint.hostname, endpoint.port or (443 if endpoint.scheme=='https' else 80), socket.AF_INET)
        return apply_route()
    except socket.gaierror:
        pass
    cli_path = cli_path or Path('/opt/cyber-agent-flow/configs/cli.json')
    cli_before = cli_path.read_bytes()
    cli = json.loads(cli_before)
    interface = configured_interface()
    matches=[]
    for path in sorted(Path('/etc/netplan').glob('*.yaml')):
        document=yaml.safe_load(path.read_text()) or {}
        for name,nic in document.get('network',{}).get('ethernets',{}).items():
            selected=nic.get('set-name') or (nic.get('match') or {}).get('name') or name
            if selected==interface:matches.append((path,document,nic))
    if len(matches)!=1:
        raise ValueError('Cannot locate the dedicated LLM interface for endpoint DNS')
    path,document,nic=matches[0]
    before=path.read_bytes()
    nameservers=nic.setdefault('nameservers',{})
    resolver=next(iter(nameservers.get('addresses',[])),None)
    gateway=next((r.get('via') for r in nic.get('routes',[]) if r.get('via')),None)
    if nic.get('dhcp4'):
        index=int((Path('/sys/class/net')/interface/'ifindex').read_text())
        lease=dict(line.split('=',1) for line in Path(f'/run/systemd/netif/leases/{index}').read_text().splitlines() if '=' in line and not line.startswith('#'))
        resolver=resolver or next(iter(lease.get('DNS','').split()),None)
        gateway=gateway or next(iter(lease.get('ROUTER','').split()),None)
        subnet=ipaddress.IPv4Interface(lease['ADDRESS']+'/'+lease['NETMASK']).network
    else:
        subnet=ipaddress.ip_interface(nic['addresses'][0]).network
    resolver=resolver or gateway
    if not resolver or ipaddress.ip_address(resolver) not in subnet:
        raise ValueError('No on-link DNS resolver available on the dedicated LLM interface; configure LLM DNS first')
    domain='~'+endpoint.hostname
    domains=nameservers.setdefault('search',[])
    previous=cli.get('llm_route_dns_domain')
    if previous and cli.get('llm_route_dns_domain_managed') and previous in domains and previous!=domain:domains.remove(previous)
    managed=domain not in domains or (previous==domain and cli.get('llm_route_dns_domain_managed',False))
    if domain not in domains:domains.append(domain)
    if not nameservers.get('addresses'):nameservers['addresses']=[resolver]
    apply=['netplan','apply']
    try:
        write_atomic(path,yaml.safe_dump(document,sort_keys=False).encode())
        subprocess.run(apply,check=True,timeout=60,capture_output=True,text=True)
        result=apply_route()
        cli=json.loads(cli_path.read_text());cli['llm_route_dns_domain']=domain;cli['llm_route_dns_domain_managed']=managed
        write_atomic(cli_path,(json.dumps(cli,indent=2)+'\n').encode())
        result['dns']=dict(server=resolver,domain=domain)
        return result
    except Exception:
        write_atomic(path,before);write_atomic(cli_path,cli_before)
        subprocess.run(apply,check=False,timeout=60,capture_output=True,text=True)
        raise


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--sync-policy', metavar='DESTINATION')
        parser.add_argument('--url', help='Noninteractive endpoint update; resolve its IPv4 destination')
        parser.add_argument('--destination', help='Explicit destination IPv4 for --url')
        parser.add_argument('--cli-config', default='/opt/cyber-agent-flow/configs/cli.json')
        parser.add_argument('--json', action='store_true', help='Emit a structured route update result')
        args = parser.parse_args()
        if args.sync_policy and args.url:
            parser.error('--sync-policy and --url are mutually exclusive')
        if args.sync_policy:
            interface = configured_interface()
            sync_gateway_policy(Path(args.cli_config), args.sync_policy, interface)
        elif args.url:
            with contextlib.redirect_stdout(io.StringIO()) if args.json else contextlib.nullcontext():
                result = main(args.destination, args.url, Path(args.cli_config))
            if args.json:
                print(json.dumps(result))
        else:
            main()
    except Exception as error:
        raise SystemExit(f'LLM update failed: {error}')
