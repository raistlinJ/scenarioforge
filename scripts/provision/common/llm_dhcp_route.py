#!/usr/bin/python3
"""Maintain only the provider host route from the selected NIC DHCP lease."""
import ipaddress
import json
import re
from pathlib import Path
import subprocess


def interface_name(config):
    name = config.get('interface', 'ens20')
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', name) or name in ('.', '..'):
        raise ValueError('Invalid LLM interface name')
    return name


def route_arguments(config, lease):
    address = ipaddress.IPv4Interface(lease['ADDRESS'] + '/' + lease['NETMASK'])
    provider = ipaddress.IPv4Address(config['provider'])
    for cidr in config['protected']:
        network = ipaddress.ip_interface(cidr).network
        if address.network.overlaps(network) or provider in network:
            raise ValueError('DHCP LLM network overlaps management or HITL')
    if provider == address.ip:
        raise ValueError('Provider address equals the guest DHCP address')
    args = ['ip', '-4', 'route', 'replace', f'{provider}/32']
    if provider not in address.network:
        gateway = ipaddress.IPv4Address(lease['ROUTER'].split()[0])
        if gateway not in address.network or gateway in (address.ip, address.network.network_address, address.network.broadcast_address):
            raise ValueError('Invalid DHCP gateway')
        args += ['via', str(gateway)]
    return args + ['dev', interface_name(config), 'src', str(address.ip)]


if __name__ == '__main__':
    config = json.loads(Path('/etc/scenarioforge-llm-route.json').read_text())
    index = int((Path('/sys/class/net') / interface_name(config) / 'ifindex').read_text())
    lease = dict(line.split('=', 1) for line in Path(f'/run/systemd/netif/leases/{index}').read_text().splitlines()
                 if '=' in line and not line.startswith('#'))
    subprocess.run(route_arguments(config, lease), check=True)
    subprocess.run(['/usr/local/sbin/update-llm-destination', '--sync-policy', config['provider']], check=True)
