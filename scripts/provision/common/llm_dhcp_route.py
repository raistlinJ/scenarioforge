#!/usr/bin/python3
"""Maintain only the provider host route from ens20's systemd-networkd lease."""
import ipaddress
import json
from pathlib import Path
import subprocess


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
    return args + ['dev', 'ens20', 'src', str(address.ip)]


if __name__ == '__main__':
    config = json.loads(Path('/etc/scenarioforge-llm-route.json').read_text())
    index = int(Path('/sys/class/net/ens20/ifindex').read_text())
    lease = dict(line.split('=', 1) for line in Path(f'/run/systemd/netif/leases/{index}').read_text().splitlines()
                 if '=' in line and not line.startswith('#'))
    subprocess.run(route_arguments(config, lease), check=True)
