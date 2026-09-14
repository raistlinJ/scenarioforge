"""Select static Fusion addresses outside DHCP pools and known reservations."""
import ipaddress
from pathlib import Path
import re
import subprocess
import sys
import platform
import configparser


def select(path, vmnet, overrides, occupied=lambda address: False):
    values = dict(re.findall(r'^answer\s+(\S+)\s+(\S+)', path.read_text(), re.M))
    prefix = 'VNET_' + vmnet.removeprefix('vmnet') + '_'
    network = ipaddress.IPv4Network(values[prefix + 'HOSTONLY_SUBNET'] + '/' + values[prefix + 'HOSTONLY_NETMASK'])
    excluded = {network.network_address, network.broadcast_address, network.network_address + 1}
    if values.get(prefix + 'NAT') == 'yes':
        excluded.add(network.network_address + 2)
    pools = []
    if values.get(prefix + 'DHCP') == 'yes':
        dhcp_path = path.parent / vmnet / 'dhcpd.conf'
        if not dhcp_path.exists():
            dhcp_path = path.parent / vmnet / 'dhcpd/dhcpd.conf'
        config = dhcp_path.read_text()
        config = re.sub(r'#.*', '', config)
        for start, end in re.findall(r'\brange\s+(?:dynamic-bootp\s+)?([\d.]+)\s+([\d.]+)\s*;', config):
            pools.append((ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)))
        if not pools:
            raise ValueError('Cannot determine DHCP pool; refusing automatic address allocation')
        for address in re.findall(r'\bfixed-address\s+([\d.]+)\s*;', config):
            excluded.add(ipaddress.IPv4Address(address))
    def available(address):
        return address not in excluded and not any(start <= address <= end for start, end in pools)
    chosen = [None] * len(overrides)
    for index, value in enumerate(overrides):
        if not value:
            continue
        interface = ipaddress.IPv4Interface(value)
        if interface.network != network or not available(interface.ip):
            raise ValueError(f'{value} must match {vmnet} subnet {network} and avoid DHCP/reserved addresses')
        if occupied(interface.ip):
            raise ValueError(f'{interface.ip} responds on the network; choose another address')
        chosen[index] = interface.ip
        excluded.add(interface.ip)
    for index in range(len(overrides)):
        if chosen[index] is not None:
            continue
        for address in network.hosts():
            if available(address) and not occupied(address):
                chosen[index] = address
                excluded.add(address)
                break
        else:
            raise ValueError(f'No available static management address in {network}')
    return ' '.join(f'{address}/{network.prefixlen}' for address in chosen)


def select_llm(path, vmnet, interface='', gateway='', occupied=lambda address: False):
    values = dict(re.findall(r'^answer\s+(\S+)\s+(\S+)', path.read_text(), re.M))
    prefix = 'VNET_' + vmnet.removeprefix('vmnet') + '_'
    if values.get(prefix + 'NAT') != 'yes':
        raise ValueError('Automatic LLM addressing requires a NAT vmnet with readable NAT/DHCP configuration')
    nat_path = path.parent / vmnet / 'nat.conf'
    if not nat_path.exists():
        nat_path = path.parent / vmnet / 'nat/nat.conf'
    nat = configparser.ConfigParser(strict=False, inline_comment_prefixes=('#', ';'))
    nat.read_string(nat_path.read_text())
    actual_gateway = ipaddress.IPv4Address(nat['host']['ip'])
    network = ipaddress.IPv4Network(values[prefix + 'HOSTONLY_SUBNET'] + '/' + values[prefix + 'HOSTONLY_NETMASK'])
    if actual_gateway not in network:
        raise ValueError('NAT gateway does not match the selected vmnet subnet')
    if gateway and ipaddress.IPv4Interface(gateway).ip != actual_gateway:
        raise ValueError(f'LLM gateway override must match {vmnet} NAT gateway {actual_gateway}')
    selected = select(path, vmnet, [interface], lambda ip: ip == actual_gateway or occupied(ip))
    return selected + ' ' + str(actual_gateway)


if __name__ == '__main__':
    def occupied(address):
        # A silent host can still own an address; this is a best-effort check.
        wait = '500' if platform.system() == 'Darwin' else '1'
        return subprocess.run(['ping', '-n', '-c', '1', '-W', wait, str(address)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=3).returncode == 0
    try:
        if sys.argv[1] == '--llm':
            print(select_llm(Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], occupied))
        else:
            print(select(Path(sys.argv[1]), sys.argv[2], sys.argv[3:5], occupied))
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
