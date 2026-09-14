import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('management', Path(__file__).resolve().parents[1] / 'scripts/provision/common/management_addresses.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.mark.parametrize('layout', ['fusion', 'linux'])
def test_llm_gateway_comes_from_nat_configuration(tmp_path, layout):
    config = tmp_path / 'networking'
    config.write_text('answer VNET_8_HOSTONLY_SUBNET 192.168.20.0\nanswer VNET_8_HOSTONLY_NETMASK 255.255.255.0\nanswer VNET_8_DHCP yes\nanswer VNET_8_NAT yes\n')
    directory = tmp_path / 'vmnet8'
    nat = directory / ('nat.conf' if layout == 'fusion' else 'nat/nat.conf')
    dhcp = directory / ('dhcpd.conf' if layout == 'fusion' else 'dhcpd/dhcpd.conf')
    nat.parent.mkdir(parents=True, exist_ok=True)
    dhcp.parent.mkdir(parents=True, exist_ok=True)
    nat.write_text('[host]\nip = 192.168.20.2\nnetmask = 255.255.255.0\n')
    dhcp.write_text('range 192.168.20.128 192.168.20.254;\n')
    assert module.select_llm(config, 'vmnet8') == '192.168.20.3/24 192.168.20.2'
    with pytest.raises(ValueError, match='gateway override'):
        module.select_llm(config, 'vmnet8', '', '14.0.0.1')
    with pytest.raises(ValueError):
        module.select_llm(config, 'vmnet8', '14.0.0.100/24', '')


@pytest.mark.parametrize('dhcp_relative', ['vmnet1/dhcpd.conf', 'vmnet1/dhcpd/dhcpd.conf'])
def test_auto_selection_and_overrides(tmp_path, dhcp_relative):
    config = tmp_path / 'networking'
    config.write_text('answer VNET_1_HOSTONLY_SUBNET 192.168.230.0\nanswer VNET_1_HOSTONLY_NETMASK 255.255.255.0\nanswer VNET_1_DHCP yes\n')
    dhcp_path = tmp_path / dhcp_relative
    dhcp_path.parent.mkdir(parents=True)
    dhcp_path.write_text('range 192.168.230.128 192.168.230.254;\nfixed-address 192.168.230.2;\n')
    assert module.select(config, 'vmnet1', ['', ''], lambda ip: str(ip).endswith('.3')) == '192.168.230.4/24 192.168.230.5/24'
    assert module.select(config, 'vmnet1', ['', '192.168.230.3/24']) == '192.168.230.4/24 192.168.230.3/24'
    for invalid in ['172.31.250.2/24', '192.168.230.130/24', '192.168.230.1/24']:
        with pytest.raises(ValueError):
            module.select(config, 'vmnet1', [invalid, ''])
    with pytest.raises(ValueError):
        module.select(config, 'vmnet1', ['192.168.230.3/24'] * 2)
