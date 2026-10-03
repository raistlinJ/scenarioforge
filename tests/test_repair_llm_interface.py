"""A repair must select the explicitly identified adapter and retain clone-safe names."""
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('repair_llm', ROOT/'scripts/provision/common/repair_llm_interface.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def fixture_guest(tmp_path, name='eth2'):
    net = tmp_path/'sys/class/net'
    for interface, mac in [('eth0', 'bc:24:11:00:00:10'), ('eth1', 'bc:24:11:00:00:11'), (name, 'bc:24:11:00:00:12')]:
        p = net/interface
        p.mkdir(parents=True)
        (p/'address').write_text(mac + '\n')
        (p/'ifindex').write_text('4')
    path = tmp_path/'etc/netplan/50-cloud-init.yaml'
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump({'network': {'version': 2, 'ethernets': {
        'participant': {'match': {'name': 'eth0'}, 'addresses': ['10.254.200.10/24'], 'routes': [{'to': 'default', 'via': '10.254.200.1'}]},
        'bootstrap-uplink': {'match': {'name': 'eth1'}, 'dhcp4': True},
        'llm': {'match': {'macaddress': '02:00:00:ff:ff:ff'}, 'set-name': 'ens20', 'dhcp4': True, 'dhcp4-overrides': {'use-dns': False}}
    }}}))
    route = tmp_path/'etc/scenarioforge-llm-route.json'
    route.write_text(json.dumps({'interface': 'ens20', 'provider': '192.0.2.5', 'protected': ['10.254.200.10/24']}))
    return path, route


@pytest.mark.parametrize('name', ['eth2', 'ens20', 'enp6s0'])
def test_repair_matches_current_adapter_and_persists_only_its_name(tmp_path, name):
    path, route = fixture_guest(tmp_path, name)
    before = {path: path.read_bytes(), route: route.read_bytes()}
    interface, owned, provider, changes = helper.repair_plan('BC:24:11:00:00:12', tmp_path)
    assert interface == name and set(owned) == {'eth0', 'eth1', name}
    assert provider == '192.0.2.5'
    original = yaml.safe_load(before[path])
    network = yaml.safe_load(changes[path])
    assert network['network']['renderer'] == 'networkd'
    llm = network['network']['ethernets']['llm']
    assert llm['match'] == {'name': name} and 'set-name' not in llm
    assert llm['dhcp4-overrides'] == {'use-dns': False, 'use-routes': False}
    for role in ['participant', 'bootstrap-uplink']:
        assert network['network']['ethernets'][role] == original['network']['ethernets'][role]
    assert json.loads(changes[route])['interface'] == name
    policy = changes[tmp_path/'etc/NetworkManager/conf.d/90-scenarioforge-netplan.conf']
    assert 'managed=0' in policy and 'interface-name:' + name in policy
    assert before == {path: path.read_bytes(), route: route.read_bytes()}


@pytest.mark.parametrize('mac', ['bc:24:11:00:00:10', 'bc:24:11:00:00:11', 'bc:24:11:00:00:99', 'invalid'])
def test_repair_rejects_protected_or_unknown_adapter_before_mutating(tmp_path, mac):
    path, route = fixture_guest(tmp_path)
    before = path.read_bytes(), route.read_bytes()
    with pytest.raises(ValueError):
        helper.repair_plan(mac, tmp_path)
    assert before == (path.read_bytes(), route.read_bytes())


@pytest.mark.parametrize('problem', ['duplicate', 'static', 'symlink'])
def test_repair_rejects_unsafe_or_unsupported_configurations(tmp_path, problem):
    path, route = fixture_guest(tmp_path)
    if problem == 'duplicate':
        (path.parent/'another.yaml').write_bytes(path.read_bytes())
    elif problem == 'static':
        doc = yaml.safe_load(path.read_text())
        doc['network']['ethernets']['llm']['dhcp4'] = False
        path.write_text(yaml.safe_dump(doc))
    else:
        target = route.with_suffix('.saved')
        route.rename(target)
        route.symlink_to(target)
    with pytest.raises(ValueError):
        helper.repair_plan('bc:24:11:00:00:12', tmp_path)



@pytest.mark.parametrize('separate_file', [False, True])
def test_explicit_legacy_uplink_migration_removes_bootstrap_role(tmp_path, separate_file):
    path, route = fixture_guest(tmp_path)
    # The clone retained HITL net0 and the external net1, but no net2.
    import shutil
    shutil.rmtree(tmp_path/'sys/class/net/eth2')
    if separate_file:
        document = yaml.safe_load(path.read_text())
        uplink = document['network']['ethernets'].pop('bootstrap-uplink')
        path.write_text(yaml.safe_dump(document))
        other = path.parent/'60-bootstrap.yaml'
        other.write_text(yaml.safe_dump({'network': {'version': 2, 'ethernets': {'bootstrap-uplink': uplink}}}))
    before = path.read_bytes(), route.read_bytes()
    interface, owned, provider, changes = helper.repair_plan('bc:24:11:00:00:11', tmp_path, reuse_bootstrap_uplink=True)
    assert interface == 'eth1' and set(owned) == {'eth0', 'eth1'}
    assert json.loads(changes[route])['interface'] == 'eth1'
    network = yaml.safe_load(changes[path])['network']
    assert network['ethernets']['llm']['match'] == {'name': 'eth1'}
    assert 'bootstrap-uplink' not in network['ethernets']
    assert network['ethernets']['participant']['routes'] == [{'to': 'default', 'via': '10.254.200.1'}]
    if separate_file:
        assert yaml.safe_load(changes[other])['network']['ethernets'] == {}
    assert before == (path.read_bytes(), route.read_bytes())


@pytest.mark.parametrize('mac', ['bc:24:11:00:00:10', 'bc:24:11:00:00:12'])
def test_uplink_opt_in_never_reassigns_hitl_or_an_unrelated_adapter(tmp_path, mac):
    fixture_guest(tmp_path)
    with pytest.raises(ValueError):
        helper.repair_plan(mac, tmp_path, reuse_bootstrap_uplink=True)


def test_uplink_reuse_rejects_a_static_or_routed_bootstrap_role(tmp_path):
    path, _ = fixture_guest(tmp_path)
    document = yaml.safe_load(path.read_text())
    document['network']['ethernets']['bootstrap-uplink']['routes'] = [{'to': '192.0.2.0/24', 'via': '192.0.2.1'}]
    path.write_text(yaml.safe_dump(document))
    with pytest.raises(ValueError, match='another Netplan role'):
        helper.repair_plan('bc:24:11:00:00:11', tmp_path, reuse_bootstrap_uplink=True)



def test_default_cleanup_keeps_hitl_default_and_provider_host_route(monkeypatch):
    routes = [
        {'dst': 'default', 'dev': 'eth0', 'gateway': '10.254.200.1', 'metric': 2000},
        {'dst': 'default', 'dev': 'eth1', 'gateway': '10.36.20.1', 'metric': 100},
        {'dst': 'default', 'dev': 'eth1', 'gateway': '10.36.20.1', 'metric': 101},
        {'dst': '129.108.156.63/32', 'dev': 'eth1', 'gateway': '10.36.20.1'},
    ]
    monkeypatch.setattr(helper.subprocess, 'check_output', lambda *a, **k: json.dumps([r for r in routes if r['dst'] == 'default']))
    def run(command, **kwargs):
        assert command[:5] == ['ip', '-4', 'route', 'del', 'default']
        interface = command[command.index('dev') + 1]
        metric = int(command[command.index('metric') + 1])
        routes[:] = [r for r in routes if not (r['dst'] == 'default' and r['dev'] == interface and r.get('metric') == metric)]
    monkeypatch.setattr(helper.subprocess, 'run', run)
    helper.remove_llm_defaults('eth1')
    assert [r['dst'] for r in routes] == ['default', '129.108.156.63/32']
    assert routes[0]['dev'] == 'eth0' and routes[1]['dev'] == 'eth1'
