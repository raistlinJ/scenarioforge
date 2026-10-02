import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('update_llm', Path(__file__).resolve().parents[1] / 'scripts/provision/common/update-llm-destination.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_destination_validation(monkeypatch):
    monkeypatch.setattr(module.socket, 'getaddrinfo', lambda *args: [(None, None, None, None, ('203.0.113.20', 443))])
    assert module.validate_destination('203.0.113.20', 'https://provider.example/v1', ['10.254.200.0/24']) == '203.0.113.20'
    for address, url in [('10.254.200.20', 'https://provider.example'), ('203.0.113.21', 'https://provider.example'), ('203.0.113.20', 'https://user:password@provider.example'), ('127.0.0.1', 'http://localhost')]:
        with pytest.raises(ValueError):
            module.validate_destination(address, url, ['10.254.200.0/24'])


def test_atomic_config_update_preserves_permissions(tmp_path):
    path = tmp_path / 'cli.json'
    path.write_text('{}')
    path.chmod(0o600)
    module.write_atomic(path, b'{"url":"http://203.0.113.20"}')
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == b'{"url":"http://203.0.113.20"}'


def test_endpoint_and_gateway_exclusions_track_route_and_preserve_custom_policy(tmp_path, monkeypatch):
    path = tmp_path / 'cli.json'
    path.write_text(json.dumps({'network_policy': {'allow': ['10.0.0.0/24'], 'disallow': ['10.0.0.10']}}))
    route = {'dev': 'ens20', 'gateway': '192.168.80.2'}
    monkeypatch.setattr(module.subprocess, 'check_output', lambda *a, **kw: json.dumps([route]))
    module.sync_gateway_policy(path, '203.0.113.20')
    first = path.read_bytes()
    module.sync_gateway_policy(path, '203.0.113.20')
    assert path.read_bytes() == first
    assert json.loads(first)['network_policy'] == {
        'allow': ['10.0.0.0/24'], 'disallow': ['10.0.0.10', '192.168.80.2', '203.0.113.20'],
    }
    route['gateway'] = '192.168.80.3'
    module.sync_gateway_policy(path, '203.0.113.21')
    assert json.loads(path.read_text())['network_policy']['disallow'] == ['10.0.0.10', '192.168.80.3', '203.0.113.21']
    del route['gateway']
    module.sync_gateway_policy(path, '192.168.80.20')
    assert json.loads(path.read_text())['network_policy']['disallow'] == ['10.0.0.10', '192.168.80.20']


def test_preexisting_gateway_exclusion_is_not_removed(tmp_path, monkeypatch):
    path = tmp_path / 'cli.json'
    path.write_text(json.dumps({'network_policy': {'allow': ['*'], 'disallow': ['192.168.80.2']}}))
    route = {'dev': 'ens20', 'gateway': '192.168.80.2'}
    monkeypatch.setattr(module.subprocess, 'check_output', lambda *a, **kw: json.dumps([route]))
    module.sync_gateway_policy(path, '203.0.113.20')
    route['gateway'] = '192.168.80.3'
    module.sync_gateway_policy(path, '203.0.113.20')
    assert json.loads(path.read_text())['network_policy']['disallow'] == ['192.168.80.2', '203.0.113.20', '192.168.80.3']


def test_user_defined_endpoint_exclusion_is_preserved_after_endpoint_change(tmp_path, monkeypatch):
    path = tmp_path / 'cli.json'
    path.write_text(json.dumps({'network_policy': {'allow': ['*'], 'disallow': ['203.0.113.20']}}))
    monkeypatch.setattr(module.subprocess, 'check_output', lambda *a, **kw: '[{"dev":"ens20"}]')
    module.sync_gateway_policy(path, '203.0.113.20')
    module.sync_gateway_policy(path, '203.0.113.21')
    assert json.loads(path.read_text())['network_policy']['disallow'] == ['203.0.113.20', '203.0.113.21']


def test_shared_endpoint_and_gateway_remain_excluded_until_neither_is_used(tmp_path, monkeypatch):
    path = tmp_path / 'cli.json'
    path.write_text('{}')
    route = {'dev': 'ens20', 'gateway': '192.168.80.2'}
    monkeypatch.setattr(module.subprocess, 'check_output', lambda *a, **kw: json.dumps([route]))
    module.sync_gateway_policy(path, '192.168.80.2')
    assert json.loads(path.read_text())['network_policy']['disallow'] == ['192.168.80.2']
    route['gateway'] = '192.168.80.3'
    module.sync_gateway_policy(path, '192.168.80.2')
    assert json.loads(path.read_text())['network_policy']['disallow'] == ['192.168.80.2', '192.168.80.3']
    del route['gateway']
    module.sync_gateway_policy(path, '192.168.80.20')
    assert json.loads(path.read_text())['network_policy'] == {'allow': ['*'], 'disallow': ['192.168.80.20']}


def test_wrong_route_does_not_change_config(tmp_path, monkeypatch):
    path = tmp_path / 'cli.json'
    path.write_text('{}')
    monkeypatch.setattr(module.subprocess, 'check_output', lambda *a, **kw: '[{"dev":"ens18","gateway":"10.0.0.1"}]')
    with pytest.raises(ValueError, match='ens20'):
        module.sync_gateway_policy(path, '203.0.113.20')
    assert path.read_text() == '{}'


@pytest.mark.parametrize('interface', ['ens20', 'eth2'])
@pytest.mark.parametrize('interactive', [False, True])
@pytest.mark.parametrize('dynamic', [False, True])
@pytest.mark.parametrize('fail_policy', [False, True])
def test_desktop_update_changes_policy_with_route_and_rolls_back(tmp_path, monkeypatch, dynamic, fail_policy, interface, interactive):
    cli_path = tmp_path / 'opt/cyber-agent-flow/configs/cli.json'
    cli_path.parent.mkdir(parents=True)
    cli_path.write_text(json.dumps({
        'url': 'http://203.0.113.20:11434',
        'network_policy': {'allow': ['*'], 'disallow': ['10.0.0.10', '192.168.80.2']},
        'llm_route_gateway': '192.168.80.2', 'llm_route_gateway_managed': True,
    }))
    netplan = tmp_path / 'etc/netplan/llm.yaml'
    netplan.parent.mkdir(parents=True)
    netplan.write_text(module.yaml.safe_dump({'network': {'ethernets': {'llm': {'set-name':interface,
        'dhcp4': dynamic, 'addresses': ['192.168.80.10/24'],
        'routes': [{'to': '203.0.113.20/32', 'via': '192.168.80.3'}],
    }}}}))
    dhcp = tmp_path / 'etc/scenarioforge-llm-route.json'
    dhcp.write_text(json.dumps({'provider': '203.0.113.20', 'protected': [], 'interface':interface}))
    before = {path: path.read_bytes() for path in (cli_path, netplan, dhcp)}
    monkeypatch.setattr(module, 'Path', lambda value: tmp_path / str(value).lstrip('/')
                        if str(value).startswith(('/opt/', '/etc/')) else Path(value))
    monkeypatch.setattr(module.os, 'geteuid', lambda: 0)
    answers = iter(['203.0.113.21', 'http://203.0.113.21:11434'])
    monkeypatch.setattr('builtins.input', lambda _: next(answers) if interactive else pytest.fail('Noninteractive route update prompted'))
    monkeypatch.setattr(module.socket, 'getaddrinfo', lambda *a: [(None, None, None, None, ('203.0.113.21', 443))])
    commands = []
    monkeypatch.setattr(module.subprocess, 'run', lambda args, **kw: commands.append(args))

    def route_output(args, **kwargs):
        if '-j' in args:
            if fail_policy:
                raise ValueError('route lookup failed')
            return json.dumps([{'dev':interface,'gateway':'192.168.80.3'}])
        return '203.0.113.21 via 192.168.80.3 dev ' + interface

    monkeypatch.setattr(module.subprocess, 'check_output', route_output)
    if fail_policy:
        with pytest.raises(ValueError, match='route lookup failed'):
            module.main() if interactive else module.main(url='http://203.0.113.21:11434')
        assert {path: path.read_bytes() for path in before} == before
        assert ['ip', '-4', 'route', 'del', '203.0.113.21/32', 'dev', interface] in commands
    else:
        result=module.main() if interactive else module.main(url='http://203.0.113.21:11434')
        assert result['interface']==interface
        updated = json.loads(cli_path.read_text())
        assert updated['url'] == 'http://203.0.113.21:11434'
        assert updated['network_policy']['disallow'] == ['10.0.0.10', '192.168.80.3', '203.0.113.21']
        if dynamic:
            assert json.loads(dhcp.read_text())['provider'] == '203.0.113.21'
        else:
            assert module.yaml.safe_load(netplan.read_text())['network']['ethernets']['llm']['routes'][0]['to'] == '203.0.113.21/32'


@pytest.mark.parametrize('fail_route',[False,True])
def test_missing_dns_is_scoped_to_provider_and_rolled_back(tmp_path,monkeypatch,fail_route):
    cli_path=tmp_path/'opt/cyber-agent-flow/configs/cli.json';cli_path.parent.mkdir(parents=True)
    cli_path.write_text(json.dumps({'url':'http://203.0.113.20:80'}))
    netplan=tmp_path/'etc/netplan/llm.yaml';netplan.parent.mkdir(parents=True)
    netplan.write_text(module.yaml.safe_dump({'network':{'ethernets':{'llm':{'set-name':'eth2','addresses':['192.168.80.10/24'],'routes':[{'to':'203.0.113.20/32','via':'192.168.80.2'}]}}}}))
    before={path:path.read_bytes() for path in (cli_path,netplan)}
    monkeypatch.setattr(module,'Path',lambda value:tmp_path/str(value).lstrip('/') if str(value).startswith(('/opt/','/etc/')) else Path(value))
    monkeypatch.setattr(module.os,'geteuid',lambda:0)
    monkeypatch.setattr(module.socket,'getaddrinfo',lambda *a:(_ for _ in ()).throw(module.socket.gaierror('No DNS')))
    commands=[];monkeypatch.setattr(module.subprocess,'run',lambda command,**kw:commands.append(command))
    def update(address,url,path):
        document=module.yaml.safe_load(netplan.read_text())
        assert document['network']['ethernets']['llm']['nameservers']=={'addresses':['192.168.80.2'],'search':['~model.example']}
        if fail_route:raise ValueError('route failed')
        return {'status':'updated','destination':'203.0.113.21','interface':'eth2'}
    monkeypatch.setattr(module,'update_route',update)
    if fail_route:
        with pytest.raises(ValueError,match='route failed'):module.main(url='http://model.example:10101/v1')
        assert {path:path.read_bytes() for path in before}==before
        assert len(commands)==2
    else:
        result=module.main(url='http://model.example:10101/v1')
        assert result['dns']=={'server':'192.168.80.2','domain':'~model.example'}
        assert json.loads(cli_path.read_text())['llm_route_dns_domain']=='~model.example'
        assert len(commands)==1
