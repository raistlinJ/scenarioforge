"""Proxmox network snippets must survive regenerated clone MAC addresses."""
import json
import subprocess
from pathlib import Path
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT/'scripts/provision/proxmox/install-scenarioforge-lab.sh'

@pytest.mark.parametrize('guest_os,expected',[('debian',['ens18','ens19']),('kali',['eth0','eth1'])])
def test_network_generation_does_not_depend_on_mac(tmp_path,guest_os,expected):
    def generate(mac):
        probe = f'''source "$1"
WORK_DIR="$2"
PARTICIPANT_OS="$3"
PARTICIPANT_GATEWAY=10.254.200.1
for name in CORE_NET0_MAC CORE_NET1_MAC CORE_NET2_MAC APP_NET0_MAC APP_NET1_MAC PARTICIPANT_NET0_MAC PARTICIPANT_NET1_MAC; do printf -v "$name" '%s' "$4"; done
write_guest_network_files
'''
        result=subprocess.run(['bash','-c',probe,'check',str(SCRIPT),str(tmp_path),guest_os,mac],capture_output=True,text=True)
        assert result.returncode==0,result.stderr
        return {role:(tmp_path/(role+'-network.yaml')).read_text() for role in ['core','app','participant']}
    original=generate('02:00:00:00:00:01')
    clone=generate('bc:24:11:31:16:b0')
    assert original==clone
    for content in clone.values():
        assert 'macaddress' not in content and 'set-name' not in content
    participant=yaml.safe_load(clone['participant'])['ethernets']
    assert [participant[key]['match']['name'] for key in ['participant','bootstrap-uplink']]==expected
    assert participant['participant']['addresses']==['10.254.200.10/24']
    assert participant['participant']['routes'][0]['via']=='10.254.200.1'
    core=yaml.safe_load(clone['core'])['ethernets']
    assert core['hitl']['match']=={'name':'ens19'}


def test_proxmox_optional_llm_nic_uses_name_and_bootstrap_validates_same_name():
    source=SCRIPT.read_text()
    assert 'caf_generate network "$PARTICIPANT_NET2_MAC" --match-name "$(participant_interface_name 2)"' in source
    assert 'caf_generate inject "$WORK_DIR/participant-bootstrap.sh" --interface-name "$(participant_interface_name 2)"' in source


@pytest.mark.parametrize('platform', ['vmware-fusion-mac', 'vmware-workstation-linux'])
@pytest.mark.parametrize('guest_os', ['debian', 'kali'])
def test_vmware_networks_bind_adapters_and_rename_for_shared_bootstraps(tmp_path, platform, guest_os):
    script = ROOT/'scripts/provision'/platform/'install-scenarioforge-lab.sh'
    result = subprocess.run(['bash', '-c', '''source "$1"
WORK_DIR="$2"
PARTICIPANT_OS="$3"
PARTICIPANT_GATEWAY=10.254.200.1
CORE_NET0_MAC=00:50:56:00:00:01
CORE_NET1_MAC=00:50:56:00:00:02
CORE_NET2_MAC=00:50:56:00:00:03
APP_NET0_MAC=00:50:56:00:01:01
APP_NET1_MAC=00:50:56:00:01:02
PARTICIPANT_NET0_MAC=00:50:56:00:02:01
PARTICIPANT_NET1_MAC=00:50:56:00:02:02
write_guest_network_files
participant_interface_name 2
''', 'check', str(script), str(tmp_path), guest_os], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'ens20'
    participant = yaml.safe_load((tmp_path/'participant-network.yaml').read_text())['ethernets']
    assert participant['participant']['match'] == {'macaddress':'00:50:56:00:02:01'}
    assert participant['participant']['set-name'] == 'ens18'
    assert participant['bootstrap-uplink']['set-name'] == 'ens19'
    assert participant['participant']['addresses'] == ['10.254.200.10/24']
    assert participant['participant']['routes'][0]['via'] == '10.254.200.1'
    core = yaml.safe_load((tmp_path/'core-network.yaml').read_text())['ethernets']
    assert core['hitl']['match'] == {'macaddress':'00:50:56:00:00:02'}
    assert core['hitl']['set-name'] == 'ens19'


@pytest.mark.parametrize('caf', ['0', '1'])
def test_bootstrap_detach_preserves_nic_slots_with_or_without_caf(tmp_path, caf):
    config=tmp_path/'qm-config'
    config.write_text('net0: virtio=BC:24:11:00:00:01,bridge=sfhitl1\nnet1: virtio=BC:24:11:00:00:02,bridge=vmbr0\nnet2: virtio=BC:24:11:00:00:03,bridge=vmbr0\n')
    calls=tmp_path/'calls'
    script = r'''source "$1"
CYBER_AGENT_FLOW="$2"
PARTICIPANT_VMID=123
config="$3"
calls="$4"
qm() {
    if [[ "$1" == config ]]; then cat "$config"; return; fi
    printf '%s\n' "$*" >> "$calls"
    if [[ "$1" == set ]]; then
        if [[ "$3" == --delete ]]; then
            sed -i.bak '/^net1:/d' "$config"
        else
            sed -i.bak '/^net1:/d' "$config"
            printf 'net1: %s\n' "$4" >> "$config"
        fi
    fi
}
run() { "$@"; }
write_state() { :; }
detach_participant_bootstrap_uplink
'''
    result=subprocess.run(['bash','-c',script,'test',str(SCRIPT),caf,str(config),str(calls)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    actual=config.read_text()
    assert 'net2: virtio=BC:24:11:00:00:03' in actual
    assert 'net1: virtio=BC:24:11:00:00:02,bridge=vmbr0,link_down=1' in actual
    assert '--delete' not in calls.read_text()
    assert 'reboot 123' in calls.read_text()


@pytest.mark.parametrize('platform,names', [
    ('proxmox',['eth0','eth1','eth2']),
    ('vmware-workstation-linux',['ens18','ens19','ens20']),
    ('vmware-fusion-mac',['ens18','ens19','ens20']),
])
def test_participant_nics_have_one_network_owner_before_desktop_install(tmp_path, platform, names):
    installer=ROOT/'scripts/provision'/platform/'install-scenarioforge-lab.sh'
    probe=r'''source "$1"
WORK_DIR="$2"
PARTICIPANT_OS=kali
PARTICIPANT_GATEWAY=10.254.200.1
for name in CORE_NET0_MAC CORE_NET1_MAC CORE_NET2_MAC APP_NET0_MAC APP_NET1_MAC PARTICIPANT_NET0_MAC PARTICIPANT_NET1_MAC; do printf -v "$name" '%s' '02:00:00:00:00:01'; done
write_guest_bootstraps
write_guest_network_files
'''
    result=subprocess.run(['bash','-c',probe,'test',str(installer),str(tmp_path)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    network=yaml.safe_load((tmp_path/'participant-network.yaml').read_text())
    assert network['renderer']=='networkd'
    script=(tmp_path/'participant-bootstrap.sh').read_text()
    assert 'match-device='+';'.join('interface-name:'+name for name in names) in script
    assert 'managed=0' in script
    assert 'for iface in '+' '.join(names)+'; do' in script
    assert script.index('90-scenarioforge-netplan.conf') < script.index('apt-get update')
    assert '__PARTICIPANT_' not in script
    assert 'unmanaged-devices=*' not in script
    subprocess.run(['bash','-n',str(tmp_path/'participant-bootstrap.sh')],check=True)
