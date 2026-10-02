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
