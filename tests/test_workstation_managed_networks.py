"""Exercise native network planning and cleanup without touching host networks."""
from pathlib import Path
import os
import shlex
import subprocess
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]
LINUX = ROOT / "scripts/provision/vmware-workstation-linux/install-scenarioforge-lab.sh"


@pytest.mark.parametrize("force", [False, True])
def test_linux_creates_free_network_and_removes_its_directory(tmp_path, force):
    config = tmp_path / "networking"
    original = "VERSION=1,0\nanswer VNET_2_DHCP yes\nanswer VNET_2_HOSTONLY_SUBNET 192.168.99.0\n"
    config.write_text(original)
    state = tmp_path / "state"
    work = tmp_path / "work"
    state.mkdir()
    work.mkdir()
    result = subprocess.run(["bash", "-c", f"""
source {shlex.quote(str(LINUX))}
VMWARE_NETWORKING_FILE={shlex.quote(str(config))}
STATE_DIR={shlex.quote(str(state))}
WORK_DIR={shlex.quote(str(work))}
vmware-networks() {{ :; }}
vmrun() {{
    if [[ "$3" == list ]]; then echo 'Total running VMs: 0'; return; fi
    echo 'Total host networks: 4'
    echo 'INDEX NAME TYPE DHCP SUBNET MASK'
    echo '1 vmnet1 hostOnly false 172.31.250.0 255.255.255.0'
    echo '2 vmnet2 hostOnly true 192.168.99.0 255.255.255.0'
    echo '8 vmnet8 nat true 192.168.20.0 255.255.255.0'
    if grep -q VNET_3_ "$VMWARE_NETWORKING_FILE"; then
        echo '3 vmnet3 hostOnly false 10.254.200.0 255.255.255.0'
    fi
}}
write_state() {{ printf '%s\\n' "$INSTALLER_CREATED_HITL_VMNET" > "$STATE_DIR/owner"; }}
sudo() {{
    if [[ "$1" == install ]]; then cp "$8" "$9"
    elif [[ "$1" == vmware-networks ]]; then
        if [[ "$2" == --migrate-network-settings ]] && grep -q VNET_3_ "$3"; then
            mkdir -p {shlex.quote(str(tmp_path / 'vmnet3'))}
        fi
    else "$@"
    fi
}}
parse_args install --yes
prepare_host_network_plan
validate_host_network_plan
[[ "$HITL_VMNET" == vmnet3 ]]
[[ "$INSTALLER_CREATED_HITL_VMNET" == "" ]]
apply_host_network_plan
[[ "$INSTALLER_CREATED_HITL_VMNET" == vmnet3 ]]
[[ -d {shlex.quote(str(tmp_path / 'vmnet3'))} ]]
FORCE_CLEANUP={int(force)}
if [[ "$FORCE_CLEANUP" == 1 ]]; then
    sed 's/VNET_3_DHCP no/VNET_3_DHCP yes/' "$VMWARE_NETWORKING_FILE" > "$WORK_DIR/changed"
    cp "$WORK_DIR/changed" "$VMWARE_NETWORKING_FILE"
fi
cleanup_host_networks
[[ "$INSTALLER_CREATED_HITL_VMNET" == "" ]]
"""], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout
    assert config.read_text() == original
    assert not (tmp_path / "vmnet3").exists()


def test_linux_manual_mode_and_failed_inventory_do_not_allocate(tmp_path):
    config = tmp_path / "networking"
    config.write_text("VERSION=1,0\n")
    result = subprocess.run(["bash", "-c", f"""
source {shlex.quote(str(LINUX))}
VMWARE_NETWORKING_FILE={shlex.quote(str(config))}
vmware-networks() {{ :; }}
vmrun() {{ return 1; }}
prepare_host_network_plan
"""], capture_output=True, text=True)
    assert result.returncode != 0
    assert "cannot inspect" in result.stderr
    assert config.read_text() == "VERSION=1,0\n"


def test_linux_reuses_safe_existing_network_without_ownership(tmp_path):
    result = subprocess.run(["bash", "-c", f"""
source {shlex.quote(str(LINUX))}
workstation_hitl_network_is_safe() {{ return 0; }}
prepare_host_network_plan
[[ "$WORKSTATION_NETWORK_PLAN" == 0 ]]
[[ "$INSTALLER_CREATED_HITL_VMNET" == "" ]]
apply_host_network_plan
cleanup_host_networks
"""], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_windows_managed_network_regressions():
    pwsh = os.environ.get("SF_TEST_PWSH") or shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell runs in Windows CI")
    result = subprocess.run([pwsh, "-NoProfile", "-File", str(ROOT / "tests/test_workstation_managed_networks.ps1")],
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr


def test_linux_force_preserves_network_used_by_another_running_vm(tmp_path):
    vmx = tmp_path / 'other.vmx'
    vmx.write_text('ethernet0.vnet="vmnet3"\n')
    result = subprocess.run(['bash', '-c', f'''
source {shlex.quote(str(LINUX))}
INSTALLER_CREATED_HITL_VMNET=vmnet3
FORCE_CLEANUP=1
vmrun() {{ printf 'Total running VMs: 1\\n%s\\n' {shlex.quote(str(vmx))}; }}
sudo() {{ echo UNEXPECTED_MUTATION; return 1; }}
cleanup_host_networks
'''], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'another running VM references' in result.stderr
    assert 'UNEXPECTED_MUTATION' not in result.stdout


def test_windows_install_plans_before_validation_and_persists_selected_vmnet():
    source = (ROOT / 'scripts/provision/vmware-workstation-windows/install-scenarioforge-lab.ps1').read_text()
    install = source[source.index('    $config = Read-InstallerConfig'):]
    plan = install.index('Plan-HitlNetwork $state')
    assert plan < install.index('$config.hitl_vmnet = $state.Config.hitl_vmnet') < install.index('Assert-HostNetworks $state')
    assert install.index('if ($DryRun)') < install.index('Create-OwnedHitlNetwork $state $stateFile')
    assert install.index('Save-LabState $state $stateFile') < install.index('Create-OwnedHitlNetwork $state $stateFile')
    resume = source[source.index("if ($Command -eq 'resume')"):source.index('        do {')]
    assert 'Plan-HitlNetwork' not in resume
    assert '$config.' not in resume
