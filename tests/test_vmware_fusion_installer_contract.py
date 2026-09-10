from pathlib import Path
import shlex
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "provision" / "vmware-fusion-mac" / "install-scenarioforge-lab.sh"
README = ROOT / "scripts" / "provision" / "vmware-fusion-mac" / "README.md"
CONFIG_EXAMPLE = ROOT / "scripts" / "provision" / "vmware-fusion-mac" / "scenarioforge-lab.conf.example"


def run_bash(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )


def test_fusion_installer_has_valid_bash_syntax_and_executable_bit() -> None:
    result = subprocess.run(
        ["bash", "-n", str(INSTALLER)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert INSTALLER.stat().st_mode & 0o111


def test_fusion_help_does_not_require_fusion_or_macos() -> None:
    result = subprocess.run(
        ["bash", str(INSTALLER), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    for expected in (
        "VMware Fusion",
        "Apple silicon",
        "--from-source",
        "--management-vmnet",
        "--hitl-vmnet",
        "--manage-hitl-network",
        "--no-manage-hitl-network",
        "--headless",
        "--flag-generators",
        "--vulnhub",
        "--config FILE",
        "--watch",
        "cleanup [--dry-run] [--force] [--yes]",
    ):
        assert expected in result.stdout


def test_apple_silicon_selects_arm_images_guest_types_and_nvme(tmp_path: Path) -> None:
    vmx = tmp_path / "arm.vmx"
    probe = f"""
uname() {{
  case "$1" in
    -m) printf 'arm64\\n' ;;
    -s) printf 'Darwin\\n' ;;
    *) command uname "$@" ;;
  esac
}}
source {shlex.quote(str(INSTALLER))}
create_vmx {shlex.quote(str(vmx))} test-arm "$DEBIAN_GUEST_OS" 2048 2 \
  {shlex.quote(str(tmp_path / 'disk.vmdk'))} {shlex.quote(str(tmp_path / 'seed.iso'))}
printf 'VALUES|%s|%s|%s|%s\\n' \
  "$DEBIAN_IMAGE_URL" "$UBUNTU_IMAGE_URL" "$DEBIAN_GUEST_OS" "$VMWARE_DISK_BUS"
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    values_line = next(line for line in result.stdout.splitlines() if line.startswith("VALUES|"))
    assert "debian-12-generic-arm64.qcow2" in values_line
    assert "noble-server-cloudimg-arm64.img" in values_line
    assert values_line.endswith("|arm-debian12-64|nvme")

    generated = vmx.read_text(encoding="utf-8")
    for expected in (
        'virtualHW.version = "20"',
        'guestOS = "arm-debian12-64"',
        'firmware = "efi"',
        'nvme0.present = "TRUE"',
        'nvme0:0.fileName = "disk.vmdk"',
        'sound.autoDetect = "TRUE"',
        'sound.virtualDev = "hdaudio"',
        'sound.fileName = "-1"',
        'scenarioforge.install.owner = "scenarioforge-vmware-fusion-v1"',
    ):
        assert expected in generated
    assert "scsi0:0.fileName" not in generated


def test_intel_mac_selects_amd64_images_and_scsi(tmp_path: Path) -> None:
    vmx = tmp_path / "intel.vmx"
    probe = f"""
uname() {{
  case "$1" in
    -m) printf 'x86_64\\n' ;;
    -s) printf 'Darwin\\n' ;;
    *) command uname "$@" ;;
  esac
}}
source {shlex.quote(str(INSTALLER))}
create_vmx {shlex.quote(str(vmx))} test-intel "$DEBIAN_GUEST_OS" 2048 2 \
  {shlex.quote(str(tmp_path / 'disk.vmdk'))} {shlex.quote(str(tmp_path / 'seed.iso'))}
printf 'VALUES|%s|%s|%s\\n' "$DEBIAN_IMAGE_URL" "$DEBIAN_GUEST_OS" "$VMWARE_DISK_BUS"
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    values_line = next(line for line in result.stdout.splitlines() if line.startswith("VALUES|"))
    assert "debian-12-generic-amd64.qcow2" in values_line
    assert values_line.endswith("|debian12-64|scsi")
    generated = vmx.read_text(encoding="utf-8")
    assert 'scsi0:0.fileName = "disk.vmdk"' in generated
    assert 'sound.virtualDev = "hdaudio"' in generated
    assert "nvme0:0.fileName" not in generated


def test_config_file_uses_fusion_paths_bundles_and_precedence(tmp_path: Path) -> None:
    config_path = tmp_path / "fusion.conf"
    config_lab = tmp_path / "from-config"
    cli_lab = tmp_path / "from-cli"
    config_path.write_text(
        f'lab_dir="{config_lab}"\nmanagement_vmnet=vmnet4\nhitl_vmnet=vmnet5\n',
        encoding="utf-8",
    )
    probe = f"""
export SF_FUSION_MANAGEMENT_VMNET=vmnet6
source {shlex.quote(str(INSTALLER))}
parse_args install --config {shlex.quote(str(config_path))} --lab-dir {shlex.quote(str(cli_lab))}
printf 'VALUES|%s|%s|%s|%s\\n' "$LAB_DIR" "$MANAGEMENT_VMNET" "$HITL_VMNET" "$CORE_VMX"
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    values = next(line for line in result.stdout.splitlines() if line.startswith("VALUES|"))
    assert values.split("|")[1:] == [
        str(cli_lab),
        "vmnet6",
        "vmnet5",
        str(cli_lab / "scenarioforge-core.vmwarevm" / "scenarioforge-core.vmx"),
    ]


def test_fusion_example_config_parses_successfully() -> None:
    probe = f"""
source {shlex.quote(str(INSTALLER))}
parse_args install --config {shlex.quote(str(CONFIG_EXAMPLE))}
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr


def test_unsafe_hitl_network_plans_unused_isolated_replacement(tmp_path: Path) -> None:
    networking = tmp_path / "networking"
    networking.write_text(
        "\n".join(
            [
                "VERSION=1,0",
                "answer VNET_1_DHCP yes",
                "answer VNET_1_HOSTONLY_SUBNET 192.168.230.0",
                "answer VNET_1_VIRTUAL_ADAPTER yes",
                "answer VNET_2_DHCP yes",
                "answer VNET_2_HOSTONLY_SUBNET 12.0.0.0",
                "answer VNET_2_VIRTUAL_ADAPTER yes",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    vmrun_output = """\
Total host networks: 3
INDEX  NAME         TYPE         DHCP         SUBNET           MASK
0      vmnet0       bridged      false        empty            empty
1      vmnet1       hostOnly     true         192.168.230.0    255.255.255.0
2      vmnet2       hostOnly     true         12.0.0.0         255.255.255.0
"""
    probe = f"""
source {shlex.quote(str(INSTALLER))}
VMWARE_NETWORKING_FILE={shlex.quote(str(networking))}
vmrun() {{
  if [[ "$*" == *listHostNetworks ]]; then printf '%s' {shlex.quote(vmrun_output)};
  elif [[ "$*" == *' list' ]]; then printf 'Total running VMs: 0\n';
  fi
}}
DRY_RUN=1
ASSUME_YES=1
prepare_host_network_plan
validate_host_network_plan
printf 'VALUES|%s|%s|%s|%s|%s\n' "$FUSION_NETWORK_PLAN" \
  "$FUSION_ORIGINAL_HITL_VMNET" "$HITL_VMNET" \
  "$FUSION_PLANNED_HITL_SUBNET" "$FUSION_PLANNED_HITL_NETMASK"
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    assert "VALUES|1|vmnet2|vmnet3|10.254.200.0|255.255.255.0" in result.stdout


def test_unattended_network_change_requires_explicit_manage_flag(tmp_path: Path) -> None:
    networking = tmp_path / "networking"
    networking.write_text(
        "VERSION=1,0\nanswer VNET_2_DHCP yes\n"
        "answer VNET_2_HOSTONLY_SUBNET 12.0.0.0\n"
        "answer VNET_2_VIRTUAL_ADAPTER yes\n",
        encoding="utf-8",
    )
    probe = f"""
source {shlex.quote(str(INSTALLER))}
VMWARE_NETWORKING_FILE={shlex.quote(str(networking))}
vmrun() {{ printf 'Total host networks: 1\n2 vmnet2 hostOnly true 12.0.0.0 255.255.255.0\n'; }}
MANAGE_HITL_NETWORK=ask
ASSUME_YES=1
DRY_RUN=0
prepare_host_network_plan
"""
    result = run_bash(probe)
    assert result.returncode != 0
    assert "--manage-hitl-network" in result.stderr


def test_interactive_network_plan_requires_explicit_combined_confirmation() -> None:
    probe = f"""
source {shlex.quote(str(INSTALLER))}
FUSION_NETWORK_PLAN=1
FUSION_ORIGINAL_HITL_VMNET=vmnet2
FUSION_PLANNED_HITL_SUBNET=10.254.200.0
FUSION_PLANNED_HITL_NETMASK=255.255.255.0
HITL_VMNET=vmnet3
ASSUME_YES=0
DRY_RUN=0
confirm_install
"""
    accepted = subprocess.run(
        ["bash", "-c", probe],
        input="INSTALL+NETWORK\n",
        capture_output=True,
        text=True,
        check=False,
    )
    assert accepted.returncode == 0, accepted.stderr
    assert "Type INSTALL+NETWORK" in accepted.stdout

    rejected = subprocess.run(
        ["bash", "-c", probe],
        input="INSTALL\n",
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert "installation cancelled" in rejected.stderr


def test_network_candidate_add_and_guarded_remove_round_trip(tmp_path: Path) -> None:
    original = tmp_path / "networking"
    added = tmp_path / "networking.added"
    removed = tmp_path / "networking.removed"
    changed = tmp_path / "networking.changed"
    original.write_text(
        "VERSION=1,0\nanswer VNET_1_DHCP yes\n"
        "answer VNET_1_HOSTONLY_SUBNET 192.168.230.0\n",
        encoding="utf-8",
    )
    probe = f"""
source {shlex.quote(str(INSTALLER))}
build_fusion_networking_candidate add {shlex.quote(str(original))} \
  {shlex.quote(str(added))} vmnet3 10.254.200.0 255.255.255.0
build_fusion_networking_candidate remove {shlex.quote(str(added))} \
  {shlex.quote(str(removed))} vmnet3 10.254.200.0 255.255.255.0
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    generated = added.read_text(encoding="utf-8")
    for expected in (
        "answer VNET_3_DHCP no",
        "answer VNET_3_HOSTONLY_SUBNET 10.254.200.0",
        "answer VNET_3_NAT no",
        "answer VNET_3_VIRTUAL_ADAPTER no",
    ):
        assert expected in generated
    assert removed.read_text(encoding="utf-8") == original.read_text(encoding="utf-8")

    changed.write_text(generated.replace("VNET_3_DHCP no", "VNET_3_DHCP yes"), encoding="utf-8")
    guarded = run_bash(
        f"source {shlex.quote(str(INSTALLER))}; "
        f"build_fusion_networking_candidate remove {shlex.quote(str(changed))} "
        f"{shlex.quote(str(tmp_path / 'must-not-apply'))} vmnet3 10.254.200.0 255.255.255.0"
    )
    assert guarded.returncode != 0
    assert "changed; preserving" in guarded.stderr


def test_network_plan_application_uses_privileged_install_and_verifies_result(
    tmp_path: Path,
) -> None:
    networking = tmp_path / "networking"
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    networking.write_text(
        "VERSION=1,0\nanswer VNET_1_DHCP yes\n"
        "answer VNET_1_HOSTONLY_SUBNET 192.168.230.0\n"
        "answer VNET_1_VIRTUAL_ADAPTER yes\n",
        encoding="utf-8",
    )
    probe = f"""
source {shlex.quote(str(INSTALLER))}
VMWARE_NETWORKING_FILE={shlex.quote(str(networking))}
WORK_DIR={shlex.quote(str(work_dir))}
HITL_VMNET=vmnet3
FUSION_NETWORK_PLAN=1
FUSION_PLANNED_HITL_SUBNET=10.254.200.0
FUSION_PLANNED_HITL_NETMASK=255.255.255.0
write_state() {{ :; }}
fusion_reload_networking() {{ :; }}
sudo() {{
  [[ "$1" == install ]] || return 1
  command cp "$8" "$9"
}}
vmrun() {{
  if grep -q 'VNET_3_DHCP no' "$VMWARE_NETWORKING_FILE"; then
    printf 'Total host networks: 1\n3 vmnet3 hostOnly false 10.254.200.0 255.255.255.0\n'
  else
    printf 'Total host networks: 0\n'
  fi
}}
apply_host_network_plan
validate_host_networks() {{ fusion_hitl_network_is_safe "$HITL_VMNET"; }}
validate_host_networks
printf 'VALUES|%s|%s|%s\n' "$INSTALLER_CREATED_HITL_VMNET" \
  "$INSTALLER_CREATED_HITL_SUBNET" "$INSTALLER_CREATED_HITL_NETMASK"
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    assert "VALUES|vmnet3|10.254.200.0|255.255.255.0" in result.stdout
    assert "answer VNET_3_DHCP no" in networking.read_text(encoding="utf-8")


def test_fusion_contract_reuses_graphical_guest_provisioning() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    workstation = (
        ROOT / "scripts" / "provision" / "vmware-workstation-linux" / "install-scenarioforge-lab.sh"
    ).read_text(encoding="utf-8")
    shared = (
        ROOT / "scripts" / "provision" / "proxmox" / "install-scenarioforge-lab.sh"
    ).read_text(encoding="utf-8")

    assert 'VMRUN_TYPE="fusion"' in source
    assert 'VM_BUNDLE_SUFFIX=".vmwarevm"' in source
    assert 'FUSION_APP="${SF_FUSION_APP:-/Applications/VMware Fusion.app}"' in source
    assert 'VMWARE_NETWORKING_FILE="${SF_FUSION_NETWORKING_FILE:-/Library/Preferences/VMware Fusion/networking}"' in source
    assert "create_seed_iso()" in source
    assert "hdiutil makehybrid" in source
    assert 'append_nic "$CORE_VMX" 1 custom "$HITL_VMNET"' in workstation
    assert 'deleteNetworkAdapter "$PARTICIPANT_VMX" 1' in workstation
    assert "open-vm-tools, open-vm-tools-desktop" in workstation
    assert '"$(dpkg --print-architecture)" == arm64' in shared
    assert "qemu-user-static binfmt-support" in shared
    assert "update-binfmts --enable qemu-x86_64" in shared
    assert "grep -q '^flags:.*F'" in shared
    assert '--from-source "$CORE_REPO_URL" "$CORE_REPO_REF"' in shared
    assert "CORETG_VM_MODE_HITL_CORE_IFX_NAME=ens19" in shared
    assert "ExecStart=/opt/scenarioforge/.venv/bin/python -m webapp.app_backend" in shared
    assert "epiphany-browser" in shared
    assert "terminator xdot xfce4" in shared


def test_fusion_readme_and_root_link_cover_operations_and_arm_limit() -> None:
    readme = README.read_text(encoding="utf-8")
    root_readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for expected in (
        "Apple silicon",
        "Intel Macs",
        "brew install qemu",
        "Virtual Machines.localized",
        "status --watch",
        "cleanup --force",
        "ARM64",
        "x86-only",
        "credentials.env",
    ):
        assert expected in readme
    assert "VMware Fusion macOS three-VM installer" in root_readme


def test_fusion_dry_run_reaches_completion_with_host_checks_stubbed(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    lab_dir = tmp_path / "lab"
    runtime = tmp_path / "runtime.status"
    probe = f"""
SCENARIOFORGE_FUSION_STATE_DIR={shlex.quote(str(state_dir))}
SCENARIOFORGE_FUSION_RUNTIME_STATUS_FILE={shlex.quote(str(runtime))}
source {shlex.quote(str(INSTALLER))}
parse_args install --dry-run --yes --lab-dir {shlex.quote(str(lab_dir))}
require_linux_workstation() {{ :; }}
host_network_exists() {{ return 0; }}
validate_hitl_isolation() {{ :; }}
perform_install
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    assert "[100%] [2/2] Dry-run validation complete" in result.stdout
    assert not state_dir.exists()
    assert not lab_dir.exists()


def test_cleanup_can_preserve_a_replaced_network(tmp_path: Path) -> None:
    networking = tmp_path / "networking"
    contents = ("VERSION=1,0\nanswer VNET_3_DHCP yes\n"
                "answer VNET_3_HOSTONLY_SUBNET 172.16.124.0\n")
    networking.write_text(contents)
    backup = tmp_path / "fusion-networking.cleanup-before"
    backup.write_text("previous cleanup backup")
    probe = f"""
source {shlex.quote(str(INSTALLER))}
STATE_DIR={shlex.quote(str(tmp_path))}
VMWARE_NETWORKING_FILE={shlex.quote(str(networking))}
INSTALLER_CREATED_HITL_VMNET=vmnet3
parse_args cleanup --keep-hitl-network
sudo() {{ echo 'must not modify host networking' >&2; exit 90; }}
fusion_vmnet_is_used_by_running_vm() {{ echo 'must preserve even a reused network' >&2; exit 91; }}
cleanup_host_networks
printf 'OWNERSHIP=%s\n' "$INSTALLER_CREATED_HITL_VMNET"
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    assert "OWNERSHIP=\n" in result.stdout
    assert networking.read_text() == contents
    assert not backup.exists()


def test_keep_network_dry_run_retains_state_and_backup(tmp_path: Path) -> None:
    backup = tmp_path / "fusion-networking.cleanup-before"
    backup.write_text("backup")
    result = run_bash(f"""
source {shlex.quote(str(INSTALLER))}
STATE_DIR={shlex.quote(str(tmp_path))}
INSTALLER_CREATED_HITL_VMNET=vmnet3
parse_args cleanup --keep-hitl-network --dry-run
cleanup_host_networks
printf 'OWNERSHIP=%s\n' "$INSTALLER_CREATED_HITL_VMNET"
""")
    assert result.returncode == 0, result.stderr
    assert "OWNERSHIP=vmnet3" in result.stdout
    assert backup.read_text() == "backup"


def test_changed_network_still_requires_explicit_keep_option(tmp_path: Path) -> None:
    networking = tmp_path / "networking"
    contents = "answer VNET_3_DHCP yes\nanswer VNET_3_HOSTONLY_SUBNET 172.16.124.0\n"
    networking.write_text(contents)
    result = run_bash(f"""
source {shlex.quote(str(INSTALLER))}
STATE_DIR={shlex.quote(str(tmp_path))}
VMWARE_NETWORKING_FILE={shlex.quote(str(networking))}
INSTALLER_CREATED_HITL_VMNET=vmnet3
INSTALLER_CREATED_HITL_SUBNET=10.254.200.0
INSTALLER_CREATED_HITL_NETMASK=255.255.255.0
fusion_vmnet_is_used_by_running_vm() {{ return 1; }}
fusion_vmnet_is_configured() {{ return 0; }}
cleanup_host_networks
""")
    assert result.returncode != 0
    assert "changed since installation" in result.stderr
    assert "--keep-hitl-network" in result.stderr
    assert networking.read_text() == contents


def test_keep_network_option_is_cleanup_only() -> None:
    result = run_bash(f"source {shlex.quote(str(INSTALLER))}; parse_args install --keep-hitl-network")
    assert result.returncode != 0
    assert "only valid with cleanup" in result.stderr


@pytest.mark.parametrize("reload_fails", [False, True])
def test_force_cleanup_removes_changed_vmnet_and_its_directory(tmp_path: Path, reload_fails: bool) -> None:
    config = tmp_path / "networking"
    config.write_text("answer VNET_1_DHCP yes\nanswer VNET_3_DHCP yes\n"
                      "answer VNET_3_HOSTONLY_SUBNET 172.16.124.0\n")
    directory = tmp_path / "vmnet3"
    directory.mkdir()
    (directory / "dhcpd.conf").write_text("stale vmnet configuration")
    state = tmp_path / "state"
    state.mkdir()
    events = tmp_path / "events"
    original = config.read_text()
    result = run_bash(f"""
source {shlex.quote(str(INSTALLER))}
STATE_DIR={shlex.quote(str(state))}
VMWARE_NETWORKING_FILE={shlex.quote(str(config))}
INSTALLER_CREATED_HITL_VMNET=vmnet3
INSTALLER_CREATED_HITL_SUBNET=10.254.200.0
INSTALLER_CREATED_HITL_NETMASK=255.255.255.0
parse_args cleanup --force
fusion_vmnet_is_used_by_running_vm() {{ return 1; }}
fusion_vmnet_is_configured() {{ grep -q VNET_3_ "$VMWARE_NETWORKING_FILE"; }}
sudo() {{
    if [[ "$1" == "$FUSION_VMNET_CLI" ]]; then
        echo "$2" >> {shlex.quote(str(events))}
        if [[ "$2" == --configure && {int(reload_fails)} -eq 1 ]]; then return 81; fi
        if [[ "$2" == --configure ]]; then
            [[ ! -e {shlex.quote(str(directory))} ]] || return 80
        fi
    elif [[ "$1" == install ]]; then
        cp "$8" "$9"
    else
        "$@"
    fi
}}
cleanup_host_networks
echo "OWNERSHIP=$INSTALLER_CREATED_HITL_VMNET"
""")
    if reload_fails:
        assert result.returncode != 0
        assert "rollback was attempted" in result.stderr
        assert config.read_text() == original
        assert (directory / "dhcpd.conf").read_text() == "stale vmnet configuration"
        assert (state / "fusion-networking.cleanup-before").exists()
        return
    assert result.returncode == 0, result.stderr
    assert config.read_text() == "answer VNET_1_DHCP yes\n"
    assert not directory.exists()
    assert not list(state.iterdir())
    assert events.read_text().splitlines() == ["--stop", "--configure", "--start"]
    assert "OWNERSHIP=\n" in result.stdout


def test_force_cleanup_does_not_remove_network_used_by_running_vm(tmp_path: Path) -> None:
    result = run_bash(f"""
source {shlex.quote(str(INSTALLER))}
STATE_DIR={shlex.quote(str(tmp_path))}
INSTALLER_CREATED_HITL_VMNET=vmnet3
parse_args cleanup --force
fusion_vmnet_is_used_by_running_vm() {{ return 0; }}
sudo() {{ exit 90; }}
cleanup_host_networks
""")
    assert result.returncode != 0
    assert "another running VM references" in result.stderr


def test_force_cleanup_never_removes_reserved_network() -> None:
    for vmnet in ("vmnet0", "vmnet1", "vmnet8", "../vmnet3"):
        result = run_bash(f"""
source {shlex.quote(str(INSTALLER))}
INSTALLER_CREATED_HITL_VMNET={shlex.quote(vmnet)}
parse_args cleanup --force
cleanup_host_networks
""")
        assert result.returncode != 0
        assert "refusing to remove" in result.stderr or "invalid installer-created" in result.stderr
