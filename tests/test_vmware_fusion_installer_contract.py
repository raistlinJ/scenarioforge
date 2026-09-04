from pathlib import Path
import shlex
import subprocess


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "vmware-fusion" / "install-scenarioforge-lab.sh"
README = ROOT / "scripts" / "vmware-fusion" / "README.md"
CONFIG_EXAMPLE = ROOT / "scripts" / "vmware-fusion" / "scenarioforge-lab.conf.example"


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
    assert "debian-12-genericcloud-arm64.qcow2" in values_line
    assert "noble-server-cloudimg-arm64.img" in values_line
    assert values_line.endswith("|arm-debian12-64|nvme")

    generated = vmx.read_text(encoding="utf-8")
    for expected in (
        'virtualHW.version = "20"',
        'guestOS = "arm-debian12-64"',
        'firmware = "efi"',
        'nvme0.present = "TRUE"',
        'nvme0:0.fileName = "disk.vmdk"',
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
    assert "debian-12-genericcloud-amd64.qcow2" in values_line
    assert values_line.endswith("|debian12-64|scsi")
    generated = vmx.read_text(encoding="utf-8")
    assert 'scsi0:0.fileName = "disk.vmdk"' in generated
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


def test_fusion_contract_reuses_graphical_guest_provisioning() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    workstation = (
        ROOT / "scripts" / "vmware-workstation" / "install-scenarioforge-lab.sh"
    ).read_text(encoding="utf-8")
    shared = (
        ROOT / "scripts" / "proxmox" / "install-scenarioforge-lab.sh"
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
