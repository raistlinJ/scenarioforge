from pathlib import Path
import re
import shlex
import subprocess

import yaml


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = (
    ROOT / "scripts" / "vmware-workstation" / "install-scenarioforge-lab.sh"
)
README = ROOT / "scripts" / "vmware-workstation" / "README.md"
CONFIG_EXAMPLE = (
    ROOT / "scripts" / "vmware-workstation" / "scenarioforge-lab.conf.example"
)


def run_bash(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )


def test_installer_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", str(INSTALLER)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_help_does_not_require_linux_or_vmware() -> None:
    result = subprocess.run(
        ["bash", str(INSTALLER), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    for expected in (
        "VMware Workstation",
        "--from-source",
        "--management-vmnet",
        "--hitl-vmnet",
        "--headless",
        "--flag-generators",
        "--vulnhub",
        "--core-password",
        "--app-password",
        "--participant-password",
        "--web-admin-password",
        "--config FILE",
        "--verbose",
        "--watch",
        "--cleanup",
        "cleanup [--dry-run] [--force] [--yes]",
    ):
        assert expected in result.stdout


def test_password_override_flags_preserve_exact_values() -> None:
    values = ("core one", "app two", "participant three", "web four")
    probe = f"""
source {shlex.quote(str(INSTALLER))}
parse_args install \
  --core-password {shlex.quote(values[0])} \
  --app-password {shlex.quote(values[1])} \
  --participant-password {shlex.quote(values[2])} \
  --web-admin-password {shlex.quote(values[3])}
printf '%s\n' "$REQUESTED_CORE_PASSWORD" "$REQUESTED_APP_PASSWORD" \
  "$REQUESTED_PARTICIPANT_PASSWORD" "$REQUESTED_WEB_ADMIN_PASSWORD"
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == list(values)


def test_config_file_is_safe_and_lower_precedence_than_environment_and_cli(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lab.conf"
    side_effect_path = tmp_path / "must-not-exist"
    config_path.write_text(
        "\n".join(
            [
                f'lab_dir="{tmp_path / "config lab"}"',
                "management_vmnet=vmnet4",
                "hitl_vmnet=vmnet5",
                'core_password="config value # with = sign"',
                f"app_password=$(touch {side_effect_path})",
                "vulnhub=on",
                "headless=true",
                "no_wait=yes",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    cli_lab = tmp_path / "cli-lab"
    probe = f"""
export SF_VMWARE_MANAGEMENT_VMNET=vmnet8
source {shlex.quote(str(INSTALLER))}
parse_args install --config={shlex.quote(str(config_path))} --lab-dir {shlex.quote(str(cli_lab))}
printf 'VALUES|%s|%s|%s|%s|%s|%s|%s|%s\n' \
  "$LAB_DIR" "$MANAGEMENT_VMNET" "$HITL_VMNET" "$REQUESTED_CORE_PASSWORD" \
  "$REQUESTED_APP_PASSWORD" "$INSTALL_VULNHUB" "$HEADLESS" "$WAIT_FOR_BOOTSTRAP"
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    values_line = next(line for line in result.stdout.splitlines() if line.startswith("VALUES|"))
    assert values_line.split("|")[1:] == [
        str(cli_lab),
        "vmnet8",
        "vmnet5",
        "config value # with = sign",
        f"$(touch {side_effect_path})",
        "1",
        "1",
        "0",
    ]
    assert not side_effect_path.exists()


def test_example_config_parses_successfully() -> None:
    probe = f"""
source {shlex.quote(str(INSTALLER))}
parse_args install --config {shlex.quote(str(CONFIG_EXAMPLE))}
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr


def test_topology_native_app_and_graphical_guest_contracts() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    shared = (ROOT / "scripts" / "proxmox" / "install-scenarioforge-lab.sh").read_text(
        encoding="utf-8"
    )

    assert 'MANAGEMENT_VMNET="${SF_VMWARE_MANAGEMENT_VMNET:-vmnet1}"' in source
    assert 'HITL_VMNET="${SF_VMWARE_HITL_VMNET:-vmnet2}"' in source
    assert 'append_nic "$CORE_VMX" 0 custom "$MANAGEMENT_VMNET"' in source
    assert 'append_nic "$CORE_VMX" 1 custom "$HITL_VMNET"' in source
    assert 'append_nic "$CORE_VMX" 2 nat' in source
    assert 'append_nic "$APP_VMX" 0 nat' in source
    assert 'append_nic "$APP_VMX" 1 custom "$MANAGEMENT_VMNET"' in source
    assert 'append_nic "$PARTICIPANT_VMX" 0 custom "$HITL_VMNET"' in source
    assert 'append_nic "$PARTICIPANT_VMX" 1 nat' in source
    assert 'deleteNetworkAdapter "$PARTICIPANT_VMX" 1' in source
    assert 'scenarioforge.install.owner = "$INSTALLER_OWNER"' in source
    assert "open-vm-tools, open-vm-tools-desktop" in source
    assert "transfer_optional_content_to_app" in source

    assert '--from-source "$CORE_REPO_URL" "$CORE_REPO_REF"' in shared
    assert "CORETG_VM_MODE_HITL_CORE_IFX_NAME=ens19" in shared
    assert "ExecStart=/opt/scenarioforge/.venv/bin/python -m webapp.app_backend" in shared
    assert "systemctl enable --now lightdm" in shared
    assert "command -v core-gui" in shared
    assert "epiphany-browser" in shared
    assert "Exec=epiphany https://localhost/" in shared
    assert "_install_generator_pack_or_bundle" in shared
    assert "/opt/scenarioforge/outputs/installed_generators" in shared
    assert "_install_vuln_catalog_zip_file" in shared
    assert "docker compose --env-file .scenarioforge.env up -d" not in shared


def test_vmx_generator_emits_safe_owner_hardware_and_networks(tmp_path: Path) -> None:
    vmx = tmp_path / "test.vmx"
    disk = tmp_path / "test.vmdk"
    seed = tmp_path / "seed.iso"
    probe = f"""
source {shlex.quote(str(INSTALLER))}
create_vmx {shlex.quote(str(vmx))} test-vm debian12-64 2048 2 \
    {shlex.quote(str(disk))} {shlex.quote(str(seed))}
append_nic {shlex.quote(str(vmx))} 0 custom vmnet1 00:50:56:01:02:03
append_nic {shlex.quote(str(vmx))} 1 nat '' 00:50:56:04:05:06
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    generated = vmx.read_text(encoding="utf-8")
    for expected in (
        'virtualHW.version = "20"',
        'firmware = "efi"',
        'guestOS = "debian12-64"',
        'scenarioforge.install.owner = "scenarioforge-vmware-linux-v1"',
        'ethernet0.connectionType = "custom"',
        'ethernet0.vnet = "vmnet1"',
        'ethernet1.connectionType = "nat"',
    ):
        assert expected in generated


def test_vmware_mac_generator_uses_reserved_manual_range() -> None:
    result = run_bash(
        f"source {shlex.quote(str(INSTALLER))}; for _ in 1 2 3 4 5; do random_vmware_mac; done"
    )
    assert result.returncode == 0, result.stderr
    for mac in result.stdout.splitlines():
        assert re.fullmatch(r"00:50:56:[0-3][0-9a-f]:[0-9a-f]{2}:[0-9a-f]{2}", mac)


def test_cloud_init_adapter_replaces_qemu_agent_with_vmware_tools(
    tmp_path: Path,
) -> None:
    probe = f"""
source {shlex.quote(str(INSTALLER))}
WORK_DIR={shlex.quote(str(tmp_path))}
CORE_PASSWORD=core-secret
APP_PASSWORD=app-secret
PARTICIPANT_PASSWORD=participant-secret
SCENARIOFORGE_ADMIN_PASSWORD=web-secret
CORE_NET0_MAC=00:50:56:01:00:01
CORE_NET1_MAC=00:50:56:01:00:02
CORE_NET2_MAC=00:50:56:01:00:03
APP_NET0_MAC=00:50:56:02:00:01
APP_NET1_MAC=00:50:56:02:00:02
PARTICIPANT_NET0_MAC=00:50:56:03:00:01
PARTICIPANT_NET1_MAC=00:50:56:03:00:02
write_vmware_cloud_init_files
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    for role in ("core", "app", "participant"):
        cloud_config = (tmp_path / f"{role}-user.yaml").read_text(encoding="utf-8")
        assert "qemu-guest-agent" not in cloud_config
        assert "open-vm-tools" in cloud_config
        assert "open-vm-tools-desktop" in cloud_config
        assert "open-vm-tools.service" in cloud_config
        parsed = yaml.safe_load(cloud_config)
        assert "open-vm-tools" in parsed["packages"]
        assert "open-vm-tools-desktop" in parsed["packages"]


def test_host_network_table_parsing_and_hitl_dhcp_guard() -> None:
    vmrun_output = """\
Total host networks: 3
INDEX  NAME         TYPE         DHCP         SUBNET           MASK
0      vmnet0       bridged      false        empty            empty
1      vmnet1       hostOnly     true         192.168.10.0     255.255.255.0
2      vmnet2       hostOnly     false        10.254.200.0     255.255.255.0
"""
    probe = f"""
source {shlex.quote(str(INSTALLER))}
vmrun() {{ printf '%s' {shlex.quote(vmrun_output)}; }}
host_network_exists vmnet2
HITL_VMNET=vmnet2
validate_hitl_isolation
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr

    unsafe_output = vmrun_output.replace(
        "vmnet2       hostOnly     false", "vmnet2       hostOnly     true "
    )
    probe = f"""
source {shlex.quote(str(INSTALLER))}
vmrun() {{ printf '%s' {shlex.quote(unsafe_output)}; }}
HITL_VMNET=vmnet2
validate_hitl_isolation
"""
    result = run_bash(probe)
    assert result.returncode != 0
    assert "has DHCP enabled" in result.stderr


def test_progress_credentials_and_cleanup_guards_are_present() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    root_readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for expected in (
        "Guest bootstrap (elapsed $elapsed): CORE=${cp}% APP=${ap}% PARTICIPANT=${pp}%",
        "ScenarioForge VMware lab installation complete",
        "CORE VM:",
        "APP VM:",
        "PARTICIPANT VM:",
        "Stored securely:",
        "vmx_owned",
        "safe_vm_dir",
        "cleanup --force",
    ):
        assert expected in source
    assert "Virtual Network Editor" in readme
    assert "VMware Workstation Linux three-VM installer" in root_readme


def test_dry_run_reaches_completion_without_creating_vm_files(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    lab_dir = tmp_path / "lab"
    runtime = tmp_path / "runtime.status"
    probe = f"""
SCENARIOFORGE_VMWARE_STATE_DIR={shlex.quote(str(state_dir))}
SCENARIOFORGE_VMWARE_RUNTIME_STATUS_FILE={shlex.quote(str(runtime))}
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


def test_initial_progress_never_rewrites_a_preexisting_lab_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_file = state_dir / "state.env"
    state_file.write_text("EXISTING_STATE=preserve-me\n", encoding="utf-8")
    probe = f"""
SCENARIOFORGE_VMWARE_STATE_DIR={shlex.quote(str(state_dir))}
source {shlex.quote(str(INSTALLER))}
RUNTIME_TRACKING=0
progress 2 'Validating VMware Workstation'
"""
    result = run_bash(probe)
    assert result.returncode == 0, result.stderr
    assert state_file.read_text(encoding="utf-8") == "EXISTING_STATE=preserve-me\n"
