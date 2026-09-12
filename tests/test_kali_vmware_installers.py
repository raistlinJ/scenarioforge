"""Exercise Kali selection across the shared VMware shell installers."""
import os
from pathlib import Path
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = [
    ("vmware-workstation-linux", "x86_64", "amd64"),
    ("vmware-fusion-mac", "x86_64", "amd64"),
    ("vmware-fusion-mac", "arm64", "arm64"),
]


def shell(platform, host_arch, body):
    installer = ROOT / "scripts/provision" / platform / "install-scenarioforge-lab.sh"
    env = {key: value for key, value in os.environ.items() if not key.startswith("SF_")}
    return subprocess.run(
        ["bash", "-c", f"""
uname() {{
  case "$1" in
    -m) printf '%s\n' {host_arch} ;;
    *) command uname "$@" ;;
  esac
}}
source {shlex.quote(str(installer))}
{body}
"""], env=env, capture_output=True, text=True,
    )


@pytest.mark.parametrize("platform,host_arch,guest_arch", PLATFORMS)
def test_kali_config_architecture_and_resource_defaults(tmp_path, platform, host_arch, guest_arch):
    config = tmp_path / "lab.conf"
    config.write_text("participant_os=kali\n")
    result = shell(platform, host_arch, f"""
parse_args install --config {shlex.quote(str(config))}
printf 'VALUES|%s|%s|%s|%s\n' "$PARTICIPANT_OS" "$PARTICIPANT_MEMORY_MB" "$PARTICIPANT_DISK_GB" "$KALI_IMAGE_URL"
""")
    assert result.returncode == 0, result.stderr
    line = next(line for line in result.stdout.splitlines() if line.startswith("VALUES|"))
    assert line.startswith("VALUES|kali|2048|40|")
    assert line.endswith(f"genericcloud-{guest_arch}.tar.xz")


@pytest.mark.parametrize("platform,host_arch,guest_arch", PLATFORMS)
def test_kali_vm_creation_keeps_other_guests_and_isolation(tmp_path, platform, host_arch, guest_arch):
    result = shell(platform, host_arch, f"""
parse_args install --participant-os kali --lab-dir {shlex.quote(str(tmp_path))}
PARTICIPANT_IMAGE=/images/kali.raw
CORE_NET0_MAC=00:50:56:00:00:10
CORE_NET1_MAC=00:50:56:00:00:11
CORE_NET2_MAC=00:50:56:00:00:12
APP_NET0_MAC=00:50:56:00:00:20
APP_NET1_MAC=00:50:56:00:00:21
PARTICIPANT_NET0_MAC=00:50:56:00:00:30
PARTICIPANT_NET1_MAC=00:50:56:00:00:31
prepare_disk() {{ printf 'DISK|%s|%s|%s\n' "$1" "$3" "${{4:-qcow2}}"; }}
create_seed_iso() {{ :; }}
append_guestinfo_cloud_init() {{ :; }}
create_vms
""")
    assert result.returncode == 0, result.stderr
    disks = [line for line in result.stdout.splitlines() if line.startswith("DISK|")]
    assert len(disks) == 3
    assert disks[0].endswith("|80|qcow2")
    assert f"debian-12-generic-{guest_arch}.qcow2" in disks[0]
    assert disks[1].endswith("|40|qcow2")
    assert disks[2] == "DISK|/images/kali.raw|40|raw"
    participant = next(tmp_path.rglob("scenarioforge-participant.vmx")).read_text()
    core = next(tmp_path.rglob("scenarioforge-core.vmx")).read_text()
    assert 'memsize = "2048"' in participant
    assert 'nvme0.present = "TRUE"' in participant
    assert 'scsi0.present' not in participant
    assert 'ethernet0.vnet = "vmnet2"' in participant
    assert 'ethernet1.connectionType = "nat"' in participant
    assert ('nvme0.present' if host_arch == "arm64" else 'scsi0.present') in core


@pytest.mark.parametrize("platform,host_arch,guest_arch", PLATFORMS)
def test_kali_cli_precedence_and_invalid_value(tmp_path, platform, host_arch, guest_arch):
    config = tmp_path / "lab.conf"
    config.write_text("participant_os=kali\n")
    result = shell(platform, host_arch, f"""
parse_args install --config {shlex.quote(str(config))} --participant-os debian
printf 'VALUES|%s|%s|%s\n' "$PARTICIPANT_OS" "$PARTICIPANT_MEMORY_MB" "$PARTICIPANT_DISK_GB"
""")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == "VALUES|debian|2048|20"
    result = shell(platform, host_arch, "parse_args install --participant-os invalid")
    assert result.returncode != 0
    assert "--participant-os must be debian or kali" in result.stderr


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
def test_vmware_kernel_reboot_and_loop_guard(tmp_path, architecture):
    shared = (ROOT / "scripts/provision/proxmox/install-scenarioforge-lab.sh").read_text()
    block = shared.split('if [[ "$ID" == kali ]] && systemd-detect-virt', 1)[1]
    block = 'if [[ "$ID" == kali ]] && systemd-detect-virt' + block.split(
        "set_bootstrap_status 85", 1
    )[0]
    # Run the real control flow against temporary paths and mocked guest commands.
    for path in ("/etc", "/boot", "/var/lib"):
        block = block.replace(path, str(tmp_path) + path)
    boot = tmp_path / "boot"
    boot.mkdir()
    (boot / f"vmlinuz-7.0.10+kali-{architecture}").touch()
    state = tmp_path / "var/lib/scenarioforge"
    state.mkdir(parents=True)
    (tmp_path / "etc/systemd/system").mkdir(parents=True)
    log = tmp_path / "commands"
    prefix = f"""
set -eu
ID=kali
systemd-detect-virt() {{ if [[ "$*" != *--quiet* ]]; then echo vmware; fi; }}
dpkg() {{ printf '%s\n' {architecture}; }}
apt-get() {{ printf 'APT %s\n' "$*" >> {shlex.quote(str(log))}; }}
systemctl() {{ printf 'SYSTEMCTL %s\n' "$*" >> {shlex.quote(str(log))}; }}
systemd-run() {{ printf 'REBOOT %s\n' "$*" >> {shlex.quote(str(log))}; }}
update-grub() {{ :; }}
set_bootstrap_status() {{ :; }}
fail_bootstrap() {{ printf '%s\n' "$*" >&2; exit 1; }}
"""
    cloud_kernel = f"uname() {{ echo '7.0.10+kali-cloud-{architecture}'; }}\n"
    full_kernel = f"uname() {{ echo '7.0.10+kali-{architecture}'; }}\n"
    result = subprocess.run(["bash", "-c", prefix + cloud_kernel + block],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (state / "participant-kernel-reboot").exists()
    assert not (state / "participant-ready").exists()
    commands = log.read_text()
    assert f"APT install -y linux-image-{architecture}" in commands
    assert "enable scenarioforge-participant-bootstrap.service" in commands
    unit = (tmp_path / "etc/systemd/system/scenarioforge-participant-bootstrap.service").read_text()
    assert "After=network-online.target\n" in unit
    # cloud-final runs after multi-user.target. Making this oneshot a
    # prerequisite of multi-user.target creates a cycle and skips recovery.
    assert "cloud-final.service" not in unit
    assert "WantedBy=multi-user.target" in unit
    assert "REBOOT --unit=scenarioforge-participant-reboot" in commands
    assert str(boot / f"vmlinuz-7.0.10+kali-{architecture}") in (
        tmp_path / "etc/default/grub.d/99-scenarioforge-kernel.cfg"
    ).read_text()
    result = subprocess.run(["bash", "-c", prefix + cloud_kernel + block],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "did not boot the full kernel" in result.stderr
    result = subprocess.run(["bash", "-c", prefix + full_kernel + block + "echo desktop-next"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "desktop-next"
    assert log.read_text() == commands
