from pathlib import Path
import base64
import subprocess

import yaml


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "proxmox" / "install-scenarioforge-lab.sh"


def test_installer_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", str(INSTALLER)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_installer_help_does_not_require_proxmox() -> None:
    result = subprocess.run(
        ["bash", str(INSTALLER), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "--dry-run" in result.stdout
    assert "--verbose" in result.stdout
    assert "--from-source" in result.stdout


def test_installer_preserves_required_network_separation_and_core_install_path() -> None:
    source = INSTALLER.read_text(encoding="utf-8")

    assert "sfmgmt0" in source
    assert "sfhitl0" in source
    assert "CORETG_VM_MODE_HITL_CORE_IFX_NAME=ens19" in source
    assert '--from-source "$CORE_REPO_URL" "$CORE_REPO_REF"' in source
    assert "grpcaddress = 0.0.0.0" in source
    assert '"bridge":"none","iptables":false' in source
    assert "/opt/core/custom_services" in source
    assert "this installer never overwrites VMs" in source
    assert "docker compose --env-file .scenarioforge.env up -d" in source
    assert "report_guest_activity CORE" in source
    assert "on_unexpected_error" in source


def test_generated_cloud_init_and_guest_scripts_are_valid(tmp_path: Path) -> None:
    render = f"""
source {INSTALLER!s}
WORK_DIR={tmp_path!s}
SSH_PUBLIC_KEY_FILE=
CORE_PASSWORD=core-password-for-test
APP_PASSWORD=app-password-for-test
PARTICIPANT_PASSWORD=participant-password-for-test
SCENARIOFORGE_ADMIN_PASSWORD=admin-password-for-test
CORE_NET0_MAC=02:00:00:00:00:10
CORE_NET1_MAC=02:00:00:00:00:11
CORE_NET2_MAC=02:00:00:00:00:12
APP_NET0_MAC=02:00:00:00:00:20
APP_NET1_MAC=02:00:00:00:00:21
PARTICIPANT_NET0_MAC=02:00:00:00:00:30
write_guest_bootstraps
write_cloud_init_files
"""
    result = subprocess.run(
        ["bash", "-c", render],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    for path in tmp_path.glob("*.yaml"):
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(payload, dict), path.name

    for user_data_name in ("core-user.yaml", "app-user.yaml"):
        payload = yaml.safe_load((tmp_path / user_data_name).read_text(encoding="utf-8"))
        written_files = {entry["path"]: entry for entry in payload["write_files"]}
        bootstrap = next(value for key, value in written_files.items() if key.startswith("/usr/local/sbin/"))
        decoded = base64.b64decode(bootstrap["content"])
        script_path = tmp_path / f"decoded-{user_data_name}.sh"
        script_path.write_bytes(decoded)
        syntax = subprocess.run(
            ["bash", "-n", str(script_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert syntax.returncode == 0, syntax.stderr
