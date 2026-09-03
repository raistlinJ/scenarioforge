from pathlib import Path
import base64
import shlex
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
    assert "--watch" in result.stdout
    assert "--from-source" in result.stdout
    assert "cleanup [--dry-run] [--force] [--yes]" in result.stdout
    assert "--cleanup" in result.stdout


def test_installer_preserves_required_network_separation_and_core_install_path() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    install_body = source.split("perform_install() {", maxsplit=1)[1]

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
    assert "guest_progress_text" in source
    assert "set_bootstrap_status 'installing system packages and building CORE from source'" in source
    assert "set_bootstrap_status 'building ScenarioForge and nginx container images'" in source
    assert 'shell_assignment INSTALL_PHASE' in source
    assert 'printf \'  Host installer:' in source
    assert install_body.index("write_state") < install_body.index("download_verified_image")


def test_status_watch_waits_for_fresh_install_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    probe = f"""
SCENARIOFORGE_LAB_STATE_DIR={shlex.quote(str(state_dir))}
source {shlex.quote(str(INSTALLER))}
STATUS_INTERVAL=0.05
show_status() {{ printf 'status-observed\\n'; }}
guest_marker_exists() {{ return 0; }}
(sleep 0.1; touch "$STATE_FILE") &
watch_status
"""
    result = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Waiting for installer state" in result.stdout
    assert "check the install shell's preflight output" in result.stdout
    assert "Installer state detected" in result.stdout
    assert "status-observed" in result.stdout


def test_storage_probe_uses_proxmox_api_json() -> None:
    probe = f"""
source {INSTALLER!s}
pvesh() {{
    case "$2" in
        /storage/local-lvm)
            printf '%s\\n' '{{"storage":"local-lvm","type":"lvmthin","content":"rootdir,images"}}'
            ;;
        /storage/local)
            printf '%s\\n' '{{"storage":"local","type":"dir","content":"iso,vztmpl,backup","path":"/var/lib/vz"}}'
            ;;
        *) return 1 ;;
    esac
}}
vm_config="$(storage_config local-lvm)"
snippet_config="$(storage_config local)"
storage_has_content "$vm_config" images
[[ "$(storage_field "$vm_config" type)" == lvmthin ]]
[[ "$(storage_field "$snippet_config" type)" == dir ]]
[[ "$(storage_field "$snippet_config" path)" == /var/lib/vz ]]
"""
    result = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_cleanup_is_identity_scoped_and_protects_a_healthy_lab() -> None:
    source = INSTALLER.read_text(encoding="utf-8")

    assert 'Type CLEANUP to permanently remove the resources listed above' in source
    assert 'rerun cleanup with --force to remove it' in source
    assert 'vm_owned_by_installer "$vmid" "$expected_name" "$snippet_name"' in source
    assert 'qm shutdown "$vmid" --timeout 60' in source
    assert 'qm destroy "$vmid" --purge 1 --destroy-unreferenced-disks 1' in source
    assert 'command -v pct' in source
    assert 'preserving installer-created bridge' in source
    assert 'cached base images were preserved for reuse' in source


def test_cleanup_dry_run_preserves_a_recorded_vmid_with_wrong_identity(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    snippet_dir = tmp_path / "snippets"
    state_dir.mkdir()
    snippet_dir.mkdir()
    state_file = state_dir / "state.env"
    state_file.write_text(
        """\
PVE_NODE=testnode
SNIPPET_STORAGE=local
MANAGEMENT_BRIDGE=sfmgmt0
HITL_BRIDGE=sfhitl0
CREATED_MANAGEMENT_BRIDGE=1
CREATED_HITL_BRIDGE=1
CORE_VMID=9401
APP_VMID=9402
PARTICIPANT_VMID=9403
CORE_NAME=scenarioforge-core
APP_NAME=scenarioforge-app
PARTICIPANT_NAME=scenarioforge-participant
INSTALL_COMPLETE=0
""",
        encoding="utf-8",
    )
    state_file.chmod(0o600)
    (snippet_dir / "scenarioforge-core-user.yaml").touch()

    probe = f"""
SCENARIOFORGE_LAB_STATE_DIR={shlex.quote(str(state_dir))}
source {shlex.quote(str(INSTALLER))}
PVE_NODE=testnode
DRY_RUN=1
ASSUME_YES=1
qm() {{
    case "$1" in
        status) printf 'status: running\\n' ;;
        config)
            case "$2" in
                9401) printf 'name: scenarioforge-core\\n' ;;
                9402) printf 'name: unrelated-reused-vmid\\n' ;;
                9403) printf 'name: scenarioforge-participant\\n' ;;
            esac
            ;;
        guest) return 1 ;;
        list)
            printf ' VMID NAME\\n9401 scenarioforge-core\\n9402 unrelated\\n9403 scenarioforge-participant\\n'
            ;;
    esac
}}
pvesh() {{
    case "$2" in
        /storage/local)
            printf '%s\\n' {shlex.quote('{"type":"dir","path":"' + str(tmp_path) + '"}')}
            ;;
        /nodes/testnode/network/sfmgmt0)
            printf '%s\\n' '{{"type":"bridge","comments":"ScenarioForge isolated CORE management"}}'
            ;;
        /nodes/testnode/network/sfhitl0)
            printf '%s\\n' '{{"type":"bridge","comments":"ScenarioForge isolated participant HITL"}}'
            ;;
        *) return 1 ;;
    esac
}}
perform_cleanup
"""
    result = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "qm destroy 9401" in result.stdout
    assert "qm destroy 9403" in result.stdout
    assert "qm destroy 9402" not in result.stdout
    assert "preserving VMID 9402" in result.stderr
    assert "pvesh delete /nodes/testnode/network/sfmgmt0" in result.stdout
    assert "scenarioforge-core-user.yaml" in result.stdout


def test_cleanup_requires_force_for_a_complete_running_lab() -> None:
    probe = f"""
source {shlex.quote(str(INSTALLER))}
PVE_NODE=testnode
DRY_RUN=1
CLEANUP_VMIDS=(9401 9402 9403)
CLEANUP_LABELS=(CORE APP PARTICIPANT)
INSTALL_COMPLETE=1
qm() {{ printf 'status: running\\n'; }}
confirm_cleanup
"""
    result = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "rerun cleanup with --force" in result.stderr


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
