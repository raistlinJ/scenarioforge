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
    assert "--flag-generators" in result.stdout
    assert "--vulnhub" in result.stdout
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
    assert "ExecStart=/opt/scenarioforge/.venv/bin/python -m webapp.app_backend" in source
    assert "systemctl enable scenarioforge-web nginx" in source
    assert "systemctl restart nginx" in source
    assert "systemctl start scenarioforge-web" in source
    assert "proxy_pass http://127.0.0.1:9090" in source
    assert "docker compose --env-file .scenarioforge.env up -d" not in source
    assert "command -v core-gui" in source
    assert "systemctl enable --now lightdm" in source
    assert "--serial0 socket --vga std" in source
    assert "/var/lib/scenarioforge/participant-ready" in source
    assert 'qm set "$PARTICIPANT_VMID" --delete net1' in source
    assert "report_guest_activity CORE" in source
    assert "report_guest_activity PARTICIPANT" in source
    assert "on_unexpected_error" in source
    assert "guest_progress_text" in source
    assert "set_bootstrap_status 10 'installing system packages and building CORE from source'" in source
    assert "set_bootstrap_status 30 'creating the native ScenarioForge Python environment'" in source
    assert "set_bootstrap_status 25 'installing the minimal XFCE desktop'" in source
    assert 'set_bootstrap_status "$percent" "failed (exit $exit_code at bootstrap line $line: $command)"' in source
    assert 'trap \'on_bootstrap_error "$?" "$LINENO" "$BASH_COMMAND"\' ERR' in source
    assert "xserver-xorg-input-all xserver-xorg-video-all" in source
    assert "restarting and verifying the CORE XFCE graphical login" in source
    assert "verifying the APP XFCE graphical login" in source
    assert "APP XFCE graphical login did not become active" in source
    assert "participant XFCE graphical login did not become active" in source
    assert "journalctl -u lightdm -n 100 --no-pager" in source
    assert "Permit status/watch to recognize a manually completed recovery" in source
    assert "epiphany-browser" in source
    assert "Exec=epiphany https://localhost/" in source
    assert "prepare_optional_content" in source
    assert "transfer_optional_content_to_app" in source
    assert "INSTALL_FLAG_GENERATORS" in source
    assert "INSTALL_VULNHUB" in source
    assert "_install_vuln_catalog_zip_file" in source
    assert "PYTHONPATH=/opt/scenarioforge" in source
    assert "do not embed credentials in SF_FLAG_GENERATORS_URL" in source
    assert "/var/lib/scenarioforge/bootstrap-percent" in source
    assert "Guest bootstrap heartbeat (elapsed $elapsed)" in source
    assert "Install progress:" in source
    assert "show_completion_credentials" in source
    assert "Credentials were shown above and saved at" in source
    assert 'bootstrap="in-progress"' in source
    assert 'agent="optional"' in source
    assert "for attempt in $(seq 1 60)" in source
    assert "journalctl -u core-daemon -n 100 --no-pager" in source
    assert 'waiting for core-daemon gRPC on 0.0.0.0:50051' in source
    assert "timeout 2 bash -c '</dev/tcp/'\"$CORE_MANAGEMENT_IP\"'/50051'" in source
    assert "guest_bootstrap_failure_text" in source
    assert "cloud-final failed while bootstrap phase was" in source
    assert 'shell_assignment INSTALL_PHASE' in source
    assert 'printf \'  Host installer:' in source
    assert install_body.index("write_state") < install_body.index("download_verified_image")


def test_progress_output_and_parallel_guest_weighting() -> None:
    probe = f"""
source {shlex.quote(str(INSTALLER))}
COMMAND=status
CURRENT_STEP=0
TOTAL_STEPS=8
progress 18 'Downloading images'
INSTALL_PERCENT=55
INSTALL_COMPLETE=0
CORE_VMID=9401
APP_VMID=9402
PARTICIPANT_VMID=9403
guest_marker_exists() {{ return 1; }}
guest_command_output() {{
    case "$1" in
        9401) printf '10\\n' ;;
        9402) printf '35\\n' ;;
        9403) printf '55\\n' ;;
    esac
}}
printf 'combined=%s\\n' "$(current_install_percent)"
"""
    result = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "PROGRESS [ 18%] [1/8] Downloading images" in result.stdout
    assert "combined=69" in result.stdout


def test_initial_progress_does_not_rewrite_existing_lab_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_file = state_dir / "state.env"
    state_file.write_text("EXISTING_LAB_STATE=preserve-me\n", encoding="utf-8")
    probe = f"""
SCENARIOFORGE_LAB_STATE_DIR={shlex.quote(str(state_dir))}
source {shlex.quote(str(INSTALLER))}
COMMAND=install
DRY_RUN=0
RUNTIME_TRACKING=0
progress 2 'Validating Proxmox'
"""
    result = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert state_file.read_text(encoding="utf-8") == "EXISTING_LAB_STATE=preserve-me\n"


def test_completion_prints_every_generated_credential_and_storage_path(tmp_path: Path) -> None:
    credentials_file = tmp_path / "credentials.env"
    probe = f"""
source {shlex.quote(str(INSTALLER))}
CREDENTIALS_FILE={shlex.quote(str(credentials_file))}
CORE_VMID=9401
APP_VMID=9402
PARTICIPANT_VMID=9403
CORE_MANAGEMENT_CIDR=172.31.250.3/24
PARTICIPANT_CIDR=10.254.200.10/24
CORE_PASSWORD=core-secret
APP_PASSWORD=app-secret
PARTICIPANT_PASSWORD=participant-secret
SCENARIOFORGE_ADMIN_PASSWORD=web-secret
app_uplink_ip() {{ printf '192.0.2.25\\n'; }}
show_completion_credentials
"""
    result = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    for expected in (
        "CORE VM",
        "corevm",
        "core-secret",
        "APP VM",
        "scenarioforge",
        "app-secret",
        "PARTICIPANT VM",
        "participant-secret",
        "WEB ADMIN",
        "web-secret",
        "https://192.0.2.25/",
        "Proxmox Console/noVNC",
        "scenarioforge-web and nginx",
        str(credentials_file),
        "root-only, mode 0600",
    ):
        assert expected in result.stdout


def test_guest_cloud_init_failure_is_reported_from_a_stale_phase() -> None:
    probe = f"""
source {shlex.quote(str(INSTALLER))}
guest_command_output() {{
    shift
    case "$*" in
        'cat /var/lib/scenarioforge/bootstrap-status')
            printf '%s\\n' 'waiting for core-daemon gRPC on 0.0.0.0:50051'
            ;;
        'systemctl show cloud-final --property ActiveState --value')
            printf '%s\\n' failed
            ;;
    esac
}}
guest_bootstrap_failure_text 9401
"""
    result = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "cloud-final failed while bootstrap phase was" in result.stdout
    assert "waiting for core-daemon gRPC" in result.stdout


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
    assert "No active install status found" in result.stdout
    assert "Installer state detected" in result.stdout
    assert "status-observed" in result.stdout


def test_status_watch_surfaces_prestate_installer_failure(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    runtime_status = tmp_path / "install.status"
    state_dir.mkdir()
    runtime_status.write_text(
        """\
RUNTIME_PID=99999999
RUNTIME_STATE=failed
RUNTIME_PHASE=Installer\\ stopped
RUNTIME_DETAIL=storage\\ preflight\\ failed
RUNTIME_UPDATED=now
""",
        encoding="utf-8",
    )
    runtime_status.chmod(0o600)
    probe = f"""
SCENARIOFORGE_LAB_STATE_DIR={shlex.quote(str(state_dir))}
SCENARIOFORGE_LAB_RUNTIME_STATUS_FILE={shlex.quote(str(runtime_status))}
source {shlex.quote(str(INSTALLER))}
STATUS_INTERVAL=0.05
watch_status
"""
    result = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Host installer failed" in result.stdout
    assert "Installer error: storage preflight failed" in result.stderr


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
    assert "validate_network_reload" in source
    assert "Proxmox rejected the network reload" in source
    assert "preflight_cleanup_network" in source
    assert "sanitize_host_environment" in source
    assert 'PATH="/usr/sbin:/usr/bin:/sbin:/bin"' in source
    assert "unset PYTHONHOME PYTHONPATH" in source
    assert 'cached base images were preserved for reuse' in source


def test_network_apply_surfaces_captured_proxmox_errors(tmp_path: Path) -> None:
    probe = f"""
source {shlex.quote(str(INSTALLER))}
PVE_NODE=testnode
NETWORK_CHANGES=1
pvesh() {{
    printf '%s\\n' "proxy handler failed: incompatible ifupdown2 package"
    printf '%s\\n' "info: executing ifreload -V" >&2
    return 1
}}
apply_network_changes
"""
    result = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "proxy handler failed: incompatible ifupdown2 package" in result.stderr
    assert "info: executing ifreload -V" in result.stderr
    assert "staged changes remain unapplied" in result.stderr


def test_cleanup_bridge_absence_is_success() -> None:
    probe = f"""
source {shlex.quote(str(INSTALLER))}
DRY_RUN=0
CLEANUP_BRIDGES=(sfmgmt0 sfhitl0)
bridge_in_use_after_cleanup() {{ return 1; }}
run() {{ return 0; }}
apply_network_changes() {{ return 0; }}
ip() {{ return 1; }}
remove_cleanup_bridges
"""
    result = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


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
ifreload() {{ printf '%s\n' 'ifupdown2:3.2.0-1+pmx1'; }}
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
    user_key = tmp_path / "user.pub"
    transfer_key = tmp_path / "transfer.pub"
    user_key.write_text("ssh-ed25519 AAAAuser operator\n", encoding="utf-8")
    transfer_key.write_text(
        "ssh-ed25519 AAAAtransfer scenarioforge-installer-transfer\n",
        encoding="utf-8",
    )
    render = f"""
source {INSTALLER!s}
WORK_DIR={tmp_path!s}
SSH_PUBLIC_KEY_FILE={shlex.quote(str(user_key))}
CATALOG_TRANSFER_PUBLIC_KEY_FILE={shlex.quote(str(transfer_key))}
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
PARTICIPANT_NET1_MAC=02:00:00:00:00:31
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

    core_user = yaml.safe_load((tmp_path / "core-user.yaml").read_text(encoding="utf-8"))
    app_user = yaml.safe_load((tmp_path / "app-user.yaml").read_text(encoding="utf-8"))
    participant_user = yaml.safe_load(
        (tmp_path / "participant-user.yaml").read_text(encoding="utf-8")
    )
    assert core_user["users"][0]["ssh_authorized_keys"] == ["ssh-ed25519 AAAAuser operator"]
    assert participant_user["users"][0]["ssh_authorized_keys"] == [
        "ssh-ed25519 AAAAuser operator"
    ]
    assert app_user["users"][0]["ssh_authorized_keys"] == [
        "ssh-ed25519 AAAAuser operator",
        "ssh-ed25519 AAAAtransfer scenarioforge-installer-transfer",
    ]

    for path in tmp_path.glob("*.yaml"):
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(payload, dict), path.name

    for user_data_name in ("core-user.yaml", "app-user.yaml", "participant-user.yaml"):
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

    app_script = (tmp_path / "app-bootstrap.sh").read_text(encoding="utf-8")
    for start, end in (
        ("<<'VULNHUB_ZIP'\n", "\nVULNHUB_ZIP"),
        ("<<'VULNHUB_INSTALL'\n", "\nVULNHUB_INSTALL"),
    ):
        python_source = app_script.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]
        compile(python_source, "app-bootstrap-heredoc", "exec")


def test_optional_catalog_payload_contains_only_requested_content(tmp_path: Path) -> None:
    source_repo = tmp_path / "source"
    work_dir = tmp_path / "work"
    for relative in (
        "flag_generators/demo/manifest.yaml",
        "flag_node_generators/demo/manifest.yaml",
        "vulnhub/content/demo/docker-compose.yml",
    ):
        path = source_repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("test: true\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main", str(source_repo)], check=True)
    subprocess.run(["git", "-C", str(source_repo), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source_repo),
            "-c",
            "user.name=ScenarioForge Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    work_dir.mkdir()
    probe = f"""
source {shlex.quote(str(INSTALLER))}
WORK_DIR={shlex.quote(str(work_dir))}
FLAG_GENERATORS_URL={shlex.quote(str(source_repo))}
FLAG_GENERATORS_REF=main
INSTALL_FLAG_GENERATORS=1
INSTALL_VULNHUB=0
prepare_optional_content
"""
    result = subprocess.run(
        ["bash", "-c", probe], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    archive = work_dir / "scenarioforge-optional-content.tar.gz"
    assert archive.is_file()
    listing = subprocess.run(
        ["tar", "-tzf", str(archive)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "flag_generators/demo/manifest.yaml" in listing
    assert "flag_node_generators/demo/manifest.yaml" in listing
    assert "vulnhub/" not in listing
    assert (work_dir / "catalog-transfer-key").is_file()
    assert (work_dir / "catalog-transfer-key.pub").is_file()

    vulnhub_work_dir = tmp_path / "work-vulnhub"
    vulnhub_work_dir.mkdir()
    vulnhub_probe = f"""
source {shlex.quote(str(INSTALLER))}
WORK_DIR={shlex.quote(str(vulnhub_work_dir))}
FLAG_GENERATORS_URL={shlex.quote(str(source_repo))}
FLAG_GENERATORS_REF=main
INSTALL_FLAG_GENERATORS=0
INSTALL_VULNHUB=1
prepare_optional_content
"""
    result = subprocess.run(
        ["bash", "-c", vulnhub_probe],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    vulnhub_listing = subprocess.run(
        ["tar", "-tzf", str(vulnhub_work_dir / "scenarioforge-optional-content.tar.gz")],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "vulnhub/content/demo/docker-compose.yml" in vulnhub_listing
    assert "flag_generators/" not in vulnhub_listing
    assert "flag_node_generators/" not in vulnhub_listing
