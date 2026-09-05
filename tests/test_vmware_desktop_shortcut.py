import plistlib
from pathlib import Path
import shlex
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(params=["vmware-workstation-linux", "vmware-fusion-mac"])
def installer(request):
    return ROOT / "scripts/provision" / request.param / "install-scenarioforge-lab.sh"


def run_bash(installer, script):
    result = subprocess.run(
        ["bash", "-c", f"unset SF_DESKTOP_SHORTCUT; source {shlex.quote(str(installer))}\n{script}"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_shortcut_defaults_and_option_precedence(installer, tmp_path):
    config = tmp_path / "lab.conf"
    config.write_text("desktop_shortcut=false\n")
    output = run_bash(installer, f'''
printf '%s\n' "$CREATE_DESKTOP_SHORTCUT"
parse_args install --config {shlex.quote(str(config))}
printf '%s\n' "$CREATE_DESKTOP_SHORTCUT"
SF_DESKTOP_SHORTCUT=1
CREATE_DESKTOP_SHORTCUT=1
parse_args install --config {shlex.quote(str(config))}
printf '%s\n' "$CREATE_DESKTOP_SHORTCUT"
parse_args install --config {shlex.quote(str(config))} --no-desktop-shortcut
printf '%s\n' "$CREATE_DESKTOP_SHORTCUT"
parse_args install --desktop-shortcut
printf '%s\n' "$CREATE_DESKTOP_SHORTCUT"
''')
    assert [line for line in output.splitlines() if line in {"0", "1"}] == ["1", "0", "1", "0", "1"]


def test_native_shortcut_refresh_and_cleanup(installer, tmp_path):
    fusion = "fusion" in str(installer)
    shortcut = tmp_path / "Desktop with spaces" / ("ScenarioForge.webloc" if fusion else "ScenarioForge.desktop")
    initial = tmp_path / "initial"
    refreshed = tmp_path / "refreshed"
    run_bash(installer, f'''
HOST_DESKTOP_SHORTCUT={shlex.quote(str(shortcut))}
create_host_desktop_shortcut 192.168.42.10
cp "$HOST_DESKTOP_SHORTCUT" {shlex.quote(str(initial))}
create_host_desktop_shortcut 192.168.42.20
cp "$HOST_DESKTOP_SHORTCUT" {shlex.quote(str(refreshed))}
DRY_RUN=1
cleanup_host_desktop_shortcut
test -f "$HOST_DESKTOP_SHORTCUT"
DRY_RUN=0
cleanup_host_desktop_shortcut
''')
    assert not shortcut.exists()
    if fusion:
        assert plistlib.loads(initial.read_bytes())["URL"] == "https://192.168.42.10/"
        assert plistlib.loads(refreshed.read_bytes())["URL"] == "https://192.168.42.20/"
    else:
        assert "Exec=xdg-open https://192.168.42.10/" in initial.read_text()
        assert "Exec=xdg-open https://192.168.42.20/" in refreshed.read_text()
        assert refreshed.stat().st_mode & 0o111


def test_shortcut_skips_disabled_dry_run_and_unavailable_address(installer, tmp_path):
    shortcut = tmp_path / "must-not-exist"
    run_bash(installer, f'''
HOST_DESKTOP_SHORTCUT={shlex.quote(str(shortcut))}
parse_args install --no-desktop-shortcut
create_host_desktop_shortcut 192.168.42.10
CREATE_DESKTOP_SHORTCUT=1
DRY_RUN=1
create_host_desktop_shortcut 192.168.42.10
DRY_RUN=0
create_host_desktop_shortcut ""
create_host_desktop_shortcut 'error: no guest address'
''')
    assert not shortcut.exists()


def test_existing_and_modified_shortcuts_are_preserved(installer, tmp_path):
    shortcut = tmp_path / "ScenarioForge.shortcut"
    shortcut.write_text("user shortcut")
    run_bash(installer, f'''
HOST_DESKTOP_SHORTCUT={shlex.quote(str(shortcut))}
create_host_desktop_shortcut 192.168.42.10
cleanup_host_desktop_shortcut
''')
    assert shortcut.read_text() == "user shortcut"
    shortcut.unlink()
    run_bash(installer, f'''
HOST_DESKTOP_SHORTCUT={shlex.quote(str(shortcut))}
create_host_desktop_shortcut 192.168.42.10
printf 'user edit' > "$HOST_DESKTOP_SHORTCUT"
create_host_desktop_shortcut 192.168.42.20
cleanup_host_desktop_shortcut
''')
    assert shortcut.read_text() == "user edit"


def test_linux_shortcut_uses_xdg_desktop_directory(tmp_path):
    installer = ROOT / "scripts/provision/vmware-workstation-linux/install-scenarioforge-lab.sh"
    desktop = tmp_path / "Localized Desktop"
    run_bash(installer, f'''
xdg-user-dir() {{ printf '%s\n' {shlex.quote(str(desktop))}; }}
create_host_desktop_shortcut 192.168.42.10
''')
    assert (desktop / "ScenarioForge.desktop").is_file()


def test_participant_shortcut_launch_target_and_cleanup(installer, tmp_path):
    fusion = "fusion" in str(installer)
    vmx = tmp_path / "VMs with spaces" / "participant.vmx"
    vmx.parent.mkdir()
    vmx.touch()
    shortcut = tmp_path / ("Participant.command" if fusion else "Participant.desktop")
    snapshot = tmp_path / "launcher"
    run_bash(installer, f'''
PARTICIPANT_VMX={shlex.quote(str(vmx))}
HOST_PARTICIPANT_SHORTCUT={shlex.quote(str(shortcut))}
create_participant_desktop_shortcut
cp "$HOST_PARTICIPANT_SHORTCUT" {shlex.quote(str(snapshot))}
create_participant_desktop_shortcut
DRY_RUN=1
cleanup_participant_desktop_shortcut
test -f "$HOST_PARTICIPANT_SHORTCUT"
DRY_RUN=0
cleanup_participant_desktop_shortcut
''')
    assert not shortcut.exists()
    assert snapshot.stat().st_mode & 0o111
    if fusion:
        command = shlex.split(snapshot.read_text().splitlines()[-1])
        assert command == ["exec", "open", "-a", "/Applications/VMware Fusion.app", str(vmx)]
    else:
        command = next(line[5:] for line in snapshot.read_text().splitlines() if line.startswith("Exec="))
        assert shlex.split(command) == ["vmware", str(vmx)]
        assert "Terminal=false" in snapshot.read_text()


def test_participant_shortcut_skips_disabled_dry_run_and_missing_vm(installer, tmp_path):
    shortcut = tmp_path / "must-not-exist"
    vmx = tmp_path / "participant.vmx"
    vmx.touch()
    run_bash(installer, f'''
HOST_PARTICIPANT_SHORTCUT={shlex.quote(str(shortcut))}
PARTICIPANT_VMX={shlex.quote(str(vmx))}
CREATE_DESKTOP_SHORTCUT=0
create_participant_desktop_shortcut
CREATE_DESKTOP_SHORTCUT=1
DRY_RUN=1
create_participant_desktop_shortcut
DRY_RUN=0
PARTICIPANT_VMX={shlex.quote(str(tmp_path / 'missing.vmx'))}
create_participant_desktop_shortcut
''')
    assert not shortcut.exists()


def test_modified_participant_shortcut_is_preserved(installer, tmp_path):
    vmx = tmp_path / "participant.vmx"
    vmx.touch()
    shortcut = tmp_path / "participant.shortcut"
    run_bash(installer, f'''
PARTICIPANT_VMX={shlex.quote(str(vmx))}
HOST_PARTICIPANT_SHORTCUT={shlex.quote(str(shortcut))}
create_participant_desktop_shortcut
printf 'user edit' > "$HOST_PARTICIPANT_SHORTCUT"
create_participant_desktop_shortcut
cleanup_participant_desktop_shortcut
''')
    assert shortcut.read_text() == "user edit"


def test_untracked_participant_shortcut_does_not_inherit_browser_ownership(installer, tmp_path):
    vmx = tmp_path / "participant.vmx"
    vmx.touch()
    desktop = tmp_path / "Desktop"
    desktop.mkdir()
    fusion = "fusion" in str(installer)
    shortcut = desktop / ("ScenarioForge Participant VM.command" if fusion else "ScenarioForge Participant VM.desktop")
    shortcut.write_text("user shortcut")
    run_bash(installer, f'''
host_desktop_directory() {{ printf '%s\n' {shlex.quote(str(desktop))}; }}
PARTICIPANT_VMX={shlex.quote(str(vmx))}
create_host_desktop_shortcut 192.168.42.10
create_participant_desktop_shortcut
cleanup_participant_desktop_shortcut
''')
    assert shortcut.read_text() == "user shortcut"


def test_participant_launcher_quotes_special_paths(installer, tmp_path):
    fusion = "fusion" in str(installer)
    vmx = tmp_path / 'lab $USER `whoami` "quote" \\ %f' / "participant.vmx"
    vmx.parent.mkdir()
    vmx.touch()
    shortcut = tmp_path / "participant.shortcut"
    fusion_app = tmp_path / "Custom VMware Fusion.app"
    run_bash(installer, f'''
PARTICIPANT_VMX={shlex.quote(str(vmx))}
FUSION_APP={shlex.quote(str(fusion_app))}
HOST_PARTICIPANT_SHORTCUT={shlex.quote(str(shortcut))}
create_participant_desktop_shortcut
''')
    content = shortcut.read_text()
    if fusion:
        assert shlex.split(content.splitlines()[-1]) == ["exec", "open", "-a", str(fusion_app), str(vmx)]
    else:
        # Undo Desktop Entry string escaping, Exec quoting, and field-code
        # escaping, in that order. The result must remain one literal VM path.
        import re
        argument = next(line[len('Exec=vmware "'):-1] for line in content.splitlines() if line.startswith('Exec='))
        argument = argument.replace('\\\\', '\\')
        argument = re.sub(r'\\([\\"`$])', r'\1', argument).replace('%%', '%')
        assert argument == str(vmx)


def test_linux_participant_shortcut_uses_xdg_desktop_without_app_address(tmp_path):
    installer = ROOT / "scripts/provision/vmware-workstation-linux/install-scenarioforge-lab.sh"
    desktop = tmp_path / "Localized Desktop"
    vmx = tmp_path / "participant.vmx"
    vmx.touch()
    run_bash(installer, f'''
xdg-user-dir() {{ printf '%s\n' {shlex.quote(str(desktop))}; }}
PARTICIPANT_VMX={shlex.quote(str(vmx))}
create_host_desktop_shortcut ""
create_participant_desktop_shortcut
''')
    assert (desktop / "ScenarioForge Participant VM.desktop").is_file()
    assert not (desktop / "ScenarioForge.desktop").exists()


def test_participant_shortcut_ownership_survives_saved_state(installer, tmp_path):
    vmx = tmp_path / "participant.vmx"
    vmx.touch()
    shortcut = tmp_path / "participant.shortcut"
    state_dir = tmp_path / "state"
    run_bash(installer, f'''
STATE_DIR={shlex.quote(str(state_dir))}
STATE_FILE="$STATE_DIR/state.env"
CREDENTIALS_FILE="$STATE_DIR/credentials.env"
CORE_PASSWORD=test-only
APP_PASSWORD=test-only
PARTICIPANT_PASSWORD=test-only
SCENARIOFORGE_ADMIN_PASSWORD=test-only
PARTICIPANT_VMX={shlex.quote(str(vmx))}
HOST_PARTICIPANT_SHORTCUT={shlex.quote(str(shortcut))}
write_state
create_participant_desktop_shortcut
HOST_PARTICIPANT_SHORTCUT=""
HOST_PARTICIPANT_SHORTCUT_SHA256=""
source "$STATE_FILE"
test -n "$HOST_PARTICIPANT_SHORTCUT"
test -n "$HOST_PARTICIPANT_SHORTCUT_SHA256"
cleanup_participant_desktop_shortcut
''')
    assert not shortcut.exists()
    assert "HOST_PARTICIPANT_SHORTCUT_SHA256=" in (state_dir / "state.env").read_text()
