from pathlib import Path
import shlex
import subprocess
import tempfile
import re

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(params=["vmware-workstation-linux", "vmware-fusion-mac"])
def installer(request):
    return ROOT / "scripts/provision" / request.param / "install-scenarioforge-lab.sh"


def run_bash(installer, script):
    with tempfile.TemporaryDirectory() as state_dir:
        result = subprocess.run(
            ["bash", "-c", f"unset SF_DESKTOP_SHORTCUT; source {shlex.quote(str(installer))}\n"
             f"STATE_DIR={shlex.quote(state_dir)}\nSTATE_FILE=\"$STATE_DIR/state.env\"\n{script}"],
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


def shortcut_arguments(content, fusion):
    if fusion:
        return shlex.split(content.splitlines()[-1])[1:]
    line = next(line[5:] for line in content.splitlines() if line.startswith("Exec="))
    # Undo Desktop Entry string escaping, then quoted arguments and field codes.
    line = line.replace('\\\\', '\\')
    return [re.sub(r'\\([\\"`$])', r'\1', token).replace('%%', '%')
            for token in re.findall(r'"((?:\\.|[^"\\])*)"', line)]


def test_native_shortcut_refresh_and_cleanup(installer, tmp_path):
    fusion = "fusion" in str(installer)
    shortcut = tmp_path / "Desktop with spaces" / ("ScenarioForge.command" if fusion else "ScenarioForge.desktop")
    initial = tmp_path / "initial"
    refreshed = tmp_path / "refreshed"
    run_bash(installer, f'''
HOST_DESKTOP_SHORTCUT={shlex.quote(str(shortcut))}
create_host_desktop_shortcut ""
cp "$HOST_DESKTOP_SHORTCUT" {shlex.quote(str(initial))}
APP_VMX={shlex.quote(str(tmp_path / 'new-app.vmx'))}
create_host_desktop_shortcut ""
cp "$HOST_DESKTOP_SHORTCUT" {shlex.quote(str(refreshed))}
DRY_RUN=1
cleanup_host_desktop_shortcut
test -f "$HOST_DESKTOP_SHORTCUT"
DRY_RUN=0
cleanup_host_desktop_shortcut
cleanup_host_desktop_launcher
test ! -e "$HOST_DESKTOP_LAUNCHER"
''')
    assert not shortcut.exists()
    args = shortcut_arguments(refreshed.read_text(), fusion)
    assert args[args.index("--mode") + 1] == "browser"
    assert args[args.index("--app") + 1] == str(tmp_path / 'new-app.vmx')
    assert initial.read_bytes() != refreshed.read_bytes()
    assert refreshed.stat().st_mode & 0o111


def test_shortcut_skips_disabled_and_dry_run(installer, tmp_path):
    shortcut = tmp_path / "must-not-exist"
    run_bash(installer, f'''
HOST_DESKTOP_SHORTCUT={shlex.quote(str(shortcut))}
parse_args install --no-desktop-shortcut
create_host_desktop_shortcut 192.168.42.10
CREATE_DESKTOP_SHORTCUT=1
DRY_RUN=1
create_host_desktop_shortcut 192.168.42.10
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
    args = shortcut_arguments(snapshot.read_text(), fusion)
    assert args[args.index("--mode") + 1] == "participant"
    assert args[args.index("--participant") + 1] == str(vmx)
    if not fusion:
        assert "Terminal=true" in snapshot.read_text()


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
    args = shortcut_arguments(content, fusion)
    assert args[args.index("--participant") + 1] == str(vmx)
    assert args[args.index("--fusion-app") + 1] == str(fusion_app)


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
    assert (desktop / "ScenarioForge.desktop").is_file()


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


def test_fusion_migrates_owned_webloc_after_writing_command(tmp_path):
    import hashlib
    import plistlib
    installer = ROOT / "scripts/provision/vmware-fusion-mac/install-scenarioforge-lab.sh"
    old = tmp_path / "ScenarioForge.webloc"
    old.write_bytes(plistlib.dumps({"URL": "https://192.168.42.10/"}))
    digest = hashlib.sha256(old.read_bytes()).hexdigest()
    run_bash(installer, f'''
HOST_DESKTOP_SHORTCUT={shlex.quote(str(old))}
HOST_DESKTOP_SHORTCUT_SHA256={shlex.quote(digest)}
create_host_desktop_shortcut ""
test "$HOST_DESKTOP_SHORTCUT" = {shlex.quote(str(old.with_suffix('.command')))}
''')
    assert not old.exists()
    args = shortcut_arguments(old.with_suffix('.command').read_text(), True)
    assert args[args.index('--mode') + 1] == 'browser'


@pytest.mark.parametrize("conflict", ["modified-webloc", "existing-command"])
def test_fusion_migration_preserves_user_files(tmp_path, conflict):
    import hashlib
    installer = ROOT / "scripts/provision/vmware-fusion-mac/install-scenarioforge-lab.sh"
    old = tmp_path / "ScenarioForge.webloc"
    old.write_text("existing browser link")
    digest = hashlib.sha256(old.read_bytes()).hexdigest()
    new = old.with_suffix('.command')
    if conflict == "modified-webloc":
        old.write_text("user edit")
    else:
        new.write_text("user launcher")
    before = old.read_bytes()
    run_bash(installer, f'''
HOST_DESKTOP_SHORTCUT={shlex.quote(str(old))}
HOST_DESKTOP_SHORTCUT_SHA256={shlex.quote(digest)}
create_host_desktop_shortcut ""
''')
    assert old.read_bytes() == before
    if new.exists():
        assert new.read_text() == "user launcher"


def test_modified_runtime_helper_is_preserved(installer, tmp_path):
    shortcut = tmp_path / "browser.shortcut"
    runtime = tmp_path / "desktop-launcher.py"
    run_bash(installer, f'''
HOST_DESKTOP_SHORTCUT={shlex.quote(str(shortcut))}
HOST_DESKTOP_LAUNCHER={shlex.quote(str(runtime))}
create_host_desktop_shortcut ""
printf 'user runtime edit' > "$HOST_DESKTOP_LAUNCHER"
create_host_desktop_shortcut ""
cleanup_host_desktop_shortcut
cleanup_host_desktop_launcher
''')
    assert runtime.read_text() == "user runtime edit"


@pytest.mark.parametrize("hung_start", [False, True])
def test_generated_browser_shortcut_checks_and_prompts_before_opening(installer, tmp_path, hung_start):
    """Run the actual generated shortcut and installed helper with fake host CLIs."""
    import json
    import os
    import sys
    fusion = "fusion" in str(installer)
    fake_bin = tmp_path / "fake bin"
    fake_bin.mkdir()
    state = tmp_path / "vm-state.json"
    state.write_text(json.dumps({"running": [], "calls": [], "consent": False}))
    fake = f'''#!{sys.executable}
import fcntl
import json
from pathlib import Path
import sys
import time
state_path = Path({str(state)!r})
lock = open(str(state_path) + '.lock', 'w')
fcntl.flock(lock, fcntl.LOCK_EX)
state = json.loads(state_path.read_text())
name = Path(sys.argv[0]).name
args = sys.argv[1:]
state['calls'].append([name] + args)
status = 0
if name == 'vmrun':
    action = args[2]
    if action == 'list':
        print('Total running VMs: ' + str(len(state['running'])))
        print('\\n'.join(state['running']))
    elif action == 'start':
        state['running'].append(args[3])
    elif action == 'getGuestIPAddress':
        print('192.168.42.99')
elif name in ('osascript', 'zenity'):
    status = 0 if state['consent'] else 1
    if status and name == 'osascript':
        print('User canceled. (-128)', file=sys.stderr)
state_path.write_text(json.dumps(state))
lock.close()
if {hung_start!r} and name == 'vmrun' and args[2] == 'start':
    time.sleep(120)
sys.exit(status)
'''
    for name in ("vmrun", "osascript", "zenity", "open", "xdg-open"):
        path = fake_bin / name
        path.write_text(fake)
        path.chmod(0o755)
    core, app = tmp_path / "CORE VM.vmx", tmp_path / "APP VM.vmx"
    core.touch()
    app.touch()
    shortcut = tmp_path / ("ScenarioForge.command" if fusion else "ScenarioForge.desktop")
    helper = tmp_path / "installed launcher.py"
    run_bash(installer, f'''
PATH={shlex.quote(str(fake_bin))}:"$PATH"
CORE_VMX={shlex.quote(str(core))}
APP_VMX={shlex.quote(str(app))}
FUSION_VMRUN={shlex.quote(str(fake_bin / 'vmrun'))}
HOST_DESKTOP_SHORTCUT={shlex.quote(str(shortcut))}
HOST_DESKTOP_LAUNCHER={shlex.quote(str(helper))}
create_host_desktop_shortcut ""
''')
    args = ["sh", str(shortcut)] if fusion else shortcut_arguments(shortcut.read_text(), False)
    env = dict(os.environ, PATH=str(fake_bin) + os.pathsep + os.environ['PATH'])
    result = subprocess.run(args, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    data = json.loads(state.read_text())
    assert data['running'] == []
    assert not any(call[0] in ('open', 'xdg-open') for call in data['calls'])
    data['consent'] = True
    data['calls'] = []
    state.write_text(json.dumps(data))
    result = subprocess.run(args, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    data = json.loads(state.read_text())
    assert data['running'] == [str(core), str(app)]
    start_calls = [call for call in data['calls'] if call[0] == 'vmrun' and call[3] == 'start']
    assert len(start_calls) == 2
    assert all(call[-1] == 'gui' for call in start_calls)
    if fusion:
        attachment = next(i for i, call in enumerate(data['calls']) if call[:3] == ['open', '-g', '-a'])
        assert data['calls'][attachment][-2:] == [str(core), str(app)]
        network = next(i for i, call in enumerate(data['calls']) if 'getGuestIPAddress' in call)
        assert attachment < network
    assert data['calls'][-1] == ['open' if fusion else 'xdg-open', 'https://192.168.42.99/']
    prompts = [call for call in data['calls'] if call[0] in ('osascript', 'zenity')]
    assert len(prompts) == 1
