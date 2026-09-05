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
