"""Exercise host dependency setup without running a real package manager."""
from pathlib import Path
import shlex
import subprocess

import pytest


INSTALLER = Path(__file__).resolve().parents[1] / 'scripts/provision/vmware-workstation-linux/install-scenarioforge-lab.sh'


def run_probe(script):
    return subprocess.run(['bash', '-c', f'source {shlex.quote(str(INSTALLER))}\n' + script],
                          text=True, capture_output=True)


@pytest.mark.parametrize('manager,qemu,xz,ssh', [
    ('apt-get', 'qemu-utils', 'xz-utils', 'openssh-client'),
    ('dnf', 'qemu-img', 'xz', 'openssh-clients'),
    ('yum', 'qemu-img', 'xz', 'openssh-clients'),
])
def test_installs_missing_packages_and_rechecks(manager, qemu, xz, ssh):
    result = run_probe(f'''
INSTALL_FLAG_GENERATORS=1
installed=0
host_command_available() {{
    case "$1" in
        qemu-img|xz|git|ssh|ssh-keygen|scp|modinfo|modprobe|timeout|nohup|pgrep|sha256sum|sha512sum|gzip|xorriso|genisoimage) [[ "$installed" == 1 ]] ;;
        apt-get|dnf|yum) [[ "$1" == {shlex.quote(manager)} ]] ;;
        *) return 0 ;;
    esac
}}
run() {{
    printf 'CALL'; printf ' <%s>' "$@"; printf '\\n'
    if [[ "$3" == install ]]; then installed=1; fi
}}
ensure_linux_host_dependencies
printf 'DONE\\n'
''')
    assert result.returncode == 0, result.stderr
    calls = [line for line in result.stdout.splitlines() if line.startswith('CALL')]
    assert len(calls) == (2 if manager == 'apt-get' else 1)
    install = calls[-1]
    procps = 'procps' if manager == 'apt-get' else 'procps-ng'
    for package in [qemu, xz, ssh, 'coreutils', procps, 'gzip', 'xorriso', 'git', 'ca-certificates', 'kmod']:
        assert install.count(f'<{package}>') == 1
    assert 'DONE' in result.stdout


def test_existing_tools_need_no_package_manager():
    result = run_probe('''
host_command_available() { return 0; }
run() { printf 'UNEXPECTED PACKAGE INSTALL'; return 1; }
ensure_linux_host_dependencies
''')
    assert result.returncode == 0, result.stderr
    assert 'UNEXPECTED' not in result.stdout


def test_existing_genisoimage_and_unused_catalog_tools_are_accepted():
    result = run_probe('''
INSTALL_FLAG_GENERATORS=0
INSTALL_VULNHUB=0
host_command_available() {
    case "$1" in xorriso|git|ssh|scp|ssh-keygen) return 1 ;; *) return 0 ;; esac
}
run() { return 1; }
ensure_linux_host_dependencies
''')
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('failure', ['unsupported', 'sudo', 'install', 'recheck', 'dry-run'])
def test_failure_and_dry_run_stop_before_provisioning(failure):
    result = run_probe(f'''
failure={shlex.quote(failure)}
[[ "$failure" != dry-run ]] || DRY_RUN=1
host_command_available() {{
    case "$1" in
        qemu-img) return 1 ;;
        apt-get) [[ "$failure" != unsupported ]] ;;
        dnf|yum) return 1 ;;
        sudo) [[ "$failure" != sudo ]] ;;
        *) return 0 ;;
    esac
}}
# Retain the real run() in dry-run mode: its output must be non-mutating.
if [[ "$failure" != dry-run ]]; then
    run() {{ [[ "$failure" != install ]]; }}
fi
sudo() {{ printf 'SHOULD NOT EXECUTE SUDO'; return 99; }}
ensure_linux_host_dependencies
printf 'SHOULD NOT PROVISION'
''')
    assert result.returncode != 0
    assert 'SHOULD NOT' not in result.stdout
    if failure == 'dry-run':
        assert 'DRY-RUN' in result.stdout
        assert 'qemu-utils' in result.stdout
    if failure == 'recheck':
        assert 'still missing after package installation: qemu-img' in result.stderr
