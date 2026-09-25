"""Exercise the kernel handoff with all guest mutations confined to a temp dir."""
from pathlib import Path
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'scripts/provision/proxmox/install-scenarioforge-lab.sh'


@pytest.mark.parametrize('running,already_rebooted,expected', [
    ('6.1-cloud-amd64', False, 'reboot'),
    ('6.1-cloud-amd64', True, 'failed'),
    ('6.1-amd64', True, 'continue'),
    ('6.1-amd64', False, 'continue'),
])
def test_core_kernel_handoff(tmp_path, running, already_rebooted, expected):
    source = INSTALLER.read_text().split("<<'CORE_SCRIPT'\n", 1)[1].split('\nCORE_SCRIPT', 1)[0]
    block = source.split('export DEBIAN_FRONTEND=noninteractive\n', 1)[1].split("set_bootstrap_status 5", 1)[0]
    block = block.replace('/var/lib/scenarioforge', str(tmp_path / 'state')).replace('/etc/', str(tmp_path / 'etc') + '/')
    (tmp_path / 'state').mkdir()
    (tmp_path / 'etc/systemd/system').mkdir(parents=True)
    if already_rebooted:
        (tmp_path / 'state/core-kernel-reboot').touch()
    result = subprocess.run(['bash', '-c', f'''
set -eu
uname() {{ echo {shlex.quote(running)}; }}
dpkg() {{ echo amd64; }}
find() {{ printf '%s\\n' /boot/vmlinuz-6.1.0-53-amd64; }}
apt-get() {{ echo "apt $*"; }}
update-grub() {{ echo grub-updated; }}
systemctl() {{ echo "systemctl $*"; }}
systemd-run() {{ echo "reboot $*"; }}
set_bootstrap_status() {{ echo "$*"; }}
fail_bootstrap() {{ echo "failed: $*"; exit 1; }}
{block}
echo continue
'''], capture_output=True, text=True, timeout=10)
    output = result.stdout + result.stderr
    assert (result.returncode == 0) == (expected != 'failed'), output
    if expected == 'reboot':
        assert 'apt install -y linux-image-amd64' in output
        assert 'reboot --unit=scenarioforge-core-reboot' in output
        assert 'continue' not in output
        unit = (tmp_path / 'etc/systemd/system/scenarioforge-core-bootstrap.service').read_text()
        assert 'ExecStart=/usr/local/sbin/scenarioforge-core-bootstrap' in unit
        assert 'TimeoutStartSec=infinity' in unit
        config = tmp_path / 'etc/default/grub.d/99-scenarioforge-core-kernel.cfg'
        # The selection is evaluated anew for each update-grub, including upgrades.
        selection = subprocess.run(['bash', '-c', '''
dpkg() { echo amd64; }
find() { printf '%s\n' /boot/vmlinuz-6.1.0-53-amd64 /boot/vmlinuz-6.1.0-54-amd64; }
source "$1"
printf '%s|%s' "$GRUB_DEFAULT" "$GRUB_DISABLE_SUBMENU"
''', 'test', str(config)], capture_output=True, text=True, check=True)
        assert selection.stdout == 'Advanced options for Debian GNU/Linux>Debian GNU/Linux, with Linux 6.1.0-54-amd64|false'
    elif expected == 'failed':
        assert 'did not boot the standard kernel' in output
        assert 'reboot --unit=' not in output
    else:
        assert output.strip() == 'continue'
