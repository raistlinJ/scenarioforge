"""Disk-size precedence must survive OS selection on every shell entry point."""
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = ['proxmox', 'vmware-workstation-linux', 'vmware-fusion-mac']


@pytest.mark.parametrize('platform', PLATFORMS)
@pytest.mark.parametrize('guest_os', ['debian', 'kali'])
@pytest.mark.parametrize('source,expected', [('defaults', '80 80 80'), ('config', '90 100 110'), ('env', '120 130 140'), ('cli', '150 160 170')])
def test_disk_size_precedence(tmp_path, platform, guest_os, source, expected):
    config = tmp_path / 'lab.conf'
    config.write_text('core_disk_gb=90\napp_disk_gb=100\nparticipant_disk_gb=110\n')
    env = {key: value for key, value in os.environ.items() if not key.startswith('SF_')}
    args = ['install', '--participant-os', guest_os]
    if source != 'defaults':
        args += ['--config', str(config)]
    if source in ('env', 'cli'):
        env.update(SF_CORE_DISK_GB='120', SF_APP_DISK_GB='130', SF_PARTICIPANT_DISK_GB='140')
    if source == 'cli':
        # CLI flags before --config still take precedence over the config file.
        args = ['install', '--core-disk-gb', '150', '--app-disk-gb', '160', '--participant-disk-gb', '170', *args[1:]]
    installer = ROOT / 'scripts/provision' / platform / 'install-scenarioforge-lab.sh'
    result = subprocess.run(['bash', '-c', 'source "$1"; shift; parse_args "$@"; printf "%s %s %s\\n" "$CORE_DISK_GB" "$APP_DISK_GB" "$PARTICIPANT_DISK_GB"', 'check', str(installer), *args],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == expected


@pytest.mark.parametrize('platform', PLATFORMS)
@pytest.mark.parametrize('role,value', [('core', '0'), ('app', 'abc'), ('participant', '24')])
def test_invalid_disk_sizes_rejected_before_install(platform, role, value):
    installer = ROOT / 'scripts/provision' / platform / 'install-scenarioforge-lab.sh'
    env = {key: value for key, value in os.environ.items() if not key.startswith('SF_')}
    result = subprocess.run(['bash', '-c', 'source "$1"; shift; parse_args "$@"', 'check', str(installer),
                             '--participant-os', 'kali', f'--{role}-disk-gb', value],
                            env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert 'disk size' in result.stderr
