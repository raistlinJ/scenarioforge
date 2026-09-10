"""A stuck graceful vmrun must reach the bounded hard-stop fallback."""
from pathlib import Path
import subprocess

import pytest

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/provision/vmware-workstation-linux/install-scenarioforge-lab.sh'


@pytest.mark.parametrize('hard_fails', [False, True])
def test_cleanup_bounds_shutdown_and_preserves_files_on_failure(hard_fails):
    text = SOURCE.read_text()
    block = text.split('                log "Requesting graceful shutdown', 1)[1].split('\n            fi\n        fi', 1)[0]
    block = 'log "Requesting graceful shutdown' + block
    script = '''
set -e
vmx=/test/participant.vmx
VMRUN_TYPE=fusion
FUSION_VMRUN='/Applications/VMware Fusion.app/Contents/Library/vmrun'
running=1
log() { :; }
warn() { :; }
die() { echo "$*"; exit 1; }
vm_running() { [[ "$running" == 1 ]]; }
date() { echo 100; }
sleep() { deadline=0; }
timeout() {
    [[ "$1" == 30 && "$2" == "$FUSION_VMRUN" ]] || exit 90
    echo "stop:${7}"
    if [[ "$7" == soft ]]; then return 124; fi
''' + ('return 1\n' if hard_fails else 'running=0; return 0\n') + '}\nstop_vm() {\n' + block + '\n}\nstop_vm\necho SAFE_TO_DELETE\n'
    result = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
    assert 'stop:soft' in result.stdout
    assert 'stop:hard' in result.stdout
    assert (result.returncode != 0) == hard_fails
    assert ('SAFE_TO_DELETE' in result.stdout) != hard_fails
