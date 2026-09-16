from pathlib import Path
import shlex
import subprocess

import pytest

INSTALLER = Path(__file__).resolve().parents[1] / 'scripts/provision/vmware-workstation-linux/install-scenarioforge-lab.sh'


@pytest.mark.parametrize('sample,expected,unavailable', [('unavailable', 100, True), ('25', 25, False), ('100', 100, False)])
def test_guest_poll_preserves_only_unreadable_progress(sample, expected, unavailable):
    result = subprocess.run(['bash', '-c', f'''
source {shlex.quote(str(INSTALLER))}
percent=100
guest_percent() {{ echo {shlex.quote(sample)}; }}
poll_guest_percent percent vm.vmx
printf '%s|%s' "$percent" "$percent_availability"
'''], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith(f'{expected}|')
    assert ('temporarily unavailable' in result.stdout) == unavailable
    assert ('may have restarted' in result.stderr) == (sample == '25')


def test_unreadable_guest_percent_is_not_zero():
    result = subprocess.run(['bash', '-c', f'''
source {shlex.quote(str(INSTALLER))}
guest_file_exists() {{ return 1; }}
guest_file_text() {{ return 0; }}
guest_percent vm user password marker
'''], capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout.strip() == 'unavailable'


@pytest.mark.parametrize('state', ['installed', 'running'])
@pytest.mark.parametrize('operation_status', [0, 1])
def test_guest_marker_checks_use_actual_operation_result(state, operation_status):
    result = subprocess.run(['bash', '-c', f'''
source {shlex.quote(str(INSTALLER))}
vmrun() {{
    if [[ "$*" == *checkToolsState* ]]; then echo {state}; return 0; fi
    return {operation_status}
}}
timeout() {{ shift; "$@"; }}
if guest_file_exists vm.vmx user password marker; then echo ready; else echo waiting; fi
'''], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ('ready' if operation_status == 0 else 'waiting')
