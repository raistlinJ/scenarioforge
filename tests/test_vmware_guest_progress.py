from pathlib import Path
import shlex
import subprocess

import pytest

INSTALLER = Path(__file__).resolve().parents[1] / 'scripts/provision/vmware-workstation-linux/install-scenarioforge-lab.sh'


@pytest.mark.parametrize('platform', ['vmware-workstation-linux', 'vmware-fusion-mac'])
@pytest.mark.parametrize('wait_function', ['wait_for_all_guests', 'wait_for_participant', 'reinstall_wait_for_guest participant'])
def test_install_and_reinstall_show_sampled_package_activity(platform, wait_function):
    installer = INSTALLER.parent.parent / platform / INSTALLER.name
    result = subprocess.run(['bash', '-c', f'''
source {shlex.quote(str(installer))}
VERBOSE=0
WAIT_MINUTES=1
INSTALL_STARTED_EPOCH=$(date +%s)
CORE_VMX=core.vmx; APP_VMX=app.vmx; PARTICIPANT_VMX=participant.vmx
CORE_PASSWORD=test; APP_PASSWORD=test; PARTICIPANT_PASSWORD=test
poll=0
guest_file_exists() {{ (( poll >= 4 )); }}
guest_percent() {{ if (( poll >= 4 )); then echo 100; else echo 25; fi; }}
guest_file_text() {{
    (( poll > 0 )) || return 0
    case "$4" in
        */bootstrap-status) echo 'installing packages' ;;
        */bootstrap-percent) echo 25 ;;
        /var/log/*)
            if (( poll < 3 )); then
                [[ "$4" != /var/log/cloud-init-output.log ]] || printf 'older output\\nUnpacking chromium-common ...\\n'
            else
                printf 'older output\\nSetting up chromium ...\\n'
            fi ;;
    esac
}}
write_runtime_status() {{ :; }}
write_state() {{ :; }}
sleep() {{ poll=$((poll + 1)); }}
{wait_function}
'''], capture_output=True, text=True, timeout=10)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    roles = ['core', 'app', 'participant'] if wait_function == 'wait_for_all_guests' else ['participant']
    for role in roles:
        assert output.count(f'{role} guest: Unpacking chromium-common ...') == 1
        assert output.count(f'{role} guest: Setting up chromium ...') == 1
    assert 'installing packages' in output
    assert 'elapsed ' in output
    assert 'older output' not in output
    assert 'DEBUG' not in output


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
