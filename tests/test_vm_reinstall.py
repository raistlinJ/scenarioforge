import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / 'scripts/provision/common'
spec = importlib.util.spec_from_file_location('reinstall_cache', COMMON / 'image_cache.py')
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


def test_windows_reinstall_orchestration():
    pwsh = os.environ.get('SF_TEST_PWSH') or shutil.which('pwsh')
    if not pwsh:
        pytest.skip('PowerShell is available in the Windows CI job')
    result = subprocess.run([pwsh, '-NoProfile', '-File', str(ROOT / 'tests/test_vmware_reinstall.ps1')], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_cached_receipt_reuses_pinned_image_without_network(tmp_path, monkeypatch):
    image = tmp_path / 'base.img'
    image.write_bytes(b'verified original release')
    url = 'https://example.test/latest/base.img'
    checksum = hashlib.sha256(image.read_bytes()).hexdigest()
    cache.remember(image, url, 'sha256', checksum)
    monkeypatch.setattr(cache.urllib.request, 'urlopen', lambda *a, **k: pytest.fail('No network with a receipt'))
    assert cache.require_cached(image, url, 'sha256', 'unused') == image
    with pytest.raises(ValueError, match='source differs'):
        cache.require_cached(image, url + 'changed', 'sha256', 'unused')
    image.write_bytes(b'corrupt')
    with pytest.raises(ValueError, match='verification failed'):
        cache.require_cached(image, url, 'sha256', 'unused')
    image.unlink()
    with pytest.raises(ValueError, match='requires cached image'):
        cache.require_cached(image, url, 'sha256', 'unused')


def test_legacy_cache_only_fetches_checksum_list(tmp_path, monkeypatch):
    image = tmp_path / 'cached.img'
    image.write_bytes(b'old image')
    checksum = hashlib.sha256(image.read_bytes()).hexdigest()
    calls = []
    def request(url, **kwargs):
        calls.append(url)
        return io.BytesIO(f'{checksum}  upstream.img\n'.encode())
    monkeypatch.setattr(cache.urllib.request, 'urlopen', request)
    assert cache.require_cached(image, 'https://example.test/upstream.img', 'sha256', 'checksums') == image
    assert calls == ['checksums']
    assert list(tmp_path.iterdir()) == [image]


@pytest.mark.parametrize('platform', ['proxmox', 'vmware-workstation-linux', 'vmware-fusion-mac'])
@pytest.mark.parametrize('mode', ['valid', 'corrupt', 'missing', 'checksum_failure', 'download_failure', 'preview', 'preview_missing', 'symlink'])
def test_force_refresh_preserves_cache_until_verified(tmp_path, platform, mode):
    image = tmp_path / 'noble-server-cloudimg-amd64.img'
    events = tmp_path / 'downloads'
    payload = b'fresh image'
    expected = hashlib.sha256(payload).hexdigest()
    url = 'https://example.test/noble-server-cloudimg-amd64.img'
    if mode not in ('missing', 'preview_missing'):
        image.write_bytes(payload if mode == 'valid' else b'old image')
        cache.remember(image, url, 'sha256', hashlib.sha256(image.read_bytes()).hexdigest())
    if mode == 'symlink':
        image.rename(tmp_path / 'original')
        image.symlink_to(tmp_path / 'original')
    original_receipt = Path(str(image) + '.verified.json')
    before_receipt = original_receipt.read_bytes() if original_receipt.exists() else None
    installer = ROOT / 'scripts/provision' / platform / 'install-scenarioforge-lab.sh'
    script = f'''
source {shlex.quote(str(installer))}
parse_args --reinstall app --force {'--dry-run' if mode.startswith('preview') else ''}
IMAGE_CACHE={shlex.quote(str(tmp_path))}
UBUNTU_IMAGE_URL={url}
UBUNTU_IMAGE_CACHE_NAME=noble-server-cloudimg-amd64.img
UBUNTU_SUMS_URL=https://example.test/SHA256SUMS
curl() {{
    if [[ "$1" == -fsSL ]]; then printf '%s *noble-server-cloudimg-amd64.img\\n' {expected}; return; fi
    echo download >> {shlex.quote(str(events))}
    [[ {mode} != download_failure ]] || return 22
    while [[ "$1" != -o ]]; do shift; done
    printf '%s' {'corrupt' if mode == 'checksum_failure' else "'fresh image'"} > "$2"
}}
sha256sum() {{ python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"; }}
sha512sum() {{ echo WRONG_ALGORITHM; exit 99; }}
reinstall_cached_images
'''
    result = subprocess.run(['bash', '-c', script], input='', capture_output=True, text=True)
    success = mode in ('valid', 'corrupt', 'missing', 'preview', 'preview_missing')
    assert (result.returncode == 0) == success, result.stdout + result.stderr
    assert events.exists() == (not mode.startswith('preview') and mode != 'symlink')
    if mode in ('valid', 'corrupt', 'missing'):
        assert image.read_bytes() == payload
        assert cache.require_cached(image, url, 'sha256', 'unused') == image
    else:
        assert (original_receipt.read_bytes() if original_receipt.exists() else None) == before_receipt
        if mode != 'preview_missing':
            assert image.read_bytes() == b'old image'
    if mode.startswith('preview'):
        assert 'force download and verify' in result.stdout


@pytest.mark.parametrize('platform', ['proxmox', 'vmware-workstation-linux', 'vmware-fusion-mac'])
def test_app_reinstall_accepts_sha256_receipt_from_regular_install(tmp_path, platform):
    image = tmp_path / 'noble-server-cloudimg-amd64.img'
    image.write_bytes(b'original verified ubuntu')
    url = 'https://example.test/noble-server-cloudimg-amd64.img'
    cache.remember(image, url, 'sha256', hashlib.sha256(image.read_bytes()).hexdigest())
    installer = ROOT / 'scripts/provision' / platform / 'install-scenarioforge-lab.sh'
    result = subprocess.run(['bash', '-c', f'''
source {shlex.quote(str(installer))}
parse_args --reinstall app
IMAGE_CACHE={shlex.quote(str(tmp_path))}
UBUNTU_IMAGE_URL={url}
UBUNTU_IMAGE_CACHE_NAME=noble-server-cloudimg-amd64.img
curl() {{ echo UNEXPECTED_DOWNLOAD >&2; return 99; }}
reinstall_cached_images
'''], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'UNEXPECTED_DOWNLOAD' not in result.stderr


@pytest.mark.parametrize('platform', ['proxmox', 'vmware-workstation-linux'])
def test_normal_download_dry_run_does_not_create_receipt(tmp_path, platform):
    image = tmp_path / 'base.img'
    image.write_bytes(b'valid cache')
    checksum = hashlib.sha256(image.read_bytes()).hexdigest()
    installer = ROOT / 'scripts/provision' / platform / 'install-scenarioforge-lab.sh'
    script = f'''
source {shlex.quote(str(installer))}
DRY_RUN=1
curl() {{ printf '%s  base.img\\n' {checksum}; }}
sha256sum() {{ printf '%s  base.img\\n' {checksum}; }}
download_verified_image https://example.test/base.img checksums sha256 {shlex.quote(str(image))}
'''
    result = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert list(tmp_path.iterdir()) == [image]


@pytest.mark.parametrize('platform', ['proxmox', 'vmware-workstation-linux', 'vmware-fusion-mac'])
@pytest.mark.parametrize('mode', ['yes', 'no', 'empty', 'eof', 'preview', 'valid', 'invalid', 'download_failure'])
def test_missing_reinstall_image_download_prompt(tmp_path, platform, mode):
    image = tmp_path / 'base.img'
    events = tmp_path / 'downloads'
    checksum = hashlib.sha256(b'image').hexdigest()
    if mode in ('valid', 'invalid'):
        image.write_bytes(b'image' if mode == 'valid' else b'corrupt')
        cache.remember(image, 'https://example.test/base.img', 'sha256', checksum)
    installer = ROOT / 'scripts/provision' / platform / 'install-scenarioforge-lab.sh'
    script = f'''
source {shlex.quote(str(installer))}
REINSTALL_TARGET=participant
ASSUME_YES=1
DRY_RUN={int(mode == 'preview')}
curl() {{
    if [[ "$1" == -fsSL ]]; then printf '%s  base.img\\n' {checksum}; return; fi
    while [[ "$1" != -o ]]; do shift; done
    printf image > "$2"
    echo download >> {shlex.quote(str(events))}
}}
sha256sum() {{ printf '%s  base.img\\n' {'invalid' if mode == 'download_failure' else checksum}; }}
download_verified_image https://example.test/base.img checksums sha256 {shlex.quote(str(image))}
echo VERIFIED
'''
    answer = 'yes\n' if mode in ('yes', 'download_failure') else 'no\n' if mode == 'no' else '\n' if mode == 'empty' else ''
    result = subprocess.run(['bash', '-c', script], input=answer, capture_output=True, text=True)
    assert (result.returncode == 0) == (mode in ('yes', 'valid')), result.stderr
    assert events.exists() == (mode in ('yes', 'download_failure'))
    if mode == 'yes':
        assert image.read_bytes() == b'image'
        assert cache.require_cached(image, 'https://example.test/base.img', 'sha256', 'unused') == image
    if mode in ('no', 'empty', 'eof'):
        assert 'download declined' in result.stderr
        assert not image.exists()
    if mode == 'preview':
        assert 'Dry run' in result.stderr
        assert not image.exists()
    if mode == 'invalid':
        assert image.read_bytes() == b'corrupt'
    if mode == 'download_failure':
        assert not image.exists()


def test_proxmox_reinstall_stops_on_cloud_init_failure():
    installer = ROOT / 'scripts/provision/proxmox/install-scenarioforge-lab.sh'
    script = f'''
source {shlex.quote(str(installer))}
guest_marker_exists() {{ return 1; }}
guest_bootstrap_failure_text() {{ echo 'cloud-init failed'; }}
sleep() {{ echo UNEXPECTED_WAIT; exit 99; }}
reinstall_wait_for_guest participant
'''
    result = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'cloud-init failed' in result.stderr
    assert 'UNEXPECTED_WAIT' not in result.stdout


@pytest.mark.parametrize('platform', ['proxmox', 'vmware-workstation-linux', 'vmware-fusion-mac'])
@pytest.mark.parametrize('mode', ['progress', 'unavailable', 'failed', 'timeout'])
def test_reinstall_reports_guest_progress(platform, mode):
    installer = ROOT / 'scripts/provision' / platform / 'install-scenarioforge-lab.sh'
    script = f'''
source {shlex.quote(str(installer))}
mode={mode}
poll=0
WAIT_MINUTES=1
[[ "$mode" != timeout ]] || WAIT_MINUTES=0
PARTICIPANT_VMX=participant.vmx
PARTICIPANT_PASSWORD=test
guest_marker_exists() {{ (( poll >= 3 )); }}
guest_file_exists() {{ (( poll >= 3 )); }}
guest_bootstrap_failure_text() {{ return 0; }}
sample_phase() {{
    if [[ "$mode" == failed ]]; then echo 'failed: package installation';
    elif [[ "$mode" != unavailable ]]; then echo 'installing Kali XFCE and the default Kali tools'; fi
}}
sample_percent() {{
    if [[ "$mode" == unavailable ]]; then echo invalid; else echo 025; fi
}}
guest_phase() {{ sample_phase; }}
guest_file_text() {{
    case "$4" in
        */bootstrap-percent) sample_percent ;;
        /var/log/*) guest_last_log_line "$1" "$4" ;;
    esac
}}
guest_command_output() {{
    case "$3" in
        */bootstrap-status) sample_phase ;;
        */bootstrap-percent) sample_percent ;;
    esac
}}
guest_last_log_line() {{
    [[ "$mode" != unavailable ]] || return 0
    # Exercise the early Cloud-Init fallback before the role log exists.
    if (( poll < 2 )); then
        [[ "$2" != /var/log/cloud-init-output.log ]] || echo 'Unpacking x11-utils ...'
    else
        echo 'Setting up chromium ...'
    fi
}}
sleep() {{ poll=$((poll + 1)); }}
reinstall_wait_for_guest participant
'''
    result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=10)
    output = result.stdout + result.stderr
    if mode == 'failed':
        assert result.returncode != 0
        assert 'failed: package installation' in output
        assert 'ready after' not in output
    elif mode == 'timeout':
        assert result.returncode != 0
        assert 'reinstall timed out' in output
    else:
        assert result.returncode == 0, output
        assert 'elapsed ' in output
        assert 'ready after' in output
        if mode == 'progress':
            assert '[25%] installing Kali XFCE and the default Kali tools' in output
            assert output.count('Unpacking x11-utils ...') == 1
            assert output.count('Setting up chromium ...') == 1
        else:
            assert 'waiting for guest agent / Cloud-Init' in output
            assert '[0%]' not in output
            assert 'invalid' not in output


@pytest.mark.parametrize('platform', ['proxmox', 'vmware-workstation-linux', 'vmware-fusion-mac'])
@pytest.mark.parametrize('target,valid', [('core', True), ('app', True), ('participant', True), ('all', True), ('other', False)])
def test_reinstall_flag_parsing(platform, target, valid):
    installer = ROOT / 'scripts/provision' / platform / 'install-scenarioforge-lab.sh'
    result = subprocess.run(['bash', '-c', f'source {shlex.quote(str(installer))}\nparse_args --reinstall {target} --dry-run\necho "$COMMAND:$REINSTALL_TARGET:$DRY_RUN"'], capture_output=True, text=True)
    assert (result.returncode == 0) == valid, result.stderr
    if valid:
        assert result.stdout.strip() == f'reinstall:{target}:1'


@pytest.mark.parametrize('platform', ['vmware-workstation-linux', 'vmware-fusion-mac'])
@pytest.mark.parametrize('target', ['core', 'app', 'participant', 'all'])
@pytest.mark.parametrize('mode', ['run', 'preview', 'bad_cache', 'unowned'])
def test_unix_reinstall_scope_and_preflight(tmp_path, platform, target, mode):
    installer = ROOT / 'scripts/provision' / platform / 'install-scenarioforge-lab.sh'
    suffix = '.vmwarevm' if platform == 'vmware-fusion-mac' else ''
    lab = tmp_path / 'lab'
    lab.mkdir()
    events = tmp_path / 'events'
    for role in ('core', 'app', 'participant'):
        directory = lab / (f'scenarioforge-{role}' + suffix)
        directory.mkdir()
        (directory / 'original').write_text(role)
        owner = 'scenarioforge-vmware-fusion-v1' if suffix else 'scenarioforge-vmware-linux-v1'
        (directory / f'scenarioforge-{role}.vmx').write_text(
            f'scenarioforge.install.owner = "{owner if mode != "unowned" else "other"}"\n'
            'memsize = "4096"\nnumvcpus = "2"\n'
            'ethernet0.address = "00:50:56:00:00:10"\n')
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    qemu = bindir / 'qemu-img'
    qemu.write_text('#!/bin/sh\necho \'{"virtual-size":42949672960}\'\n')
    qemu.chmod(0o755)
    script = f'''
source {shlex.quote(str(installer))}
PATH={shlex.quote(str(bindir))}:"$PATH"
LAB_DIR={shlex.quote(str(lab))}
REINSTALL_TARGET={target}
DRY_RUN={int(mode == 'preview')}
ASSUME_YES=1
CORE_PASSWORD=core
APP_PASSWORD=app
PARTICIPANT_PASSWORD=participant
SCENARIOFORGE_ADMIN_PASSWORD=admin
INSTALL_COMPLETE=1
INSTALL_FLAG_GENERATORS=0
INSTALL_VULNHUB=0
PARTICIPANT_OS=debian
for prefix in CORE APP PARTICIPANT; do
    name="${{prefix}}_NAME"
    printf -v "${{prefix}}_DIR" '%s' "$LAB_DIR/${{!name}}$VM_BUNDLE_SUFFIX"
    printf -v "${{prefix}}_VMX" '%s' "$LAB_DIR/${{!name}}$VM_BUNDLE_SUFFIX/${{!name}}.vmx"
done
event() {{ printf '%s\\n' "$*" >> {shlex.quote(str(events))}; }}
load_state() {{ :; }}
require_linux_workstation() {{ :; }}
download_verified_image() {{ event "cache $4"; [[ {mode} != bad_cache ]]; }}
write_vmware_cloud_init_files() {{ event seed-inputs; }}
prepare_optional_content() {{ event catalogs; }}
write_state() {{ event "state $INSTALL_COMPLETE $PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED"; }}
vm_running() {{ return 1; }}
prepare_disk() {{ event "disk $2"; touch "$2"; }}
create_seed_iso() {{ event "seed $1"; touch "$3"; }}
append_guestinfo_cloud_init() {{ :; }}
start_vm() {{ event "start $1"; }}
transfer_optional_content_to_app() {{ event transfer; }}
reinstall_wait_for_guest() {{ event "wait $1"; }}
detach_participant_uplink() {{ event detach; PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=0; }}
perform_reinstall
'''
    result = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
    assert (result.returncode == 0) == (mode in ('run', 'preview')), result.stderr
    calls = events.read_text().splitlines() if events.exists() else []
    selected = ['core', 'app', 'participant'] if target == 'all' else [target]
    for role in ('core', 'app', 'participant'):
        directory = lab / (f'scenarioforge-{role}' + suffix)
        rebuilt = mode == 'run' and role in selected
        assert (directory / 'original').exists() != rebuilt
        assert (f'wait {role}' in calls) == rebuilt
        if rebuilt:
            vmx = (directory / f'scenarioforge-{role}.vmx').read_text()
            assert 'memsize = "4096"' in vmx
            assert 'ethernet0.address = "00:50:56:00:00:10"' in vmx
            if role == 'participant':
                assert 'ethernet1.connectionType = "nat"' in vmx
    assert ('detach' in calls) == (mode == 'run' and 'participant' in selected)
    assert ('catalogs' in calls) == (mode == 'run' and 'app' in selected)
    if mode != 'run':
        assert not any(call.startswith(('state ', 'start ', 'disk ')) for call in calls)


def test_proxmox_inventory_retains_hardware(tmp_path):
    path = tmp_path / 'config'
    path.write_text('memory: 8192\ncores: 2\nsockets: 2\nscsi0: local:vm-9403-disk-0,size=40G\nnet0: virtio=02:00:00:00:00:10,bridge=hitl\n')
    result = subprocess.run(['python3', str(COMMON / 'reinstall_inventory.py'), 'proxmox', 'participant', str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'PARTICIPANT_MEMORY_MB=8192' in result.stdout
    assert 'PARTICIPANT_CORES=4' in result.stdout
    assert 'PARTICIPANT_DISK_GB=40' in result.stdout
    assert 'PARTICIPANT_NET0_MAC=02:00:00:00:00:10' in result.stdout


@pytest.mark.parametrize('target', ['core', 'app', 'participant', 'all'])
@pytest.mark.parametrize('mode', [
    'run', 'preview', 'bad_cache', 'unowned', 'graceful',
    'shutdown_timeout', 'late_shutdown', 'stop_failed', 'still_running', 'ownership_changed',
])
def test_proxmox_reinstall_preserves_other_vmids_and_snippets(tmp_path, target, mode):
    installer = ROOT / 'scripts/provision/proxmox/install-scenarioforge-lab.sh'
    snippets = tmp_path / 'snippets'
    snippets.mkdir()
    for role in ('core', 'app', 'participant'):
        for kind in ('user', 'network'):
            (snippets / f'scenarioforge-{role}-{kind}.yaml').write_text('original')
    credentials = tmp_path / 'credentials'
    credentials.write_text('CORE_VM_PASSWORD=core\nAPP_VM_PASSWORD=app\nPARTICIPANT_VM_PASSWORD=participant\nSCENARIOFORGE_ADMIN_PASSWORD=admin\n')
    credentials.chmod(0o600)
    state = tmp_path / 'state'
    state.touch()
    events = tmp_path / 'events'
    script = f'''
source {shlex.quote(str(installer))}
STATE_FILE={shlex.quote(str(state))}
CREDENTIALS_FILE={shlex.quote(str(credentials))}
REINSTALL_TARGET={target}
DRY_RUN={int(mode == 'preview')}
ASSUME_YES=1
INSTALL_COMPLETE=1
PARTICIPANT_OS=debian
CORE_VMID=9401
APP_VMID=9402
PARTICIPANT_VMID=9403
event() {{ printf '%s\\n' "$*" >> {shlex.quote(str(events))}; }}
load_cleanup_scope() {{ :; }}
storage_config() {{ printf '{{"path":%s}}' {shlex.quote(json.dumps(str(tmp_path)))}; }}
ownership_changed=0
vm_owned_by_installer() {{ [[ {mode} != unowned && "$ownership_changed" == 0 ]]; }}
stopped_vmids=''
qm() {{
    case "$1" in
        config) printf 'memory: 4096\\ncores: 2\\nscsi0: local:disk,size=40G\\nnet0: virtio=02:00:00:00:00:10,bridge=hitl\\n' ;;
        status)
            case {mode} in
                graceful|shutdown_timeout|late_shutdown|stop_failed|still_running|ownership_changed)
                    if [[ " $stopped_vmids " == *" $2 "* ]]; then echo 'status: stopped'; else echo 'status: running'; fi ;;
                *) echo 'status: stopped' ;;
            esac ;;
        shutdown)
            event "qm $*"
            if [[ {mode} == ownership_changed ]]; then ownership_changed=1; fi
            if [[ {mode} == graceful || {mode} == late_shutdown ]]; then stopped_vmids="$stopped_vmids $2"; fi
            [[ {mode} == graceful ]] ;;
        stop)
            event "qm $*"
            [[ {mode} != stop_failed ]] || return 255
            if [[ {mode} != still_running ]]; then stopped_vmids="$stopped_vmids $2"; fi ;;
        *) event "qm $*" ;;
    esac
}}
download_verified_image() {{ event cache; [[ {mode} != bad_cache ]]; }}
prepare_optional_content() {{ event catalogs; }}
write_guest_bootstraps() {{ :; }}
write_cloud_init_files() {{
    for role in core app participant; do
        for kind in user network; do echo replacement > "$WORK_DIR/$role-$kind.yaml"; done
    done
}}
write_state() {{ event state; }}
transfer_optional_content_to_app() {{ event transfer; }}
reinstall_wait_for_guest() {{ event "wait $1"; }}
detach_participant_bootstrap_uplink() {{ event detach; }}
perform_reinstall
'''
    result = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
    rebuild = mode in ('run', 'graceful', 'shutdown_timeout', 'late_shutdown')
    assert (result.returncode == 0) == (rebuild or mode == 'preview'), result.stderr
    calls = events.read_text().splitlines() if events.exists() else []
    selected = ['core', 'app', 'participant'] if target == 'all' else [target]
    for role, vmid in [('core', 9401), ('app', 9402), ('participant', 9403)]:
        replaced = rebuild and role in selected
        assert (f'qm destroy {vmid} --purge 1' in calls) == replaced
        assert (f'qm start {vmid}' in calls) == replaced
        for kind in ('user', 'network'):
            text = (snippets / f'scenarioforge-{role}-{kind}.yaml').read_text()
            assert text == ('replacement\n' if replaced else 'original')
    assert ('detach' in calls) == (rebuild and 'participant' in selected)
    shutdown_vmids = [call.split()[2] for call in calls if call.startswith('qm shutdown ')]
    stop_vmids = [call.split()[2] for call in calls if call.startswith('qm stop ')]
    selected_vmids = [str({'core': 9401, 'app': 9402, 'participant': 9403}[role]) for role in selected]
    if mode in ('graceful', 'shutdown_timeout', 'late_shutdown'):
        assert shutdown_vmids == selected_vmids
        assert stop_vmids == (selected_vmids if mode == 'shutdown_timeout' else [])
        first_destroy = next(i for i, call in enumerate(calls) if call.startswith('qm destroy '))
        assert all(i < first_destroy for i, call in enumerate(calls) if call.startswith(('qm stop ', 'qm shutdown ')))
    elif mode in ('stop_failed', 'still_running', 'ownership_changed'):
        assert shutdown_vmids == selected_vmids[:1]
        assert stop_vmids == ([] if mode == 'ownership_changed' else selected_vmids[:1])
        assert 'state' not in calls
        assert not any(call.startswith(('qm destroy ', 'qm start ')) for call in calls)
        assert any(message in result.stderr for message in ('not stopped', 'Could not stop', 'VM ownership changed'))
    else:
        assert shutdown_vmids == stop_vmids == []
    if mode in ('preview', 'bad_cache', 'unowned'):
        assert not any(call.startswith('qm ') or call == 'state' for call in calls)
