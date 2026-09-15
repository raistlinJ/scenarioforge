"""Secure Boot approval, early exit, and signing with isolated fake host tools."""
from pathlib import Path
import os
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'scripts/provision/vmware-workstation-linux/install-scenarioforge-lab.sh'
HELPER = INSTALLER.with_name('secure-boot.sh')


def probe(body):
    return subprocess.run(['bash', '-c', f'source {shlex.quote(str(INSTALLER))}\n' + body],
                          text=True, capture_output=True)


BASE = '''
workstation_module_loaded() { return 1; }
workstation_secure_boot_enabled() { return 0; }
modinfo() { [[ "$1" != -n ]] || echo /fake/module.ko; }
sudo() { echo UNEXPECTED_MUTATION; return 99; }
'''


def test_loaded_modules_do_not_require_signing_or_sudo():
    result = probe(BASE + '''
workstation_module_loaded() { return 0; }
ensure_vmware_kernel_modules
''')
    assert result.returncode == 0, result.stderr
    assert 'UNEXPECTED' not in result.stdout


@pytest.mark.parametrize('mode', ['dry_run', 'yes', 'decline'])
def test_signing_requires_explicit_interactive_approval(mode):
    setup = {'dry_run': 'DRY_RUN=1', 'yes': 'ASSUME_YES=1',
             'decline': 'workstation_approve_module_signing() { return 1; }'}[mode]
    result = probe(BASE + setup + '\nensure_vmware_kernel_modules\n')
    assert result.returncode != 0
    assert 'UNEXPECTED' not in result.stdout
    assert ('dry run stopped' if mode == 'dry_run' else 'not approved') in result.stderr


@pytest.mark.parametrize('status', [0, 20, 1])
def test_approved_signing_handles_enrolled_pending_and_failed(status):
    result = probe(BASE + f'''
workstation_approve_module_signing() {{ return 0; }}
sudo() {{
    if [[ "$1" == bash ]]; then echo SIGNING_APPROVED; return {status}; fi
    echo MODULE_LOADED
}}
ensure_vmware_kernel_modules
echo CONTINUE_INSTALL
''')
    assert 'SIGNING_APPROVED' in result.stdout
    if status == 0:
        assert result.returncode == 0, result.stderr
        assert result.stdout.count('MODULE_LOADED') == 2
        assert 'CONTINUE_INSTALL' in result.stdout
    else:
        assert result.returncode != 0
        assert 'MODULE_LOADED' not in result.stdout
        assert 'CONTINUE_INSTALL' not in result.stdout
        if status == 20:
            assert 'Enroll MOK' in result.stdout
            assert 'enrollment pending' in result.stderr
        else:
            assert 'signing/enrollment failed' in result.stderr


def test_other_module_failure_does_not_offer_signing():
    result = probe(BASE + '''
modinfo() { echo existing-signer; }
sudo() { echo 'Unknown symbol in module'; return 1; }
workstation_approve_module_signing() { echo UNEXPECTED_APPROVAL; return 0; }
ensure_vmware_kernel_modules
''')
    assert result.returncode != 0
    assert 'Unknown symbol' in result.stderr
    assert 'UNEXPECTED_APPROVAL' not in result.stdout


def test_missing_module_stops_before_approval():
    result = probe(BASE + '''
modinfo() { return 1; }
ensure_vmware_kernel_modules
''')
    assert result.returncode != 0
    assert 'module vmmon is missing' in result.stderr
    assert 'UNEXPECTED' not in result.stdout


def signing_fixture(tmp_path):
    """Run real OpenSSL in a private temp dir; emulate signing and EFI writes."""
    key_dir = tmp_path / 'keys'
    module_dir = tmp_path / 'modules/test-kernel'
    sign_tool = module_dir / 'build/scripts/sign-file'
    sign_tool.parent.mkdir(parents=True)
    sign_tool.write_text('#!/bin/sh\nprintf "%s\\n" "$4" >> "$TEST_TRACE"\n')
    sign_tool.chmod(0o700)
    for module in ['vmmon', 'vmnet']:
        (module_dir / f'{module}.ko').write_text('original module')
    script = tmp_path / 'helper.sh'
    script.write_text(HELPER.read_text().replace('/var/lib/scenarioforge-vmware-secure-boot', str(key_dir))
                      .replace('/lib/modules/', str(tmp_path / 'modules') + '/'))
    trace = tmp_path / 'trace'
    shell = f'''
source {shlex.quote(str(script))}
uname() {{ echo test-kernel; }}
modinfo() {{ echo {shlex.quote(str(module_dir))}/"$2".ko; }}
# Emulate root ownership/install on a macOS test host without elevation.
stat() {{ echo 0:700; }}
install() {{ mkdir -m 700 "$8"; }}
mokutil() {{
    case "$1" in
        --test-key) [[ "$TEST_ENROLLED" == 1 ]] ;;
        --list-new)
            if [[ "$TEST_PENDING" == 1 ]]; then
                openssl x509 -inform DER -in {shlex.quote(str(key_dir / 'MOK.der'))} -fingerprint -sha1 -noout
            fi ;;
        --import) echo IMPORT >> "$TEST_TRACE" ;;
        *) return 1 ;;
    esac
}}
workstation_sign_modules_as_root
'''
    env = dict(os.environ, TEST_TRACE=str(trace), TEST_ENROLLED='0', TEST_PENDING='0')
    return shell, env, key_dir, trace


def test_signing_reuses_key_and_handles_pending_then_enrolled(tmp_path):
    shell, env, key_dir, trace = signing_fixture(tmp_path)
    result = subprocess.run(['bash', '-c', shell], env=env, capture_output=True, text=True)
    assert result.returncode == 20, result.stderr
    original_key = (key_dir / 'MOK.priv').read_bytes()
    assert (key_dir.stat().st_mode & 0o777) == 0o700
    assert (key_dir / 'MOK.priv').stat().st_mode & 0o077 == 0
    assert trace.read_text().count('IMPORT') == 1
    assert len(list(key_dir.glob('*.before-signing'))) == 2

    env['TEST_PENDING'] = '1'
    result = subprocess.run(['bash', '-c', shell], env=env, capture_output=True, text=True)
    assert result.returncode == 20, result.stderr
    assert trace.read_text().count('IMPORT') == 1
    assert (key_dir / 'MOK.priv').read_bytes() == original_key

    env['TEST_ENROLLED'] = '1'
    result = subprocess.run(['bash', '-c', shell], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert trace.read_text().count('IMPORT') == 1


def test_incomplete_key_is_preserved_without_signing(tmp_path):
    shell, env, key_dir, trace = signing_fixture(tmp_path)
    key_dir.mkdir(mode=0o700)
    (key_dir / 'MOK.priv').write_text('preserve me')
    result = subprocess.run(['bash', '-c', shell], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert 'Incomplete signing key pair' in result.stderr
    assert (key_dir / 'MOK.priv').read_text() == 'preserve me'
    assert not trace.exists()


def test_module_signing_failure_does_not_request_enrollment(tmp_path):
    shell, env, key_dir, trace = signing_fixture(tmp_path)
    sign_tool = tmp_path / 'modules/test-kernel/build/scripts/sign-file'
    sign_tool.write_text('#!/bin/sh\nexit 17\n')
    result = subprocess.run(['bash', '-c', shell], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert not trace.exists()
    assert (key_dir / 'test-kernel-vmmon.ko.before-signing').exists()


def test_signing_directory_symlink_is_rejected(tmp_path):
    shell, env, key_dir, trace = signing_fixture(tmp_path)
    target = tmp_path / 'elsewhere'
    target.mkdir()
    key_dir.symlink_to(target, target_is_directory=True)
    result = subprocess.run(['bash', '-c', shell], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert 'Refusing symlink' in result.stderr
    assert not list(target.iterdir())
    assert not trace.exists()


def test_key_rejection_offers_approved_repair():
    result = probe(BASE + '''
modinfo() { echo existing-signer; }
workstation_approve_module_signing() { return 0; }
sudo() {
    if [[ "$1" == bash ]]; then echo SIGNING_APPROVED; return 20; fi
    echo 'modprobe: ERROR: could not insert vmnet: Key was rejected by service' >&2
    return 1
}
ensure_vmware_kernel_modules
''')
    assert result.returncode != 0
    assert 'SIGNING_APPROVED' in result.stdout
    assert 'enrollment pending' in result.stderr
