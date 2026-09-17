"""Native image preparation, using real ISOs and small real disks when available."""
import base64
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/provision/vmware-workstation-windows'
spec = importlib.util.spec_from_file_location('windows_image_builder', SOURCE / 'prepare-images.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def test_windows_powershell_regressions():
    pwsh = os.environ.get('SF_TEST_PWSH') or shutil.which('pwsh')
    if not pwsh:
        pytest.skip('PowerShell regressions run in the dedicated Windows CI job')
    result = subprocess.run([pwsh, '-NoProfile', '-File', str(ROOT / 'tests/test_vmware_windows.ps1')],
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture
def config(tmp_path):
    pytest.importorskip('pycdlib', reason='Native builder requirements are installed in Windows CI')
    pytest.importorskip('passlib')
    request = json.loads((SOURCE / 'scenarioforge-lab.json.example').read_text())
    lab = tmp_path / 'Windows lab with spaces'
    lab.mkdir()
    request.update(participant_disk_gb=20, lab_dir=str(lab), image_cache=str(tmp_path / 'cache'), qemu_img='qemu-img',
                   install_id='windows-test-owner', core_password='core $literal', app_password='app password',
                   participant_password='participant password', web_admin_password='web password')
    return request


def test_shared_guest_bodies_are_read_without_running_bash(monkeypatch):
    monkeypatch.setattr(builder.subprocess, 'run', lambda *a, **k: pytest.fail('No host shell may execute'))
    scripts = builder.guest_scripts()
    assert 'CORE_MINIMAL_REF' in scripts['core']
    assert '--from-source "$CORE_REPO_URL" "$CORE_REPO_REF"' in scripts['core']
    assert 'CORETG_VM_MODE_HITL_CORE_IFX_NAME=ens19' in scripts['app']
    assert 'participant-ready' in scripts['participant']
    assert 'After=network-online.target\n' in scripts['participant']
    assert 'After=network-online.target cloud-final.service' not in scripts['participant']
    assert all(script.startswith('#!/usr/bin/env bash\n') for script in scripts.values())


def test_missing_shared_template_fails_explicitly(tmp_path):
    missing = tmp_path / 'empty.sh'
    missing.write_text('changed template')
    with pytest.raises(builder.BuildError, match='shared core bootstrap'):
        builder.guest_scripts(missing)


def read_iso(path):
    import pycdlib
    iso = pycdlib.PyCdlib()
    iso.open(str(path))
    try:
        assert iso.pvd.volume_identifier.decode().strip() == 'cidata'
        data = {}
        for name in ('user-data', 'meta-data', 'network-config'):
            rr = io.BytesIO()
            joliet = io.BytesIO()
            iso.get_file_from_iso_fp(rr, rr_path='/' + name)
            iso.get_file_from_iso_fp(joliet, joliet_path='/' + name)
            assert rr.getvalue() == joliet.getvalue()
            data[name] = json.loads(rr.getvalue().decode().removeprefix('#cloud-config\n'))
        return data
    finally:
        iso.close()


@pytest.mark.parametrize('participant_os', ['debian', 'kali'])
@pytest.mark.parametrize('catalogs', [False, True])
def test_native_builder_creates_real_seed_isos_and_portable_vmx(config, monkeypatch, tmp_path, catalogs, participant_os):
    from passlib.hash import sha512_crypt
    config.update(flag_generators=catalogs, vulnhub=catalogs, participant_os=participant_os,
                  participant_disk_gb=40 if participant_os == 'kali' else 20)
    lab = Path(config['lab_dir'])
    monkeypatch.setattr(builder, 'download_verified', lambda *args: tmp_path / 'fake.qcow2')
    disk_calls = []
    def prepare(qemu, image, disk, size, work, source_format='qcow2'):
        disk_calls.append((disk.parent.name, image, source_format, size))
        disk.write_bytes(b'fake disk')
    monkeypatch.setattr(builder, 'prepare_disk', prepare)
    monkeypatch.setattr(builder, 'extract_kali_disk', lambda *args: tmp_path / 'kali.raw')
    monkeypatch.setattr(builder, 'prepare_catalogs', lambda *args: ('catalog-checksum', 'catalog-commit') if catalogs else ('', ''))
    monkeypatch.setattr(builder.subprocess, 'run', lambda *a, **k: pytest.fail('Host Bash must not be needed'))
    builder.prepare_images(config, tmp_path)
    participant_call = next(call for call in disk_calls if call[0] == 'scenarioforge-participant')
    assert participant_call[2] == ('raw' if participant_os == 'kali' else 'qcow2')
    assert next(call for call in disk_calls if call[0] == 'scenarioforge-core')[2] == 'qcow2'
    assert next(call for call in disk_calls if call[0] == 'scenarioforge-app')[2] == 'vmdk'
    for role in ('core', 'app', 'participant'):
        vmx = lab / f'scenarioforge-{role}/scenarioforge-{role}.vmx'
        text = vmx.read_text()
        assert str(tmp_path) not in text
        assert 'floppy0.present = "FALSE"' in text
        assert 'floppy0.startConnected = "FALSE"' in text
        assert 'serial0.present = "TRUE"' in text
        assert 'serial0.fileType = "file"' in text
        assert 'serial0.fileName = "serial-console.log"' in text
        assert 'answer.msg.serial.file.open = "Append"' in text
        assert 'scenarioforge.install.owner = "windows-test-owner"' in text
        assert vmx.with_name('.scenarioforge-owner').read_text().strip() == 'windows-test-owner'
        values = dict(line.split(' = ', 1) for line in text.splitlines() if ' = ' in line)
        userdata = json.loads(gzip.decompress(base64.b64decode(values['guestinfo.userdata'].strip('"'))).decode().removeprefix('#cloud-config\n'))
        metadata = json.loads(gzip.decompress(base64.b64decode(values['guestinfo.metadata'].strip('"'))))
        seed = read_iso(vmx.with_name(f'scenarioforge-{role}-cidata.iso'))
        assert seed['user-data'] == userdata
        assert seed['network-config'] == metadata['network']
        assert seed['meta-data']['instance-id'] == metadata['instance-id']
        assert metadata['redact'] == ['userdata']
        assert 'open-vm-tools' in userdata['packages']
        assert 'qemu-guest-agent' not in userdata['packages']
        assert sha512_crypt.verify(config[role + '_password'], userdata['users'][0]['passwd'])
        guest = next(f for f in userdata['write_files'] if f['path'].endswith(f'{role}-bootstrap'))
        assert base64.b64decode(guest['content']).decode() == builder.guest_scripts()[role]
        if role == 'participant':
            assert values['memsize'] == '"2048"'
            if participant_os == 'kali':
                assert values['nvme0.present'] == '"TRUE"'
                assert 'scsi0.present' not in values
            assert values['ethernet0.vnet'] == '"vmnet2"'
            assert values['ethernet1.connectionType'] == '"nat"'
        if role == 'core':
            assert metadata['network']['ethernets']['hitl']['set-name'] == 'ens19'
        if role == 'app':
            env = next(f for f in userdata['write_files'] if f['path'] == '/etc/scenarioforge-installer.env')
            decoded = base64.b64decode(env['content']).decode()
            assert f'INSTALL_FLAG_GENERATORS={int(catalogs)}' in decoded
            assert f'INSTALL_VULNHUB={int(catalogs)}' in decoded
            if catalogs:
                assert 'OPTIONAL_CONTENT_SHA256=catalog-checksum' in decoded
    with pytest.raises(builder.BuildError, match='VM destination already exists'):
        builder.prepare_images(config, tmp_path)


def test_network_layout_matches_guest_interfaces(config):
    for role, count in [('core', 3), ('app', 2), ('participant', 2)]:
        macs = [f'00:50:56:00:00:{i:02x}' for i in range(count)]
        networks, net = builder.network_layout(role, config, macs)
        assert len(networks) == count
        interfaces = list(net['ethernets'].values())
        assert [nic['match']['macaddress'] for nic in interfaces] == macs
        assert [nic['set-name'] for nic in interfaces] == ['ens' + str(18 + i) for i in range(count)]
    _, net = builder.network_layout('participant', config, ['mac0', 'mac1'])
    assert not net['ethernets']['participant']['dhcp4']
    assert net['ethernets']['participant']['routes'] == [
        {'to': '0.0.0.0/0', 'via': builder.CORE_HITL_CIDR.split('/')[0], 'metric': 2000}
    ]
    assert net['ethernets']['bootstrap-uplink']['dhcp4'] is True


@pytest.mark.parametrize('source_format', ['qcow2', 'raw', 'vmdk'])
def test_native_qemu_converts_and_grows_without_modifying_base(tmp_path, source_format):
    qemu = shutil.which('qemu-img')
    if not qemu:
        pytest.skip('Real qemu-img validation requires QEMU; command construction is tested separately')
    base = tmp_path / ('base disk.' + source_format)
    destination = tmp_path / 'guest disk.vmdk'
    if source_format == 'vmdk':
        raw = tmp_path / 'seed.raw'
        with raw.open('wb') as stream:
            stream.write(b'ScenarioForge disk contents' * 100)
            stream.truncate(16 * 1024 ** 2)
        subprocess.run([qemu, 'convert', '-f', 'raw', '-O', 'vmdk', '-o', 'subformat=streamOptimized',
                        str(raw), str(base)], check=True, capture_output=True)
    else:
        subprocess.run([qemu, 'create', '-f', source_format, str(base), '16M'], check=True, capture_output=True)
    original_hash = builder.file_hash(base)
    builder.prepare_disk(qemu, base, destination, 1, tmp_path, source_format=source_format)
    assert builder.file_hash(base) == original_hash
    info = json.loads(subprocess.check_output([qemu, 'info', '--output=json', str(destination)], text=True))
    assert info['format'] == 'vmdk'
    assert info['virtual-size'] == 1024 ** 3
    assert 'backing-filename' not in info
    assert not (tmp_path / 'resize.qcow2').exists()
    subprocess.run([qemu, 'compare', '-f', source_format, '-F', 'vmdk', str(base), str(destination)],
                   check=True, capture_output=True)


def test_disk_resize_uses_argv_and_disposable_overlay(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(builder, 'run', lambda args, **kwargs: calls.append([str(arg) for arg in args]))
    base = tmp_path / 'base with spaces.qcow2'
    dest = tmp_path / 'target.vmdk'
    builder.prepare_disk('C:/Program Files/qemu/qemu-img.exe', base, dest, 80, tmp_path)
    assert calls[0][1:] == ['create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(tmp_path / 'resize.qcow2')]
    assert calls[1][1:] == ['resize', str(tmp_path / 'resize.qcow2'), '80G']
    assert calls[2][-2:] == [str(tmp_path / 'resize.qcow2'), str(dest)]


@pytest.mark.parametrize('bad', [False, True])
def test_download_cache_checks_hash_and_never_keeps_partial_files(tmp_path, monkeypatch, bad):
    payload = b'test cloud image'
    expected = builder.hashlib.sha256(payload).hexdigest()
    def response(url, **kwargs):
        return io.BytesIO((expected + '  image.qcow2\n').encode() if url.endswith('SUMS') else (b'corrupt' if bad else payload))
    monkeypatch.setattr(builder.urllib.request, 'urlopen', response)
    monkeypatch.setattr(builder.time, 'sleep', lambda _: None)
    if bad:
        with pytest.raises(builder.BuildError, match='Checksum verification failed'):
            builder.download_verified('https://images/image.qcow2', 'https://images/SUMS', 'sha256', tmp_path)
        assert not (tmp_path / 'image.qcow2').exists()
    else:
        path = builder.download_verified('https://images/image.qcow2', 'https://images/SUMS', 'sha256', tmp_path)
        assert path.read_bytes() == payload
        # A verified cached image only needs the checksum list on the next run.
        monkeypatch.setattr(builder.urllib.request, 'urlopen', lambda url, **kw: io.BytesIO((expected + '  image.qcow2').encode()) if url.endswith('SUMS') else pytest.fail('Unnecessary image download'))
        assert builder.download_verified('https://images/image.qcow2', 'https://images/SUMS', 'sha256', tmp_path) == path
    assert not list(tmp_path.glob('*.part'))


def test_optional_catalog_archive_preserves_unix_mode_without_checkout(config, tmp_path, monkeypatch):
    monkeypatch.setenv('GIT_CONFIG_COUNT', '1')
    monkeypatch.setenv('GIT_CONFIG_KEY_0', 'core.autocrlf')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0', 'true')
    git = shutil.which('git')
    if not git:
        pytest.skip('Git is needed for optional catalog tests')
    repository = tmp_path / 'fixture repo'
    repository.mkdir()
    subprocess.run([git, 'init', str(repository)], check=True, capture_output=True)
    for name in ('flag_generators', 'flag_node_generators', 'vulnhub/content'):
        directory = repository / name
        directory.mkdir(parents=True)
        (directory / 'run.sh').write_bytes(b'#!/bin/sh\necho fixture\n')
    (repository / 'pack.json').write_text('{}')
    prefix = [git, '-C', str(repository)]
    subprocess.run(prefix + ['-c', 'core.autocrlf=false', 'add', '.'], check=True)
    subprocess.run(prefix + ['update-index', '--chmod=+x', 'flag_generators/run.sh'], check=True)
    subprocess.run(prefix + ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture'], check=True, capture_output=True)
    commit = subprocess.check_output(prefix + ['rev-parse', 'HEAD'], text=True).strip()
    monkeypatch.setattr(builder, 'CATALOG_URL', str(repository))
    config.update(flag_generators=True, vulnhub=True, git_exe=git, flag_generators_ref=commit)
    work = tmp_path / 'work'
    work.mkdir()
    checksum, actual_commit = builder.prepare_catalogs(config, work, Path(config['lab_dir']))
    archive = Path(config['lab_dir']) / 'scenarioforge-optional-content.tar.gz'
    assert checksum == builder.file_hash(archive)
    assert actual_commit == commit
    with tarfile.open(archive) as tar:
        assert tar.getmember('flag_generators/run.sh').mode & 0o111
        assert tar.extractfile('flag_generators/run.sh').read() == b'#!/bin/sh\necho fixture\n'
        assert tar.extractfile('pack.json').read() == b'{}'
        assert tar.getmember('vulnhub/content/run.sh')


def test_public_builder_does_not_invoke_git(config, monkeypatch, tmp_path):
    config.update(flag_generators=False, vulnhub=False)
    monkeypatch.setattr(builder, 'run', lambda *args, **kwargs: pytest.fail('Public install must not access Git catalogs'))
    assert builder.prepare_catalogs(config, tmp_path, Path(config['lab_dir'])) == ('', '')


def test_native_installer_has_no_wsl_or_host_bash_dependency():
    script = (SOURCE / 'install-scenarioforge-lab.ps1').read_text()
    assert 'wsl.exe' not in script.lower()
    assert 'wsl_distribution' not in script
    assert 'prepare-images.py' in script
    assert not (SOURCE / 'prepare-images.sh').exists()
    config = json.loads((SOURCE / 'scenarioforge-lab.json.example').read_text())
    assert config['desktop_shortcut'] is True
    assert 'python_exe' in config and 'qemu_img' in config


@pytest.mark.parametrize('member_type', ['regular', 'symlink', 'missing'])
def test_kali_archive_extraction(tmp_path, member_type):
    archive = tmp_path / 'kali.tar.xz'
    payload = b'header' + bytes(2 * 1024 * 1024) + b'tail'
    with tarfile.open(archive, 'w:xz') as tar:
        member = tarfile.TarInfo('missing.raw' if member_type == 'missing' else 'disk.raw')
        if member_type == 'symlink':
            member.type = tarfile.SYMTYPE
            member.linkname = '/outside'
            tar.addfile(member)
        else:
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))
    if member_type == 'regular':
        disk = builder.extract_kali_disk(archive, tmp_path)
        assert disk.read_bytes() == payload
    else:
        with pytest.raises(builder.BuildError, match='regular disk.raw'):
            builder.extract_kali_disk(archive, tmp_path)
        assert not (tmp_path / 'kali-disk.raw').exists()


def test_invalid_kali_archive_has_clear_error(tmp_path):
    archive = tmp_path / 'bad.tar.xz'
    archive.write_bytes(b'not an archive')
    with pytest.raises(builder.BuildError, match='Could not extract Kali'):
        builder.extract_kali_disk(archive, tmp_path)


def test_cyber_agent_flow_kali_has_dedicated_llm_nic_and_route(config, monkeypatch, tmp_path):
    config.update(cyber_agent_flow=True, participant_os='kali', participant_disk_gb=40,
                  flag_generators=False, vulnhub=False,
                  llm_provider_address='203.0.113.20', llm_provider_url='http://203.0.113.20:11434',
                  llm_interface_cidr='192.168.80.10/24', llm_gateway='192.168.80.2', llm_vmnet='vmnet8')
    monkeypatch.setattr(builder, 'download_verified', lambda *args: tmp_path / 'image')
    monkeypatch.setattr(builder, 'extract_kali_disk', lambda *args: tmp_path / 'kali.raw')
    monkeypatch.setattr(builder, 'prepare_disk', lambda *args, **kwargs: args[2].write_bytes(b'disk'))
    builder.prepare_images(config, tmp_path)
    directory = Path(config['lab_dir']) / 'scenarioforge-participant'
    vmx = (directory / 'scenarioforge-participant.vmx').read_text()
    assert 'ethernet1.connectionType = "nat"' in vmx
    assert 'ethernet2.vnet = "vmnet8"' in vmx
    seed = read_iso(directory / 'scenarioforge-participant-cidata.iso')
    llm = seed['network-config']['ethernets']['llm']
    assert llm['set-name'] == 'ens20' and llm['dhcp4'] is False
    assert llm['routes'] == [{'to': '203.0.113.20/32', 'via': '192.168.80.2'}]
    assert f'ethernet2.address = "{llm["match"]["macaddress"]}"' in vmx
    guest = next(f for f in seed['user-data']['write_files'] if f['path'].endswith('participant-bootstrap'))
    bootstrap = base64.b64decode(guest['content']).decode()
    assert 'cyber-agent-flow.git' in bootstrap
    assert 'ip -4 route get 203.0.113.20' in bootstrap
