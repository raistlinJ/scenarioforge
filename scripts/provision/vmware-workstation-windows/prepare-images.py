#!/usr/bin/env python3
"""Native Windows image preparation. No host Bash, WSL, or Linux tools.

Only qemu-img (and git for optional catalogs) are executed. Quoted guest-script
heredocs are read as text from the shared installer and run later inside VMs.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import tarfile
import time
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'common'))
import cyber_agent_flow as caf
import image_cache
SHARED = HERE.parent / 'proxmox' / 'install-scenarioforge-lab.sh'
TESTED_CATALOG_COMMIT = '5f612eecb8ff5df74a0e517d0de1e54385a62044'
CORE_HITL_CIDR = '10.254.200.3/24'
CATALOG_URL = 'https://github.com/raistlinJ/flag-generators.git'
IMAGES = {
    'debian': ('https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2',
               'https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS', 'sha512'),
    'kali': ('https://kali.download/cloud-images/kali-2026.2/kali-linux-2026.2-cloud-genericcloud-amd64.tar.xz',
             'https://kali.download/cloud-images/kali-2026.2/SHA256SUMS', 'sha256'),
    'ubuntu': ('https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.vmdk',
               'https://cloud-images.ubuntu.com/noble/current/SHA256SUMS', 'sha256'),
}


class BuildError(RuntimeError):
    pass


def run(args, *, capture=False, allow_failure=False):
    # Arguments are an argv list, never shell code. No guest passwords are passed.
    result = subprocess.run([str(arg) for arg in args], shell=False, check=False,
                            capture_output=capture, text=True)
    if result.returncode and not allow_failure:
        raise BuildError(f'{Path(args[0]).name} failed (exit {result.returncode}). See its output above.')
    return result


def guest_scripts(source=SHARED):
    text = Path(source).read_text(encoding='utf-8')
    scripts = {}
    for role in ('core', 'app', 'participant'):
        delimiter = role.upper() + '_SCRIPT'
        pattern = (r'cat > "\$WORK_DIR/' + role + r'-bootstrap\.sh" <<\'' + delimiter
                   + r"'\n(.*?)\n" + delimiter + r'\n')
        matches = re.findall(pattern, text, re.DOTALL)
        if len(matches) != 1:
            raise BuildError(f'Could not locate the shared {role} bootstrap. Keep the full repository checkout together.')
        scripts[role] = matches[0] + '\n'
    return scripts


def check_dependencies(qemu_img, git=None):
    if sys.version_info < (3, 11):
        raise BuildError('Windows Python 3.11 or newer is required.')
    try:
        import pycdlib  # noqa: F401
        from passlib.hash import sha512_crypt
        sha512_crypt.set_backend('builtin')  # Works without Unix crypt/OpenSSL.
    except ImportError as exc:
        raise BuildError('Install requirements-installer.txt into the selected Windows Python environment.') from exc
    guest_scripts()
    run([qemu_img, '--version'])
    if git:
        run([git, '--version'])


def file_hash(path, algorithm='sha256'):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def download_verified(url, sums_url, algorithm, cache, *, cached_only=False):
    filename = url.rsplit('/', 1)[-1]
    if cached_only:
        return image_cache.require_cached(Path(cache) / filename, url, algorithm, sums_url)
    with urllib.request.urlopen(sums_url, timeout=60) as response:
        checksums = response.read().decode('utf-8')
    expected = None
    for line in checksums.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip('*').removeprefix('./') == filename:
            expected = parts[0].lower()
            break
    if not expected or not re.fullmatch(r'[a-f0-9]{' + str(hashlib.new(algorithm).digest_size * 2) + '}', expected):
        raise BuildError(f'No valid {algorithm} checksum found for {filename}.')
    cache = Path(cache)
    destination = cache / filename
    if destination.is_file() and file_hash(destination, algorithm) == expected:
        image_cache.remember(destination, url, algorithm, expected)
        print(f'Using verified cached image {filename}', flush=True)
        return destination
    cache.mkdir(parents=True, exist_ok=True)
    for attempt in range(3):
        temporary = None
        try:
            print(f'Downloading {filename} (attempt {attempt + 1}/3)...', flush=True)
            with tempfile.NamedTemporaryFile(dir=cache, suffix='.part', delete=False) as output:
                temporary = Path(output.name)
                with urllib.request.urlopen(url, timeout=60) as response:
                    shutil.copyfileobj(response, output, length=1024 * 1024)
            if file_hash(temporary, algorithm) != expected:
                raise BuildError(f'Checksum verification failed for {filename}.')
            os.replace(temporary, destination)
            image_cache.remember(destination, url, algorithm, expected)
            return destination
        except (OSError, BuildError):
            if attempt == 2:
                raise
            time.sleep(2)
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)


def extract_kali_disk(archive, work):
    """Copy only the regular disk.raw member, never archive-controlled paths."""
    destination = work / 'kali-disk.raw'
    try:
        with tarfile.open(archive, 'r:xz') as tar:
            members = [member for member in tar.getmembers() if member.name == 'disk.raw']
            if len(members) != 1 or not members[0].isreg():
                raise BuildError('Kali archive must contain one regular disk.raw.')
            with tar.extractfile(members[0]) as source, destination.open('wb') as output:
                # Skip writing zero blocks in the cloud image. Filesystems that
                # support holes can retain a sparse file with identical bytes.
                while block := source.read(1024 * 1024):
                    if block.count(0) == len(block):
                        output.seek(len(block), os.SEEK_CUR)
                    else:
                        output.write(block)
                output.truncate(members[0].size)
        return destination
    except (tarfile.TarError, OSError, BuildError) as exc:
        destination.unlink(missing_ok=True)
        raise BuildError(f'Could not extract Kali disk.raw: {exc}') from exc


def prepare_catalogs(config, work, lab):
    if not (config['flag_generators'] or config['vulnhub']):
        return '', ''
    git = config.get('git_exe') or 'git.exe'
    ref = config['flag_generators_ref']
    if not ref or ref.startswith('-'):
        raise BuildError('flag_generators_ref must be a Git reference or commit, not an option.')
    repository = work / 'catalog.git'
    run([git, 'init', '--bare', repository], capture=True)
    prefix = [git, '--git-dir=' + str(repository)]
    print(f'Fetching optional catalogs at {ref} using Windows Git credentials...', flush=True)
    run(prefix + ['fetch', '--depth=1', CATALOG_URL, ref])
    commit = run(prefix + ['rev-parse', 'FETCH_HEAD'], capture=True).stdout.strip()
    selected = []
    for enabled, directories in ((config['flag_generators'], ['flag_generators', 'flag_node_generators']),
                                 (config['vulnhub'], ['vulnhub/content'])):
        if not enabled:
            continue
        for directory in directories:
            result = run(prefix + ['cat-file', '-t', 'FETCH_HEAD:' + directory], capture=True, allow_failure=True)
            if result.returncode or result.stdout.strip() != 'tree':
                raise BuildError(f'Optional catalog is missing directory {directory}.')
            selected.append(directory.split('/')[0])
    if config['flag_generators']:
        result = run(prefix + ['cat-file', '-t', 'FETCH_HEAD:pack.json'], capture=True, allow_failure=True)
        if result.returncode == 0 and result.stdout.strip() == 'blob':
            selected.append('pack.json')
        elif commit == TESTED_CATALOG_COMMIT:
            raise BuildError('The tested catalog snapshot is missing pack.json.')
    raw_archive = work / 'catalog.tar'
    # git archive preserves Unix executable bits and symlinks without a Windows
    # checkout or tar executable. It also avoids CRLF conversion in guest scripts.
    run(prefix + ['-c', 'core.autocrlf=false', '-c', 'core.eol=lf',
                  'archive', '--format=tar', '--output=' + str(raw_archive), 'FETCH_HEAD', '--', *selected])
    archive = lab / 'scenarioforge-optional-content.tar.gz'
    with raw_archive.open('rb') as source, gzip.open(archive, 'wb') as output:
        shutil.copyfileobj(source, output)
    return file_hash(archive), commit


def shell_environment(values):
    return ''.join(f'{key}={shlex.quote(str(value))}\n' for key, value in values.items())


def cloud_config(role, config, script, checksum='', commit=''):
    from passlib.hash import sha512_crypt
    sha512_crypt.set_backend('builtin')
    user_name = {'core': 'corevm', 'app': 'scenarioforge', 'participant': 'participant'}[role]
    user = dict(name=user_name, groups=['sudo'], shell='/bin/bash', sudo='ALL=(ALL) ALL', lock_passwd=False,
                passwd=sha512_crypt.using(rounds=5000).hash(config[role + '_password']))
    if config.get('ssh_public_key'):
        keys = [line.strip() for line in Path(config['ssh_public_key']).read_text(encoding='utf-8-sig').splitlines()
                if line.strip() and not line.startswith('#')]
        if not keys or any(not re.match(r'^(ssh-|ecdsa-|sk-)[^ ]+ [A-Za-z0-9+/=]+(?: |$)', key) for key in keys):
            raise BuildError('ssh_public_key must contain OpenSSH public keys, not a private key.')
        user['ssh_authorized_keys'] = keys
    files = []
    if role != 'participant':
        values = dict(SCENARIOFORGE_URL='https://github.com/raistlinJ/scenarioforge.git',
                      SCENARIOFORGE_REF=config['scenarioforge_ref'], CORE_MANAGEMENT_IP='172.31.250.3')
        if role == 'core':
            values.update(CORE_MINIMAL_URL='https://github.com/raistlinJ/coreemu-minimal.git',
                          CORE_MINIMAL_REF=config['core_minimal_ref'], CORE_REPO_URL='https://github.com/raistlinJ/core.git',
                          CORE_REPO_REF=config['core_ref'], CORE_USE_SYSTEMD_RESOLVED_STUB=1)
        else:
            values.update(CORE_HITL_CIDR=CORE_HITL_CIDR, CORE_PASSWORD=config['core_password'],
                          SCENARIOFORGE_ADMIN_PASSWORD=config['web_admin_password'],
                          INSTALL_FLAG_GENERATORS=int(config['flag_generators']), INSTALL_VULNHUB=int(config['vulnhub']),
                          OPTIONAL_CONTENT_SHA256=checksum, FLAG_GENERATORS_RESOLVED_COMMIT=commit,
                          TESTED_FLAG_GENERATORS_COMMIT=TESTED_CATALOG_COMMIT)
        files.append(dict(path='/etc/scenarioforge-installer.env', owner='root:root', permissions='0600',
                          encoding='b64', content=base64.b64encode(shell_environment(values).encode()).decode()))
    if role == 'participant':
        script = caf.inject(script, config)
    script_path = f'/usr/local/sbin/scenarioforge-{role}-bootstrap'
    files.append(dict(path=script_path, owner='root:root', permissions='0700', encoding='b64',
                      content=base64.b64encode(script.encode()).decode()))
    packages = ['open-vm-tools', 'open-vm-tools-desktop']
    if role != 'participant':
        packages = ['git', 'curl', 'ca-certificates'] + packages
    # JSON is valid YAML; quoting is handled by the standard library.
    data = dict(hostname=f'scenarioforge-{role}', manage_etc_hosts=True, ssh_pwauth=True, disable_root=True,
                users=[user], chpasswd={'expire': False}, package_update=True, packages=packages, write_files=files,
                runcmd=[['systemctl', 'enable', '--now', 'open-vm-tools.service'], ['bash', script_path]])
    return '#cloud-config\n' + json.dumps(data, indent=2) + '\n'


def network_layout(role, config, macs):
    def nic(index, name, **settings):
        return {'match': {'macaddress': macs[index]}, 'set-name': name, **settings}
    if role == 'core':
        networks = [('custom', config['management_vmnet']), ('custom', config['hitl_vmnet']), ('nat', '')]
        interfaces = dict(management=nic(0, 'ens18', addresses=['172.31.250.3/24']),
                          hitl=nic(1, 'ens19', dhcp4=False, dhcp6=False, **{'accept-ra': False, 'optional': True}),
                          uplink=nic(2, 'ens20', dhcp4=True, dhcp6=False))
    elif role == 'app':
        networks = [('nat', ''), ('custom', config['management_vmnet'])]
        interfaces = dict(uplink=nic(0, 'ens18', dhcp4=True, dhcp6=False),
                          management=nic(1, 'ens19', addresses=['172.31.250.2/24']))
    else:
        networks = [('custom', config['hitl_vmnet']), ('nat', '')]
        interfaces = {'participant': nic(0, 'ens18', addresses=['10.254.200.10/24'], dhcp4=False, dhcp6=False,
                                          # Temporary NAT wins during bootstrap until its adapter is detached.
                                          routes=[{'to': '0.0.0.0/0', 'via': CORE_HITL_CIDR.split('/')[0], 'metric': 2000}],
                                          **{'accept-ra': False}),
                      'bootstrap-uplink': nic(1, 'ens19', dhcp4=True, dhcp6=False)}
    if role == 'participant' and config.get('cyber_agent_flow', False):
        networks.append(('custom', config.get('llm_vmnet', 'vmnet8')))
        interfaces['llm'] = caf.interface(config, macs[2])
    return networks, {'version': 2, 'ethernets': interfaces}


def write_seed(path, userdata, metadata, network):
    import pycdlib
    iso = pycdlib.PyCdlib()
    streams = []
    try:
        iso.new(interchange_level=3, vol_ident='cidata', joliet=3, rock_ridge='1.09')
        for name, iso_name, content in [('user-data', 'USERDATA.;1', userdata),
                                        ('meta-data', 'METADATA.;1', json.dumps(metadata)),
                                        ('network-config', 'NETWORK.;1', json.dumps(network))]:
            payload = content.encode('utf-8')
            stream = io.BytesIO(payload)
            streams.append(stream)
            iso.add_fp(stream, len(payload), iso_path='/' + iso_name, rr_name=name,
                       joliet_path='/' + name, file_mode=0o100600)
        iso.write(str(path))
    finally:
        iso.close()
        for stream in streams:
            stream.close()


def encode_guestinfo(content):
    return base64.b64encode(gzip.compress(content.encode('utf-8'), mtime=0)).decode('ascii')


def write_vmx(path, role, config, macs, networks, userdata, metadata, network):
    name = 'scenarioforge-' + role
    values = {'.encoding': 'UTF-8', 'config.version': 8, 'virtualHW.version': 20, 'pciBridge0.present': 'TRUE'}
    for bridge in range(4, 8):
        values.update({f'pciBridge{bridge}.present': 'TRUE', f'pciBridge{bridge}.virtualDev': 'pcieRootPort',
                       f'pciBridge{bridge}.functions': 8})
    values.update({'displayName': name, 'guestOS': 'ubuntu-64' if role == 'app' else 'debian12-64',
                   'floppy0.present': 'FALSE', 'floppy0.startConnected': 'FALSE',
                   'firmware': 'efi', 'memsize': config[role + '_memory_mb'], 'numvcpus': config[role + '_cores'],
                   'cpuid.coresPerSocket': config[role + '_cores'],
                   'sata0.present': 'TRUE', 'sata0:1.present': 'TRUE', 'sata0:1.deviceType': 'cdrom-image',
                   'sata0:1.fileName': name + '-cidata.iso', 'sata0:1.startConnected': 'TRUE',
                   # Cloud images may select ttyS0 as /dev/console during
                   # initramfs disk growth; a missing UART can panic PID 1.
                   'serial0.present': 'TRUE', 'serial0.fileType': 'file',
                   'serial0.fileName': 'serial-console.log', 'serial0.startConnected': 'TRUE',
                   'serial0.yieldOnMsrRead': 'TRUE',
                   'answer.msg.serial.file.open': 'Append',
                   'usb.present': 'TRUE', 'ehci.present': 'TRUE', 'usb_xhci.present': 'TRUE',
                   'sound.present': 'TRUE', 'sound.autoDetect': 'TRUE', 'mks.enable3d': 'FALSE', 'tools.syncTime': 'TRUE',
                   'scenarioforge.install.owner': config['install_id'], 'scenarioforge.install.role': name,
                   'scsi0.present': 'TRUE', 'scsi0.virtualDev': 'lsilogic', 'scsi0:0.present': 'TRUE',
                   'scsi0:0.fileName': name + '.vmdk',
                   'guestinfo.metadata': encode_guestinfo(json.dumps({**metadata, 'network': network, 'redact': ['userdata']})),
                   'guestinfo.metadata.encoding': 'gzip+base64', 'guestinfo.userdata': encode_guestinfo(userdata),
                   'guestinfo.userdata.encoding': 'gzip+base64'})
    if role == 'participant' and config.get('participant_os', 'debian') == 'kali':
        for key in ('scsi0.present', 'scsi0.virtualDev', 'scsi0:0.present', 'scsi0:0.fileName'):
            values.pop(key)
        values.update({'nvme0.present': 'TRUE', 'nvme0:0.present': 'TRUE',
                       'nvme0:0.fileName': name + '.vmdk'})
    for index, (kind, network_name) in enumerate(networks):
        for key, value in {'present': 'TRUE', 'virtualDev': 'vmxnet3', 'startConnected': 'TRUE',
                           'addressType': 'static', 'address': macs[index], 'connectionType': kind}.items():
            values[f'ethernet{index}.{key}'] = value
        if kind == 'custom':
            values[f'ethernet{index}.vnet'] = network_name
    if any(re.search(r'["\r\n]', str(value)) for value in values.values()):
        raise BuildError('Invalid VMX value.')
    path.write_text(''.join(f'{key} = "{value}"\n' for key, value in values.items()), encoding='utf-8', newline='\n')


def prepare_disk(qemu, source, destination, size_gb, work, source_format="qcow2"):
    overlay = work / 'resize.qcow2'
    try:
        run([qemu, 'create', '-f', 'qcow2', '-F', source_format, '-b', source, overlay], capture=True)
        run([qemu, 'resize', overlay, f'{size_gb}G'])
        run([qemu, 'convert', '-p', '-f', 'qcow2', '-O', 'vmdk', '-o', 'subformat=monolithicSparse,adapter_type=lsilogic',
             overlay, destination])
    finally:
        overlay.unlink(missing_ok=True)


def image_selection(config, roles):
    selected = set()
    for role in roles:
        selected.add('ubuntu' if role == 'app' else config.get('participant_os', 'debian') if role == 'participant' else 'debian')
    for name in sorted(selected):
        parameters = IMAGES[name]
        if name == 'kali':
            parameters = (config.get('kali_image_url') or parameters[0],
                          config.get('kali_sums_url') or parameters[1], parameters[2])
        yield name, parameters


def selected_roles(config):
    roles = config.get('reinstall_roles', ['core', 'app', 'participant'])
    if not isinstance(roles, list) or not roles or len(set(roles)) != len(roles) or any(role not in ('core', 'app', 'participant') for role in roles):
        raise BuildError('Invalid reinstall_roles')
    return roles


def check_reinstall_cache(config, *, prompt_missing=False):
    for _, parameters in image_selection(config, selected_roles(config)):
        try:
            download_verified(*parameters, Path(config['image_cache']), cached_only=True)
        except image_cache.MissingCachedImage:
            if not prompt_missing:
                raise
            url = parameters[0]
            destination = Path(config['image_cache']) / url.rsplit('/', 1)[-1]
            print(f'Required cached image is missing: {destination}', flush=True)
            print(f'Download source: {url} (the base image may be several GB)', flush=True)
            try:
                answer = input('Download and verify this image before reinstalling? [y/N] ')
            except EOFError:
                answer = ''
            if answer.strip().lower() not in ('y', 'yes'):
                raise BuildError('Image download declined; no VMs were replaced.')
            download_verified(*parameters, Path(config['image_cache']))


def prepare_images(config, work):
    caf.validate(config)
    participant_os = config.get('participant_os', 'debian')
    if participant_os not in ('debian', 'kali'):
        raise BuildError('participant_os must be debian or kali.')
    scripts = guest_scripts()
    roles = selected_roles(config)
    lab = Path(config['lab_dir'])
    for role in roles:
        if (lab / ('scenarioforge-' + role)).exists():
            raise BuildError(f'VM destination already exists: scenarioforge-{role}')
    checksum, commit = prepare_catalogs(config, work, lab) if 'app' in roles else ('', '')
    images = {}
    for name, parameters in image_selection(config, roles):
        if config.get('reinstall_roles'):
            images[name] = download_verified(*parameters, Path(config['image_cache']), cached_only=True)
        else:
            images[name] = download_verified(*parameters, Path(config['image_cache']))
    if 'kali' in images:
        images['kali'] = extract_kali_disk(images['kali'], work)
    used_macs = set()
    for role, script in scripts.items():
        if role not in roles:
            continue
        name = 'scenarioforge-' + role
        directory = lab / name
        directory.mkdir()
        (directory / '.scenarioforge-owner').write_text(config['install_id'] + '\n', encoding='utf-8')
        macs = []
        while len(macs) < (3 if role == 'core' or (role == 'participant' and config.get('cyber_agent_flow', False)) else 2):
            mac = f'00:50:56:{secrets.randbelow(64):02x}:' + ':'.join(f'{byte:02x}' for byte in secrets.token_bytes(2))
            if mac not in used_macs:
                used_macs.add(mac)
                macs.append(mac)
        networks, network = network_layout(role, config, macs)
        userdata = cloud_config(role, config, script, checksum, commit)
        metadata = {'instance-id': f'scenarioforge-{role}-{uuid.uuid4()}', 'local-hostname': name}
        write_seed(directory / (name + '-cidata.iso'), userdata, metadata, network)
        print(f'Preparing {role} disk...', flush=True)
        image_os = 'ubuntu' if role == 'app' else (participant_os if role == 'participant' else 'debian')
        disk_args = (config['qemu_img'], images[image_os], directory / (name + '.vmdk'),
                     config[role + '_disk_gb'], work)
        if image_os == 'kali':
            prepare_disk(*disk_args, source_format='raw')
        elif image_os == 'ubuntu':
            # The upstream VMware disk is a distribution image; normalize it to
            # our writable sparse layout while growing through the small overlay.
            prepare_disk(*disk_args, source_format='vmdk')
        else:
            prepare_disk(*disk_args)
        write_vmx(directory / (name + '.vmx'), role, config, macs, networks, userdata, metadata, network)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('request', nargs='?', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--qemu-img')
    parser.add_argument('--git')
    parser.add_argument('--check-cache', action='store_true')
    parser.add_argument('--prompt-missing-images', action='store_true')
    args = parser.parse_args()
    if args.check:
        if not args.qemu_img:
            parser.error('--check requires --qemu-img')
        check_dependencies(args.qemu_img, args.git)
        print('Native image preparation prerequisites verified.')
        return
    if not args.request:
        parser.error('provide the build request JSON file')
    config = json.loads(args.request.read_text(encoding='utf-8-sig'))
    if args.check_cache:
        check_reinstall_cache(config, prompt_missing=args.prompt_missing_images)
        print('Required cached images verified; no VM changes.')
        return
    check_dependencies(config['qemu_img'], config.get('git_exe') if config['flag_generators'] or config['vulnhub'] else None)
    # The parent PowerShell installer protects this directory with Windows ACLs.
    with tempfile.TemporaryDirectory(prefix='image-build-', dir=args.request.parent) as temporary:
        prepare_images(config, Path(temporary))


if __name__ == '__main__':
    try:
        main()
    except (BuildError, OSError, ValueError) as exc:
        print(f'Image preparation failed: {exc}', file=sys.stderr)
        sys.exit(1)
