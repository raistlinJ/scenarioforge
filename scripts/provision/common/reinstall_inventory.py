"""Read existing VM hardware into shell assignments; never modify a VM."""
import argparse
import json
import math
from pathlib import Path
import re
import secrets
import shlex
import subprocess


def inventory(platform, role, path):
    prefix = role.upper()
    text = Path(path).read_text()
    result = {}
    if platform == 'vmware':
        values = dict(re.findall(r'^([^\s=]+)\s*=\s*"([^"\r\n]*)"\s*$', text, re.M))
        result[prefix + '_MEMORY_MB'] = int(values['memsize'])
        result[prefix + '_CORES'] = int(values['numvcpus'])
        disk = Path(path).with_suffix('.vmdk')
        info = json.loads(subprocess.check_output(['qemu-img', 'info', '-U', '--output=json', str(disk)]))
        result[prefix + '_DISK_GB'] = math.ceil(info['virtual-size'] / 1024 ** 3)
        macs = [values.get(f'ethernet{i}.address', '') for i in range(3)]
    else:
        values = dict(line.split(': ', 1) for line in text.splitlines() if ': ' in line)
        result[prefix + '_MEMORY_MB'] = int(values['memory'])
        result[prefix + '_CORES'] = int(values.get('cores', '1')) * int(values.get('sockets', '1'))
        size = re.search(r'(?:^|,)size=(\d+(?:\.\d+)?)([KMGT])(?:,|$)', values['scsi0'])
        if not size:
            raise ValueError('Cannot determine existing scsi0 disk size')
        result[prefix + '_DISK_GB'] = math.ceil(float(size[1]) * 1024 ** ('KMGT'.index(size[2]) - 2))
        macs = [re.search(r'(?:^|,)(?:virtio|vmxnet3)=([0-9a-fA-F:]{17})(?:,|$)', values.get(f'net{i}', '')) for i in range(3)]
        macs = [match[1] if match else '' for match in macs]
    for index, mac in enumerate(macs):
        if not mac:
            mac = f'00:50:56:{secrets.randbelow(64):02x}:' + ':'.join(f'{b:02x}' for b in secrets.token_bytes(2))
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
            raise ValueError('Invalid VM MAC address')
        result[f'{prefix}_NET{index}_MAC'] = mac
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('platform', choices=['vmware', 'proxmox'])
    parser.add_argument('role', choices=['core', 'app', 'participant'])
    parser.add_argument('path')
    args = parser.parse_args()
    for key, value in inventory(args.platform, args.role, args.path).items():
        print(f'{key}={shlex.quote(str(value))}')
