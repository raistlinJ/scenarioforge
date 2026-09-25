"""Inject a deterministic network clue on an existing scenario host."""
import hashlib
import ipaddress
import json
from pathlib import Path


def generate(config, output):
    subnet = str(ipaddress.ip_network(config['internal_subnet'], strict=False))
    if not config.get('seed') or not config.get('secret'):
        raise ValueError('seed and secret are required')
    flag = 'FLAG{' + hashlib.sha256(
        f"{config['seed']}|{config['secret']}|network-clue".encode()).hexdigest()[:24] + '}'
    output = Path(output)
    artifact = output / 'artifacts/network.conf'
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(f'# Internal service configuration\ninternal_subnet={subnet}\n# maintenance_token={flag}\n')
    result = {'generator_id': 'network-discovery-clue', 'outputs': {
        'Flag(flag_id)': flag, 'FlagDelivery(mode)': 'file',
        'FlagFile(path)': 'artifacts/network.conf', 'File(path)': 'artifacts/network.conf',
        'InternalNetwork(subnet)': subnet}}
    (output / 'outputs.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    generate(json.loads(Path('/inputs/config.json').read_text()), Path('/outputs'))
