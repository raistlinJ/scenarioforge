"""Read-only participant readiness contract shared by Proxmox and VMware."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit


def verify(helper, config, expected_hash):
    helper, config = Path(helper), Path(config)
    if helper.is_symlink() or not helper.is_file():
        raise ValueError('Participant routing helper is missing or is a symlink')
    actual = hashlib.sha256(helper.read_bytes()).hexdigest()
    if actual != expected_hash:
        raise ValueError('Participant routing helper differs from this provisioner; update/reprovision the guest helper before marking ready')
    result = subprocess.run([sys.executable, str(helper), '--help'], capture_output=True, text=True, timeout=15)
    if result.returncode or any(option not in result.stdout for option in ('--url', '--cli-config', '--json')):
        raise ValueError('Participant routing helper cannot provide the orchestrator CLI options; check its Python dependencies')
    if config.is_symlink() or not config.is_file():
        raise ValueError('Participant CAF model configuration is missing or is a symlink')
    data = json.loads(config.read_text())
    if not isinstance(data, dict):
        raise ValueError('Participant CAF configuration must be an object')
    model = data.get('model')
    if not isinstance(model, str) or not model.strip() or len(model)>2048 or any(ord(c)<32 for c in model):
        raise ValueError('Participant CAF model name is empty or invalid; set llm_model before provisioning')
    if data.get('provider') not in ('openai', 'litellm', 'ollama_direct', 'claude'):
        raise ValueError('Participant CAF provider is missing or invalid')
    endpoint=urlsplit(data.get('url',''))
    if endpoint.scheme not in ('http','https') or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError('Participant CAF endpoint is missing or invalid')
    return dict(status='verified',helper_sha256=actual,model=model)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('helper')
    parser.add_argument('config')
    parser.add_argument('expected_hash')
    args=parser.parse_args()
    try:
        print(json.dumps(verify(args.helper,args.config,args.expected_hash)))
    except Exception as error:
        raise SystemExit('CAF participant verification failed: '+str(error))
