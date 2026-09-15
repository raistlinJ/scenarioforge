import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('update_llm', Path(__file__).resolve().parents[1] / 'scripts/provision/common/update-llm-destination.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_destination_validation(monkeypatch):
    monkeypatch.setattr(module.socket, 'getaddrinfo', lambda *args: [(None, None, None, None, ('203.0.113.20', 443))])
    assert module.validate_destination('203.0.113.20', 'https://provider.example/v1', ['10.254.200.0/24']) == '203.0.113.20'
    for address, url in [('10.254.200.20', 'https://provider.example'), ('203.0.113.21', 'https://provider.example'), ('203.0.113.20', 'https://user:password@provider.example'), ('127.0.0.1', 'http://localhost')]:
        with pytest.raises(ValueError):
            module.validate_destination(address, url, ['10.254.200.0/24'])


def test_atomic_config_update_preserves_permissions(tmp_path):
    path = tmp_path / 'cli.json'
    path.write_text('{}')
    path.chmod(0o600)
    module.write_atomic(path, b'{"url":"http://203.0.113.20"}')
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == b'{"url":"http://203.0.113.20"}'
