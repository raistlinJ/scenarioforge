from pathlib import Path


SERVICE = Path('on_core_machine/custom_services/HTTPS.py')


def test_https_custom_service_runs_a_real_tls_listener():
    source = SERVICE.read_text(encoding='utf-8')

    assert 'name: str = "HTTPS"' in source
    assert 'dependencies: list[str] = ["CoreTGPrereqs"]' in source
    assert 'openssl req -x509' in source
    assert 'openssl s_server' in source
    assert '-accept 443' in source
