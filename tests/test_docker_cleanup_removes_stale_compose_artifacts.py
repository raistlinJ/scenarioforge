from pathlib import Path

from webapp import app_backend as backend


def test_remote_docker_cleanup_removes_stale_vuln_compose_artifacts() -> None:
    txt = Path("webapp/app_backend.py").read_text(encoding="utf-8")

    assert "def _run_sudo(cmd, timeout=20):" in txt
    assert "glob.glob('/tmp/vulns/docker-compose-*.yml')" in txt
    assert "glob.glob('/tmp/vulns/docker-compose-*.orig.yml')" in txt
    assert "glob.glob('/tmp/vulns/docker-wrap-*')" in txt
    assert "targets.append('/tmp/vulns/compose_assignments.json')" in txt
    assert "_run_sudo(['rm', '-rf', '--', real]" in txt
    assert "removed_vuln_artifacts" in txt


def test_remote_docker_cleanup_script_with_sudo_password_compiles() -> None:
    script = backend._remote_docker_cleanup_script(['docker-1'], 'secret')

    compile(script, '<remote_docker_cleanup_script>', 'exec')
    assert 'input=str(SUDO_PASSWORD) + "\\n"' in script


def test_async_cleanup_shell_removes_stale_vuln_compose_artifacts() -> None:
    txt = Path("webapp/app_backend.py").read_text(encoding="utf-8")

    assert "find /tmp/vulns -maxdepth 1" in txt
    assert "-name 'docker-compose-*.yml'" in txt
    assert "-name 'docker-compose-*.orig.yml'" in txt
    assert "-name 'compose_assignments.json'" in txt
    assert "-name 'docker-wrap-*'" in txt