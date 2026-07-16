from __future__ import annotations

import os


class _FakeSFTP:
    def __init__(self):
        self.put_calls: list[tuple[str, str]] = []

    def put(self, localpath, remotepath, *args, **kwargs):
        self.put_calls.append((str(localpath), str(remotepath)))

    def close(self):
        pass


class _FakeClient:
    def __init__(self, sftp: _FakeSFTP):
        self.sftp = sftp

    def open_sftp(self):
        return self.sftp

    def close(self):
        pass


def test_remote_vuln_sync_uploads_generated_compose_bind_source(tmp_path, monkeypatch):
    """Remote Compose must receive CGI/support files used as absolute bind mounts."""
    from webapp import app_backend as backend

    local_dir = tmp_path / "vulns"
    staged_dir = local_dir / "bash-cve-2014-6271" / "node-bash-1"
    staged_dir.mkdir(parents=True)
    victim = staged_dir / "victim.cgi"
    victim.write_text("#!/bin/bash\necho vulnerable\n", encoding="utf-8")

    compose = local_dir / "docker-compose-bash-1.yml"
    compose.write_text(
        "services:\n"
        "  bash-1:\n"
        "    image: vulhub/bash:4.3.0-with-httpd\n"
        "    volumes:\n"
        f"      - {victim}:/var/www/html/victim.cgi\n",
        encoding="utf-8",
    )

    sftp = _FakeSFTP()
    monkeypatch.setattr(backend, "_open_ssh_client", lambda _cfg: _FakeClient(sftp))
    monkeypatch.setattr(backend, "_remote_expand_path", lambda _sftp, path: path)
    monkeypatch.setattr(backend, "_remote_mkdirs", lambda *_args, **_kwargs: None)

    assert backend._sync_local_vulns_to_remote(
        {}, local_dir=str(local_dir), remote_dir="/tmp/vulns"
    )

    assert (str(victim), "/tmp/vulns/bash-cve-2014-6271/node-bash-1/victim.cgi") in sftp.put_calls


def test_staging_repairs_non_executable_shebang_cgi_support_file(tmp_path):
    """Catalogs installed before mode-preserving extraction must still run CGI files."""
    from scenarioforge.utils.vuln_process import _copy_support_paths_and_absolutize_binds

    source_dir = tmp_path / "catalog"
    source_dir.mkdir()
    victim = source_dir / "victim.cgi"
    victim.write_text("#!/bin/bash\necho vulnerable\n", encoding="utf-8")
    victim.chmod(0o644)
    staged_dir = tmp_path / "staged"

    compose = {
        "services": {
            "web": {
                "image": "vulhub/bash:4.3.0-with-httpd",
                "volumes": ["./victim.cgi:/var/www/html/victim.cgi"],
            }
        }
    }
    updated = _copy_support_paths_and_absolutize_binds(compose, str(source_dir), str(staged_dir))

    staged_victim = staged_dir / "victim.cgi"
    assert staged_victim.is_file()
    assert os.stat(staged_victim).st_mode & 0o111 == 0o111
    assert updated["services"]["web"]["volumes"] == [f"{staged_victim}:/var/www/html/victim.cgi"]
