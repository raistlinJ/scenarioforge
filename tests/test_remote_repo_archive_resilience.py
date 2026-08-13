import os
import tarfile

from webapp import app_backend as backend


def test_repo_snapshot_skips_file_that_vanishes_during_packaging(tmp_path, monkeypatch) -> None:
    repo = tmp_path / 'repo'
    repo.mkdir()
    stable = repo / 'stable.txt'
    vanished = repo / 'vanished.md'
    stable.write_text('stable', encoding='utf-8')
    vanished.write_text('transient', encoding='utf-8')

    original_add = tarfile.TarFile.add

    def _add_with_vanishing_source(self, name, arcname=None, recursive=True, **kwargs):
        if os.path.basename(str(name)) == 'vanished.md' and os.path.exists(name):
            os.remove(name)
            raise OSError(22, 'Invalid argument', str(name))
        return original_add(self, name, arcname=arcname, recursive=recursive, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, 'add', _add_with_vanishing_source)

    archive = backend._create_local_repo_archive(str(repo), 'scenarioforge', allowed_outputs=[])
    try:
        with tarfile.open(archive, 'r:gz') as handle:
            names = set(handle.getnames())
        assert 'scenarioforge/stable.txt' in names
        assert 'scenarioforge/vanished.md' not in names
    finally:
        if os.path.exists(archive):
            os.remove(archive)


def test_repo_snapshot_still_fails_for_persistently_unreadable_file(tmp_path, monkeypatch) -> None:
    repo = tmp_path / 'repo'
    repo.mkdir()
    blocked = repo / 'blocked.txt'
    blocked.write_text('blocked', encoding='utf-8')

    original_add = tarfile.TarFile.add

    def _add_with_persistent_failure(self, name, arcname=None, recursive=True, **kwargs):
        if os.path.basename(str(name)) == 'blocked.txt':
            raise OSError(13, 'Permission denied', str(name))
        return original_add(self, name, arcname=arcname, recursive=recursive, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, 'add', _add_with_persistent_failure)

    try:
        backend._create_local_repo_archive(str(repo), 'scenarioforge', allowed_outputs=[])
    except OSError as exc:
        assert exc.errno == 13
    else:
        raise AssertionError('persistent source read failure was silently ignored')


def test_repo_snapshot_skips_security_blocked_installed_vuln_source(tmp_path, monkeypatch) -> None:
    repo = tmp_path / 'repo'
    blocked = repo / 'outputs' / 'installed_vuln_catalogs' / 'pack-1' / 'content' / 'poc.py'
    blocked.parent.mkdir(parents=True)
    blocked.write_text('proof of concept', encoding='utf-8')

    original_add = tarfile.TarFile.add

    def _add_with_security_block(self, name, arcname=None, recursive=True, **kwargs):
        if os.path.basename(str(name)) == 'poc.py':
            raise OSError(22, 'Invalid argument', str(name))
        return original_add(self, name, arcname=arcname, recursive=recursive, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, 'add', _add_with_security_block)

    archive = backend._create_local_repo_archive(str(repo), 'scenarioforge')
    try:
        with tarfile.open(archive, 'r:gz') as handle:
            names = set(handle.getnames())
        assert not any(name.endswith('/poc.py') for name in names)
    finally:
        if os.path.exists(archive):
            os.remove(archive)
