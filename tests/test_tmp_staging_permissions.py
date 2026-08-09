import os
import shlex

import pytest

from scenarioforge.utils import tmp_staging


def test_is_tmp_staging_path_rejects_non_tmp_and_bare_tmp():
    assert tmp_staging.is_tmp_staging_path('/tmp/vulns') is True
    assert tmp_staging.is_tmp_staging_path('/tmp/vulns/flow-x') is True
    assert tmp_staging.is_tmp_staging_path('/tmp') is False
    assert tmp_staging.is_tmp_staging_path('/tmp/') is False
    assert tmp_staging.is_tmp_staging_path('/var/lib/thing') is False
    assert tmp_staging.is_tmp_staging_path('/tmp/../etc') is False
    assert tmp_staging.is_tmp_staging_path('') is False
    assert tmp_staging.is_tmp_staging_path(None) is False


def test_ensure_local_refuses_paths_outside_tmp():
    ok, detail = tmp_staging.ensure_local_tmp_writable('/etc/passwd')
    assert ok is False
    assert 'refusing' in detail


def test_ensure_local_creates_missing_dir(monkeypatch, tmp_path):
    target = tmp_path / 'vulns' / 'flow-x'
    monkeypatch.setattr(tmp_staging, 'is_tmp_staging_path', lambda p: True)

    ok, detail = tmp_staging.ensure_local_tmp_writable(str(target))

    assert ok is True
    assert detail == 'created'
    assert target.is_dir()


def test_ensure_local_reports_already_writable(monkeypatch, tmp_path):
    target = tmp_path / 'vulns'
    target.mkdir()
    monkeypatch.setattr(tmp_staging, 'is_tmp_staging_path', lambda p: True)

    ok, detail = tmp_staging.ensure_local_tmp_writable(str(target))

    assert (ok, detail) == (True, 'already writable')


def test_ensure_local_uses_non_interactive_sudo(monkeypatch, tmp_path):
    """Repair must never block a web request on a sudo password prompt."""
    target = tmp_path / 'vulns'
    target.mkdir()
    monkeypatch.setattr(tmp_staging, 'is_tmp_staging_path', lambda p: True)
    monkeypatch.setattr(tmp_staging, '_usable', lambda p: False)

    seen = {}

    class _Proc:
        returncode = 0
        stdout = ''
        stderr = ''

    def _fake_run(cmd, **kwargs):
        seen['cmd'] = cmd
        return _Proc()

    monkeypatch.setattr(tmp_staging.subprocess, 'run', _fake_run)

    ok, _detail = tmp_staging.ensure_local_tmp_writable(str(target))

    assert ok is False  # _usable stays False, so the repair is reported as failed
    assert seen['cmd'][:3] == ['sudo', '-n', 'chmod']
    assert seen['cmd'][3] == '1777'


def test_prepare_output_dir_skips_guard_for_non_tmp(monkeypatch, tmp_path):
    """Non-/tmp output dirs behave exactly like os.makedirs, with no probing."""
    def _boom(*_a, **_k):  # pragma: no cover - must not be called
        raise AssertionError('guard should not run outside /tmp')

    monkeypatch.setattr(tmp_staging, 'ensure_local_tmp_writable', _boom)
    target = tmp_path / 'out' / 'nested'

    assert tmp_staging.prepare_output_dir(str(target)) == str(target)
    assert target.is_dir()


def test_prepare_output_dir_repairs_tmp_dirs_then_makedirs(monkeypatch, tmp_path):
    target = tmp_path / 'traffic'
    seen = {}

    monkeypatch.setattr(tmp_staging, 'is_tmp_staging_path', lambda p: True)

    def _fake_ensure(path, *, logger=None):
        seen['path'] = path
        return True, 'repaired'

    monkeypatch.setattr(tmp_staging, 'ensure_local_tmp_writable', _fake_ensure)

    tmp_staging.prepare_output_dir(str(target))

    assert seen['path'] == str(target)
    assert target.is_dir()


def test_prepare_output_dir_still_makedirs_when_repair_fails(monkeypatch, tmp_path):
    """A failed repair must not block the write; the caller reports the real error."""
    target = tmp_path / 'traffic'
    monkeypatch.setattr(tmp_staging, 'is_tmp_staging_path', lambda p: True)
    monkeypatch.setattr(
        tmp_staging, 'ensure_local_tmp_writable', lambda p, logger=None: (False, 'nope')
    )

    warnings = []

    class _Log:
        def warning(self, msg, *args):
            warnings.append(msg % args if args else msg)

    tmp_staging.prepare_output_dir(str(target), logger=_Log())

    assert target.is_dir()
    assert any('may not be writable' in w for w in warnings)


def _exec_returning(mapping):
    calls = []

    def _exec(cmd, *, timeout=None):
        calls.append(cmd)
        for needle, result in mapping.items():
            if needle in cmd:
                return result
        return (0, '', '')

    return _exec, calls


def test_ensure_remote_short_circuits_when_writable():
    _exec, calls = _exec_returning({'DENIED': (0, 'OK\n', '')})

    ok, detail = tmp_staging.ensure_remote_tmp_writable(_exec, '/tmp/vulns')

    assert (ok, detail) == (True, 'already writable')
    assert len(calls) == 1


def test_ensure_remote_fails_clearly_without_sudo():
    _exec, _calls = _exec_returning({'DENIED': (0, 'DENIED\n', '')})

    ok, detail = tmp_staging.ensure_remote_tmp_writable(_exec, '/tmp/traffic')

    assert ok is False
    assert 'no sudo password is configured' in detail


def test_ensure_remote_repairs_with_sudo_chmod():
    probe_results = iter([(0, 'DENIED\n', ''), (0, 'OK\n', '')])

    def _exec(cmd, *, timeout=None):
        return next(probe_results)

    sudo_calls = []

    def _exec_sudo(cmd, *, timeout=None):
        sudo_calls.append(cmd)
        return (0, '', '')

    ok, detail = tmp_staging.ensure_remote_tmp_writable(
        _exec, '/tmp/traffic', exec_sudo=_exec_sudo
    )

    assert ok is True
    assert 'repaired' in detail
    assert 'chmod 1777' in sudo_calls[0]
    assert shlex.quote('/tmp/traffic') in sudo_calls[0]


def test_ensure_remote_reports_sudo_failure():
    def _exec(cmd, *, timeout=None):
        return (0, 'DENIED\n', '')

    def _exec_sudo(cmd, *, timeout=None):
        return (1, '', 'chmod: permission denied')

    ok, detail = tmp_staging.ensure_remote_tmp_writable(
        _exec, '/tmp/vulns', exec_sudo=_exec_sudo
    )

    assert ok is False
    assert 'permission denied' in detail


def test_ensure_remote_refuses_non_tmp_path():
    def _exec(cmd, *, timeout=None):  # pragma: no cover - must not be called
        raise AssertionError('probe should not run for a non-/tmp path')

    ok, detail = tmp_staging.ensure_remote_tmp_writable(_exec, '/var/lib/core')

    assert ok is False
    assert 'refusing' in detail
