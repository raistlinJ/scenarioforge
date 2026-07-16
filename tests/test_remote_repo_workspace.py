import io

from webapp import app_backend as backend


def test_remote_repo_workspace_repairs_default_tmp_repo_ownership(monkeypatch):
    calls = []
    probe_results = iter([
        (1, '', 'touch: Permission denied'),
        (0, '', ''),
    ])

    def fake_exec(_client, command, **_kwargs):
        calls.append(command)
        if command.startswith('test -L '):
            return 1, '', ''
        return next(probe_results)

    sudo_calls = []
    monkeypatch.setattr(backend, '_exec_ssh_command', fake_exec)
    monkeypatch.setattr(
        backend,
        '_exec_ssh_sudo_command',
        lambda _client, command, **_kwargs: (sudo_calls.append(command) or (0, '', '')),
    )

    log = io.StringIO()
    backend._ensure_remote_repo_workspace(
        object(),
        '/tmp/scenarioforge',
        {'ssh_username': 'coreuser', 'ssh_password': 'secret'},
        log_handle=log,
    )

    assert len(sudo_calls) == 1
    assert 'chown -R' in sudo_calls[0]
    assert 'ownership repaired' in log.getvalue()
    assert len(calls) == 3


def test_remote_repo_workspace_does_not_chown_custom_path(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_exec_ssh_command',
        lambda _client, command, **_kwargs: (1, '', '' if command.startswith('test -L ') else 'Permission denied'),
    )
    sudo_calls = []
    monkeypatch.setattr(
        backend,
        '_exec_ssh_sudo_command',
        lambda *_args, **_kwargs: sudo_calls.append(True),
    )

    try:
        backend._ensure_remote_repo_workspace(
            object(),
            '/srv/scenarioforge',
            {'ssh_username': 'coreuser'},
        )
    except RuntimeError as exc:
        assert 'not writable' in str(exc)
        assert 'CORE_REMOTE_STATIC_REPO' in str(exc)
    else:
        raise AssertionError('expected an actionable workspace error')

    assert sudo_calls == []


def test_remote_repo_workspace_rejects_symlink(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_exec_ssh_command',
        lambda *_args, **_kwargs: (0, '', ''),
    )

    try:
        backend._ensure_remote_repo_workspace(object(), '/tmp/scenarioforge', {})
    except RuntimeError as exc:
        assert 'must not be a symlink' in str(exc)
    else:
        raise AssertionError('expected a symlink safety error')


def test_async_repo_finalize_records_hash_after_extract(monkeypatch):
    class _Client:
        def close(self):
            return None

    class _ImmediateThread:
        def __init__(self, *, target, daemon):
            self.target = target

        def start(self):
            self.target()

    commands = []
    hashes = []
    monkeypatch.setattr(backend, '_open_ssh_client', lambda _cfg: _Client())
    monkeypatch.setattr(
        backend,
        '_exec_ssh_command',
        lambda _client, command, **_kwargs: (commands.append(command) or (0, '', '')),
    )
    monkeypatch.setattr(backend, '_write_remote_repo_hash', lambda _client, repo, value: hashes.append((repo, value)))
    monkeypatch.setattr(backend, '_update_repo_push_progress', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend.threading, 'Thread', _ImmediateThread)

    backend._schedule_remote_repo_finalize(
        'progress-1',
        {'ssh_username': 'coreuser'},
        remote_repo='/tmp/scenarioforge',
        remote_parent='/tmp',
        remote_archive='/tmp/upload.tar.gz',
        remote_hash_value='abc123',
    )

    assert any('tar -xzf' in command for command in commands)
    assert hashes == [('/tmp/scenarioforge', 'abc123')]
