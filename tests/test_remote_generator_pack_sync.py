from pathlib import Path
from types import SimpleNamespace

from webapp import app_backend
from webapp.app_backend import app
from webapp.flow_prepare_preview_execute import _prepare_remote_generator_execution


def test_prune_remote_installed_generator_packs_uses_local_catalog_names(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / 'outputs' / 'installed_generators' / 'flag_node_generators' / 'current-pack').mkdir(parents=True)
    (tmp_path / 'outputs' / 'installed_generators' / 'flag_generators' / 'flag-pack').mkdir(parents=True)
    commands: list[str] = []

    def _fake_exec(_client, command, **_kwargs):
        commands.append(command)
        return 0, '["flag_node_generators/stale-pack"]\n', ''

    monkeypatch.setattr(app_backend, '_exec_ssh_command', _fake_exec)

    removed = app_backend._prune_remote_installed_generator_packs(
        object(),
        repo_root=str(tmp_path),
        remote_repo='/tmp/scenarioforge',
    )

    assert removed == ['flag_node_generators/stale-pack']
    assert len(commands) == 1
    assert 'current-pack' in commands[0]
    assert 'flag-pack' in commands[0]
    assert '/tmp/scenarioforge' in commands[0]


def test_remote_flow_refuses_to_run_when_selected_generator_has_no_sync_path() -> None:
    deps = SimpleNamespace(
        _flow_required_installed_generator_outputs=lambda *_args, **_kwargs: [],
        _flow_required_generator_repo_paths=lambda *_args, **_kwargs: [],
        _get_repo_root=lambda: '/tmp/local-scenarioforge',
    )

    with app.app_context():
        result = _prepare_remote_generator_execution(
            deps,
            run_generators=True,
            flow_run_remote=True,
            flow_remote_forced=False,
            flow_core_cfg={'ssh_host': 'core.example'},
            flag_assignments=[{'id': 'dep_api_key_admin_endpoint', 'type': 'flag-node-generator'}],
            flow_progress=lambda _message: None,
        )

    response, status = result['response']
    assert status == 500
    assert 'No generator paths resolved for Flow sync' in response.get_json()['error']


def test_pack_uninstall_removes_matching_core_runtime_directory(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / 'repo'
    local_pack_dir = repo_root / 'outputs' / 'installed_generators' / 'flag_node_generators' / 'p_current__51'
    local_pack_dir.mkdir(parents=True)
    removed: list[str] = []

    class FakeSftp:
        def stat(self, _path):
            return object()

        def close(self):
            return None

    class FakeClient:
        def open_sftp(self):
            return FakeSftp()

        def close(self):
            return None

    monkeypatch.setattr(app_backend, '_get_repo_root', lambda: str(repo_root))
    monkeypatch.setattr(app_backend, '_installed_generators_root', lambda: str(repo_root / 'outputs' / 'installed_generators'))
    monkeypatch.setattr(app_backend, '_core_config_for_request', lambda **_kwargs: {'ssh_host': 'core.example'})
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(app_backend, '_open_ssh_client', lambda _cfg: FakeClient())
    monkeypatch.setattr(app_backend, '_remote_static_repo_dir', lambda _sftp: '/tmp/scenarioforge')
    monkeypatch.setattr(app_backend, '_remote_remove_path', lambda _client, path: removed.append(path))

    ok, note = app_backend._cleanup_remote_generator_pack({
        'installed': [{'path': str(local_pack_dir)}],
    })

    assert ok is True
    assert note == 'removed 1 CORE runtime generator directory(s)'
    assert removed == ['/tmp/scenarioforge/outputs/installed_generators/flag_node_generators/p_current__51']
