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
