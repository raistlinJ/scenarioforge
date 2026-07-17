from pathlib import Path

from webapp import app_backend


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
