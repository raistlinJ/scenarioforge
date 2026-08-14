"""The final CLI compose rewrite must not erase stable namespace supervision."""

from __future__ import annotations

import inspect

from scenarioforge import cli


def test_finalizer_visits_only_the_requested_node_names(monkeypatch) -> None:
    seen = []
    monkeypatch.setattr(cli, '_docker_node_compose_path', lambda name: f'/tmp/{name}/docker-compose.yml')
    monkeypatch.setattr(
        cli,
        '_finalize_shared_namespace_supervisor',
        lambda path, name: seen.append((path, name)) or name == 'docker-12',
    )

    applied = cli._finalize_prepared_shared_namespace_nodes(['docker-11', '', 'docker-12'])

    assert applied == ['docker-12']
    assert seen == [
        ('/tmp/docker-11/docker-compose.yml', 'docker-11'),
        ('/tmp/docker-12/docker-compose.yml', 'docker-12'),
    ]


def test_finalizer_runs_after_the_last_compose_generation_pass() -> None:
    source = inspect.getsource(cli.main)
    prepare_at = source.rindex(
        'created = prepare_compose_for_assignments(all_docker_nodes, out_base="/tmp/vulns")'
    )
    finalize_at = source.index(
        '_finalize_prepared_shared_namespace_nodes(list(all_docker_nodes.keys()))',
        prepare_at,
    )
    summary_at = source.index('_write_compose_assignments_summary(', finalize_at)
    assert prepare_at < finalize_at < summary_at
