from scenarioforge import cli


def test_docker_compose_node_names_filters_non_compose_entries():
    docker_by_name = {
        'docker-1': {'Type': 'docker-compose'},
        'docker-2': {'Type': 'docker'},
        'docker-3': {'Type': 'docker-compose'},
        'docker-4': {},
        'docker-5': 'not-a-dict',
    }

    assert cli._docker_compose_node_names(docker_by_name) == ['docker-1', 'docker-3']


def test_should_tolerate_configuration_state_for_docker_accepts_running_nodes():
    docker_runtime = {
        'total': 1,
        'running': ['docker-1'],
        'not_running': [],
        'items': [{'name': 'docker-1', 'running': True, 'status': 'running'}],
    }

    assert cli._should_tolerate_configuration_state_for_docker(
        'configuration',
        ['docker-1'],
        docker_runtime,
    ) is True


def test_should_tolerate_configuration_state_for_docker_rejects_pending_or_mismatch():
    pending_runtime = {
        'total': 1,
        'running': [],
        'not_running': ['docker-1'],
        'items': [{'name': 'docker-1', 'running': False, 'status': 'created'}],
    }

    assert cli._should_tolerate_configuration_state_for_docker(
        'configuration',
        ['docker-1'],
        pending_runtime,
    ) is False

    ok_runtime = {
        'total': 1,
        'running': ['docker-1'],
        'not_running': [],
        'items': [{'name': 'docker-1', 'running': True, 'status': 'running'}],
    }
    assert cli._should_tolerate_configuration_state_for_docker(
        'configuration',
        ['docker-1'],
        ok_runtime,
        mismatches=[{'name': 'docker-1'}],
    ) is False

    assert cli._should_tolerate_configuration_state_for_docker(
        'runtime',
        ['docker-1'],
        ok_runtime,
    ) is False


def test_tail_core_daemon_journal_supports_exact_start_epoch(monkeypatch):
    captured = {}

    class _Result:
        stdout = 'journal output\n'

    def _run(cmd, **kwargs):
        captured['cmd'] = list(cmd)
        return _Result()

    monkeypatch.setattr(cli.sys, 'platform', 'linux')
    monkeypatch.setattr(cli.shutil, 'which', lambda name: '/usr/bin/journalctl' if name == 'journalctl' else None)
    monkeypatch.setattr(cli.subprocess, 'run', _run)

    result = cli._tail_core_daemon_journal(lines=75, since_epoch=1234.5)

    assert result == 'journal output'
    since_index = captured['cmd'].index('--since')
    assert captured['cmd'][since_index + 1] == '@1234.500'


def test_extract_core_daemon_boot_error_requires_threadpool_marker():
    traceback = """
core-daemon: thread pool exception
core.services.base.ServiceBootError: node(router-1) service(OSPFv2) failed to validate
"""

    assert 'ServiceBootError' in str(cli._extract_core_daemon_boot_error(traceback))
    assert cli._extract_core_daemon_boot_error(
        'core.services.base.ServiceBootError: stale error from an earlier run'
    ) is None


def test_extract_core_daemon_boot_error_prefers_mako_ast_failure():
    traceback = """
core-daemon: thread pool exception
mako.exceptions.SyntaxException: wrapper
SystemError: AST constructor recursion depth mismatch (before=84, after=80)
"""

    assert 'AST constructor recursion depth mismatch' in str(
        cli._extract_core_daemon_boot_error(traceback)
    )
