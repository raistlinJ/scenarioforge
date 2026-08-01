"""Leftover containers are cleared before an execute, and only the right ones.

Every execute leaves its containers behind once the CORE session goes away. The
next run's conflict check then finds those names taken and resolves it by
deleting *images*, forcing a rebuild of work already done -- one observed run
removed six images to reclaim five container names.

Cleanup is deliberately narrow: Compose has to label a container as belonging to
a CORE or ScenarioForge project, and it has to not be running.
"""

from __future__ import annotations

import subprocess

import pytest

from scenarioforge.utils import vuln_process


class _Recorder:
    """Stands in for docker, recording what would be removed."""

    def __init__(self, containers):
        self.containers = containers          # name -> (state, config_files)
        self.removed = []

    def __call__(self, argv, **kwargs):
        if argv[:3] == ['docker', 'ps', '-a']:
            lines = [f'{n}\t{v[0]}' for n, v in self.containers.items()]
            return subprocess.CompletedProcess(argv, 0, stdout='\n'.join(lines), stderr='')
        if argv[:2] == ['docker', 'inspect']:
            name = argv[2]
            marker = self.containers.get(name, ('', ''))[1]
            return subprocess.CompletedProcess(argv, 0, stdout=f'{marker}|{marker}', stderr='')
        if argv[:3] == ['docker', 'rm', '-f']:
            self.removed.append(argv[3])
            return subprocess.CompletedProcess(argv, 0, stdout='', stderr='')
        raise AssertionError(f'unexpected command: {argv}')


@pytest.fixture
def docker(monkeypatch):
    def _install(containers):
        rec = _Recorder(containers)
        monkeypatch.setattr(vuln_process, '__name__', vuln_process.__name__)
        monkeypatch.setattr(subprocess, 'run', rec)
        import shutil
        monkeypatch.setattr(shutil, 'which', lambda _n: '/usr/bin/docker')
        return rec
    return _install


def test_removes_leftover_core_and_scenarioforge_containers(docker):
    rec = docker({
        'core-1-20-docker-15-inject_copy-1': ('created', '/tmp/pycore.1/docker-15.conf/docker-compose.yml'),
        'docker-11': ('created', '/tmp/vulns/.compose-projects/docker-11/docker-compose.yml'),
        'docker-12conf-node-1': ('exited', '/tmp/pycore.1/docker-12.conf/docker-compose.yml'),
    })
    result = vuln_process.remove_stale_scenarioforge_containers()

    assert sorted(rec.removed) == [
        'core-1-20-docker-15-inject_copy-1', 'docker-11', 'docker-12conf-node-1',
    ]
    assert sorted(result['removed']) == sorted(rec.removed)


def test_a_running_leftover_is_removed_by_default(docker):
    """The case that blocks a new run hardest.

    Execute refuses to start while another CORE session is active, so a
    container still running here belongs to a run that is already over -- and it
    is holding a node name the new run needs.
    """
    rec = docker({
        'docker-11': ('running', '/tmp/vulns/.compose-projects/docker-11/docker-compose.yml'),
        'docker-12': ('created', '/tmp/vulns/.compose-projects/docker-12/docker-compose.yml'),
    })
    vuln_process.remove_stale_scenarioforge_containers()

    assert sorted(rec.removed) == ['docker-11', 'docker-12']


def test_running_containers_can_still_be_spared(docker):
    rec = docker({
        'docker-11': ('running', '/tmp/vulns/.compose-projects/docker-11/docker-compose.yml'),
        'docker-12': ('created', '/tmp/vulns/.compose-projects/docker-12/docker-compose.yml'),
    })
    result = vuln_process.remove_stale_scenarioforge_containers(include_running=False)

    assert rec.removed == ['docker-12']
    assert 'docker-11' in result['skipped_running']


def test_an_operator_container_survives_even_when_running(docker):
    """The project-label rule holds regardless of state."""
    rec = docker({
        'my-postgres': ('running', '/home/me/db/docker-compose.yml'),
        'docker-11': ('running', '/tmp/vulns/.compose-projects/docker-11/docker-compose.yml'),
    })
    vuln_process.remove_stale_scenarioforge_containers()

    assert rec.removed == ['docker-11']


def test_never_touches_an_unrelated_container(docker):
    """Someone else's stopped container carries no ScenarioForge project label."""
    rec = docker({
        'my-postgres': ('exited', '/home/me/projects/db/docker-compose.yml'),
        'jenkins': ('created', ''),
        'docker-11': ('created', '/tmp/vulns/.compose-projects/docker-11/docker-compose.yml'),
    })
    vuln_process.remove_stale_scenarioforge_containers()

    assert rec.removed == ['docker-11']


def test_a_removal_failure_is_reported_not_raised(docker):
    rec = docker({'docker-11': ('created', '/tmp/vulns/x/docker-compose.yml')})

    def _failing(argv, **kwargs):
        if argv[:3] == ['docker', 'rm', '-f']:
            return subprocess.CompletedProcess(argv, 1, stdout='device or resource busy', stderr='')
        return _Recorder.__call__(rec, argv, **kwargs)

    subprocess.run = _failing
    result = vuln_process.remove_stale_scenarioforge_containers()

    assert result['removed'] == []
    assert 'docker-11' in result['errors']


def test_compose_failure_reason_is_extracted_for_the_operator():
    """`rc=1` alone is unactionable; the cause is in the captured output."""
    from scenarioforge import cli

    meta = {'docker_nodes_start_recovery_attempts': [
        {'ok': False, 'error': 'docker compose up rc=1',
         'output': 'Image docker-11-node Building \nopen /home/corevm/.docker/buildx/.lock: permission denied'},
    ]}
    reason = cli._first_docker_restart_failure_reason(meta)
    assert 'permission denied' in reason


def test_no_reason_when_every_restart_succeeded():
    from scenarioforge import cli

    meta = {'docker_nodes_start_recovery_attempts': [{'ok': True, 'output': 'Started'}]}
    assert cli._first_docker_restart_failure_reason(meta) == ''


def test_docker_home_permission_repair_is_scoped_and_idempotent():
    """Running docker as root seeds root-owned state into the invoking user's
    ~/.docker; buildx/.lock is the usual casualty, and every later build that
    needs it dies with a bare `rc=1`."""
    from webapp import app_backend as backend

    cmd = backend._docker_home_permission_repair_command('corevm')

    # Scoped to that user's own ~/.docker, resolved from passwd rather than
    # assuming /home/<user>.
    assert 'getent passwd corevm' in cmd
    assert '"$HOME_DIR/.docker"' in cmd
    # Only files not already owned by the user are touched.
    assert '! -user corevm' in cmd
    assert 'chown corevm:corevm' in cmd
    # Nothing to do -> exits without output, so a clean VM stays quiet.
    assert 'exit 0' in cmd

    import subprocess
    assert subprocess.run(['sh', '-n', '-c', cmd], capture_output=True).returncode == 0


def test_docker_home_permission_repair_quotes_the_username():
    """The username reaches a root shell, so it must not be interpolated raw."""
    from webapp import app_backend as backend

    cmd = backend._docker_home_permission_repair_command('bad; rm -rf /')
    assert '; rm -rf /' not in cmd.replace("'bad; rm -rf /'", '')
    import subprocess
    assert subprocess.run(['sh', '-n', '-c', cmd], capture_output=True).returncode == 0


def test_docker_home_permission_repair_can_be_disabled(monkeypatch):
    from webapp import app_backend as backend

    monkeypatch.delenv('CORETG_REPAIR_DOCKER_HOME_PERMS', raising=False)
    assert backend._docker_home_permission_repair_enabled() is True
    monkeypatch.setenv('CORETG_REPAIR_DOCKER_HOME_PERMS', '0')
    assert backend._docker_home_permission_repair_enabled() is False


def test_cleanup_runs_before_the_topology_build():
    """Placement is the whole fix.

    Building the topology is the first thing to run `docker compose up`, so a
    leftover container aborts the run there. Cleaning up afterwards -- next to
    the conflict check, where this started -- never gets the chance.
    """
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / 'scenarioforge' / 'cli.py').read_text(
        encoding='utf-8', errors='ignore'
    ).splitlines()
    cleanup = [i for i, line in enumerate(source) if 'remove_stale_scenarioforge_containers()' in line]
    build = [
        i for i, line in enumerate(source)
        if 'build_segmented_topology(' in line and not line.strip().startswith('def ')
    ]
    assert cleanup, 'execute no longer clears leftover containers'
    assert build, 'could not locate the topology build'
    assert max(cleanup) < min(build), (
        f'cleanup at {cleanup} must precede the topology build at {min(build)}'
    )


def test_conflict_resolution_keeps_images():
    """Freeing a container name must not delete the image behind it.

    Deleting images was meant to stop CORE reusing a stale per-session build,
    but conflict resolution runs *after* preflight has already built the
    wrapper image for this run, so it deleted work moments old and CORE failed
    with `No such image` on a node whose image had just existed:

        09:03:47  preflight wrapper build service=vulnslot-6 image=coretg/...
        09:04:59  Removed Docker conflicts: containers=18 images=20
        09:12:33  No such image: coretg/...-vulnslot-6-...:iproute2

    Staleness is already handled twice over: a wrapper tag embeds a sha256 of
    its identity, so changed content yields a different tag, and preflight
    rebuilds wrappers unconditionally before CORE starts.
    """
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / 'scenarioforge' / 'cli.py').read_text(
        encoding='utf-8', errors='ignore'
    )
    assert 'remove_docker_conflicts(conflicts)' in source, 'containers must still be freed'

    vuln = (Path(__file__).resolve().parents[1] / 'scenarioforge' / 'utils' / 'vuln_process.py').read_text(
        encoding='utf-8', errors='ignore'
    )
    body = vuln[vuln.index('def remove_docker_conflicts'):]
    body = body[:body.index('\ndef ', 1)]
    assert "'image', 'rm'" not in body, 'conflict resolution must not delete images'


def test_an_existing_image_is_not_reported_as_a_conflict(monkeypatch, tmp_path):
    """An image present locally is the cache, not a conflict."""
    compose = tmp_path / 'docker-compose.yml'
    compose.write_text(
        'services:\n'
        '  vulnslot-6:\n'
        '    image: coretg/scenarios-x-vulnslot-6-bc7c2020c62e:iproute2\n'
        '    container_name: vulnslot-6\n'
        '  inject_copy:\n'
        '    image: alpine:3.19\n',
        encoding='utf-8',
    )

    class _Proc:
        def __init__(self, rc):
            self.returncode = rc

    # Everything exists locally, which used to mean "all of it is a conflict".
    # The helper imports these inside the function, so patch the real modules.
    monkeypatch.setattr('shutil.which', lambda _n: '/usr/bin/docker')
    monkeypatch.setattr('subprocess.run', lambda *a, **k: _Proc(0))

    conflicts = vuln_process.detect_docker_conflicts_for_compose_files([str(compose)])

    assert conflicts['images'] == [], 'a cached image must never be a conflict'
    assert 'vulnslot-6' in conflicts['containers'], 'container names still conflict'
