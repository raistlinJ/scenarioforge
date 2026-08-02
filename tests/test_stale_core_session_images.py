"""CORE's per-session node images must not survive into the next run.

CORE starts a node with `docker compose --project-name core-<session>-<node>-<name>
up -d`, which tags what it builds `core-<session>-<node>-<name>-<service>` and
builds only when that tag is absent. Session and node ids repeat between runs, so
the tag carries no content identity:

    flaggenslot-5 was rebuilt from a Python ticket-portal context, but CORE
    reused a 12-hour-old WebDAV image and the container crash-looped on
    "DAV_USER: parameter not set"

Images that genuinely are a cache -- generator images keyed by source digest,
wrapper images keyed by an identity hash, and upstream base images -- are keyed
by content and must survive.
"""

from __future__ import annotations

import subprocess

import pytest

from scenarioforge.utils import vuln_process
from scenarioforge.utils.vuln_process import CORE_SESSION_IMAGE_RE

PRESENT = [
    'core-1-10-flaggenslot-5-flaggenslot-5:latest',
    'core-1-23-docker-18-docker-18:latest',
    'coretg-gen-p-07-01-26-15-10-01-6de4d6-53-generator-dffd95e22686:latest',
    'coretg/scenarios-08-01-26-scenario2-vulnslot-6-bc7c2020c62e:iproute2',
    'alpine:3.19',
    'vulhub/solr:8.11.0',
    'python:3.12-slim',
    'core-utils:latest',
    'my-core-1-2-thing:latest',
    '<none>:<none>',
]


@pytest.fixture
def docker(monkeypatch):
    removed = []

    def fake_run(argv, **kwargs):
        if argv[:2] == ['docker', 'images']:
            return subprocess.CompletedProcess(argv, 0, stdout='\n'.join(PRESENT), stderr='')
        if argv[:4] == ['docker', 'image', 'rm', '-f']:
            removed.append(argv[4])
            return subprocess.CompletedProcess(argv, 0, stdout='', stderr='')
        raise AssertionError(f'unexpected command: {argv}')

    monkeypatch.setattr('shutil.which', lambda _n: '/usr/bin/docker')
    monkeypatch.setattr('subprocess.run', fake_run)
    return removed


def test_removes_only_core_session_images(docker):
    result = vuln_process.remove_stale_core_session_images()

    assert sorted(docker) == [
        'core-1-10-flaggenslot-5-flaggenslot-5:latest',
        'core-1-23-docker-18-docker-18:latest',
    ]
    assert sorted(result['removed']) == sorted(docker)


@pytest.mark.parametrize(
    'ref',
    [
        'coretg-gen-p-x-53-generator-dffd95e22686',
        'coretg/scenarios-x-vulnslot-6-bc7c2020c62e',
        'alpine',
        'vulhub/solr',
        'python',
    ],
)
def test_content_addressed_and_base_images_survive(docker, ref):
    vuln_process.remove_stale_core_session_images()
    assert not any(r.startswith(ref) for r in docker), f'{ref} is a cache, not a build output'


@pytest.mark.parametrize(
    'repository',
    ['core-utils', 'coredns', 'my-core-1-2-thing', 'core-1-notanode', 'core'],
)
def test_operator_images_that_merely_start_with_core_are_untouched(repository):
    assert not CORE_SESSION_IMAGE_RE.match(repository)


@pytest.mark.parametrize(
    'repository',
    ['core-1-10-flaggenslot-5-flaggenslot-5', 'core-12-345-docker-7-docker-7'],
)
def test_the_pattern_matches_core_project_builds(repository):
    assert CORE_SESSION_IMAGE_RE.match(repository)


def test_a_removal_failure_is_reported_not_raised(monkeypatch):
    def fake_run(argv, **kwargs):
        if argv[:2] == ['docker', 'images']:
            return subprocess.CompletedProcess(argv, 0, stdout='core-1-10-a-a:latest', stderr='')
        return subprocess.CompletedProcess(argv, 1, stdout='image is being used', stderr='')

    monkeypatch.setattr('shutil.which', lambda _n: '/usr/bin/docker')
    monkeypatch.setattr('subprocess.run', fake_run)

    result = vuln_process.remove_stale_core_session_images()

    assert result['removed'] == []
    assert 'core-1-10-a-a:latest' in result['errors']


def test_no_docker_is_not_fatal(monkeypatch):
    monkeypatch.setattr('shutil.which', lambda _n: None)
    assert vuln_process.remove_stale_core_session_images() == {'removed': [], 'errors': {}}


def test_execute_clears_them_before_building_the_topology():
    """A rebuild only helps if it happens before CORE starts the nodes."""
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / 'scenarioforge' / 'cli.py').read_text(
        encoding='utf-8', errors='ignore'
    )
    lines = source.splitlines()
    cleanup = [i for i, ln in enumerate(lines) if 'remove_stale_core_session_images()' in ln]
    build = [i for i, ln in enumerate(lines) if 'build_segmented_topology(' in ln]
    assert cleanup, 'execute no longer clears stale CORE session images'
    assert build, 'could not locate the topology build'
    assert max(cleanup) < min(build), 'the clear must precede the topology build'
