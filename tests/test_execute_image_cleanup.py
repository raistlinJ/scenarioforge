"""Execute removes the images this application builds, but never operator pins.

The previous cleanup shelled out to `docker images | grep … | xargs docker rmi -f`,
which matched only legacy names and ignored the `persistent` keep set entirely,
so current `coretg/<slug>:iproute2` images accumulated while a pinned image could
be deleted.
"""

from types import SimpleNamespace

from scenarioforge import cli
from scenarioforge.cli import (
    _is_generated_image_repo,
    _select_removable_generated_images,
)


# Observed on a live CORE VM: these must survive, because re-pulling them needs
# a registry the host may not be able to reach.
THIRD_PARTY = [
    'vulhub/grafana:8.5.4', 'vulhub/solr:8.11.0', 'tonistiigi/binfmt:latest',
    'alpine:3.19', 'postgres:9.6-alpine', 'python:3.12-slim',
]
GENERATED = [
    'coretg/scenarios-x-scenario2-vulnslot-6-087a:iproute2',  # current wrapper
    'coretg-gen-foo:latest',                                  # legacy generator
    'myproj_wrapper_thing:v1',                                # legacy wrapper
    'core-1-14-vulnslot-9-db:latest',                         # per-session build
    'p_07-01-26-15-10-01-516b21__115-generator:latest',       # generator pack build
    'docker-27conf-docker-27:latest',                         # CORE compose build
    'docker-15-docker-15:latest',                             # CORE compose build
    'docker-11-node:latest',                                  # CORE compose build
    'flaggenslot-9conf-flaggenslot-9:latest',                 # CORE compose build
    'vulnslot-6-vulnslot-6:latest',                           # CORE compose build
]


def test_recognizes_generated_repositories():
    for ref in GENERATED:
        assert _is_generated_image_repo(ref.rsplit(':', 1)[0]) is True
    for ref in THIRD_PARTY:
        assert _is_generated_image_repo(ref.rsplit(':', 1)[0]) is False
    assert _is_generated_image_repo('') is False


def test_selects_only_generated_images():
    selected = _select_removable_generated_images(GENERATED + THIRD_PARTY)
    assert sorted(selected) == sorted(GENERATED)


def test_third_party_images_are_never_selected():
    # Base images and vulhub pulls must survive; re-pulling them can require a
    # registry the CORE host may not be able to reach.
    assert _select_removable_generated_images(THIRD_PARTY) == []


def test_exact_ref_pin_is_respected():
    pinned = 'coretg/pinned:iproute2'
    selected = _select_removable_generated_images(GENERATED + [pinned], [pinned])
    assert pinned not in selected
    assert sorted(selected) == sorted(GENERATED)


def test_repository_level_pin_covers_every_tag():
    refs = ['coretg-gen-keepme:latest', 'coretg-gen-keepme:v2', 'coretg-gen-other:latest']
    selected = _select_removable_generated_images(refs, ['coretg-gen-keepme'])
    assert selected == ['coretg-gen-other:latest']


def test_pin_written_as_repo_tag_also_matches_other_tags_of_that_repo():
    refs = ['coretg-gen-keepme:latest', 'coretg-gen-keepme:v2']
    assert _select_removable_generated_images(refs, ['coretg-gen-keepme:latest']) == []


def test_untagged_and_malformed_refs_are_skipped():
    # Dangling images are already handled by `docker image prune`.
    refs = ['<none>:<none>', 'coretg/x:<none>', 'coretg/no-tag', '', '   ']
    assert _select_removable_generated_images(refs) == []


def test_duplicate_refs_are_removed_once():
    selected = _select_removable_generated_images(GENERATED + GENERATED)
    assert len(selected) == len(GENERATED)


def test_node_pattern_requires_a_numeric_node_id():
    # `docker-27conf-…` is ours; an unrelated image that merely starts with one
    # of these words is not. The node id is what distinguishes them.
    assert _is_generated_image_repo('docker-27conf-docker-27') is True
    assert _is_generated_image_repo('router-3-router-3') is True
    assert _is_generated_image_repo('docker-compose') is False
    assert _is_generated_image_repo('router-utils') is False
    assert _is_generated_image_repo('hostname-tools') is False


def test_generator_pack_images_are_selected_but_pinnable():
    ref = 'p_07-01-26-15-10-01-516b21__115-generator:latest'
    assert _select_removable_generated_images([ref]) == [ref]
    # An operator pins the pack item to keep its locally built image.
    assert _select_removable_generated_images([ref], [ref]) == []


def test_no_pins_supplied_still_protects_third_party():
    for keep in (None, [], ['', '  ']):
        selected = _select_removable_generated_images(GENERATED + THIRD_PARTY, keep)
        assert sorted(selected) == sorted(GENERATED)


class _CoreWithActiveSession:
    def get_sessions(self):
        return [SimpleNamespace(id=7, state='runtime')]


def _record_cleanup_order(monkeypatch, listing='coretg/x:iproute2\nvulhub/solr:8.11.0'):
    """Run the execute cleanup with every shell/docker call captured in order."""
    order = []

    def _local(cmd, **_kwargs):
        order.append(' '.join(cmd))
        return SimpleNamespace(returncode=0, stdout='ok')

    def _docker(cmd, **_kwargs):
        order.append(' '.join(cmd))
        return SimpleNamespace(returncode=0, stdout=listing)

    monkeypatch.setattr(cli, '_run_local_cmd', _local)
    monkeypatch.setattr(cli, '_run_docker_cmd', _docker)
    monkeypatch.setattr(cli, '_cleanup_stale_vuln_temp_files', lambda: [])
    monkeypatch.setattr(cli, '_persistent_images_to_keep', lambda: [])
    monkeypatch.setattr(cli.shutil, 'which', lambda name: '/usr/bin/' + name)

    args = SimpleNamespace(
        phase='execute',
        core_cleanup_before_run=True,
        docker_cleanup_before_run=True,
        overwrite_existing_images=True,
        docker_remove_all_containers=False,
    )
    cli._best_effort_cli_execute_cleanup(args, _CoreWithActiveSession())
    return order


def _index_of(order, needle):
    return next(i for i, entry in enumerate(order) if needle in entry)


def test_session_teardown_happens_before_image_and_cache_cleanup(monkeypatch):
    # Removing images while the previous session still holds them would leave
    # them behind, so the CORE session must be torn down first.
    order = _record_cleanup_order(monkeypatch)

    teardown = _index_of(order, 'core-cleanup')
    assert teardown < _index_of(order, 'docker images --format')
    assert teardown < _index_of(order, 'docker image rm')
    assert teardown < _index_of(order, 'builder prune')


def test_containers_are_pruned_before_images_are_removed(monkeypatch):
    # A stopped container pins its image, and removal is not forced, so the
    # container sweep has to come first for the image sweep to be effective.
    order = _record_cleanup_order(monkeypatch)

    assert _index_of(order, 'container prune') < _index_of(order, 'docker image rm')


def test_only_generated_images_are_removed_during_cleanup(monkeypatch):
    order = _record_cleanup_order(monkeypatch)

    removals = [entry for entry in order if entry.startswith('docker image rm')]
    assert removals == ['docker image rm coretg/x:iproute2']
    assert not any('vulhub/solr' in entry for entry in removals)
