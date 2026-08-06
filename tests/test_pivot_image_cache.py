"""Pivot provider images are cached, so Docker nodes never need the internet.

An image already on the host is never re-pulled, a pre-seeded `docker save`
tarball is loaded instead of pulling, and once present the image is pinned so
execute-time cleanup cannot reclaim it and force another download.
"""

import os

import pytest

from scenarioforge import cli
from scenarioforge.utils.pivot_access import PIVOT_SSH_IMAGE


def _summary(image=PIVOT_SSH_IMAGE):
    return {"pivot_access": {"providers": [
        {"subnet": "10.0.0.0/24", "node_name": "", "added": True, "image": image},
    ]}}


class _Recorder:
    """Stands in for docker, recording what would have been run."""

    def __init__(self, present=False, pull_ok=True, load_ok=True):
        self.present = present
        self.pull_ok = pull_ok
        self.load_ok = load_ok
        self.calls: list[list[str]] = []

    def __call__(self, args, timeout=0):
        self.calls.append(list(args))
        if 'inspect' in args:
            return (0 if self.present else 1), ''
        if 'pull' in args:
            return (0 if self.pull_ok else 1), 'pull output'
        if 'load' in args:
            return (0 if self.load_ok else 1), 'load output'
        return 0, ''

    @property
    def verbs(self):
        out = []
        for call in self.calls:
            for verb in ('inspect', 'pull', 'load'):
                if verb in call:
                    out.append(verb)
        return out


@pytest.fixture
def patched(monkeypatch):
    def _apply(recorder, cache_dir='/nonexistent-cache'):
        monkeypatch.setattr('scenarioforge.builders.topology._docker_cmd', lambda: ['docker'])
        monkeypatch.setattr('scenarioforge.builders.topology._docker_sudo_password', lambda: '')
        monkeypatch.setenv('CORETG_PIVOT_IMAGE_CACHE_DIR', cache_dir)
        monkeypatch.setattr(cli.subprocess, 'run', _fake_run(recorder))
        return recorder
    return _apply


def _fake_run(recorder):
    class _Proc:
        def __init__(self, rc, out):
            self.returncode = rc
            self.stdout = out

    def _run(args, **kwargs):
        rc, out = recorder(args)
        return _Proc(rc, out)
    return _run


# --------------------------------------------------------------------------- #
# Never pull what is already there
# --------------------------------------------------------------------------- #

def test_an_image_already_present_is_not_pulled(patched):
    rec = patched(_Recorder(present=True))
    out = cli._ensure_pivot_provider_images(_summary())
    assert out[PIVOT_SSH_IMAGE] == 'cached'
    assert 'pull' not in rec.verbs        # the offline guarantee


def test_a_missing_image_is_pulled_once(patched):
    rec = patched(_Recorder(present=False))
    out = cli._ensure_pivot_provider_images(_summary())
    assert out[PIVOT_SSH_IMAGE] == 'pulled'
    assert rec.verbs.count('pull') == 1


def test_each_distinct_image_is_handled_once(patched):
    rec = patched(_Recorder(present=True))
    summary = {"pivot_access": {"providers": [
        {"image": "img/a:1"}, {"image": "img/a:1"}, {"image": "img/b:2"},
    ]}}
    out = cli._ensure_pivot_provider_images(summary)
    assert sorted(out) == ['img/a:1', 'img/b:2']
    assert rec.verbs.count('inspect') == 2


# --------------------------------------------------------------------------- #
# Pre-seeding avoids the network entirely
# --------------------------------------------------------------------------- #

def test_a_seeded_tarball_is_loaded_instead_of_pulled(patched, tmp_path):
    rec = patched(_Recorder(present=False), cache_dir=str(tmp_path))
    tar = tmp_path / cli._pivot_image_tar_name(PIVOT_SSH_IMAGE)
    tar.write_text('not really a tarball', encoding='utf-8')
    out = cli._ensure_pivot_provider_images(_summary())
    assert out[PIVOT_SSH_IMAGE] == 'loaded-from-tarball'
    assert 'load' in rec.verbs
    assert 'pull' not in rec.verbs


def test_a_broken_tarball_falls_back_to_pulling(patched, tmp_path):
    rec = patched(_Recorder(present=False, load_ok=False), cache_dir=str(tmp_path))
    (tmp_path / cli._pivot_image_tar_name(PIVOT_SSH_IMAGE)).write_text('x', encoding='utf-8')
    out = cli._ensure_pivot_provider_images(_summary())
    assert out[PIVOT_SSH_IMAGE] == 'pulled'
    assert rec.verbs == ['inspect', 'load', 'pull']


def test_tar_name_is_filesystem_safe():
    name = cli._pivot_image_tar_name('lscr.io/linuxserver/openssh-server:latest')
    assert '/' not in name and ':' not in name
    assert name.endswith('.tar')


# --------------------------------------------------------------------------- #
# Failure is reported, not fatal
# --------------------------------------------------------------------------- #

def test_an_unpullable_image_is_reported_without_raising(patched):
    patched(_Recorder(present=False, pull_ok=False))
    out = cli._ensure_pivot_provider_images(_summary())
    assert out[PIVOT_SSH_IMAGE] == 'unavailable'


def test_nothing_to_do_when_no_provider_needs_an_image(patched):
    rec = patched(_Recorder(present=True))
    assert cli._ensure_pivot_provider_images({}) == {}
    assert cli._ensure_pivot_provider_images(
        {"pivot_access": {"providers": [{"image": ""}]}}) == {}
    assert rec.calls == []


# --------------------------------------------------------------------------- #
# Cached forever: cleanup must not reclaim it
# --------------------------------------------------------------------------- #

def test_the_pivot_image_is_always_in_the_keep_set(monkeypatch):
    monkeypatch.delenv('CORETG_PERSISTENT_IMAGES_JSON', raising=False)
    assert PIVOT_SSH_IMAGE in cli._persistent_images_to_keep()


def test_operator_pins_are_preserved_alongside_it(monkeypatch):
    monkeypatch.setenv('CORETG_PERSISTENT_IMAGES_JSON', '["my/pinned:1"]')
    keep = cli._persistent_images_to_keep()
    assert 'my/pinned:1' in keep
    assert PIVOT_SSH_IMAGE in keep


def test_a_malformed_pin_payload_still_keeps_the_pivot_image(monkeypatch):
    monkeypatch.setenv('CORETG_PERSISTENT_IMAGES_JSON', 'not json')
    assert PIVOT_SSH_IMAGE in cli._persistent_images_to_keep()


def test_execute_prepares_images_after_segmentation():
    import inspect
    src = inspect.getsource(cli)
    assert '_ensure_pivot_provider_images(seg_summary)' in src


# --------------------------------------------------------------------------- #
# A subnet left without a usable pivot must not fail silently
# --------------------------------------------------------------------------- #

def test_an_uncreated_provider_is_warned_about(caplog):
    summary = {"pivot_access": {"providers": [
        {"subnet": "10.0.123.0/24", "added": True, "node_id": None},
        {"subnet": "172.18.9.0/24", "added": True, "node_id": None},
    ]}}
    with caplog.at_level('WARNING'):
        stranded = cli._warn_unmaterialised_pivot_providers(summary)
    assert stranded == ["10.0.123.0/24", "172.18.9.0/24"]
    text = caplog.text
    assert "no usable pivot" in text
    assert "10.0.123.0/24" in text and "172.18.9.0/24" in text
    # It says what to do about it, not just that it happened.
    assert "disable" in text or "reachable service" in text


def test_a_reused_provider_is_not_warned_about(caplog):
    summary = {"pivot_access": {"providers": [
        {"subnet": "10.0.0.0/24", "added": False, "node_id": 6, "node_name": "docker-1"},
    ]}}
    with caplog.at_level('WARNING'):
        assert cli._warn_unmaterialised_pivot_providers(summary) == []
    assert "no usable pivot" not in caplog.text


def test_a_provider_that_gained_a_node_is_not_warned_about(caplog):
    # Once materialisation lands, an added provider with a node is fine.
    summary = {"pivot_access": {"providers": [
        {"subnet": "10.0.0.0/24", "added": True, "node_id": 42},
    ]}}
    with caplog.at_level('WARNING'):
        assert cli._warn_unmaterialised_pivot_providers(summary) == []


def test_no_pivot_access_block_is_silent(caplog):
    with caplog.at_level('WARNING'):
        assert cli._warn_unmaterialised_pivot_providers({}) == []
        assert cli._warn_unmaterialised_pivot_providers(None) == []
    assert caplog.text == ""


def test_execute_warns_after_preparing_images():
    import inspect
    src = inspect.getsource(cli)
    assert '_warn_unmaterialised_pivot_providers(seg_summary)' in src


# --------------------------------------------------------------------------- #
# The wrapper base is as necessary as the provider image
# --------------------------------------------------------------------------- #

def test_the_wrapper_base_is_pinned_against_cleanup():
    # Every Docker node's iproute2 wrapper is built FROM it. A live run lost it
    # to a prune and then could not build a single Docker node on a host whose
    # daemon had no DNS: the provider image was pinned and survived, the thing
    # it is built on top of was not.
    from scenarioforge.cli import _persistent_images_to_keep, _wrapper_base_image

    base = _wrapper_base_image()
    assert base
    assert base in _persistent_images_to_keep()


def test_the_wrapper_base_is_prepared_alongside_the_provider_images(monkeypatch):
    from scenarioforge import cli

    asked: list[list[str]] = []
    monkeypatch.setattr(cli, '_ensure_docker_images_available',
                        lambda images: asked.append(list(images)) or {})
    cli._ensure_runtime_docker_images(
        {'pivot_access': {'providers': [{'image': 'example.invalid/ssh:1'}]}})
    assert asked, 'image preparation was never asked for anything'
    assert 'example.invalid/ssh:1' in asked[0]
    assert cli._wrapper_base_image() in asked[0]


def test_the_wrapper_base_is_prepared_even_with_no_pivot_providers(monkeypatch):
    # A scenario with no pivot access still builds Docker nodes, and every one
    # of them needs the wrapper base.
    from scenarioforge import cli

    asked: list[list[str]] = []
    monkeypatch.setattr(cli, '_ensure_docker_images_available',
                        lambda images: asked.append(list(images)) or {})
    cli._ensure_runtime_docker_images({})
    assert asked and cli._wrapper_base_image() in asked[0]


def test_provider_images_are_collected_without_blanks_or_duplicates():
    from scenarioforge.cli import _pivot_provider_images

    images = _pivot_provider_images({'pivot_access': {'providers': [
        {'image': 'a:1'}, {'image': 'a:1'}, {'image': ''}, {'not': 'a dict'},
    ]}})
    assert images == ['a:1']


def test_the_execute_path_prepares_every_image_before_building():
    # CORE starts a Docker node the moment it is added, so a missing image is
    # not recoverable by the time the builder runs.
    import inspect
    from scenarioforge import cli

    src = inspect.getsource(cli)
    assert '_ensure_runtime_docker_images(' in src
    assert src.index('_ensure_runtime_docker_images(') < src.index('PHASE: Building topology')


# --------------------------------------------------------------------------- #
# Air-gapped: the operator seeds their content, the framework seeds its own
# --------------------------------------------------------------------------- #

def test_framework_prerequisites_cover_every_image_the_framework_bakes_in():
    # The operator picks the vulnerabilities and generators. They should not
    # also have to discover the plumbing images by watching a run fail.
    from scenarioforge.utils.prerequisite_images import prerequisite_images

    images = prerequisite_images()
    # The wrapper base every Docker node is built FROM.
    assert 'busybox:1.36.1-musl' in images
    # The standard node template, the inject-copy helper, the shipped generator
    # templates, and the pivot provider.
    assert 'ubuntu:22.04' in images
    assert 'alpine:3.19' in images
    assert 'python:3.12-slim' in images
    assert any('openssh-server' in i for i in images)
    assert len(images) == len(set(images))


def test_prerequisites_follow_a_site_that_mirrors_its_own(monkeypatch):
    # Pinning the upstream image on a site that replaced it would keep and
    # prepare something the run never uses.
    monkeypatch.setenv('CORETG_INJECT_COPY_IMAGE', 'mirror.invalid/alpine:3.19')
    monkeypatch.setenv('CORETG_NFS_GANESHA_WRAPPER_BASE_IMAGE', 'mirror.invalid/ubuntu:22.04')
    import importlib
    from scenarioforge.utils import prerequisite_images as mod
    importlib.reload(mod)
    try:
        images = mod.prerequisite_images()
        assert 'mirror.invalid/alpine:3.19' in images
        assert 'mirror.invalid/ubuntu:22.04' in images
        assert 'alpine:3.19' not in images
    finally:
        monkeypatch.undo()
        importlib.reload(mod)


def test_a_template_image_is_picked_up_without_anyone_registering_it(tmp_path, monkeypatch):
    # A compose template added later should register its base automatically.
    from scenarioforge.utils import prerequisite_images as mod

    root = tmp_path
    (root / 'generator_templates' / 'new-thing').mkdir(parents=True)
    (root / 'generator_templates' / 'new-thing' / 'docker-compose.yml').write_text(
        'services:\n  x:\n    image: example.invalid/newbase:1\n', encoding='utf-8')
    monkeypatch.setattr(mod, '_repo_root', lambda: str(root))
    assert 'example.invalid/newbase:1' in mod._from_templates()


def test_an_interpolated_template_image_is_not_a_prerequisite(tmp_path, monkeypatch):
    # Resolved per run, so nothing could pre-seed it.
    from scenarioforge.utils import prerequisite_images as mod

    root = tmp_path
    (root / 'scripts' / 'thing').mkdir(parents=True)
    (root / 'scripts' / 'thing' / 'docker-compose.yml').write_text(
        'services:\n  x:\n    image: ${REGISTRY}/thing:1\n', encoding='utf-8')
    monkeypatch.setattr(mod, '_repo_root', lambda: str(root))
    assert mod._from_templates() == []


def test_every_prerequisite_is_pinned_against_cleanup():
    from scenarioforge.cli import _persistent_images_to_keep
    from scenarioforge.utils.prerequisite_images import prerequisite_images

    keep = _persistent_images_to_keep()
    for image in prerequisite_images():
        assert image in keep, image


def test_web_cleanup_keep_set_also_includes_every_prerequisite(monkeypatch):
    """Web-side cleanup must use the same prerequisite exceptions as the CLI."""
    from scenarioforge.utils.prerequisite_images import prerequisite_images
    from webapp import app_backend as backend

    monkeypatch.setattr(backend, '_load_vuln_catalogs_state', lambda: {})
    monkeypatch.setattr(backend, '_flag_generators_from_all_installed_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_all_installed_sources', lambda: ([], []))

    keep = backend._persistent_image_keep_set()
    for image in prerequisite_images():
        assert image in keep, image


def test_every_prerequisite_is_prepared_before_the_build(monkeypatch):
    from scenarioforge import cli
    from scenarioforge.utils.prerequisite_images import prerequisite_images

    asked: list[list[str]] = []
    monkeypatch.setattr(cli, '_ensure_docker_images_available',
                        lambda images: asked.append(list(images)) or {})
    cli._ensure_runtime_docker_images({'pivot_access': {'providers': [{'image': 'content:1'}]}})
    requested = asked[0]
    assert 'content:1' in requested
    for image in prerequisite_images():
        assert image in requested, image


def test_missing_images_are_reported_with_the_commands_to_stage_them(monkeypatch, caplog):
    # An air-gapped host is missing all of them at once, so the operator needs
    # the list and the commands together rather than a warning per image.
    import logging as _logging
    from scenarioforge import cli

    monkeypatch.setattr(cli, '_pivot_image_cache_dir', lambda: '/opt/coretg/images')

    class _Proc:
        returncode = 1
        stdout = 'no such host'

    monkeypatch.setattr(cli.subprocess, 'run', lambda *a, **k: _Proc())
    monkeypatch.setattr(cli.os.path, 'isfile', lambda path: False)
    with caplog.at_level(_logging.WARNING):
        results = cli._ensure_docker_images_available(['a:1', 'b:2'])
    assert results == {'a:1': 'unavailable', 'b:2': 'unavailable'}
    text = caplog.text
    assert 'Air-gapped hosts need these 2 image(s)' in text
    assert 'docker save a:1 -o /opt/coretg/images/a_1.tar' in text
    assert 'docker save b:2 -o /opt/coretg/images/b_2.tar' in text
