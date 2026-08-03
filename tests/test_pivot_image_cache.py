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
