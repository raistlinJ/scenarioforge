"""A wrapper build that fails on architecture must say so.

An amd64-only base image on the arm64 CORE VM fails at the first RUN, so the
error pointed at a shell command inside the generated Dockerfile:

    ERROR: failed to build: ... process "/bin/sh -c u=$(id -un ...)"
    did not complete successfully: exit code: 255

The cause is that `vulhub/grafana:8.5.4` publishes no arm64 build and the VM has
no qemu binfmt handlers, so nothing from that image can execute there at all.
"""

from __future__ import annotations

import pytest

from scenarioforge.builders import topology as topo

DOCKERFILE = (
    '# generated wrapper\n'
    'FROM vulhub/grafana:8.5.4 AS coretg_userprobe\n'
    'RUN u=$(id -un) && echo "$u" > /tmp/coretg_base_user\n'
    '\n'
    'FROM vulhub/grafana:8.5.4\n'
    'RUN true\n'
)


@pytest.fixture
def dockerfile(tmp_path):
    path = tmp_path / 'Dockerfile'
    path.write_text(DOCKERFILE, encoding='utf-8')
    return str(path)


def _runner(*, image_arch, host_arch, image_rc=0, host_rc=0):
    def run(args, timeout=None):
        if args[:3] == ['docker', 'image', 'inspect']:
            return image_rc, image_arch
        if args[:2] == ['docker', 'version']:
            return host_rc, host_arch
        return 1, ''
    return run


def _note(dockerfile, **kwargs):
    return topo._wrapper_base_platform_note(
        dockerfile, docker_cmd=['docker'], run=_runner(**kwargs),
    )


def test_mismatch_names_both_architectures_and_the_image(dockerfile):
    note = _note(dockerfile, image_arch='amd64', host_arch='arm64')
    assert 'vulhub/grafana:8.5.4' in note
    assert 'amd64' in note and 'arm64' in note


def test_mismatch_suggests_installing_emulation_for_the_right_arch(dockerfile):
    note = _note(dockerfile, image_arch='amd64', host_arch='arm64')
    assert 'binfmt --install amd64' in note


def test_matching_architecture_says_nothing(dockerfile):
    """Only speak up when architecture is actually the problem."""
    assert _note(dockerfile, image_arch='arm64', host_arch='arm64') == ''


@pytest.mark.parametrize(
    'kwargs',
    [
        {'image_arch': '', 'host_arch': 'arm64'},
        {'image_arch': 'amd64', 'host_arch': ''},
        {'image_arch': 'amd64', 'host_arch': 'arm64', 'image_rc': 1},
        {'image_arch': 'amd64', 'host_arch': 'arm64', 'host_rc': 1},
    ],
    ids=['no-image-arch', 'no-host-arch', 'inspect-failed', 'version-failed'],
)
def test_unknown_architecture_is_not_guessed_at(dockerfile, kwargs):
    assert _note(dockerfile, **kwargs) == ''


def test_first_from_line_is_used(tmp_path):
    path = tmp_path / 'Dockerfile'
    path.write_text('FROM base/one:1 AS probe\nRUN true\nFROM base/two:2\n', encoding='utf-8')
    note = topo._wrapper_base_platform_note(
        str(path), docker_cmd=['docker'], run=_runner(image_arch='amd64', host_arch='arm64'),
    )
    assert 'base/one:1' in note
    assert 'AS probe' not in note, 'the stage alias is not part of the image name'


def test_missing_dockerfile_is_not_fatal(tmp_path):
    note = topo._wrapper_base_platform_note(
        str(tmp_path / 'nope'), docker_cmd=['docker'],
        run=_runner(image_arch='amd64', host_arch='arm64'),
    )
    assert note == ''


def test_dockerfile_without_a_from_is_not_fatal(tmp_path):
    path = tmp_path / 'Dockerfile'
    path.write_text('# nothing here\nRUN true\n', encoding='utf-8')
    note = topo._wrapper_base_platform_note(
        str(path), docker_cmd=['docker'],
        run=_runner(image_arch='amd64', host_arch='arm64'),
    )
    assert note == ''
