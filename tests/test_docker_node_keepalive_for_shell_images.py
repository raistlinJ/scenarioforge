"""A vuln image whose whole startup is a shell has to be kept alive.

`vulhub/imagemagick:7.0.10-36` declares `Cmd: ["bash"]` and no entrypoint, and
the vulhub compose gives the service no command of its own -- it is meant to be
`exec`'d into, not run as a service. Started without a TTY, bash reads EOF and
exits at once, so `docker inspect` reported `0 exited` on every poll and
preflight failed the node with "container PID remained 0 ... This would cause
CORE to fail with /proc/0/environ" (dataset-catalog-coverage-030).

`_ensure_keepalive_for_base_os_images` already handles this shape, but decides
from the image *reference* -- `ubuntu`, `alpine`, `busybox` and friends -- so a
vuln image built on one of them is invisible to it. By preflight the image's own
config has been inspected, which answers the question directly.
"""

from __future__ import annotations

from scenarioforge.builders.topology import (
    _BARE_SHELL_COMMANDS,
    _image_startup_is_bare_shell,
)


def test_the_imagemagick_config_that_failed_is_detected() -> None:
    # Copied from the run's `docker image inspect --format {{json .Config}}`.
    config = {
        'User': '0',
        'Env': ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'],
        'Cmd': ['bash'],
        'Labels': {'maintainer': 'phith0n <root@leavesongs.com>'},
    }
    assert _image_startup_is_bare_shell(config) is True


def test_absolute_shell_paths_count() -> None:
    for shell in sorted(_BARE_SHELL_COMMANDS):
        assert _image_startup_is_bare_shell({'Cmd': [f'/bin/{shell}']}) is True, shell


def test_a_shell_running_a_script_is_left_alone() -> None:
    # `sh -c ...` is the normal way to start a real service; it must not be
    # replaced with a keepalive.
    assert _image_startup_is_bare_shell(
        {'Cmd': ['sh', '-c', 'exec nginx -g "daemon off;"']}
    ) is False


def test_a_real_entrypoint_is_left_alone() -> None:
    assert _image_startup_is_bare_shell(
        {'Entrypoint': ['/docker-entrypoint.sh'], 'Cmd': ['nginx', '-g', 'daemon off;']}
    ) is False


def test_an_entrypoint_shell_with_a_command_is_left_alone() -> None:
    # Entrypoint and Cmd combine into one argv; together they are not bare.
    assert _image_startup_is_bare_shell(
        {'Entrypoint': ['bash'], 'Cmd': ['/start.sh']}
    ) is False


def test_an_empty_config_is_not_treated_as_a_shell() -> None:
    # An image with neither is already handled elsewhere (the shim declines to
    # replace a startup it cannot reconstruct); claiming "bare shell" here would
    # put a keepalive on a service that may have a command from the compose.
    assert _image_startup_is_bare_shell({}) is False
    assert _image_startup_is_bare_shell({'Cmd': []}) is False
    assert _image_startup_is_bare_shell(None) is False  # type: ignore[arg-type]


def test_a_non_shell_single_binary_is_left_alone() -> None:
    assert _image_startup_is_bare_shell({'Cmd': ['redis-server']}) is False
