"""Preflight must not leave the node's compose stack running.

Preflight and core-daemon bring up the same project (`<node>conf`) from two
different files -- CORE renders its own copy, rewriting a sidecar's
`network_mode` to `service:<node>`, dropping `depends_on` and extending
`extra_hosts`. Compose sees the drift and recreates the services.

That is free for a single-service recipe and fatal for one that initializes a
stateful sidecar, because compose reattaches the sidecar's anonymous volume to
the new container. Measured on joomla/CVE-2015-8562: preflight's container ran
`joomla site:install` and created the database, CORE's recreate re-ran the same
non-idempotent entrypoint, it aborted on "A database with name joomla already
exists", and the restart that followed could no longer reach the mysql sidecar
left behind in the old network namespace. The node served nothing while Docker
reported it running.
"""

import re

from scenarioforge.builders import topology

_SRC = open(topology.__file__, encoding='utf-8').read()
_PREFLIGHT = _SRC[_SRC.index('def _docker_compose_preflight'):_SRC.index('def _resolve_compose_interpolations')]


def test_preflight_tears_the_project_down_before_handing_off():
    assert "['down', '--remove-orphans']" in _PREFLIGHT


def test_teardown_keeps_named_volumes():
    """`--volumes` would delete the injects `inject_copy` just seeded.

    The Flow injects for the node live in the named
    `<node>conf_inject-flow-injects` volume. A sidecar's data volume is
    anonymous, so dropping its container is already enough to reset it.
    """
    down = re.search(r"_run\(compose_base \+ \[('down'[^\]]*)\]", _PREFLIGHT)
    assert down, 'no compose down call found in preflight'
    assert '--volumes' not in down.group(1)
    assert '-v' not in down.group(1).split(',')


def test_teardown_runs_after_the_pid_wait():
    """Tearing down first would discard what preflight exists to prove."""
    assert _PREFLIGHT.index('_wait_for_nonzero_pid') < _PREFLIGHT.index("['down', '--remove-orphans']")


def test_teardown_failure_is_not_fatal_but_is_reported():
    """CORE's up still reconciles the project, so this must not fail the node.

    It does change what happens next for a stateful recipe, so a silent skip
    would turn the hollow-node failure back into an unexplained one.
    """
    tail = _PREFLIGHT[_PREFLIGHT.index("['down', '--remove-orphans']"):]
    guard = tail[:tail.index('preflight done')]
    assert 'except Exception' in guard
    assert 'logger.warning' in guard
    assert 'raise' not in guard
