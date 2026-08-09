"""Container teardown must reclaim anonymous volumes.

Vulnerability stacks are database-backed -- postgres/mysql declare VOLUME on
their data directory -- so a `docker rm` without -v orphans a data volume on
every teardown. Nothing reclaims those later, and they fill the CORE VM's disk
while the scenario itself looks clean.
"""

from webapp import app_backend as ab

_SRC = open(ab.__file__, encoding='utf-8').read()


def test_named_container_removal_uses_dash_v():
    script = ab._remote_docker_cleanup_script(['docker-7'], 'pw')
    assert "_run_docker(['rm', '-v', nm]" in script
    assert "_run_docker(['rm', nm]" not in script


def test_bulk_container_removal_uses_dash_v():
    assert 'xargs -r docker rm -f -v' in _SRC
    assert 'xargs -r docker rm -f;' not in _SRC


def test_single_node_removal_uses_dash_v():
    assert 'docker rm -f -v {shlex.quote(node_token)}' in _SRC
    assert 'docker rm -f {shlex.quote(node_token)}' not in _SRC


def test_compose_teardowns_still_pass_dash_v():
    """`compose down -v` is what reclaims volumes for stacks we brought up."""
    assert _SRC.count('down -v --remove-orphans') >= 2


def test_cleanup_script_still_prunes_dangling_volumes():
    """The explicit cleanup keeps its catch-all for volumes already orphaned."""
    assert 'docker volume prune -f' in _SRC
