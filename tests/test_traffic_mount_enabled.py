"""Docker nodes must be able to read the traffic directory.

The traffic agent takes a per-node JSON config from /tmp/traffic, and future
flows may also ship input files (media samples, payload corpora) from there.
Arguments and environment cannot carry files, and this project has already hit
the kernel's per-string environment limit once, so the directory is bind-mounted
read-only instead.

Which nodes actually carry a flow is not known until the Traffic phase, which
runs after compose is written, so the mount is applied to every Docker node
rather than a selected subset.
"""

import inspect
from pathlib import Path

from scenarioforge.builders import topology
from scenarioforge.utils import vuln_process


def test_both_topology_builders_accept_the_traffic_mount_flag():
    for name in ("build_segmented_topology", "build_star_from_roles"):
        signature = inspect.signature(getattr(topology, name))
        assert "enable_traffic_mount" in signature.parameters, name


def test_cli_enables_the_traffic_mount_for_both_topology_shapes():
    source = Path("scenarioforge/cli.py").read_text(encoding="utf-8")
    # Segmented and star topologies are separate call sites; both need it.
    assert source.count("enable_traffic_mount=True") == 2


def test_every_compose_node_kind_gets_the_mount():
    """vulnerability, flag-node-generator, and plain docker nodes alike.

    They all arrive through `docker_by_name` at the final compose-prep step, so
    setting the flag there covers every kind without depending on the builder
    flag propagating into each record.
    """
    source = Path("scenarioforge/cli.py").read_text(encoding="utf-8")
    assert "_rec.setdefault('EnableTrafficMount', 'true')" in source


def test_flag_becomes_a_read_only_bind_mount():
    source = inspect.getsource(vuln_process)
    assert "'/tmp/traffic:/tmp/traffic:ro'" in source
    # The record may carry any of these spellings.
    assert "EnableTrafficMount" in source
    assert "is_traffic_node" in source


def test_builders_record_the_flag_on_docker_nodes():
    source = inspect.getsource(topology)
    assert "rec.setdefault('EnableTrafficMount', 'true')" in source
