from pathlib import Path


def test_traffic_service_uses_absolute_paths_and_runtime_dir():
    p = Path("on_core_machine/custom_services/TrafficService.py")
    txt = p.read_text("utf-8", errors="ignore")

    # The file stays at an absolute path, which is where CORE places it inside a
    # Docker node. The startup command tries the relative name first so it also
    # resolves on a namespaced vnode, whose copy only exists in the node's
    # `.conf` working directory.
    assert 'files: list[str] = ["/runtraffic.sh"]' in txt
    assert "f=runtraffic.sh;" in txt
    assert "f=/runtraffic.sh" in txt
    assert 'runtime_dir=/tmp/coretg_traffic' in txt
    # The node id is interpolated into a constant above the <%text> body,
    # so the script itself is plain shell.
    assert "NODE_ID='${node.id}'" in txt
    # Traffic runs the static Go agent against the node's config. The old
    # per-flow python3 scripts could not run in images without an interpreter,
    # which silently produced no traffic on Docker nodes.
    assert 'config="$traffic_dir"/traffic_"$NODE_ID".json' in txt
    assert '-config "$config"' in txt
    # No interpreter is invoked any more (the word may still appear in comments
    # explaining why), and the old per-flow script glob is gone.
    assert 'python3 "' not in txt
    assert 'traffic_"$NODE_ID"_*.py' not in txt


def test_traffic_service_selects_the_agent_for_the_node_architecture():
    p = Path("on_core_machine/custom_services/TrafficService.py")
    txt = p.read_text("utf-8", errors="ignore")

    # A Docker node can be an emulated amd64 image on an arm64 host, so the
    # node's own uname decides which static binary to run.
    assert 'uname -m' in txt
    assert 'traffic-agent-linux-$arch' in txt
    for arch in ('amd64', 'arm64'):
        assert arch in txt


def test_traffic_service_degrades_loudly_when_no_agent_is_present():
    p = Path("on_core_machine/custom_services/TrafficService.py")
    txt = p.read_text("utf-8", errors="ignore")

    # Silent failure is what made the previous implementation hard to notice.
    assert 'no traffic-agent binary' in txt
    assert 'no traffic config' in txt


def test_traffic_service_waits_for_a_config_that_has_not_landed_yet():
    p = Path("on_core_machine/custom_services/TrafficService.py")
    txt = p.read_text("utf-8", errors="ignore")

    # Services start as the session comes up, and the traffic artifacts are
    # staged into the shared /tmp/traffic at about the same moment. Checking
    # once and exiting left the node silent for the whole run.
    assert 'for _tick in 1 2 3' in txt
    # The wait now settles which of the two bind points holds this node's
    # config, so the loop breaks on having chosen one rather than on a
    # pre-computed path.
    assert '[ -n "$traffic_dir" ] && break' in txt
    assert 'after ~60s' in txt


def test_traffic_service_restarts_an_agent_that_dies_but_not_one_that_was_signalled():
    p = Path("on_core_machine/custom_services/TrafficService.py")
    txt = p.read_text("utf-8", errors="ignore")

    # The agent retries every dial and every listen itself; the loop covers the
    # case it cannot -- the process going away entirely.
    assert 'restarting in 5s' in txt
    # A signalled exit is session teardown. Restarting there fights CORE's
    # cleanup and leaves orphans behind.
    assert '[ "$rc" -ge 128 ]' in txt
    assert 'not restarting' in txt


def test_traffic_service_reads_a_path_a_dind_tmpfs_cannot_hide():
    """/tmp is not always ours.

    A Docker-in-Docker image runs Docker's `dind` wrapper, which does
    `mountpoint -q /tmp || mount -t tmpfs none /tmp`. /tmp itself is not a
    mountpoint -- only /tmp/traffic is -- so the tmpfs goes on top and hides the
    bind. `docker/unauthorized-rce` is the only such image in the catalog, and
    its agent logged "no traffic config" for an entire run while every other
    node on the same scenario ran its flows (dataset-catalog-coverage-013).

    The artifacts are bound at /coretg/traffic as well, and the service takes
    whichever actually holds this node's config, so a plain CORE vnode that only
    has /tmp/traffic keeps working.
    """
    p = Path("on_core_machine/custom_services/TrafficService.py")
    txt = p.read_text("utf-8", errors="ignore")

    assert '/coretg/traffic/traffic_"$NODE_ID".json' in txt
    assert '/tmp/traffic/traffic_"$NODE_ID".json' in txt
    # Whichever won is what the agent binary is looked up in first, since the
    # binary is staged beside the config and a tmpfs hides both alike.
    assert '"$traffic_dir/traffic-agent-linux-$arch"' in txt
    # The fallback list keeps its original entries.
    assert '"/tmp/traffic/traffic-agent-linux-$arch"' in txt
    assert '"/usr/local/coretg/bin/traffic-agent"' in txt


def test_traffic_service_reports_both_locations_when_it_finds_nothing():
    p = Path("on_core_machine/custom_services/TrafficService.py")
    txt = p.read_text("utf-8", errors="ignore")
    assert 'no traffic config at /coretg/traffic or /tmp/traffic' in txt
