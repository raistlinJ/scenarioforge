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
    assert 'config=/tmp/traffic/traffic_"$NODE_ID".json' in txt
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
