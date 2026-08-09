"""A traffic flow must be probed even when its endpoint's live address moved.

The VM-side traffic probe matched a flow's source and destination to running
nodes by IP address alone. An address is not an endpoint's identity: a node that
comes up on a different address than the plan recorded -- which is exactly the
state worth reporting -- matched nothing, and every one of its flows was
reported as "traffic source node not found" instead of being tested. The CORE
node id is stable, so the flow still resolves to a real node and the probe runs.
"""

import json

import pytest

import webapp.artifact_checks as ac


def _run_probe(tmp_path, *, flows, nodes, names_by_id, cidrs):
    """Execute the generated probe with the VM-side helpers stubbed out.

    Everything the script does against the CORE VM (`docker ps`, `vcmd`, node
    command execution) is replaced; the file-reading and matching logic under
    test runs for real.
    """
    traffic_dir = tmp_path / "traffic"
    traffic_dir.mkdir()
    (traffic_dir / "traffic_summary.json").write_text(json.dumps({"flows": flows}), encoding="utf-8")

    script = ac.traffic_probe_script("pw", 7, traffic_dirs=[str(traffic_dir)],
                                     node_names_by_id=names_by_id)
    namespace: dict = {"__name__": "probe"}
    exec(compile(script, "<traffic-probe>", "exec"), namespace)

    probed: list[tuple[str, list]] = []

    def _nexec_python(kind, name, program, timeout=25):
        rows = json.loads(program.splitlines()[0].split("=", 1)[1])
        probed.append((name, rows))
        return 0, json.dumps([[ip, port, proto, dname, True, "tcp-handshake", "", 1]
                              for ip, port, proto, dname in rows])

    namespace.update({
        "_read_json": lambda path: json.loads(open(path, encoding="utf-8").read()),
        "_all_nodes": lambda: list(nodes),
        "_nexec": lambda kind, name, argv, timeout=25: (0, ""),
        "_nexec_python": _nexec_python,
        "_node_cidrs": lambda kind, name: list(cidrs.get(name, [])),
        "_node_agent": lambda kind, name: {},
        "_node_agent_log": lambda kind, name: "",
        "_agent_stats": lambda kind, name, node_id: None,
    })

    import io
    import contextlib

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        namespace["main"]()
    return json.loads(out.getvalue().strip().splitlines()[-1]), probed


NODES = [("docker", "web"), ("vnode", "pc2")]


def test_flow_is_probed_when_the_source_address_does_not_match_a_running_node(tmp_path):
    # pc2 is up, but on a different address than the plan recorded.
    payload, probed = _run_probe(
        tmp_path,
        flows=[{"src_id": 2, "dst_id": 1, "protocol": "TCP",
                "src_ip": "172.30.96.14", "dst_ip": "10.9.9.1", "dst_port": 5013}],
        nodes=NODES,
        names_by_id={1: "web", 2: "pc2"},
        cidrs={"web": ["10.9.9.1/24"], "pc2": ["10.9.9.2/24"]},
    )
    assert [name for name, _ in probed] == ["pc2"], "the flow must be probed from its own source node"
    row = payload["ping"][0]
    assert row["src"] == "pc2"
    assert row["reachable"] is True


def test_destination_is_named_by_id_when_its_address_moved(tmp_path):
    payload, _ = _run_probe(
        tmp_path,
        flows=[{"src_id": 2, "dst_id": 1, "protocol": "TCP",
                "src_ip": "10.9.9.2", "dst_ip": "172.30.96.6", "dst_port": 5004}],
        nodes=NODES,
        names_by_id={1: "web", 2: "pc2"},
        cidrs={"web": ["10.9.9.1/24"], "pc2": ["10.9.9.2/24"]},
    )
    row = payload["ping"][0]
    # Named, not left as a bare address: the reader needs to know which node
    # this flow was supposed to reach.
    assert row["dst"] == "web"


def test_unresolvable_source_reports_what_the_probe_actually_saw(tmp_path):
    # No id mapping and no matching address: the failure must say why, so a
    # stale plan is distinguishable from a topology that never came up.
    payload, probed = _run_probe(
        tmp_path,
        flows=[{"src_id": 41, "dst_id": 42, "protocol": "TCP",
                "src_ip": "172.30.96.14", "dst_ip": "172.30.96.15", "dst_port": 5013}],
        nodes=NODES,
        names_by_id={1: "web", 2: "pc2"},
        cidrs={"web": ["10.9.9.1/24"], "pc2": ["10.9.9.2/24"]},
    )
    assert probed == []
    why = payload["ping"][0]["why"]
    assert "172.30.96.14" in why
    assert "10.9.9.1" in why and "10.9.9.2" in why
    assert "2 node(s) are running" in why


def test_note_names_the_session_when_no_nodes_were_discovered(tmp_path):
    payload, _ = _run_probe(
        tmp_path,
        flows=[{"src_id": 2, "dst_id": 1, "protocol": "TCP",
                "src_ip": "172.30.96.14", "dst_ip": "172.30.96.15", "dst_port": 5013}],
        nodes=[],
        names_by_id={1: "web", 2: "pc2"},
        cidrs={},
    )
    why = payload["ping"][0]["why"]
    assert "no nodes were discovered" in why
    assert "session 7" in why
    assert payload["session"]["id"] == "7"


def test_probe_reports_the_session_directory_state(tmp_path):
    payload, _ = _run_probe(
        tmp_path,
        flows=[{"src_id": 2, "dst_id": 1, "protocol": "TCP",
                "src_ip": "10.9.9.2", "dst_ip": "10.9.9.1", "dst_port": 5004}],
        nodes=NODES,
        names_by_id={1: "web", 2: "pc2"},
        cidrs={"web": ["10.9.9.1/24"], "pc2": ["10.9.9.2/24"]},
    )
    session = payload["session"]
    assert session["pycore"] == "/tmp/pycore.7"
    assert session["pycore_present"] is False or session["pycore_present"] is True
    assert isinstance(session["sessions_present"], list)


@pytest.mark.parametrize("names", [None, {}])
def test_probe_still_builds_without_a_node_name_map(names, tmp_path):
    # The map is an enrichment: address matching must keep working without it.
    payload, probed = _run_probe(
        tmp_path,
        flows=[{"src_id": 2, "dst_id": 1, "protocol": "TCP",
                "src_ip": "10.9.9.2", "dst_ip": "10.9.9.1", "dst_port": 5004}],
        nodes=NODES,
        names_by_id=names,
        cidrs={"web": ["10.9.9.1/24"], "pc2": ["10.9.9.2/24"]},
    )
    assert [name for name, _ in probed] == ["pc2"]
    assert payload["ping"][0]["dst"] == "web"


def test_probe_carries_each_endpoints_live_address(tmp_path):
    # "No route" needs the live addresses to be interpretable at all: they are
    # what separates a broken path between correctly addressed nodes from a
    # flow aimed at an address this session never had.
    payload, _ = _run_probe(
        tmp_path,
        flows=[{"src_id": 2, "dst_id": 1, "protocol": "TCP",
                "src_ip": "172.30.96.14", "dst_ip": "172.30.96.15", "dst_port": 5013}],
        nodes=NODES,
        names_by_id={1: "web", 2: "pc2"},
        cidrs={"web": ["10.9.9.1/24"], "pc2": ["10.9.9.2/24"]},
    )
    row = payload["ping"][0]
    assert row["src_live"] == ["10.9.9.2"]
    assert row["dst_live"] == ["10.9.9.1"]
    assert row["dst_ip_owned"] is False


def test_probe_marks_a_target_address_that_a_node_really_owns(tmp_path):
    payload, _ = _run_probe(
        tmp_path,
        flows=[{"src_id": 2, "dst_id": 1, "protocol": "TCP",
                "src_ip": "10.9.9.2", "dst_ip": "10.9.9.1", "dst_port": 5004}],
        nodes=NODES,
        names_by_id={1: "web", 2: "pc2"},
        cidrs={"web": ["10.9.9.1/24"], "pc2": ["10.9.9.2/24"]},
    )
    assert payload["ping"][0]["dst_ip_owned"] is True


def _run_probe_with_links(tmp_path, *, cidrs, links):
    """Same harness, but with `ip link` answers so interface state is exercised."""
    traffic_dir = tmp_path / "traffic"
    traffic_dir.mkdir()
    flows = [{"src_id": 2, "dst_id": 1, "protocol": "TCP",
              "src_ip": "172.30.96.14", "dst_ip": "172.30.96.15", "dst_port": 5013}]
    (traffic_dir / "traffic_summary.json").write_text(json.dumps({"flows": flows}), encoding="utf-8")

    script = ac.traffic_probe_script("pw", 7, traffic_dirs=[str(traffic_dir)],
                                     node_names_by_id={1: "web", 2: "pc2"})
    namespace: dict = {"__name__": "probe"}
    exec(compile(script, "<traffic-probe>", "exec"), namespace)

    def _nexec(kind, name, argv, timeout=25):
        if "ip -o link" in " ".join(str(a) for a in argv):
            entry = links.get(name)
            if entry is None:
                return 1, ""
            return 0, "".join(n + "\n" for n in entry)
        return 0, ""

    def _nexec_python(kind, name, program, timeout=25):
        rows = json.loads(program.splitlines()[0].split("=", 1)[1])
        return 0, json.dumps([[ip, port, proto, dname, False, "tcp-handshake", "no-route", 3]
                              for ip, port, proto, dname in rows])

    namespace.update({
        "_read_json": lambda path: json.loads(open(path, encoding="utf-8").read()),
        "_all_nodes": lambda: list(NODES),
        "_nexec": _nexec,
        "_nexec_python": _nexec_python,
        "_node_cidrs": lambda kind, name: list(cidrs.get(name, [])),
        "_node_agent": lambda kind, name: {},
        "_node_agent_log": lambda kind, name: "",
        "_agent_stats": lambda kind, name, node_id: None,
    })

    import io
    import contextlib

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        namespace["main"]()
    return json.loads(out.getvalue().strip().splitlines()[-1])


def test_probe_reports_the_interfaces_of_a_node_that_has_no_address(tmp_path):
    # An empty address list has three causes needing different fixes; the
    # interface list is what separates them.
    payload = _run_probe_with_links(
        tmp_path,
        cidrs={"web": ["10.9.9.1/24"], "pc2": []},
        links={"web": ["lo", "eth0"], "pc2": ["lo", "eth0"]},
    )
    row = payload["ping"][0]
    assert row["src_live"] == []
    assert row["src_links"] == ["eth0"], "loopback is not a link into the topology"
    assert row["src_links_queried"] is True
    assert row["src_kind"] == "vnode"


def test_probe_reports_a_node_with_no_interface_beyond_loopback(tmp_path):
    payload = _run_probe_with_links(
        tmp_path,
        cidrs={"web": ["10.9.9.1/24"], "pc2": []},
        links={"web": ["lo", "eth0"], "pc2": ["lo"]},
    )
    row = payload["ping"][0]
    assert row["src_links"] == []
    assert row["src_links_queried"] is True


def test_probe_marks_interfaces_it_could_not_list(tmp_path):
    payload = _run_probe_with_links(
        tmp_path,
        cidrs={"web": ["10.9.9.1/24"], "pc2": []},
        links={"web": ["lo", "eth0"]},   # pc2 answers with a failure
    )
    assert payload["ping"][0]["src_links_queried"] is False


def test_addressed_nodes_are_not_interrogated_for_interfaces(tmp_path):
    # The interface query only exists to explain a missing address; a node that
    # has one must not pay for an extra command into every node.
    payload = _run_probe_with_links(
        tmp_path,
        cidrs={"web": ["10.9.9.1/24"], "pc2": ["10.9.9.2/24"]},
        links={},
    )
    assert payload["nodes"]["pc2"]["links_queried"] is True
    assert payload["nodes"]["pc2"]["links"] == []
