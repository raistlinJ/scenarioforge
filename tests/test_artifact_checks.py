"""Unit coverage for the pure CORE artifact-check helpers."""

import ast
import xml.etree.ElementTree as ET

from webapp import artifact_checks as ac


# --------------------------------------------------------------------------- #
# Plan + validator-summary mapping (checks 1-4)
# --------------------------------------------------------------------------- #

def test_check_plan_has_seven_pending_steps_in_order():
    plan = ac.check_plan()
    assert [c["key"] for c in plan] == ac.CHECK_KEYS
    assert len(plan) == 7
    # Traffic-script health and reachability are separate checks.
    assert ac.CHECK_KEYS[-2:] == ["traffic", "reachability"]
    assert all(c["status"] == "pending" for c in plan)


def test_containers_result_pass_and_fail():
    ok = ac.containers_result({"expected_docker_nodes": ["a", "b"], "missing_docker_nodes": []})
    assert ok["status"] == "pass"
    bad = ac.containers_result({"expected_docker_nodes": ["a", "b"], "missing_docker_nodes": ["b"]})
    assert bad["status"] == "fail"
    assert any(i["name"] == "b" and i["status"] == "fail" for i in bad["items"])


def test_containers_result_skip_when_none_expected():
    assert ac.containers_result({"expected_docker_nodes": []})["status"] == "skip"


def test_services_result_flags_not_running():
    res = ac.services_result({"docker_running": ["a"], "docker_not_running": ["b"]})
    assert res["status"] == "fail"
    res_ok = ac.services_result({"docker_running": ["a", "b"], "docker_not_running": []})
    assert res_ok["status"] == "pass"


def test_ports_result_reports_unreachable():
    res = ac.ports_result({
        "ports_checked": ["a:80"],
        "port_unreachable": ["a"],
        "port_unreachable_details": [{"container": "a", "ports": [80]}],
    })
    assert res["status"] == "fail"
    assert any("80" in i["detail"] for i in res["items"])


def test_ports_result_skip_when_nothing_open():
    assert ac.ports_result({"ports_checked": [], "port_unreachable": []})["status"] == "skip"


def test_ports_probe_script_is_valid_and_uses_proc_net_tcp():
    script = ac.ports_probe_script("pw", 4)
    ast.parse(script)
    assert "/proc/net/tcp" in script          # listening-port discovery
    assert "socket.create_connection" in script  # cross-node reachability
    assert "python3" in script
    assert "vcmd" in script                    # vnodes covered too


def test_ports_result_core_network_probe_pass():
    summary = {"ports_checked": [], "port_unreachable": []}
    probe = {"ok": True, "prober": "n1",
             "nodes": {"n1": {"ip": "10.0.0.1", "listening": [22]},
                       "n2": {"ip": "10.0.0.2", "listening": [80]}},
             "checks": [{"node": "n2", "ip": "10.0.0.2", "port": 80, "reachable": True}]}
    res = ac.ports_result(summary, probe)
    assert res["status"] == "pass"
    assert any("listening on 80" in i["detail"] for i in res["items"])


def test_ports_result_warns_only_on_dropped_packets():
    # A timeout / no-route means the path is blocked (segmentation/routing).
    summary = {"ports_checked": [], "port_unreachable": []}
    probe = {"ok": True, "prober": "n1",
             "nodes": {"n1": {"ip": "10.0.0.1", "listening": []},
                       "n2": {"ip": "10.0.0.2", "listening": [5432]}},
             "checks": [{"node": "n2", "ip": "10.0.0.2", "port": 5432, "reachable": False, "error": "timeout"}]}
    res = ac.ports_result(summary, probe)
    assert res["status"] == "warn"
    assert "1 blocked" in res["summary"]
    assert any("segmentation" in i["detail"].lower() and "socket.create_connection" in i["detail"] for i in res["items"])


def test_ports_result_refused_is_transient_not_a_failure():
    # "refused" means the port closed between enumeration and probe (short-lived
    # AJP/JMX/ephemeral ports) — a benign timing race, not unreachable.
    summary = {"ports_checked": [], "port_unreachable": []}
    probe = {"ok": True, "prober": "n1",
             "nodes": {"n1": {"ip": "10.0.0.1", "listening": []},
                       "n2": {"ip": "10.0.0.2", "listening": [8080, 8009]}},
             "checks": [
                 {"node": "n2", "ip": "10.0.0.2", "port": 8080, "reachable": True, "error": ""},
                 {"node": "n2", "ip": "10.0.0.2", "port": 8009, "reachable": False, "error": "refused"},
             ]}
    res = ac.ports_result(summary, probe)
    assert res["status"] == "pass"
    assert "short-lived" in res["summary"]
    # The refused port is still surfaced, as an informational (skip) item.
    assert any(str(i.get("status")) == "skip" and "8009" in i["name"] for i in res["items"])


def test_ports_probe_excludes_loopback_bound_ports():
    # Loopback binds are not network-exposed services and must never be probed
    # from another node. /proc stores IPv4 little-endian, so 127.x.x.x ends in
    # '7F' — including the IPv4-mapped IPv6 form Java/Tomcat uses for AJP.
    script = ac.ports_probe_script("pw", 1)
    ast.parse(script)
    assert "0000000000000000FFFF0000" in script   # ::ffff:127.0.0.1 detection
    assert "endswith('7F')" in script
    assert "'loopback'" in script


def test_ports_result_reports_loopback_ports_separately():
    summary = {"ports_checked": [], "port_unreachable": []}
    probe = {"ok": True, "prober": "n1",
             "nodes": {"n1": {"ip": "10.0.0.1", "listening": []},
                       "n2": {"ip": "10.0.0.2", "listening": [8080], "loopback": [8009]}},
             "checks": [{"node": "n2", "ip": "10.0.0.2", "port": 8080, "reachable": True, "error": ""}]}
    res = ac.ports_result(summary, probe)
    assert res["status"] == "pass"
    # The loopback port is noted on the node's row, not probed as a failure.
    assert any("8009 bound to localhost only" in i["detail"] for i in res["items"])
    assert not any("8009" in i["name"] for i in res["items"])


def test_ports_published_failure_outranks_network_probe():
    summary = {"ports_checked": ["a:80"], "port_unreachable": ["a"],
               "port_unreachable_details": [{"container": "a", "ports": [80]}]}
    probe = {"ok": True, "prober": "n1", "nodes": {}, "checks": []}
    assert ac.ports_result(summary, probe)["status"] == "fail"


def test_injects_result_pass_and_missing():
    ok = ac.injects_result({"inject_files_expected_by_node": {"a": ["/x"]}, "injects_missing": []})
    assert ok["status"] == "pass"
    bad = ac.injects_result({"inject_files_expected_by_node": {"a": ["/x"]}, "injects_missing": ["/x"]})
    assert bad["status"] == "fail"


def test_validation_unavailable_becomes_error_across_checks():
    summary = {"ok": False, "validation_unavailable": True, "error": "no session xml"}
    for fn in (ac.containers_result, ac.services_result, ac.ports_result, ac.injects_result):
        res = fn(summary)
        assert res["status"] == "error"
        assert "no session xml" in res["summary"]


# --------------------------------------------------------------------------- #
# Expected flags parsed from the scenario XML
# --------------------------------------------------------------------------- #

def _xml(sections):
    body = "".join(sections)
    return ET.fromstring(f"<Scenario>{body}</Scenario>")


def test_segmentation_and_traffic_expected_from_density():
    root = _xml(['<section name="Segmentation" density="0.5"/>', '<section name="Traffic" density="0"/>'])
    assert ac.segmentation_expected(root) is True
    assert ac.traffic_expected(root) is False


def test_expected_true_when_item_selected_even_if_density_zero():
    root = _xml(['<section name="Traffic" density="0"><item selected="CUSTOM"/></section>'])
    assert ac.traffic_expected(root) is True


def test_expected_false_when_section_absent():
    root = _xml(['<section name="Routing" density="1.0"/>'])
    assert ac.segmentation_expected(root) is False


# --------------------------------------------------------------------------- #
# Probe scripts (checks 5-6) are valid, self-contained Python
# --------------------------------------------------------------------------- #

def test_probe_scripts_parse_as_python_and_reference_key_commands():
    seg = ac.segmentation_probe_script("pw", 7)
    ast.parse(seg)
    assert "iptables -S" in seg
    assert "docker" in seg
    traffic = ac.traffic_probe_script("pw", 7)
    ast.parse(traffic)
    assert "pgrep" in traffic
    assert "ping -c1" in traffic
    # sudo password is embedded for the -S fallback
    assert "pw" in seg and "pw" in traffic


def test_probe_scripts_cover_vnodes_via_vcmd():
    for script in (ac.segmentation_probe_script("pw", 3), ac.traffic_probe_script("pw", 3)):
        assert "vcmd" in script            # namespaced CORE vnodes
        assert "pycore" in script          # session channel directory
        assert '"3"' in script             # session id embedded
        assert "_all_nodes" in script      # docker + vnode enumeration


def test_traffic_probe_excludes_pgrep_self_match():
    # pgrep -fa traffic_ matches its own command line; the probe must filter it.
    assert "'pgrep' not in l" in ac.traffic_probe_script("pw", 1)


def test_traffic_probe_emits_reproduce_command():
    assert "ping -c3" in ac.traffic_probe_script("pw", 1)


# --------------------------------------------------------------------------- #
# Segmentation / traffic result shaping
# --------------------------------------------------------------------------- #

def test_segmentation_pass_when_rules_present():
    probe = {"ok": True, "seg_files": ["/tmp/segmentation/s.py"],
             "nodes": {"r1": {"rules_present": True, "rule_count": 4, "marker": True}}}
    res = ac.segmentation_result(probe, expected=True)
    assert res["status"] == "pass"


def test_segmentation_skips_when_enabled_but_no_rules_were_generated():
    # Enabling the section does not guarantee rules: density can round to none.
    # That is a "nothing to check" outcome, not a failure.
    probe = {"ok": True, "seg_files": [], "nodes": {"r1": {"rules_present": False, "rule_count": 0}}}
    res = ac.segmentation_result(probe, expected=True)
    assert res["status"] == "skip"
    assert "generated no rules" in res["summary"]


def test_segmentation_skip_when_not_expected():
    probe = {"ok": True, "seg_files": [], "nodes": {}}
    assert ac.segmentation_result(probe, expected=False)["status"] == "skip"


def test_segmentation_error_on_probe_failure():
    assert ac.segmentation_result({"ok": False, "error": "ssh down"}, expected=True)["status"] == "error"


def test_traffic_pass_with_scripts_and_reachable():
    probe = {"ok": True, "traffic_files": ["/tmp/traffic/traffic_1_s0.py"],
             "nodes": {"h": {"procs": ["x traffic_1_s0.py"], "ip": "10.0.0.5"}},
             "ping": [{"src": "h", "dst": "w", "ip": "10.0.0.6", "reachable": True}]}
    assert ac.traffic_result(probe, expected=True)["status"] == "pass"


def test_traffic_result_ignores_reachability():
    # Reachability lives in its own check now; a traffic probe with an
    # unreachable ping must not turn the traffic-script check into a warning.
    probe = {"ok": True, "traffic_files": ["/tmp/traffic/traffic_1_s0.py"],
             "summary": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.7"}]},
             "nodes": {"h": {"procs": ["x traffic_1_s0.py"], "ip": "10.0.0.5"}},
             "ping": [{"src": "h", "dst": "z", "ip": "10.0.0.7", "reachable": False}]}
    assert ac.traffic_result(probe, expected=True)["status"] == "pass"


def test_traffic_warns_when_a_flow_source_has_no_process():
    probe = {"ok": True, "traffic_files": [],
             "summary": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.7"}]},
             "nodes": {"h": {"procs": [], "ip": "10.0.0.5"}},
             "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "warn"
    assert any("no traffic process is running" in i["detail"] for i in res["items"])


def test_probes_ignore_preview_directories():
    # /tmp/scenarioforge-preview-* holds plan-time scripts that are never
    # deployed; counting them reports traffic/segmentation for a scenario
    # that configured none.
    traffic = ac.traffic_probe_script('pw', 1)
    seg = ac.segmentation_probe_script('pw', 1)
    assert 'scenarioforge-preview-traffic' not in traffic
    assert 'scenarioforge-preview-seg' not in seg
    assert '"/tmp/traffic"' in traffic or "'/tmp/traffic'" in traffic
    assert '"/tmp/segmentation"' in seg or "'/tmp/segmentation'" in seg


def test_probes_filter_scripts_older_than_the_run():
    # The shared runtime dirs keep .py scripts across runs; only the summary
    # JSON is rewritten, so it is the run boundary.
    for script in (ac.traffic_probe_script('pw', 1), ac.segmentation_probe_script('pw', 1)):
        assert '_fresh(' in script
        assert 'STALE_GRACE_S' in script
        assert 'stale_files' in script


def test_empty_runtime_summary_outranks_leftover_script_files():
    # A scenario with no traffic must stay 'skip' even when stray traffic_*
    # files are present in the shared runtime directory.
    probe = {"ok": True, "traffic_files": ["/tmp/traffic/traffic_9_s1.py"],
             "summary": {"flows": []}, "nodes": {}, "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "skip"
    assert res["items"] == []


def test_running_traffic_without_configured_flows_is_surfaced():
    # Processes are real runtime evidence, so an unexpected one is worth a warn
    # rather than being silently dropped like a stale file.
    probe = {"ok": True, "traffic_files": [], "summary": {"flows": []},
             "nodes": {"h": {"procs": ["1 traffic_1_s0.py"], "ip": "10.0.0.5"}}, "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "warn"
    assert "left over" in res["summary"]


def test_traffic_skip_when_summary_present_but_empty_even_if_xml_declares_traffic():
    # The runtime artifact is authoritative: an empty flows list means no
    # traffic, regardless of the scenario XML's Traffic-section density.
    probe = {"ok": True, "traffic_files": [], "summary": {"flows": []},
             "nodes": {"h": {"procs": [], "ip": "10.0.0.5"}}, "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "skip"
    assert "no traffic configured" in res["summary"].lower()


# --------------------------------------------------------------------------- #
# Reachability: probed along traffic source -> destination
# --------------------------------------------------------------------------- #

def test_reachability_skips_when_no_flows():
    res = ac.reachability_result({"ok": True, "ping": []})
    assert res["status"] == "skip"
    assert "no traffic flows" in res["summary"].lower()


def test_reachability_passes_along_flow_paths():
    probe = {"ok": True, "ping": [
        {"src": "h1", "dst": "h2", "ip": "10.0.0.7", "reachable": True, "port": 9000,
         "protocol": "UDP", "method": "udp-send", "error": "icmp-port-unreachable"}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "pass"
    assert "All 1 testable traffic flow(s) reach their destination" in res["summary"]
    assert any("UDP:9000" in i["name"] for i in res["items"])


def test_reachability_warns_with_repro_when_destination_unreachable():
    probe = {"ok": True, "ping": [
        {"src": "h1", "dst": "h2", "ip": "10.0.0.7", "reachable": False,
         "protocol": "TCP", "port": 9000, "method": "tcp-handshake", "error": "timeout",
         "cmd": "sudo vcmd -c /tmp/pycore.1/h1 -- ping -c3 -W2 10.0.0.7"}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "warn"
    assert "cannot reach their destination" in res["summary"]
    assert any("vcmd -c /tmp/pycore.1/h1" in i["detail"] for i in res["items"])


def test_reachability_error_on_probe_failure():
    assert ac.reachability_result({"ok": False, "error": "ssh down"})["status"] == "error"


def test_traffic_skip_when_not_declared_and_no_flows():
    probe = {"ok": True, "traffic_files": [], "summary": {"flows": []}, "nodes": {}, "ping": []}
    assert ac.traffic_result(probe, expected=False)["status"] == "skip"


def test_traffic_uses_summary_flows_as_evidence():
    probe = {"ok": True, "traffic_files": [], "summary": {"flows": [{"src": "a", "dst": "b"}]},
             "nodes": {}, "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "pass"
    assert "1 traffic flow" in res["summary"]


# --------------------------------------------------------------------------- #
# Segmentation verification artifact (allow_verification.json)
# --------------------------------------------------------------------------- #

def test_no_blocked_flows_is_the_healthy_outcome():
    # allow_verification.json comes from `verify_flows_allowed`, which confirms
    # every traffic flow is *permitted*. An empty `blocked` list is good; it is
    # not evidence that segmentation exists, so the rules decide the status.
    probe = {"ok": True, "seg_files": [], "rules_summary": {"rules": [{"a": 1}]},
             "nodes": {}, "verification": {"flows_total": 3, "blocked": [], "blocked_count": 0}}
    res = ac.segmentation_result(probe, expected=True)
    assert res["status"] == "pass"
    assert any("all 3 traffic flow(s) pass" in i["detail"] for i in res["items"])


def test_blocked_traffic_flow_is_a_failure():
    # A flow segmentation still blocks cannot arrive, which is a misconfiguration.
    probe = {"ok": True, "seg_files": [], "nodes": {},
             "verification": {"flows_total": 3,
                              "blocked": [{"dst_ip": "10.0.0.9", "dst_port": 6007, "proto": "UDP"}],
                              "blocked_count": 1}}
    res = ac.segmentation_result(probe, expected=True)
    assert res["status"] == "fail"
    assert "1 traffic flow(s) blocked" in res["summary"]
    assert any("10.0.0.9:6007" in i["name"] for i in res["items"])


def test_generated_rules_make_segmentation_pass():
    probe = {"ok": True, "seg_files": ["/tmp/segmentation/seg_allow_1_1.py"],
             "rules_summary": {"rules": [{"a": 1}, {"b": 2}]}, "nodes": {}}
    res = ac.segmentation_result(probe, expected=True)
    assert res["status"] == "pass"
    assert "2 rule(s)" in res["summary"]


def test_segmentation_verification_skip_when_no_restricted_flows():
    probe = {"ok": True, "seg_files": [], "nodes": {},
             "verification": {"flows_total": 0, "blocked": [], "blocked_count": 0}}
    assert ac.segmentation_result(probe, expected=True)["status"] == "skip"


def test_segmentation_probe_counts_only_real_applied_rules():
    # Chain policies, chain declarations, and any shell/ssh noise on the output
    # stream (e.g. "stdin: is not a tty") must not be counted as firewall rules.
    script = ac.segmentation_probe_script("pw", 1)
    ast.parse(script)
    assert "startswith('-A ')" in script
    assert "startswith('-I ')" in script


def test_segmentation_collapses_rule_free_nodes_into_one_row():
    probe = {"ok": True, "seg_files": [], "verification": None,
             "nodes": {f"n{i}": {"kind": "docker", "rules_present": False, "rule_count": 0}
                       for i in range(5)}}
    res = ac.segmentation_result(probe, expected=False)
    assert res["status"] == "skip"
    # One summary row, not one row per rule-free node.
    assert len(res["items"]) == 1
    assert "5 node(s) probed" in res["items"][0]["name"]


def test_segmentation_items_label_node_kind():
    probe = {"ok": True, "seg_files": [], "nodes": {"router-1": {"kind": "vnode", "rules_present": True, "rule_count": 2}}}
    res = ac.segmentation_result(probe, expected=True)
    assert any("router-1 (vnode)" in i["name"] for i in res["items"])


# --------------------------------------------------------------------------- #
# Overall roll-up
# --------------------------------------------------------------------------- #

def test_overall_status_precedence():
    assert ac.overall_status([{"status": "pass"}, {"status": "warn"}, {"status": "fail"}]) == "fail"
    assert ac.overall_status([{"status": "pass"}, {"status": "warn"}]) == "warn"
    assert ac.overall_status([{"status": "pass"}, {"status": "skip"}]) == "pass"
    assert ac.overall_status([{"status": "pass"}, {"status": "pending"}]) == "running"


def test_overall_summary_counts():
    summary = ac.overall_summary([{"status": "pass"}, {"status": "pass"}, {"status": "fail"}, {"status": "skip"}])
    assert "2 pass" in summary and "1 fail" in summary and "1 skip" in summary


# --------------------------------------------------------------------------- #
# A port the scenario deliberately walls off is not a fault
# --------------------------------------------------------------------------- #

def _segmented_probe(src="10.0.140.0/24", dst="172.21.240.0/24"):
    """Segmentation probe reporting one subnet_block rule."""
    return {"ok": True,
            "rules_summary": {"rules": [
                {"node_id": 1, "service": "Segmentation",
                 "rule": {"type": "subnet_block", "src": src, "dst": dst, "default_deny": True}},
                {"node_id": 1, "service": "Segmentation",
                 "rule": {"type": "allow", "src": src, "dst": "10.0.173.0/24"}},
            ]}}


def _cross_subnet_probe():
    """Prober on 10.0.140.0/24 timing out against three 172.21.240.0/24 ports."""
    return {"ok": True, "prober": "docker-23",
            "nodes": {"docker-23": {"ip": "10.0.140.6", "listening": []},
                      "docker-26": {"ip": "172.21.240.7", "listening": [16379]},
                      "docker-21": {"ip": "172.21.240.6", "listening": [1053]},
                      "flaggenslot-6": {"ip": "172.21.240.3", "listening": [5011]}},
            "checks": [
                {"node": "docker-26", "ip": "172.21.240.7", "port": 16379,
                 "reachable": False, "error": "timeout"},
                {"node": "docker-21", "ip": "172.21.240.6", "port": 1053,
                 "reachable": False, "error": "timeout"},
                {"node": "flaggenslot-6", "ip": "172.21.240.3", "port": 5011,
                 "reachable": False, "error": "timeout"},
            ]}


def test_ports_drops_explained_by_a_block_rule_are_not_a_warning():
    # The prober sits in a subnet the scenario blocks from the target subnet, so
    # the dropped packets are segmentation working, not a reachability problem.
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(), segmentation=_segmented_probe())
    assert res["status"] == "pass"
    assert "3 blocked as configured by segmentation" in res["summary"]
    assert "blocked (dropped packets" not in res["summary"]
    # Each blocked path is still shown, naming the rule that explains it.
    segmented = [i for i in res["items"] if "blocked as configured" in i["detail"]]
    assert len(segmented) == 3
    assert all(i["status"] == "pass" for i in segmented)
    assert all("172.21.240.0/24" in i["detail"] for i in segmented)


def test_ports_drops_with_no_matching_rule_still_warn():
    # Same drops, but the block rule covers a different source subnet.
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(),
                          segmentation=_segmented_probe(src="10.9.9.0/24"))
    assert res["status"] == "warn"
    assert "3 blocked" in res["summary"]
    assert any("no segmentation rule covers this path" in i["detail"] for i in res["items"])


def test_ports_without_segmentation_data_keeps_warning():
    # No segmentation probe at all: nothing can explain the drops.
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(), segmentation=None)
    assert res["status"] == "warn"


def test_ports_only_block_rules_excuse_a_drop():
    # An allow/nat rule spanning the same subnets must not silence a real drop.
    seg = {"ok": True, "rules_summary": {"rules": [
        {"rule": {"type": "nat", "internal": "10.0.140.0/24", "external": "172.21.240.0/24"}},
        {"rule": {"type": "allow", "src": "10.0.140.0/24", "dst": "172.21.240.0/24"}},
    ]}}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(), segmentation=seg)
    assert res["status"] == "warn"


def test_ports_host_block_rule_excuses_a_single_host():
    # host_block rules carry bare IPs rather than CIDRs.
    seg = {"ok": True, "rules_summary": {"rules": [
        {"rule": {"type": "host_block", "src": "10.0.140.6", "dst": "172.21.240.7"}},
    ]}}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(), segmentation=seg)
    # One of the three drops is explained; the other two still warn.
    assert res["status"] == "warn"
    assert "2 blocked" in res["summary"]
    assert any("blocked as configured" in i["detail"] and "172.21.240.7" in i["name"]
               for i in res["items"])


def test_ports_malformed_segmentation_rules_are_ignored_safely():
    seg = {"ok": True, "rules_summary": {"rules": [
        {"rule": {"type": "subnet_block", "src": "", "dst": "not-a-network"}},
        "junk",
        {"no_rule_key": True},
    ]}}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(), segmentation=seg)
    assert res["status"] == "warn"


# --------------------------------------------------------------------------- #
# Each port is probed from a node that should reach it, not one global prober
# --------------------------------------------------------------------------- #

def test_ports_probe_prefers_the_traffic_source_then_a_subnet_peer():
    script = ac.ports_probe_script("pw", 7)
    compile(script, "<probe>", "exec")          # the remote script must be valid
    assert "traffic source" in script            # first choice
    assert "same-subnet peer" in script          # fallback
    assert "traffic_summary" in script or "summary" in script
    # Targets are grouped per prober so each node is entered once.
    assert "plan.setdefault(pname, [])" in script


def test_ports_result_uses_each_rows_own_source():
    # Two targets probed from two different nodes; the item labels and the
    # segmentation match must both follow the row, not a single global prober.
    probe = {"ok": True, "prober": "n1", "probers": ["n1", "n9"],
             "nodes": {"n1": {"ip": "10.0.1.1", "listening": []},
                       "n9": {"ip": "10.0.9.9", "listening": []},
                       "n2": {"ip": "10.0.2.2", "listening": [80]},
                       "n3": {"ip": "10.0.3.3", "listening": [443]}},
             "checks": [
                 {"node": "n2", "ip": "10.0.2.2", "port": 80, "src": "n1", "src_ip": "10.0.1.1",
                  "via": "traffic source", "reachable": False, "error": "timeout"},
                 {"node": "n3", "ip": "10.0.3.3", "port": 443, "src": "n9", "src_ip": "10.0.9.9",
                  "via": "same-subnet peer", "reachable": False, "error": "timeout"},
             ]}
    # Only n1 -> 10.0.2.0/24 is a configured block.
    seg = {"ok": True, "rules_summary": {"rules": [
        {"rule": {"type": "subnet_block", "src": "10.0.1.0/24", "dst": "10.0.2.0/24"}},
    ]}}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []}, probe, segmentation=seg)
    assert res["status"] == "warn"          # n9 -> n3 is a real, unexplained drop
    labels = {i["name"]: i for i in res["items"]}
    n2 = next(v for k, v in labels.items() if "n2:80" in k)
    n3 = next(v for k, v in labels.items() if "n3:443" in k)
    assert n2["name"].startswith("n1 →") and n2["status"] == "pass"
    assert n3["name"].startswith("n9 →") and n3["status"] == "warn"
    # The unexplained one says where it was probed from, to aid follow-up.
    assert "same-subnet peer" in n3["detail"]


def test_ports_summary_credits_traffic_source_probes():
    probe = {"ok": True, "prober": "n1",
             "nodes": {"n1": {"ip": "10.0.0.1", "listening": []},
                       "n2": {"ip": "10.0.0.2", "listening": [80]}},
             "checks": [{"node": "n2", "ip": "10.0.0.2", "port": 80, "src": "n1",
                         "src_ip": "10.0.0.1", "via": "traffic source", "reachable": True}]}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []}, probe)
    assert res["status"] == "pass"
    assert "1 probed from their traffic source" in res["summary"]


def test_ports_result_still_handles_probes_without_per_row_source():
    # Older probe payloads carry only a single global prober.
    probe = {"ok": True, "prober": "n1",
             "nodes": {"n1": {"ip": "10.0.0.1", "listening": []},
                       "n2": {"ip": "10.0.0.2", "listening": [80]}},
             "checks": [{"node": "n2", "ip": "10.0.0.2", "port": 80,
                         "reachable": False, "error": "timeout"}]}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []}, probe)
    assert res["status"] == "warn"
    assert any(i["name"].startswith("n1 →") for i in res["items"])


# --------------------------------------------------------------------------- #
# TCP is two-way: the destination must be able to answer the source
# --------------------------------------------------------------------------- #

def test_traffic_probe_tests_each_flow_on_its_own_protocol_and_port():
    script = ac.traffic_probe_script("pw", 7)
    compile(script, "<probe>", "exec")
    # Ping is the wrong instrument under default-deny segmentation.
    assert "tcp-handshake" in script
    assert "udp-send" in script
    assert "socket.create_connection" in script
    # Ping survives only as a diagnostic once a flow has already failed.
    assert "separates" in script


def test_reachability_tcp_handshake_proves_both_directions():
    # A completed handshake means the SYN-ACK came back, so the return path is
    # verified without a separate reverse probe.
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 80, "protocol": "TCP",
         "method": "tcp-handshake", "error": "", "reachable": True}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "pass"
    assert "1 TCP flow(s) verified in both directions" in res["summary"]
    item = res["items"][0]
    assert "both directions" in item["detail"]
    assert "SYN-ACK" in item["detail"]


def test_reachability_tcp_rst_still_proves_the_path():
    # RST means the packet reached the host and the reply returned; the service
    # simply is not listening. That is a service problem, not a path problem.
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 80, "protocol": "TCP",
         "method": "tcp-handshake", "error": "refused", "reachable": True}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "pass"
    assert "nothing is listening" in res["items"][0]["detail"]


def test_reachability_distinguishes_filtered_port_from_dead_path():
    # Host answers ping but the port is filtered -> point at a port rule.
    filtered = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 80, "protocol": "TCP",
         "method": "tcp-handshake", "error": "timeout", "reachable": False, "icmp": True}]}
    res = ac.reachability_result(filtered)
    assert res["status"] == "warn"
    assert "port is filtered or closed" in res["items"][0]["detail"]

    # Nothing answers at all -> the whole path is down.
    dead = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 80, "protocol": "TCP",
         "method": "tcp-handshake", "error": "timeout", "reachable": False, "icmp": False}]}
    res2 = ac.reachability_result(dead)
    assert "whole path is blocked" in res2["items"][0]["detail"]

    # No route at all is its own diagnosis.
    noroute = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 80, "protocol": "TCP",
         "method": "tcp-handshake", "error": "no-route", "reachable": False}]}
    assert "no route to the destination" in ac.reachability_result(noroute)["items"][0]["detail"]


def test_reachability_icmp_only_block_no_longer_warns():
    # The real-world regression: default-deny segmentation drops ICMP while the
    # configured TCP flow is explicitly allowed. Pinging reported this healthy
    # scenario as broken; testing the flow's own port does not.
    probe = {"ok": True, "ping": [
        {"src": "flaggenslot-5", "dst": "flaggenslot-6", "ip": "172.21.240.3", "port": 5011,
         "protocol": "TCP", "method": "tcp-handshake", "error": "", "reachable": True}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "pass"


def test_reachability_udp_is_reported_as_unconfirmable():
    # UDP has no handshake, so a sent datagram is not proof of delivery.
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 53, "protocol": "UDP",
         "method": "udp-send", "error": "sent", "reachable": None}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "pass"
    assert "1 UDP flow(s) sent but not confirmable" in res["summary"]
    assert res["items"][0]["status"] == "skip"
    assert "cannot be confirmed" in res["items"][0]["detail"]


# --------------------------------------------------------------------------- #
# UDP delivery is confirmed by the receiving agent's byte counter
# --------------------------------------------------------------------------- #

def test_traffic_probe_reads_per_node_agent_stats():
    script = ac.traffic_probe_script("pw", 7)
    compile(script, "<probe>", "exec")
    # Per-node filename: CORE vnodes share the host /tmp, so a fixed name would
    # return whichever node's agent happened to write last.
    assert "'/tmp/coretg_traffic/stats_' + str(node_id) + '.json'" in script
    # Flow labels are <proto>-<src_id>-<dst_id>-<port>-tx|rx.
    assert "'-tx'" in script and "'-rx'" in script


def test_udp_flow_confirmed_by_bytes_at_the_destination():
    # The sender-side probe cannot confirm UDP, but the receiving agent counted
    # bytes, which settles it.
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 6007, "protocol": "UDP",
         "method": "udp-send", "error": "sent", "reachable": None,
         "flow_id": "udp-6-7-6007", "bytes_sent": 900000, "bytes_received": 850112,
         "achieved_kbps": 253.1}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "pass"
    assert "1 confirmed by bytes counted at the destination" in res["summary"]
    item = res["items"][0]
    assert item["status"] == "pass"
    assert "850,112 bytes" in item["detail"]
    assert "253.1 kbps" in item["detail"]


def test_udp_sent_but_nothing_arriving_is_a_warning():
    # The failure mode UDP hides: the sender writes happily into a black hole.
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 6007, "protocol": "UDP",
         "method": "udp-send", "error": "sent", "reachable": None,
         "bytes_sent": 900000, "bytes_received": 0}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "warn"
    assert "cannot reach their destination" in res["summary"]
    detail = res["items"][0]["detail"]
    assert "900,000 bytes" in detail
    assert "dropped in flight" in detail
    assert "segmentation rule covering this port" in detail


def test_udp_without_counters_stays_unconfirmable():
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 6007, "protocol": "UDP",
         "method": "udp-send", "error": "sent", "reachable": None}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "pass"
    assert res["items"][0]["status"] == "skip"
    assert "No agent counters were readable" in res["items"][0]["detail"]


def test_udp_sender_not_started_is_reported_distinctly():
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 6007, "protocol": "UDP",
         "method": "udp-send", "error": "sent", "reachable": None,
         "bytes_sent": 0, "bytes_received": 0}]}
    res = ac.reachability_result(probe)
    # Nothing sent means nothing could arrive; that is not a dropped-traffic fault.
    assert res["status"] == "pass"
    assert "written no bytes yet" in res["items"][0]["detail"]


def test_tcp_pass_reports_measured_bytes_when_available():
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 5011, "protocol": "TCP",
         "method": "tcp-handshake", "error": "", "reachable": True,
         "bytes_sent": 177345916, "bytes_received": 177345916}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "pass"
    assert "177,345,916 bytes" in res["items"][0]["detail"]
    assert "both directions" in res["items"][0]["detail"]


def test_traffic_service_writes_per_node_stats_and_logs():
    # CORE vnodes share the host's /tmp, so fixed filenames make every vnode's
    # agent clobber the previous one's stats.
    from pathlib import Path
    svc = Path("on_core_machine/custom_services/TrafficService.py").read_text(encoding="utf-8")
    assert 'stats="$runtime_dir/stats_$NODE_ID.json"' in svc
    assert 'log="$runtime_dir/output_$NODE_ID.txt"' in svc
    assert '-stats "$stats"' in svc
    # The copied binary is per-node too, so two nodes cannot race on the copy.
    assert 'traffic-agent-$NODE_ID' in svc
    assert '"$runtime_dir/stats.json"' not in svc
