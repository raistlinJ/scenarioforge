"""Unit coverage for the pure CORE artifact-check helpers."""

import ast
import xml.etree.ElementTree as ET

from webapp import artifact_checks as ac


# --------------------------------------------------------------------------- #
# Plan + validator-summary mapping (checks 1-4)
# --------------------------------------------------------------------------- #

def test_check_plan_has_nine_pending_steps_in_order():
    plan = ac.check_plan()
    assert [c["key"] for c in plan] == ac.CHECK_KEYS
    assert len(plan) == 9
    # Flow's source-to-target pivots and Segmentation's participant entry
    # providers are separate checks.
    assert ac.CHECK_KEYS[-4:] == ["traffic", "reachability", "flow_pivot", "pivot_access"]
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
    assert "sys.executable" in script
    assert "vcmd" in script                    # vnodes covered too
    assert "_nexec_python" in script
    assert "nsenter" in script                 # minimal Docker images need no Python


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


def test_probe_scripts_exclude_nested_core_compose_containers():
    for script in (ac.ports_probe_script("pw", 3), ac.traffic_probe_script("pw", 3)):
        ast.parse(script)
        assert "nested_prefix = ('core-' + SESSION_ID + '-')" in script
        assert "startswith(nested_prefix)" in script


def test_probe_scripts_discover_docker_ip_from_host_namespace_as_fallback():
    for script in (ac.ports_probe_script("pw", 3), ac.traffic_probe_script("pw", 3)):
        ast.parse(script)
        assert "docker','inspect','-f','{{.State.Pid}}'" in script
        assert "'nsenter','-t',pid,'-n','ip'" in script
        assert "_node_addr(kind, name)" in script


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
             "nodes": {"h": {"procs": ["x traffic_1_s0.py"], "ip": "10.0.0.5"},
                       "z": {"procs": ["x traffic_2_r0.py"], "ip": "10.0.0.7"}},
             "ping": [{"src": "h", "dst": "z", "ip": "10.0.0.7", "reachable": False}]}
    assert ac.traffic_result(probe, expected=True)["status"] == "pass"


def test_traffic_fails_when_a_required_flow_source_has_no_process():
    probe = {"ok": True, "traffic_files": [],
             "summary": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.7"}]},
             "nodes": {"h": {"procs": [], "ip": "10.0.0.5"},
                       "z": {"procs": ["x traffic_2_r0.py"], "ip": "10.0.0.7"}},
             "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "fail"
    assert any("no traffic process is running" in i["detail"] for i in res["items"])


def test_traffic_duplicate_ip_prefers_node_with_live_agent():
    probe = {
        "ok": True,
        "traffic_files": [],
        "summary": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.7"}]},
        "nodes": {
            "docker-15": {
                "procs": ["1 traffic_15.py"],
                "ip": "10.0.0.5",
                "agent": {"present": True, "live": True},
            },
            "core-1-18-docker-15-elasticsearch-1": {
                "procs": [],
                "ip": "10.0.0.5",
                "agent": {},
            },
            "receiver": {
                "procs": ["2 traffic_18.py"],
                "ip": "10.0.0.7",
                "agent": {"present": True, "live": True},
            },
        },
        "ping": [],
    }

    result = ac.traffic_result(probe, expected=True)

    assert result["status"] == "pass"
    assert not any(
        item["name"] == "core-1-18-docker-15-elasticsearch-1"
        and item["status"] == "warn"
        for item in result["items"]
    )


def test_traffic_matches_required_endpoints_on_secondary_node_addresses():
    probe = {
        "ok": True, "traffic_files": [],
        "summary": {"flows": [{"src_ip": "10.2.0.5", "dst_ip": "10.3.0.9"}]},
        "nodes": {
            "sender": {"ip": "10.1.0.5", "ips": ["10.1.0.5", "10.2.0.5"],
                       "procs": ["1 traffic_tx"], "agent": {"live": True}},
            "receiver": {"ip": "10.1.0.9", "ips": ["10.1.0.9", "10.3.0.9"],
                         "procs": ["2 traffic_rx"], "agent": {"live": True}},
        }, "ping": [],
    }
    assert ac.traffic_result(probe, expected=True)["status"] == "pass"


def test_declared_traffic_without_runtime_summary_is_a_failure():
    probe = {"ok": True, "traffic_files": [], "summary": None, "nodes": {}, "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "fail"
    assert "cannot be verified" in res["summary"]


def test_missing_traffic_summary_names_the_root_owned_directory():
    """The overwhelmingly common cause is /tmp/traffic being owned by root, so
    the failure has to point there rather than leave the reader auditing the
    traffic generator."""
    probe = {"ok": True, "traffic_files": [], "summary": None, "nodes": {}, "ping": []}
    summary = ac.traffic_result(probe, expected=True)["summary"]
    assert "/tmp/traffic" in summary
    assert "root" in summary
    assert "tmpfiles.d" in summary


def test_segmentation_without_rules_names_the_root_owned_directory():
    probe = {"ok": True, "seg_files": [], "nodes": {}}
    res = ac.segmentation_result(probe, expected=True)
    assert res["status"] == "skip"
    assert "/tmp/segmentation" in res["summary"]
    assert "tmpfiles.d" in res["summary"]


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
         "protocol": "TCP", "method": "tcp-handshake", "error": ""}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "pass"
    assert "All 1 required traffic flow(s) reach their destination" in res["summary"]
    assert any("TCP:9000" in i["name"] for i in res["items"])


def test_reachability_fails_with_repro_when_destination_unreachable():
    probe = {"ok": True, "ping": [
        {"src": "h1", "dst": "h2", "ip": "10.0.0.7", "reachable": False,
         "protocol": "TCP", "port": 9000, "method": "tcp-handshake", "error": "timeout",
         "cmd": "sudo vcmd -c /tmp/pycore.1/h1 -- ping -c3 -W2 10.0.0.7"}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "fail"
    assert "required flow(s) are not delivering" in res["summary"]
    assert any("vcmd -c /tmp/pycore.1/h1" in i["detail"] for i in res["items"])


def test_reachability_error_on_probe_failure():
    assert ac.reachability_result({"ok": False, "error": "ssh down"})["status"] == "error"


def test_reachability_fails_when_configured_flows_produce_no_probe_rows():
    probe = {"ok": True, "summary": {"flows": [{"src_ip": "10.0.0.1",
                                                   "dst_ip": "10.0.0.2"}]},
             "ping": []}
    res = ac.reachability_result(probe)
    assert res["status"] == "fail"
    assert "No runtime results" in res["summary"]


def test_traffic_skip_when_not_declared_and_no_flows():
    probe = {"ok": True, "traffic_files": [], "summary": {"flows": []}, "nodes": {}, "ping": []}
    assert ac.traffic_result(probe, expected=False)["status"] == "skip"


def test_traffic_requires_summary_flow_endpoints_to_exist_and_run():
    probe = {"ok": True, "traffic_files": [], "summary": {"flows": [{"src": "a", "dst": "b"}]},
             "nodes": {}, "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "fail"
    assert "2 required traffic endpoint(s)" in res["summary"]


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


def test_ports_drops_with_no_rule_and_no_default_deny_still_warn():
    # The block rule covers a different source subnet, and the policy is not
    # default-deny, so nothing explains these drops.
    seg = {"ok": True, "rules_summary": {"rules": [
        {"node_id": 1, "service": "Segmentation",
         "rule": {"type": "subnet_block", "src": "10.9.9.0/24", "dst": "172.21.240.0/24"}},
    ]}}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(), segmentation=seg)
    assert res["status"] == "warn"
    assert "3 blocked" in res["summary"]
    assert any("no segmentation rule covers this path" in i["detail"] for i in res["items"])


def test_ports_drops_under_default_deny_are_configured_behaviour():
    # Same drops, but the policy closes everything it does not open. A port no
    # rule opens is meant to be unreachable, so reporting it as a fault would
    # flag most of a segmented scenario.
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(),
                          segmentation=_segmented_probe(src="10.9.9.0/24"))
    assert res["status"] == "pass"
    assert "3 closed by the default-deny policy" in res["summary"]
    assert all("no segmentation rule covers this path" not in i["detail"] for i in res["items"])


def test_ports_a_drop_on_a_path_an_allow_opens_is_still_a_fault():
    # The one shape here worth investigating: the scenario arranged for this
    # path, the allow was installed, and the packets were dropped anyway.
    seg = {"ok": True, "rules_summary": {"rules": [
        {"node_id": 1, "service": "Segmentation",
         "rule": {"type": "subnet_block", "src": "10.0.140.0/24", "dst": "10.9.9.0/24",
                  "default_deny": True, "chain": "FORWARD"}},
        {"node_id": 26, "service": "Segmentation",
         "rule": {"type": "allow", "chain": "INPUT", "proto": "tcp", "port": 16379,
                  "src": "10.0.140.6", "dst": "172.21.240.7", "reason": "traffic"}},
    ]}}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(), segmentation=seg)
    assert res["status"] == "warn"
    opened = [i for i in res["items"] if "even though an allow rule opens this path" in i["detail"]]
    assert len(opened) == 1
    assert "172.21.240.7" in opened[0]["name"]
    # The other two drops have no allow, so the policy explains them.
    assert "2 closed by the default-deny policy" in res["summary"]


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


def _effect(scope, protects, blocks_from, *, invert=False, node_id=1):
    return {"scope": scope, "enforced_by": node_id, "blocks": True,
            "protects": protects, "blocks_from": blocks_from,
            "invert_source": invert, "default_deny_chain": "FORWARD"}


def test_ports_a_protect_internal_drop_is_explained_not_reported_as_a_fault():
    # Previously invisible: the rule filter looked for "block" in the type name,
    # so every protect_internal drop was reported as "no segmentation rule
    # covers this path" -- a fault, for a scenario doing exactly what it was
    # told to do.
    seg = {"ok": True, "rules_summary": {"rules": [
        {"node_id": 1, "service": "Segmentation",
         "rule": {"type": "protect_internal", "subnet": "172.21.240.0/24",
                  "chain": "FORWARD", "default_deny": True,
                  "effect": _effect("transit", "172.21.240.0/24", "172.21.240.0/24", invert=True)}},
    ]}}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(), segmentation=seg)
    assert res["status"] == "pass"
    assert "3 blocked as configured by segmentation" in res["summary"]
    assert not any("no segmentation rule covers this path" in i["detail"] for i in res["items"])


def test_ports_a_protect_internal_does_not_excuse_traffic_from_inside_it():
    # It shuts out everything *except* its own network, so a drop sourced from
    # inside is not explained by it.
    seg = {"ok": True, "rules_summary": {"rules": [
        {"node_id": 1, "service": "Segmentation",
         "rule": {"type": "protect_internal", "subnet": "10.0.140.0/24",
                  "effect": _effect("transit", "10.0.140.0/24", "10.0.140.0/24", invert=True)}},
    ]}}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(), segmentation=seg)
    # Not attributed to that rule; the default-deny policy explains it instead.
    assert res["status"] == "pass"
    assert all("blocked as configured" not in i["detail"] for i in res["items"])
    assert "3 closed by the default-deny policy" in res["summary"]


def test_ports_a_host_enforced_rule_only_excuses_drops_to_that_host():
    # Read from the fields, this rule names 172.21.240.0/24 and would have
    # excused all three drops. It is an INPUT rule on one node, so it shields
    # only 172.21.240.7.
    seg = {"ok": True, "rules_summary": {"rules": [
        {"node_id": 26, "service": "Segmentation",
         "rule": {"type": "protect_internal", "subnet": "172.21.240.0/24",
                  "chain": "INPUT",
                  "effect": _effect("node", "172.21.240.7", "172.21.240.0/24",
                                    invert=True, node_id=26)}},
    ]}}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(), segmentation=seg)
    explained = [i for i in res["items"] if "blocked as configured" in i["detail"]]
    assert len(explained) == 1
    assert "172.21.240.7" in explained[0]["name"]
    # Read from the fields this rule names 172.21.240.0/24 and would have
    # claimed all three; the other two fall to the policy instead.
    assert "2 closed by the default-deny policy" in res["summary"]


def test_ports_the_explanation_describes_what_the_rule_actually_does():
    seg = {"ok": True, "rules_summary": {"rules": [
        {"node_id": 1, "service": "Segmentation",
         "rule": {"type": "protect_internal", "subnet": "172.21.240.0/24",
                  "effect": _effect("transit", "172.21.240.0/24", "172.21.240.0/24", invert=True)}},
    ]}}
    res = ac.ports_result({"ports_checked": [], "port_unreachable": []},
                          _cross_subnet_probe(), segmentation=seg)
    detail = next(i["detail"] for i in res["items"] if "blocked as configured" in i["detail"])
    assert "everything outside 172.21.240.0/24" in detail
    assert "172.21.240.0/24" in detail


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
    assert "ATTEMPTS=3" in script
    assert "time.sleep(0.5)" in script
    assert "'ips': ips" in script
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


def test_reachability_tcp_rst_fails_required_delivery():
    # RST proves a route but also proves the required receiver is not listening.
    # Required traffic needs the service, not merely a round trip to the host.
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 80, "protocol": "TCP",
         "method": "tcp-handshake", "error": "refused", "reachable": True}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "fail"
    assert "destination service is not listening" in res["items"][0]["detail"]


def test_reachability_distinguishes_filtered_port_from_dead_path():
    # Host answers ping but the port is filtered -> point at a port rule.
    filtered = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 80, "protocol": "TCP",
         "method": "tcp-handshake", "error": "timeout", "reachable": False, "icmp": True}]}
    res = ac.reachability_result(filtered)
    assert res["status"] == "fail"
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


def test_reachability_unconfirmed_udp_is_a_required_delivery_failure():
    # UDP has no handshake, so destination counters are required evidence.
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 53, "protocol": "UDP",
         "method": "udp-send", "error": "sent", "reachable": None}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "fail"
    assert "required flow(s) are not delivering" in res["summary"]
    assert res["items"][0]["status"] == "fail"
    assert "not confirmed" in res["items"][0]["detail"]


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


def test_udp_sent_but_nothing_arriving_is_a_failure():
    # The failure mode UDP hides: the sender writes happily into a black hole.
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 6007, "protocol": "UDP",
         "method": "udp-send", "error": "sent", "reachable": None,
         "bytes_sent": 900000, "bytes_received": 0}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "fail"
    assert "required flow(s) are not delivering" in res["summary"]
    detail = res["items"][0]["detail"]
    assert "900,000 bytes" in detail
    assert "dropped in flight" in detail
    assert "segmentation rule covering this port" in detail


def test_udp_without_counters_fails_required_delivery():
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 6007, "protocol": "UDP",
         "method": "udp-send", "error": "sent", "reachable": None}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "fail"
    assert res["items"][0]["status"] == "fail"
    assert "no receiving-agent counters" in res["items"][0]["detail"]


def test_udp_sender_not_started_is_reported_distinctly():
    probe = {"ok": True, "ping": [
        {"src": "a", "dst": "b", "ip": "10.0.0.2", "port": 6007, "protocol": "UDP",
         "method": "udp-send", "error": "sent", "reachable": None,
         "bytes_sent": 0, "bytes_received": 0}]}
    res = ac.reachability_result(probe)
    assert res["status"] == "fail"
    assert "sending agent has written no bytes" in res["items"][0]["detail"]


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


# --------------------------------------------------------------------------- #
# Check 8: Flow Pivot(source) relationships work from source to target
# --------------------------------------------------------------------------- #

def _flow_state(*assignments):
    return {"flow_enabled": True, "flag_assignments": list(assignments)}


def _flow_pivot(role, source, target, **extra):
    item = {"role": role, "source": source, "target": target,
            "provider": "ssh-fallback", "provider_label": "Docker SSH"}
    item.update(extra)
    return item


def test_flow_pivot_relationships_use_chain_targets_not_broad_source_unlocks():
    state = _flow_state(
        {"node_id": 1, "pivot": [
            _flow_pivot("source", "jump", "db"),
            _flow_pivot("source", "jump", "unrelated"),
        ]},
        {"node_id": 2, "pivot": [
            _flow_pivot("target", "jump", "db", target_ports=[5432],
                        target_protocols=["tcp"], exposure="pivot-only"),
        ]},
    )
    relationships = ac.flow_pivot_relationships(state)
    assert [(r["source"], r["target"]) for r in relationships] == [("jump", "db")]
    assert relationships[0]["target_ports"] == [5432]
    assert relationships[0]["target_protocols"] == ["TCP"]


def test_flow_pivot_relationships_deduplicate_duplicate_chain_occurrences():
    # Duplicate target nodes can carry distinct assignment objects. The path is
    # checked once, while metadata from both occurrences remains represented.
    state = _flow_state(
        {"node_id": 18, "pivot": [
            _flow_pivot("target", "jump", "db", target_ports=[5432]),
        ]},
        {"node_id": 18, "pivot": [
            _flow_pivot("target", "jump", "db", target_ports="6432",
                        target_protocols="tcp"),
        ]},
    )
    relationships = ac.flow_pivot_relationships(state)
    assert len(relationships) == 1
    assert relationships[0]["assignment_indexes"] == [0, 1]
    assert relationships[0]["target_ports"] == [5432, 6432]


def test_flow_pivot_relationships_do_not_infer_ports_from_overwritten_assignments():
    state = _flow_state(
        {
            "node_id": 16,
            "resolved_inputs": {"service_port": 2110},
            "pivot": [_flow_pivot("target", "jump", "db")],
        },
        {
            "node_id": 16,
            "resolved_inputs": {"service_port": 17017},
            "pivot": [_flow_pivot("target", "jump", "db")],
        },
    )

    relationships = ac.flow_pivot_relationships(state)

    assert len(relationships) == 1
    assert relationships[0]["assignment_indexes"] == [0, 1]
    # Duplicate assignments can replace the compose runtime, and an external
    # PortForward need not equal the port inside the final container. Leaving
    # this empty makes the live probe discover the actual listening ports.
    assert relationships[0]["target_ports"] == []


def test_flow_pivot_relationships_fall_back_to_legacy_source_records():
    state = _flow_state({"node_id": 1, "pivot": [
        _flow_pivot("source", "jump", "db"),
        _flow_pivot("source", "jump", "web"),
    ]})
    assert [(r["source"], r["target"]) for r in ac.flow_pivot_relationships(state)] == [
        ("jump", "db"), ("jump", "web")]


def test_flow_pivot_relationships_retain_malformed_required_edge_for_reporting():
    relationships = ac.flow_pivot_relationships(_flow_state(
        {"node_id": 2, "pivot": [_flow_pivot("target", "jump", "")]},
    ))
    assert len(relationships) == 1
    assert "missing target" in relationships[0]["metadata_error"]


def test_flow_pivot_probe_script_is_valid_and_enters_the_exact_source_node():
    relationships = [{"source": "docker-12", "target": "docker-14",
                      "target_ports": [], "target_protocols": []}]
    script = ac.flow_pivot_probe_script("pw", 7, relationships)
    ast.parse(script)
    assert "/proc/net/tcp" in script
    assert "socket.create_connection" in script
    assert "_nexec_python(nodes[source]['kind'],source" in script
    assert "target listening port" in script
    assert "ATTEMPTS=3" in script
    assert "for ip in ips" in script
    assert '"source":"docker-12"' in script


def test_flow_pivot_result_passes_a_live_source_to_target_handshake():
    probe = {"ok": True,
             "pivots": [{"source": "jump", "target": "db"}],
             "checks": [{"index": 0, "source": "jump", "target": "db",
                         "ip": "10.0.0.8", "port": 5432,
                         "basis": "target listening port", "method": "tcp-handshake",
                         "reachable": True, "error": ""}]}
    res = ac.flow_pivot_result(probe)
    assert res["status"] == "pass"
    assert "1 Flow pivot path(s) traversable" in res["summary"]
    assert "both directions" in res["items"][0]["detail"]


def test_flow_pivot_result_accepts_target_rst_as_bidirectional_path_proof():
    probe = {"ok": True,
             "pivots": [{"source": "jump", "target": "db"}],
             "checks": [{"index": 0, "source": "jump", "target": "db",
                         "ip": "10.0.0.8", "port": 5432, "basis": "target listening port",
                         "method": "tcp-rst", "reachable": True, "error": "refused"}]}
    res = ac.flow_pivot_result(probe)
    assert res["status"] == "pass"
    assert "reply reached the pivot source" in res["items"][0]["detail"]


def test_flow_pivot_result_fails_an_unreachable_required_chain_path():
    probe = {"ok": True,
             "pivots": [{"source": "jump", "target": "db"}],
             "checks": [{"index": 0, "source": "jump", "target": "db",
                         "ip": "10.0.0.8", "port": 5432, "method": "tcp-connect",
                         "reachable": False, "error": "timeout",
                         "cmd": "sudo docker exec jump python3 -c ..."}]}
    res = ac.flow_pivot_result(probe)
    assert res["status"] == "fail"
    assert "challenge chain is unsolvable" in res["summary"]
    assert "Reproduce:" in res["items"][0]["detail"]


def test_flow_pivot_result_fails_a_target_with_no_port_on_its_own_terms():
    """No port to reach is a real defect, reported as such rather than as a timeout.

    The old probe invented a synthetic closed port here, which under default-deny
    segmentation timed out and was misreported as blocked routing.
    """
    probe = {"ok": True,
             "pivots": [{"source": "docker-7", "target": "vulnslot-1"}],
             "checks": [{"index": 0, "source": "docker-7", "target": "vulnslot-1",
                         "ip": "172.30.96.2", "method": "no-target-port",
                         "reachable": False,
                         "error": "the target declares no Flow port and has nothing listening"}]}
    res = ac.flow_pivot_result(probe)
    assert res["status"] == "fail"
    assert "exposes no port for this pivot" in res["items"][0]["detail"]
    assert "routing or segmentation" not in res["items"][0]["detail"]


def test_flow_pivot_result_warns_on_a_pivot_this_tcp_probe_cannot_judge():
    probe = {"ok": True,
             "pivots": [{"source": "jump", "target": "db"}],
             "checks": [{"index": 0, "source": "jump", "target": "db",
                         "ip": "10.0.0.8", "method": "unsupported-protocol",
                         "reachable": False,
                         "error": "the Flow pivot declares only UDP; this TCP probe cannot validate it"}]}
    res = ac.flow_pivot_result(probe)
    assert res["status"] == "warn"
    assert "cannot be validated" in res["summary"]
    assert "unsolvable" not in res["summary"]


def test_flow_pivot_probe_never_falls_back_to_a_synthetic_port():
    """Port 9 was never a scenario port; probing it produced uninterpretable results."""
    script = ac.flow_pivot_probe_script(relationships=[{"source": "a", "target": "b"}])
    assert "ports=[9]" not in script
    assert "closed-port route probe" not in script
    assert "no-target-port" in script


def test_flow_pivot_result_still_fails_timeout_on_a_real_target_port():
    """A timeout on an actual Flow/listening port remains a genuine failure."""
    probe = {"ok": True,
             "pivots": [{"source": "jump", "target": "db"}],
             "checks": [{"index": 0, "source": "jump", "target": "db",
                         "ip": "10.0.0.8", "port": 5432, "basis": "Flow target port",
                         "method": "tcp-connect", "reachable": False,
                         "error": "timeout", "attempts": 3}]}
    res = ac.flow_pivot_result(probe)
    assert res["status"] == "fail"
    assert "challenge chain is unsolvable" in res["summary"]


def test_flow_pivot_result_still_fails_no_route_on_the_synthetic_port():
    """EHOSTUNREACH is a real routing failure whatever port was probed."""
    probe = {"ok": True,
             "pivots": [{"source": "jump", "target": "db"}],
             "checks": [{"index": 0, "source": "jump", "target": "db",
                         "ip": "10.0.0.8", "port": 9,
                         "basis": "closed-port route probe", "method": "tcp-connect",
                         "reachable": False, "error": "no-route", "attempts": 3}]}
    res = ac.flow_pivot_result(probe)
    assert res["status"] == "fail"
    assert "no route to the target" in res["items"][0]["detail"]


def test_flow_pivot_result_fails_missing_endpoint_or_probe_row_and_skips_no_edges():
    missing_node = {"ok": True,
                    "pivots": [{"source": "jump", "target": "db"}],
                    "checks": [{"index": 0, "source": "jump", "target": "db",
                                "method": "node-lookup", "reachable": False,
                                "error": "target node not found in running CORE session"}]}
    assert ac.flow_pivot_result(missing_node)["status"] == "fail"
    assert ac.flow_pivot_result({"ok": True, "pivots": [], "checks": []})["status"] == "skip"
    assert ac.flow_pivot_result({"ok": True,
                                 "pivots": [{"source": "jump", "target": "db"}],
                                 "checks": []})["status"] == "fail"


# --------------------------------------------------------------------------- #
# Check 9: the participant can reach each pivot provider
# --------------------------------------------------------------------------- #

def _pivot_probe(providers, allows=()):
    rules = [{"node_id": 1, "service": "Segmentation", "rule": dict(a)} for a in allows]
    return {"ok": True, "rules_summary": {
        "rules": rules,
        "pivot_access": {"providers": list(providers)},
    }}


def _provider(subnet="172.21.240.0/24", address="172.21.240.4", port=2222,
              name="pivot-172-21-240-0"):
    return {"subnet": subnet, "node_id": 14, "node_name": name, "address": address,
            "entry": {"kind": "ssh", "port": port, "protocol": "tcp", "label": "SSH"},
            "added": True}


def _allow(src, dst="172.21.240.4", port=2222):
    return {"type": "allow", "chain": "FORWARD", "proto": "tcp",
            "port": port, "src": src, "dst": dst, "reason": "pivot-access"}


HITL_NET = "10.254.200.0/24"


def test_pivot_access_passes_when_the_provider_is_open_to_everyone():
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    res = ac.pivot_access_result(seg, [HITL_NET], _live())
    assert res["status"] == "pass"
    assert "1 pivot provider(s) reachable" in res["summary"]


def test_pivot_access_only_warns_when_the_rules_are_never_confirmed_on_the_wire():
    """Rules permitting it is not the same as a packet proving it."""
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    res = ac.pivot_access_result(seg, [HITL_NET])
    assert res["status"] == "warn"
    assert "not confirmed on the wire" in res["summary"]


def test_pivot_access_fails_when_the_participant_is_not_covered():
    # The shape that used to ship: the allow was scoped to the subnet the block
    # shut out, and the participant is on neither side of that rule.
    seg = _pivot_probe([_provider()], [_allow("10.0.140.0/24")])
    res = ac.pivot_access_result(seg, [HITL_NET])
    assert res["status"] == "fail"
    assert "unsolvable" in res["summary"]
    assert any("no allow rule opens this provider" in i["detail"] for i in res["items"])


def test_pivot_access_passes_when_the_allow_names_the_participant_subnet():
    seg = _pivot_probe([_provider()], [_allow(HITL_NET)])
    assert ac.pivot_access_result(seg, [HITL_NET], _live())["status"] == "pass"


def test_pivot_access_fails_when_no_node_was_placed():
    # An added provider with no address means nothing was created for the
    # subnet, so there is no way in at all.
    provider = _provider(address="", name="pivot-172-21-240-0")
    res = ac.pivot_access_result(_pivot_probe([provider]), [HITL_NET])
    assert res["status"] == "fail"
    assert any("no node was placed" in i["detail"] for i in res["items"])


def test_pivot_access_checks_the_providers_own_port():
    # An allow on a different port does not open the entry.
    seg = _pivot_probe([_provider(port=2222)], [_allow("0.0.0.0/0", port=22)])
    assert ac.pivot_access_result(seg, [HITL_NET])["status"] == "fail"


def test_pivot_access_without_hitl_asks_from_outside_the_subnet():
    # Still a meaningful question: the provider has to be reachable from
    # somewhere outside the subnet it guards. But it is answered with a stand-in
    # address, so it must not read as a verified participant path.
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    res = ac.pivot_access_result(seg, [])
    assert res["status"] == "warn"
    assert "no participant network is configured" in res["summary"]
    assert any("outside the walled-off subnet" in i["detail"] for i in res["items"])

    # A scoped allow is not a failure when there is no participant. The rule
    # opens the provider from a network outside the walled-off subnet, which is
    # exactly what the stand-in stands for; the old "fail" came only from the
    # stand-in being a documentation address no rule could cover -- a verdict
    # the check produced from its own choice of source. With a participant
    # network configured this same shape still fails, above.
    scoped = _pivot_probe([_provider()], [_allow("10.0.140.0/24")])
    assert ac.pivot_access_result(scoped, [])["status"] == "warn"


def test_pivot_access_pass_states_the_participant_network_was_the_vantage():
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    res = ac.pivot_access_result(seg, [HITL_NET], _live())
    assert res["status"] == "pass"
    assert "reachable from the participant network" in res["summary"]


def _seg_with_node_rules(providers, allows, node_rules):
    seg = _pivot_probe(providers, allows)
    seg["nodes"] = {name: {"kind": "vnode", "rule_lines": lines}
                    for name, lines in node_rules.items()}
    return seg


def test_pivot_access_fails_when_an_earlier_drop_shadows_the_allow():
    """An allow rule existing is not the same as traffic passing."""
    allow = _allow("0.0.0.0/0")
    allow["node_name"] = "router-1"
    seg = _seg_with_node_rules([_provider()], [allow], {"router-1": [
        "-A FORWARD -d 172.21.240.4/32 -j DROP",
        "-A FORWARD -s 0.0.0.0/0 -d 172.21.240.4/32 -p tcp --dport 2222 -j ACCEPT",
    ]})
    res = ac.pivot_access_result(seg, [HITL_NET])
    assert res["status"] == "fail"
    assert any("matches earlier in the same chain" in i["detail"] for i in res["items"])


def test_pivot_access_passes_when_the_allow_comes_first():
    allow = _allow("0.0.0.0/0")
    allow["node_name"] = "router-1"
    seg = _seg_with_node_rules([_provider()], [allow], {"router-1": [
        "-A FORWARD -s 0.0.0.0/0 -d 172.21.240.4/32 -p tcp -m tcp --dport 2222 -j ACCEPT",
        "-A FORWARD -d 172.21.240.4/32 -j DROP",
    ]})
    assert ac.pivot_access_result(seg, [HITL_NET], _live())["status"] == "pass"


def test_pivot_access_does_not_invent_a_shadow_from_uncaptured_rules():
    """An unseen chain is not evidence of a problem."""
    allow = _allow("0.0.0.0/0")
    allow["node_name"] = "router-1"
    seg = _seg_with_node_rules([_provider()], [allow], {})
    assert ac.pivot_access_result(seg, [HITL_NET], _live())["status"] == "pass"


def test_pivot_access_ignores_a_drop_on_an_unrelated_port_or_chain():
    allow = _allow("0.0.0.0/0")
    allow["node_name"] = "router-1"
    seg = _seg_with_node_rules([_provider()], [allow], {"router-1": [
        "-A INPUT -d 172.21.240.4/32 -j DROP",
        "-A FORWARD -d 172.21.240.4/32 -p tcp --dport 9999 -j DROP",
        "-A FORWARD -s 0.0.0.0/0 -d 172.21.240.4/32 -p tcp --dport 2222 -j ACCEPT",
    ]})
    assert ac.pivot_access_result(seg, [HITL_NET], _live())["status"] == "pass"


def test_iptables_line_parsing_skips_policies_and_chain_declarations():
    assert ac._parse_iptables_line("-P INPUT ACCEPT") is None
    assert ac._parse_iptables_line("-N custom-seg") is None
    parsed = ac._parse_iptables_line(
        "-A INPUT -s 10.0.0.0/24 -p tcp -m tcp --dport 2222 -j ACCEPT")
    assert parsed == {"chain": "INPUT", "src": "10.0.0.0/24", "dst": "",
                      "proto": "tcp", "dport": 2222, "target": "ACCEPT"}


def test_pivot_access_skips_when_the_scenario_has_no_providers():
    res = ac.pivot_access_result(_pivot_probe([]), [HITL_NET])
    assert res["status"] == "skip"
    assert "accessible by pivot" in res["summary"]


def test_pivot_access_errors_when_the_probe_failed():
    res = ac.pivot_access_result({"ok": False, "error": "ssh died"}, [HITL_NET])
    assert res["status"] == "error"
    assert "ssh died" in res["summary"]


def test_participant_sources_are_addresses_on_each_network():
    assert ac.participant_probe_sources(["10.254.200.0/24"]) == ["10.254.200.1"]
    # A single address is not a network and answers a different question.
    assert ac.participant_probe_sources(["10.254.200.3/32"]) == []
    assert ac.participant_probe_sources(["nonsense", None, ""]) == []


def test_traffic_probe_finds_the_agent_without_procps():
    """A Docker node's container is the scenario's own image, and a minimal
    vulnerability image often ships no `pgrep`/`ps`. Detecting the agent with
    pgrep alone made such a node look idle while its agent was running and
    moving megabytes, so the check reported a sender with no traffic process.
    /proc is kernel-provided, not a package, so it must be the fallback.
    """
    import json as _json
    import re as _re
    import subprocess as _subprocess

    script = ac.traffic_probe_script('pw', 1)
    scan = _json.loads(_re.search(r'^PROC_SCAN = (.*)$', script, _re.M).group(1))

    # pgrep stays the fast path, but must not be the only one.
    assert 'pgrep' in scan
    assert '/proc/' in scan and 'cmdline' in scan
    # The probe invokes the shared constant rather than an inline pgrep.
    assert "['sh','-lc', PROC_SCAN]" in script

    # The fallback runs in whatever shell the image has, which may only be sh.
    proc = _subprocess.run(['/bin/sh', '-n', '-c', scan], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    # The scanner must not count itself: its own command line contains the
    # match string, which would report traffic on every node in the topology.
    assert 'self=$$' in scan


def test_traffic_probe_excludes_its_own_scanner_from_results():
    # The parent shell's command line necessarily contains both `pgrep` and the
    # /proc glob, so both have to be filtered or every node reports a process.
    script = ac.traffic_probe_script('pw', 1)
    assert "'pgrep' not in l" in script
    assert "'/proc/[0-9]' not in l" in script


def test_live_agent_stats_count_as_running_without_a_process_listing():
    # The stats file needs only a readable file, so it is the one liveness
    # signal available on an image with no procps at all.
    probe = {"ok": True, "traffic_files": [],
             "summary": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9"}]},
             "nodes": {"docker-22": {"kind": "docker", "ip": "10.0.0.5", "procs": [],
                                      "agent": {"present": True, "live": True, "age_s": 3,
                                                "bytes_sent": 43220830, "errors": 0, "flows": 1}},
                       "docker-23": {"kind": "docker", "ip": "10.0.0.9",
                                     "procs": ["2 traffic_rx"],
                                     "agent": {"present": True, "live": True}}},
             "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "pass"
    detail = next(i["detail"] for i in res["items"] if i["name"] == "docker-22")
    assert "no process listing available" in detail
    assert "43,220,830 bytes sent" in detail


def test_stopped_agent_is_reported_differently_from_never_started():
    # Three states, not two: an agent that ran and stopped is a distinct hard
    # failure from one that never launched, and says so.
    stopped = {"ok": True, "traffic_files": [],
               "summary": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9"}]},
               "nodes": {"docker-22": {"kind": "docker", "ip": "10.0.0.5", "procs": [],
                                        "agent": {"present": True, "live": False, "age_s": 900}},
                         "docker-23": {"kind": "docker", "ip": "10.0.0.9",
                                       "procs": ["2 traffic_rx"],
                                       "agent": {"present": True, "live": True}}},
               "ping": []}
    res = ac.traffic_result(stopped, expected=True)
    assert res["status"] == "fail"
    detail = next(i["detail"] for i in res["items"] if i["name"] == "docker-22")
    assert "ran but has stopped" in detail and "900s ago" in detail

    never = {"ok": True, "traffic_files": [],
             "summary": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9"}]},
             "nodes": {"docker-22": {"kind": "docker", "ip": "10.0.0.5", "procs": [], "agent": {}},
                       "docker-23": {"kind": "docker", "ip": "10.0.0.9",
                                     "procs": ["2 traffic_rx"],
                                     "agent": {"present": True, "live": True}}},
             "ping": []}
    res = ac.traffic_result(never, expected=True)
    assert res["status"] == "fail"
    detail = next(i["detail"] for i in res["items"] if i["name"] == "docker-22")
    assert "no traffic process is running" in detail


def test_stopped_receiver_agent_is_caught_even_though_it_sends_nothing():
    # A dead required receiver is the same hard failure as a dead sender.
    probe = {"ok": True, "traffic_files": [],
             "summary": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9"}]},
             "nodes": {"docker-21": {"kind": "docker", "ip": "10.0.0.5", "procs": ["1 traffic_x"],
                                     "agent": {"present": True, "live": True}},
                       "docker-24": {"kind": "docker", "ip": "10.0.0.9", "procs": [],
                                     "agent": {"present": True, "live": False, "age_s": 400}}},
             "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "fail"
    assert "required traffic endpoint" in res["summary"]
    assert any("ran but has stopped" in i["detail"] for i in res["items"] if i["name"] == "docker-24")


def test_stopped_agent_outside_required_flows_remains_advisory():
    probe = {"ok": True, "traffic_files": [],
             "summary": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9"}]},
             "nodes": {
                 "sender": {"ip": "10.0.0.5", "procs": ["1 traffic_tx"],
                            "agent": {"present": True, "live": True}},
                 "receiver": {"ip": "10.0.0.9", "procs": ["2 traffic_rx"],
                              "agent": {"present": True, "live": True}},
                 "stale-extra": {"ip": "10.0.0.20", "procs": [],
                                 "agent": {"present": True, "live": False, "age_s": 400}},
             }, "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "warn"
    assert "extra node" in res["summary"]


def test_agent_stats_fallback_is_docker_only():
    # A vnode shares the host's /tmp, so globbing stats_*.json there returns
    # every node's file. Vnodes share the host filesystem and always have
    # pgrep, so they never need this path.
    script = ac.traffic_probe_script('pw', 1)
    assert "if kind != 'docker':" in script
    assert "stats_*.json" in script
    # utcnow() is deprecated and the CORE VM's python version is not pinned.
    assert "utcnow" not in script


def test_pivot_skip_distinguishes_the_two_meanings_of_pivot():
    """Two features are called "pivot"; the skip must say which one it means.

    Segmentation's `accessible_by_pivot` places a reachable provider node in a
    walled-off subnet. A challenge chain's Pivot(node) step is a capability the
    participant gains. A scenario can be full of the second and have none of the
    first, which reads as the check wrongly skipping.
    """
    probe = {"ok": True, "rules_summary": {"rules": []}, "nodes": {}}
    res = ac.pivot_access_result(probe, [])
    assert res["status"] == "skip"
    summary = res["summary"]
    assert "accessible by pivot" in summary
    assert "challenge chain" in summary and "Pivot(node)" in summary
    assert "accessible_by_pivot" in summary, 'name the setting to turn on'


def test_pivot_check_still_runs_when_providers_exist():
    probe = {
        "ok": True,
        "rules_summary": {
            "rules": [],
            "pivot_access": {"providers": [
                {"subnet": "10.9.5.0/24", "node_name": "docker-21",
                 "address": "10.9.5.6", "entry": {"port": 2222}},
            ]},
        },
        "nodes": {},
    }
    res = ac.pivot_access_result(probe, [])
    assert res["status"] != "skip"
    assert any("docker-21" in i["name"] for i in res["items"])


def test_flow_pivot_relationships_use_inferred_ports_when_segmentation_declares_none():
    """The check probes the offering's port when the pivot declares none."""
    state = {"assignments": [{"pivot": [
        {"role": "target", "source": "docker-7", "target": "vulnslot-1",
         "target_ports": [], "inferred_target_ports": ["8080"]},
    ]}]}
    rel = ac.flow_pivot_relationships(state)
    assert rel[0]["target_ports"] == [8080]


def test_flow_pivot_relationships_prefer_declared_ports_over_inferred():
    state = {"assignments": [{"pivot": [
        {"role": "target", "source": "docker-7", "target": "vulnslot-1",
         "target_ports": ["9200"], "inferred_target_ports": ["8080"]},
    ]}]}
    rel = ac.flow_pivot_relationships(state)
    assert rel[0]["target_ports"] == [9200]


# --------------------------------------------------------------------------- #
# Check 9: live participant-path probe
# --------------------------------------------------------------------------- #

def _live(dst="172.21.240.4", port=2222, reachable=True, reply="syn-ack",
          error="", vantage="hitl-router-eth0-hitl0"):
    return {"ok": True, "checks": [{"src": "10.254.200.1", "dst": dst, "port": port,
                                    "reachable": reachable, "reply": reply,
                                    "error": error, "vantage": vantage}]}


def test_live_probe_rows_are_built_with_or_without_a_participant_network():
    """The probe is always attempted; the vantage lookup decides if it can run."""
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    rows = ac.hitl_participant_path_probe_rows(seg, [HITL_NET])
    assert rows == [{"src": "10.254.200.1", "dst": "172.21.240.4", "port": 2222,
                     "label": "pivot-172-21-240-0"}]

    # Without HITL it falls back to the same stand-in the rule analysis uses, so
    # both halves of the check speak about the same source.
    stand_in = ac.hitl_participant_path_probe_rows(seg, [])
    assert len(stand_in) == 1
    assert stand_in[0]["src"] == ac._outside_address("172.21.240.0/24")
    assert stand_in[0]["dst"] == "172.21.240.4"


def test_pivot_access_reports_a_live_syn_ack_as_verified():
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    res = ac.pivot_access_result(seg, [HITL_NET], _live())
    assert res["status"] == "pass"
    assert "verified live" in res["summary"]
    assert "answered SYN-ACK" in res["items"][0]["detail"]


def test_pivot_access_treats_a_live_rst_as_a_working_path():
    """RST proves the round trip; the service just is not up yet."""
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    res = ac.pivot_access_result(seg, [HITL_NET], _live(reply="rst"))
    assert res["status"] == "pass"
    assert "nothing is listening yet" in res["items"][0]["detail"]


def test_pivot_access_fails_when_rules_permit_but_traffic_does_not_return():
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    res = ac.pivot_access_result(seg, [HITL_NET],
                                 _live(reachable=False, reply="", error="no reply"))
    assert res["status"] == "fail"
    assert "traffic does not return" in res["items"][0]["detail"]


def test_pivot_access_warns_when_the_live_probe_could_not_run():
    """No vantage or no raw socket is a missing measurement, not a failure.

    With no router on the source network there is nothing to send from, and in
    that topology the rule analysis is the whole answer available.
    """
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    no_vantage = ac.pivot_access_result(
        seg, [HITL_NET],
        _live(reachable=False, reply="",
              error="no node holds an interface on the participant subnet"))
    assert no_vantage["status"] == "warn"
    assert "no vantage" in no_vantage["summary"]
    assert "unsolvable" not in no_vantage["summary"]

    no_socket = ac.pivot_access_result(
        seg, [HITL_NET],
        _live(reachable=False, reply="",
              error="cannot open raw socket: [Errno 1] Operation not permitted"))
    assert no_socket["status"] == "warn"
    assert "could not run on the vantage router" in no_socket["summary"]


def test_hitl_probe_script_is_valid_python_and_enters_the_vantage_node():
    import ast
    script = ac.hitl_participant_path_probe_script(
        "pw", 7, [{"src": "10.254.200.1", "dst": "172.21.240.4", "port": 2222}])
    ast.parse(script)
    assert "_nexec_python(kind, name, program" in script
    assert "AF_PACKET" in ac._HITL_PROBE_PY
    # Non-mutating: the probe must never claim an address.
    assert "ip addr add" not in script and "ip addr add" not in ac._HITL_PROBE_PY


# --------------------------------------------------------------------------- #
# Check 6: traffic endpoints are identified by CORE node id
# --------------------------------------------------------------------------- #

def _lost_address_probe():
    """A node that lost its CORE address and whose agent died with it."""
    return {"ok": True, "traffic_files": ["/tmp/traffic/traffic_12.json"],
            "summary": {"flows": [
                {"src_id": 12, "dst_id": 14, "src_ip": "10.56.164.4", "dst_ip": "172.30.244.4"},
                {"src_id": 8, "dst_id": 12, "src_ip": "172.30.24.3", "dst_ip": "10.56.164.4"},
            ]},
            "nodes": {
                "docker-7": {"kind": "docker", "procs": [], "ip": "", "ips": [],
                             "agent": {"present": True, "age_s": 198, "live": False}},
                "docker-9": {"kind": "docker", "procs": ["traffic_14"], "ip": "172.30.244.4",
                             "ips": ["172.30.244.4"],
                             "agent": {"present": True, "age_s": 5, "live": True}},
                "workstation-3": {"kind": "vnode", "procs": ["traffic_8"], "ip": "172.30.24.3",
                                  "ips": ["172.30.24.3"],
                                  "agent": {"present": True, "age_s": 5, "live": True}},
            },
            "ping": []}


_NODE_IDS = {"8": "workstation-3", "12": "docker-7", "14": "docker-9"}


def test_traffic_names_an_endpoint_by_node_id_when_its_address_is_gone():
    """The node id is the endpoint's identity; the address is not.

    A node that lost its CORE address is exactly the case worth reporting, and
    matching on address alone makes it unidentifiable precisely then.
    """
    res = ac.traffic_result(_lost_address_probe(), expected=True, node_names_by_id=_NODE_IDS)
    assert res["status"] == "fail"
    names = [i["name"] for i in res["items"] if i["status"] != "pass"]
    assert names == ["docker-7"]
    detail = res["items"][[i["name"] for i in res["items"]].index("docker-7")]["detail"]
    assert "required traffic names this node as a source/destination" in detail
    assert "stopped updating stats" in detail


def test_traffic_without_an_id_map_still_reports_the_node_id_it_could_not_resolve():
    res = ac.traffic_result(_lost_address_probe(), expected=True)
    assert res["status"] == "fail"
    unresolved = [i for i in res["items"] if "was not found" in i["detail"]]
    assert len(unresolved) == 2
    assert all("(node 12)" in i["name"] for i in unresolved)


def test_traffic_id_map_ignores_names_absent_from_the_running_session():
    """A plan name with no running node must not resolve to nothing silently."""
    res = ac.traffic_result(_lost_address_probe(), expected=True,
                            node_names_by_id={"12": "a-node-that-was-never-created"})
    assert res["status"] == "fail"
    assert any("was not found" in i["detail"] for i in res["items"])


def test_traffic_id_resolution_does_not_disturb_address_matching():
    probe = {"ok": True, "traffic_files": [],
             "summary": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.7"}]},
             "nodes": {"h": {"procs": [], "ip": "10.0.0.5"},
                       "z": {"procs": ["x traffic_2_r0.py"], "ip": "10.0.0.7"}},
             "ping": []}
    res = ac.traffic_result(probe, expected=True, node_names_by_id={"99": "h"})
    assert res["status"] == "fail"
    assert any("no traffic process is running" in i["detail"] for i in res["items"])


def test_traffic_failure_carries_the_agent_log_reason():
    """TrafficService records why it did not start; surface it with the failure.

    Without this the reason sits on the node and every diagnosis starts with an
    SSH session.
    """
    reason = "no traffic-agent binary for arch armv7l (looked in /tmp/traffic)"
    probe = {"ok": True, "traffic_files": ["/tmp/traffic/traffic_12.json"],
             "summary": {"flows": [{"src_id": 11, "dst_id": 12, "src_ip": "172.19.138.3",
                                    "dst_ip": "172.19.138.4", "dst_port": 5012}]},
             "nodes": {
                 "docker-6": {"kind": "docker", "procs": ["traffic_11"], "ip": "172.19.138.3",
                              "ips": ["172.19.138.3"],
                              "agent": {"present": True, "age_s": 4, "live": True}},
                 "docker-7": {"kind": "docker", "procs": [], "ip": "172.19.138.4",
                              "ips": ["172.19.138.4"], "agent": {}, "agent_log": reason},
             },
             "ping": []}
    res = ac.traffic_result(probe, expected=True,
                            node_names_by_id={"11": "docker-6", "12": "docker-7"})
    assert res["status"] == "fail"
    detail = next(i["detail"] for i in res["items"] if i["name"] == "docker-7")
    assert "no traffic process is running" in detail
    assert f"Agent log: {reason}" in detail


def test_traffic_failure_without_an_agent_log_is_unchanged():
    probe = {"ok": True, "traffic_files": [],
             "summary": {"flows": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.7"}]},
             "nodes": {"h": {"procs": [], "ip": "10.0.0.5"},
                       "z": {"procs": ["x traffic_2_r0.py"], "ip": "10.0.0.7"}},
             "ping": []}
    res = ac.traffic_result(probe, expected=True)
    detail = next(i["detail"] for i in res["items"] if i["name"] == "h")
    assert "Agent log:" not in detail


def test_traffic_probe_reads_the_agent_log_only_on_docker_nodes():
    """A vnode shares the host /tmp, so the glob would return every node's log."""
    script = ac.traffic_probe_script("pw", 7)
    assert "output_*.txt" in script
    marker = script.index("def _node_agent_log")
    body = script[marker:marker + 400]
    assert "if kind != 'docker'" in body


def test_flow_pivot_reproduce_command_matches_the_endpoint_actually_tried():
    """The prober walks every candidate; the command must name what it reported.

    The command was built from candidate[0] up front while the reported port came
    from the last candidate tried, so a multi-candidate failure printed a command
    that reproduced a different port than the one in the label.
    """
    script = ac.flow_pivot_probe_script("pw", 7, [{"source": "a", "target": "b"}])
    update_at = script.index("check.update({'ip':result[2]")
    tail = script[update_at:update_at + 400]
    assert "_repro(nodes[source]['kind'],source,result[2],result[3])" in tail


def test_flow_pivot_result_reports_no_route_with_its_reproduce_command():
    probe = {"ok": True,
             "pivots": [{"source": "docker-7", "target": "docker-8"}],
             "checks": [{"index": 0, "source": "docker-7", "target": "docker-8",
                         "ip": "10.0.225.4", "port": 5005, "basis": "Flow target port",
                         "method": "tcp-connect", "reachable": False,
                         "error": "no-route", "attempts": 3,
                         "cmd": "sudo nsenter ... 10.0.225.4 5005"}]}
    res = ac.flow_pivot_result(probe)
    assert res["status"] == "fail"
    detail = res["items"][0]["detail"]
    assert "no route to the target" in detail
    assert "5005" in detail


# --------------------------------------------------------------------------- #
# "No route" is two different faults, and the live addresses tell them apart
# --------------------------------------------------------------------------- #

def _no_route_row(**extra):
    row = {"src": "pc-8", "dst": "pc-4", "ip": "172.30.96.6", "port": 5004,
           "protocol": "TCP", "reachable": False, "error": "no-route",
           "attempts": 3, "cmd": "repro", "dst_ip_owned": False}
    row.update(extra)
    return row


def test_no_route_names_the_live_addresses_when_the_target_exists_nowhere():
    res = ac.reachability_result({"ok": True, "ping": [
        _no_route_row(src_live=["10.0.5.2"], dst_live=["10.0.5.3"])]})
    detail = res["items"][0]["detail"]
    # Routing is not the fault here: the flow is aimed at an address this
    # session never had, so the fix is to regenerate the traffic artifacts.
    assert "No running node holds 172.30.96.6" in detail
    assert "pc-4 is at 10.0.5.3" in detail
    assert "pc-8 is at 10.0.5.2" in detail
    assert "regenerated" in detail


def test_no_route_reports_a_source_whose_interface_was_never_addressed():
    res = ac.reachability_result({"ok": True, "ping": [
        _no_route_row(src_live=[], dst_live=["10.0.5.3"], src_kind="vnode",
                      src_links=["eth0"], src_links_queried=True)]})
    detail = res["items"][0]["detail"]
    # A node with no address has no route to anywhere; regenerating traffic
    # would not help, so that advice must not appear.
    assert "pc-8 has eth0 but no IPv4 address on it" in detail
    assert "never applied or has been lost" in detail
    assert "regenerated" not in detail
    # A vnode cannot restart the way a container does, so that explanation must
    # not be offered for one.
    assert "restarted after execute" not in detail


def test_no_route_blames_a_restart_only_for_a_container():
    res = ac.reachability_result({"ok": True, "ping": [
        _no_route_row(src_live=[], dst_live=["10.0.5.3"], src_kind="docker",
                      src_links=["eth0"], src_links_queried=True)]})
    assert "restarted after execute" in res["items"][0]["detail"]


def test_no_route_reports_a_source_that_was_never_linked_into_the_topology():
    # No interface beyond loopback is a different fault from an interface that
    # lost its address: the node was created but never wired up.
    res = ac.reachability_result({"ok": True, "ping": [
        _no_route_row(src_live=[], dst_live=["10.0.5.3"], src_kind="vnode",
                      src_links=[], src_links_queried=True)]})
    detail = res["items"][0]["detail"]
    assert "no network interface beyond loopback" in detail
    assert "never linked into the topology" in detail


def test_no_route_says_so_when_the_interfaces_could_not_be_listed():
    res = ac.reachability_result({"ok": True, "ping": [
        _no_route_row(src_live=[], dst_live=["10.0.5.3"], src_kind="docker",
                      src_links=[], src_links_queried=False)]})
    assert "interfaces could not be listed" in res["items"][0]["detail"]


def test_no_route_reports_a_destination_that_has_no_address_at_all():
    res = ac.reachability_result({"ok": True, "ping": [
        _no_route_row(src_live=["10.0.5.2"], dst_live=[], dst_links=["eth0"],
                      dst_links_queried=True)]})
    detail = res["items"][0]["detail"]
    assert "pc-4 has eth0 but no IPv4 address on it" in detail
    assert "nothing can reach it" in detail
    assert "regenerated" not in detail


def test_no_route_stays_quiet_when_the_target_address_is_really_owned():
    # Correctly addressed endpoints with no path between them: a routing or
    # segmentation fault, and the addressing note would only be noise.
    res = ac.reachability_result({"ok": True, "ping": [
        _no_route_row(dst_ip_owned=True, src_live=["10.0.5.2"], dst_live=["172.30.96.6"])]})
    detail = res["items"][0]["detail"]
    assert "no route to the destination" in detail
    assert "No running node holds" not in detail


def test_no_route_from_an_older_probe_payload_reports_as_before():
    # Rows recorded before the probe carried live addresses must still render.
    res = ac.reachability_result({"ok": True, "ping": [_no_route_row()]})
    detail = res["items"][0]["detail"]
    assert "no route to the destination" in detail
    assert "has no IPv4 address" not in detail


# --------------------------------------------------------------------------- #
# Check 9 must be able to reach a verdict without a participant network
# --------------------------------------------------------------------------- #

def _outside_live(src, *, reachable=True, error="", **extra):
    """A live row as the VM returns it after substituting a real router."""
    row = {"src": src, "dst": "172.21.240.4", "port": 2222, "vantage": "r1",
           "reachable": reachable, "reply": "syn-ack" if reachable else "",
           "error": error}
    row.update(extra)
    return {"ok": True, "checks": [row]}


def test_stand_in_source_comes_from_the_rule_that_opens_the_provider():
    # Asking from a documentation address only works for a wildcard allow; a
    # rule scoped to one network does not cover it, and the check then blamed
    # the scenario for a source it had picked itself.
    seg = _pivot_probe([_provider()], [_allow("10.0.140.0/24")])
    rows = ac.hitl_participant_path_probe_rows(seg, [])
    assert [r["src"] for r in rows] == ["10.0.140.1"]


def test_stand_in_falls_back_to_a_documentation_address_for_a_wildcard_allow():
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    rows = ac.hitl_participant_path_probe_rows(seg, [])
    assert [r["src"] for r in rows] == ["203.0.113.1"]
    # ...and the walled-off subnet travels with the row, so the VM can swap in a
    # router that really sits outside it. Without that the vantage search could
    # never match and this check could not reach `pass` in any scenario with no
    # participant network.
    assert rows[0]["outside_of"] == "172.21.240.0/24"


def test_a_real_participant_network_is_never_second_guessed():
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    rows = ac.hitl_participant_path_probe_rows(seg, [HITL_NET])
    assert "outside_of" not in rows[0]
    assert rows[0]["src"].startswith("10.254.200.")


def test_a_substituted_router_confirms_the_path_when_the_allow_covers_it():
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    live = _outside_live("10.0.140.1", src_used="10.0.140.1",
                         source="router outside 172.21.240.0/24")
    res = ac.pivot_access_result(seg, [], live)
    assert res["status"] == "pass"
    assert "10.0.140.1" in res["items"][0]["detail"]


def test_a_substituted_router_the_allow_does_not_cover_proves_nothing():
    # The rule opens the provider from one network; the VM answered from
    # another. That reply is real but it is not evidence about this rule.
    seg = _pivot_probe([_provider()], [_allow("10.0.140.0/24")])
    live = _outside_live("192.168.5.1", src_used="192.168.5.1",
                         source="router outside 172.21.240.0/24")
    res = ac.pivot_access_result(seg, [], live)
    assert res["status"] == "warn"


def test_silence_from_a_source_we_chose_ourselves_is_not_a_failure():
    # The stand-in stands for a participant network that does not exist in this
    # scenario, so its silence cannot condemn the real participant path.
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    live = _outside_live("10.0.140.1", reachable=False, error="no reply",
                         src_used="10.0.140.1")
    res = ac.pivot_access_result(seg, [], live)
    assert res["status"] == "warn"
    assert "does not show the real participant path is broken" in res["items"][0]["detail"]


def test_a_silent_path_from_the_real_participant_is_still_a_failure():
    seg = _pivot_probe([_provider()], [_allow("0.0.0.0/0")])
    live = _outside_live("10.254.200.2", reachable=False, error="no reply")
    res = ac.pivot_access_result(seg, [HITL_NET], live)
    assert res["status"] == "fail"


def test_probe_script_can_swap_in_a_router_outside_the_walled_off_subnet():
    script = ac.hitl_participant_path_probe_script("pw", 3, [
        {"src": "203.0.113.1", "dst": "172.21.240.4", "port": 2222,
         "outside_of": "172.21.240.0/24"}])
    compile(script, "<probe>", "exec")
    assert "_outside_router" in script
    assert "src_used" in script
