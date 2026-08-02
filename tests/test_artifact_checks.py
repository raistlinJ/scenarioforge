"""Unit coverage for the pure CORE artifact-check helpers."""

import ast
import xml.etree.ElementTree as ET

from webapp import artifact_checks as ac


# --------------------------------------------------------------------------- #
# Plan + validator-summary mapping (checks 1-4)
# --------------------------------------------------------------------------- #

def test_check_plan_has_six_pending_steps_in_order():
    plan = ac.check_plan()
    assert [c["key"] for c in plan] == ac.CHECK_KEYS
    assert len(plan) == 6
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


def test_segmentation_fail_when_expected_but_absent():
    probe = {"ok": True, "seg_files": [], "nodes": {"r1": {"rules_present": False, "rule_count": 0}}}
    res = ac.segmentation_result(probe, expected=True)
    assert res["status"] == "fail"


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


def test_traffic_warn_when_a_node_unreachable():
    probe = {"ok": True, "traffic_files": ["/tmp/traffic/traffic_1_s0.py"],
             "nodes": {"h": {"procs": ["x traffic_1_s0.py"], "ip": "10.0.0.5"}},
             "ping": [{"src": "h", "dst": "z", "ip": "10.0.0.7", "reachable": False}]}
    assert ac.traffic_result(probe, expected=True)["status"] == "warn"


def test_traffic_skip_when_summary_present_but_empty_even_if_xml_declares_traffic():
    # The runtime artifact is authoritative: an empty flows list means no
    # traffic, regardless of the scenario XML's Traffic-section density.
    probe = {"ok": True, "traffic_files": [], "summary": {"flows": []},
             "nodes": {"h": {"procs": [], "ip": "10.0.0.5"}},
             "ping": [{"src": "h", "dst": "w", "ip": "10.0.0.6", "reachable": True}]}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "skip"
    assert "no traffic configured" in res["summary"].lower()
    assert "1 node(s) reachable" in res["summary"]


def test_traffic_warn_only_when_summary_artifact_missing_and_declared():
    # No traffic_summary.json at all + scenario declares traffic -> can't confirm.
    probe = {"ok": True, "traffic_files": [], "nodes": {"h": {"procs": [], "ip": "10.0.0.5"}}, "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "warn"
    assert "traffic generation" in res["summary"].lower()


def test_traffic_skip_when_not_declared_and_no_flows():
    probe = {"ok": True, "traffic_files": [], "summary": {"flows": []}, "nodes": {}, "ping": []}
    assert ac.traffic_result(probe, expected=False)["status"] == "skip"


def test_traffic_uses_summary_flows_as_evidence():
    probe = {"ok": True, "traffic_files": [], "summary": {"flows": [{"src": "a", "dst": "b"}]},
             "nodes": {}, "ping": []}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "pass"
    assert "1 traffic flow" in res["summary"]


def test_traffic_unreachable_warning_includes_reproduce_command():
    probe = {"ok": True, "traffic_files": ["/tmp/traffic/traffic_1_s0.py"],
             "nodes": {"h": {"procs": [], "ip": "10.0.0.5"}},
             "ping": [{"src": "h", "dst": "z", "ip": "10.0.0.7", "reachable": False,
                       "cmd": "sudo vcmd -c /tmp/pycore.1/h -- ping -c3 -W2 10.0.0.7"}]}
    res = ac.traffic_result(probe, expected=True)
    assert res["status"] == "warn"
    detail = next(i["detail"] for i in res["items"] if i["name"].startswith("ping"))
    assert "vcmd -c /tmp/pycore.1/h" in detail


# --------------------------------------------------------------------------- #
# Segmentation verification artifact (allow_verification.json)
# --------------------------------------------------------------------------- #

def test_segmentation_verification_pass_when_all_flows_blocked():
    probe = {"ok": True, "seg_files": [], "nodes": {},
             "verification": {"flows_total": 3, "blocked": ["a", "b", "c"], "blocked_count": 3}}
    res = ac.segmentation_result(probe, expected=True)
    assert res["status"] == "pass"
    assert "3 restricted flow" in res["summary"]


def test_segmentation_verification_fail_when_partially_blocked():
    probe = {"ok": True, "seg_files": [], "nodes": {},
             "verification": {"flows_total": 3, "blocked": ["a"], "blocked_count": 1}}
    res = ac.segmentation_result(probe, expected=True)
    assert res["status"] == "fail"
    assert "1 of 3" in res["summary"]


def test_segmentation_verification_skip_when_no_restricted_flows():
    probe = {"ok": True, "seg_files": [], "nodes": {},
             "verification": {"flows_total": 0, "blocked": [], "blocked_count": 0}}
    assert ac.segmentation_result(probe, expected=True)["status"] == "skip"


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
