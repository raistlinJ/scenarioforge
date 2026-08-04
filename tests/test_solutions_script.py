"""Unit coverage for the downloadable Solutions Script generator."""

import base64
import re
import subprocess

import pytest

from webapp.solutions_script import (
    align_assignments,
    build_solutions_script,
    _build_node_check,
    _credential_from,
    _find_output,
    _http_gates,
    _nfs_export,
    _port_from,
)


def _node(node_id, name="node", ip="10.0.0.5", **extra):
    base = {"id": node_id, "name": name, "type": "docker"}
    if ip:
        base["ipv4"] = ip
    base.update(extra)
    return base


def _ssh_assignment(node_id="1", flag="FLAG{deadbeef}"):
    return {
        "node_id": node_id,
        "type": "flag-node-generator",
        "flag_generator": "SSH",
        "resolved_outputs": {
            "Credential(user, password)": "alice:s3cr3t",
            "PortForward(host, port)": 2222,
            "FlagFile(path)": "/tmp/host/path/flag.txt",
            "Flag(flag_id)": flag,
        },
        "access_instructions": {
            "title": "SSH in",
            "steps": [
                {"step": 1, "title": "login", "instructions": "```bash\nssh -p {{PORT}} {{USERNAME}}@{{NODE}}\n```\nUse `{{PASSWORD}}`."},
                {"step": 2, "title": "read", "instructions": "```bash\ncat ~/{{FLAG_FILE}}\n```"},
            ],
        },
    }


def _http_assignment(node_id="1", flag="FLAG{web}"):
    return {
        "node_id": node_id,
        "type": "flag-node-generator",
        "flag_generator": "HTTP",
        "resolved_outputs": {
            "PortForward(host, port)": 8443,
            "Endpoint(path)": "/search",
            "Flag(flag_id)": flag,
        },
        "access_instructions": {
            "title": "SQLi",
            "steps": [
                {"step": 1, "title": "open", "instructions": "```bash\ncurl -k \"https://{{NODE}}:{{PORT}}/search?q=1\"\n```"},
            ],
        },
    }


def _nc_assignment(node_id="1", flag="FLAG{mqtt}"):
    return {
        "node_id": node_id,
        "type": "flag-node-generator",
        "flag_generator": "MQTT",
        "resolved_outputs": {
            "PortForward(host, port)": 1883,
            "FlagFile(path)": "site/alerts",
            "Flag(flag_id)": flag,
        },
        "access_instructions": {
            "title": "topic",
            "steps": [
                {"step": 1, "title": "connect", "instructions": "```bash\nnc {{NODE}} {{PORT}}\n```"},
                {"step": 2, "title": "sub", "instructions": "```text\nSUB site/alerts\nGET {{FLAG_FILE}}\n```"},
            ],
        },
    }


# --------------------------------------------------------------------------- #
# Resolved-artifact helpers
# --------------------------------------------------------------------------- #

def test_find_output_is_whitespace_insensitive():
    # The solver distinguishes 'Credential(user, password)' from the spaceless
    # form; the generator must match either spelling when reading values.
    outputs = {"Credential(user,password)": "bob:pw", "PortForward(host, port)": "host:2049"}
    assert _find_output(outputs, "credential", "password") == "bob:pw"
    assert _port_from(outputs) == "2049"


def test_credential_split():
    assert _credential_from({"Credential(user, password)": "alice:s3cr3t"}) == ("alice", "s3cr3t")
    assert _credential_from({"Credential(user)": "solo"}) == ("solo", "")


def test_port_takes_trailing_integer():
    assert _port_from({"PortForward(host, port)": 2222}) == "2222"
    assert _port_from({"PortForward(host, port)": "10.0.0.5:8080/tcp"}) == "8080"
    assert _port_from({}) == ""


# --------------------------------------------------------------------------- #
# Strategy selection
# --------------------------------------------------------------------------- #

def test_ssh_strategy_and_payload():
    check = _build_node_check(1, _node("1"), _ssh_assignment())
    assert check.strategy == "ssh"
    assert not check.skip_reason
    payload = base64.b64decode(_payload_of(check)).decode()
    assert "sshpass -p" in payload
    assert "alice@10.0.0.5" in payload
    assert "-p 2222" in payload
    assert "grep -rs" in payload  # searches for the flag on the target


def test_key_based_ssh_after_chmod_line_still_detected():
    assignment = {
        "node_id": "1",
        "type": "flag-node-generator",
        "flag_generator": "SSH",
        "resolved_outputs": {"PortForward(host, port)": 2222, "Flag(flag_id)": "FLAG{k}"},
        "access_instructions": {"title": "key", "steps": [
            {"step": 1, "title": "x", "instructions": "```bash\nchmod 600 /keys/id_ed25519\nssh -i /keys/id_ed25519 -p 2222 ops@{{NODE}}\n```"},
        ]},
    }
    check = _build_node_check(1, _node("1"), assignment)
    assert check.strategy == "ssh"
    payload = base64.b64decode(_payload_of(check)).decode()
    assert "-i /keys/id_ed25519" in payload
    assert "ops@10.0.0.5" in payload
    assert "sshpass" not in payload  # key-based: no password wrapper


def test_http_strategy_uses_documented_url():
    check = _build_node_check(1, _node("1"), _http_assignment())
    assert check.strategy == "http"
    payload = base64.b64decode(_payload_of(check)).decode()
    assert "curl" in payload
    assert "https://10.0.0.5:8443/search?q=1" in payload


def test_http_fallback_when_no_fenced_command_but_endpoint_present():
    assignment = {
        "node_id": "1",
        "type": "flag-node-generator",
        "flag_generator": "HTTP",
        "resolved_outputs": {"PortForward(host, port)": 8080, "Endpoint(path)": "/gate", "Flag(flag_id)": "FLAG{g}"},
        "access_instructions": {"title": "gate", "steps": [
            {"step": 1, "title": "present", "instructions": "Submit the prior token as a header."},
        ]},
    }
    check = _build_node_check(1, _node("1"), assignment)
    assert check.strategy == "http"
    payload = base64.b64decode(_payload_of(check)).decode()
    assert "10.0.0.5:8080/gate" in payload


def test_nc_strategy_pipes_dialog():
    check = _build_node_check(1, _node("1"), _nc_assignment())
    assert check.strategy == "nc"
    payload = base64.b64decode(_payload_of(check)).decode()
    assert "nc -w" in payload
    assert "1883" in payload
    assert "SUB site/alerts" in payload


# --------------------------------------------------------------------------- #
# Header-gated HTTP (cross-step fact passing)
# --------------------------------------------------------------------------- #

def _gate_assignment(node_id="1", value_present=True):
    return {
        "node_id": node_id,
        "type": "flag-node-generator",
        "flag_generator": "HTTP",
        "resolved_inputs": {"Checksum(sha256)": "TOKEN123"} if value_present else {},
        "resolved_outputs": {
            "PortForward(host, port)": 18658,
            "Endpoint(path)": "/evidence/download",
            "Flag(flag_id)": "FLAG{gate}",
        },
        "access_instructions": {"title": "gate", "steps": [
            {"step": 1, "title": "present",
             "instructions": "Provide the previous `Checksum(sha256)` as `sha256` or `X-Checksum-SHA256`."},
        ]},
    }


def test_http_gate_parses_fact_param_header_and_value():
    gates = _http_gates(_gate_assignment(), {"Checksum(sha256)": "TOKEN123"}, {})
    assert len(gates) == 1
    assert gates[0].fact == "Checksum(sha256)"
    assert gates[0].param == "sha256"
    assert gates[0].header == "X-Checksum-SHA256"
    assert gates[0].value == "TOKEN123"


def test_gated_http_injects_query_param_and_header():
    check = _build_node_check(1, _node("1"), _gate_assignment(), {})
    assert check.strategy == "http"
    payload = base64.b64decode(_payload_of(check)).decode()
    assert "sha256=TOKEN123" in payload
    assert "X-Checksum-SHA256: TOKEN123" in payload


def test_gate_value_falls_back_to_prior_step_facts():
    # The consuming node lacks the value in its own inputs; an earlier step
    # produced it and it arrives via the accumulated known-facts map.
    check = _build_node_check(2, _node("2"), _gate_assignment(value_present=False),
                              {"checksum(sha256)": "FROMPRIOR"})
    payload = base64.b64decode(_payload_of(check)).decode()
    assert "FROMPRIOR" in payload


def test_endpoint_fallback_tries_both_schemes():
    check = _build_node_check(1, _node("1"), _gate_assignment(), {})
    payload = base64.b64decode(_payload_of(check)).decode()
    assert "https://10.0.0.5:18658/evidence/download" in payload
    assert "http://10.0.0.5:18658/evidence/download" in payload


def test_cross_step_gate_end_to_end_counts():
    chain = [_node("1", "producer"), _node("2", "gate")]
    producer = _nc_assignment("1")
    gate = _gate_assignment("2", value_present=True)
    script = build_solutions_script("Gates", chain, [producer, gate])
    assert script.count("\ncheck_step ") == 2


# --------------------------------------------------------------------------- #
# NFS and WebDAV
# --------------------------------------------------------------------------- #

def _nfs_assignment(node_id="1", export="/legalhold"):
    return {
        "node_id": node_id,
        "type": "flag-node-generator",
        "flag_generator": "NFS",
        "resolved_outputs": {
            "PortForward(host, port)": 2049,
            "Directory(host, path)": export,
            "Credential(user, password)": "u:p",
            "Flag(flag_id)": "FLAG{nfs}",
        },
        "access_instructions": {"title": "nfs", "steps": [
            {"step": 1, "title": "mount",
             "instructions": "```bash\napt-get install -y nfs-common\nmkdir -p /mnt/x\nmount -t nfs4 -o vers=4,port={{PORT}} {{NODE}}:{{PATH}} /mnt/x\n```"},
            {"step": 2, "title": "read", "instructions": "```bash\ncat /mnt/x/{{FLAG_FILE}}\n```"},
        ]},
    }


def test_nfs_mount_strategy():
    check = _build_node_check(1, _node("1"), _nfs_assignment(), {})
    assert check.strategy == "nfs"
    assert not check.skip_reason
    payload = base64.b64decode(_payload_of(check)).decode()
    assert "mount -t nfs4" in payload
    assert "10.0.0.5:/legalhold" in payload
    assert "grep -rshI 'FLAG{'" in payload


def test_nfs_export_falls_back_when_directory_is_vm_run_dir():
    outputs = {"Directory(host, path)": "/tmp/vulns/flag_node_generators_runs/flow-x/10_nfs_docker/exports"}
    assert _nfs_export(outputs) == "/exports"
    assert _nfs_export({"Directory(host, path)": "/legalhold"}) == "/legalhold"


def test_webdav_labeled_nfs_uses_curl_with_basic_auth():
    assignment = {
        "node_id": "1",
        "type": "flag-node-generator",
        "flag_generator": "NFS",
        "resolved_outputs": {
            "PortForward(host, port)": 8080,
            "Directory(host, path)": "/evidence",
            "Credential(user, password)": "ticketuser:ticketpass",
            "Flag(flag_id)": "FLAG{dav}",
        },
        "access_instructions": {"title": "dav", "steps": [
            {"step": 1, "title": "connect",
             "instructions": "```bash\napt-get install -y curl\ncurl -u '{{USERNAME}}:{{PASSWORD}}' http://{{NODE}}:{{PORT}}/{{PATH}}/manifest.txt\n```"},
        ]},
    }
    check = _build_node_check(1, _node("1"), assignment, {})
    assert check.strategy == "http"
    payload = base64.b64decode(_payload_of(check)).decode()
    assert "-u ticketuser:ticketpass" in payload


# --------------------------------------------------------------------------- #
# Node-generator-only scoping and skip reasons
# --------------------------------------------------------------------------- #

def test_non_node_generator_is_skipped():
    check = _build_node_check(1, _node("1"), {"node_id": "1", "type": "flag-generator", "resolved_outputs": {"Flag(flag_id)": "FLAG{x}"}})
    assert check.skip_reason
    assert "flag-node-generator" in check.skip_reason


def test_missing_ip_is_skipped():
    check = _build_node_check(1, _node("1", ip=""), _ssh_assignment())
    assert check.skip_reason
    assert "IPv4" in check.skip_reason


def test_manual_only_step_is_skipped_with_clear_reason():
    # A node-generator whose steps have no automatable entry point (no ssh/
    # curl/nc/mount and no Endpoint) is skipped rather than guessed at.
    assignment = {
        "node_id": "1",
        "type": "flag-node-generator",
        "flag_generator": "Custom",
        "resolved_outputs": {"Flag(flag_id)": "FLAG{n}"},
        "access_instructions": {"title": "manual", "steps": [
            {"step": 1, "title": "inspect", "instructions": "```bash\nfoobar --do-the-thing\n```"},
        ]},
    }
    check = _build_node_check(1, _node("1"), assignment)
    assert check.skip_reason
    assert "manual setup" in check.skip_reason


# --------------------------------------------------------------------------- #
# Assignment alignment and full-script rendering
# --------------------------------------------------------------------------- #

def test_align_assignments_matches_by_node_id_then_position():
    chain = [_node("a"), _node("b")]
    assignments = [{"node_id": "b", "type": "flag-node-generator"}, {"node_id": "a", "type": "flag-node-generator"}]
    aligned = align_assignments(chain, assignments)
    assert aligned[0]["node_id"] == "a"
    assert aligned[1]["node_id"] == "b"


def test_build_script_is_valid_bash_and_reports_counts():
    chain = [_node("1", "web"), _node("2", "app"), _node("3", "novuln")]
    assignments = [_http_assignment("1"), _ssh_assignment("2"), {"node_id": "3", "type": "flag-generator"}]
    script = build_solutions_script("Demo", chain, assignments)
    assert script.startswith("#!/usr/bin/env bash")
    # Documented human steps are preserved as comments for context.
    assert "# Step 1" in script or "# --- Step 1" in script
    # Two runnable checks, one skip.
    assert script.count("\ncheck_step ") == 2
    assert script.count("\nskip_step ") == 1
    _assert_bash_syntax_ok(script)


def test_empty_chain_still_produces_runnable_script():
    script = build_solutions_script("Empty", [], [])
    assert "0 auto-checkable" in script
    _assert_bash_syntax_ok(script)


def test_flag_falls_back_to_resolved_output_when_flag_value_missing():
    assignment = _ssh_assignment(flag="FLAG{fromoutputs}")
    assignment["flag_value"] = None
    check = _build_node_check(1, _node("1"), assignment)
    assert check.flag == "FLAG{fromoutputs}"


def _payload_of(check):
    return _b64(check.retrieval)


def _b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _assert_bash_syntax_ok(script):
    import shutil
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash not available")
    proc = subprocess.run([bash, "-n"], input=script, text=True, capture_output=True)
    assert proc.returncode == 0, proc.stderr


# --------------------------------------------------------------------------- #
# Pivot steps: the way in has to work, or nothing behind it is solvable
# --------------------------------------------------------------------------- #

def _pivot_assignment(**overrides):
    decision = {
        'disposition': 'own_step', 'subnet': '172.21.240.0/24',
        'provider_node': 'pivot-172-21-240-0', 'provider_address': '172.21.240.4',
        'entry_kind': 'ssh', 'entry_port': 2222, 'insert_before': 0,
        'instruction': 'Gain access over SSH on pivot-172-21-240-0:2222.',
    }
    decision.update(overrides)
    return [{'node_id': 'n1', 'name': 'n1', 'pivot_decisions': [decision]}]


def _chain():
    return [{'id': 'n1', 'name': 'n1', 'ip4': '10.0.0.5'}]


def test_an_own_step_pivot_becomes_a_check():
    from webapp.solutions_script import build_solutions_script

    script = build_solutions_script('S', _chain(), _pivot_assignment())
    assert 'check_pivot P1' in script
    assert '172.21.240.4' in script
    assert '2222' in script
    assert '1 pivot step(s)' in script


def test_the_pivot_check_is_emitted_before_the_step_it_gates():
    from webapp.solutions_script import build_solutions_script

    script = build_solutions_script('S', _chain(), _pivot_assignment(insert_before=0))
    assert script.index('check_pivot P1') < script.index('skip_step 1')


def test_an_open_and_a_closed_port_are_told_apart():
    # A bare `grep -q REACHABLE` matches UNREACHABLE, so every closed port
    # reported as open. Found by running the generated script against a port
    # nothing served; the answers must not be substrings of one another and the
    # match is anchored.
    from webapp.solutions_script import build_solutions_script

    script = build_solutions_script('S', _chain(), _pivot_assignment())
    assert 'PIVOT_OPEN' in script and 'PIVOT_SHUT' in script
    assert 'grep -qx PIVOT_OPEN' in script
    assert 'PIVOT_SHUT'.startswith('PIVOT_OPEN') is False
    assert 'PIVOT_OPEN' not in 'PIVOT_SHUT'


def test_an_absorbed_pivot_is_not_a_check():
    # It is a consequence of a challenge already being checked.
    from webapp.solutions_script import build_solutions_script, own_step_pivots

    assignments = _pivot_assignment(disposition='absorbed')
    assert own_step_pivots(assignments) == []
    # The helper is always defined, like check_step and skip_step; what must be
    # absent is any invocation of it.
    assert 'check_pivot P' not in build_solutions_script('S', _chain(), assignments)


def test_a_provider_with_no_address_yields_no_check():
    # The plan reports such a provider as unresolved and execute warns about it;
    # inventing a check would be a confident answer to an unanswerable question.
    from webapp.solutions_script import build_solutions_script

    script = build_solutions_script('S', _chain(), _pivot_assignment(provider_address=''))
    assert 'check_pivot P' not in script


def test_the_same_pivot_is_not_checked_twice():
    from webapp.solutions_script import own_step_pivots

    decision = _pivot_assignment()[0]['pivot_decisions'][0]
    assignments = [{'node_id': 'a', 'pivot_decisions': [decision]},
                   {'node_id': 'b', 'pivot_decisions': [dict(decision)]}]
    assert len(own_step_pivots(assignments)) == 1


def test_a_pivot_the_chain_never_orders_against_is_still_checked():
    # insert_before is -1 when no chain step lives in that subnet. The way in
    # still has to work.
    from webapp.solutions_script import build_solutions_script

    script = build_solutions_script('S', _chain(), _pivot_assignment(insert_before=-1))
    assert 'check_pivot P1' in script


def test_pivots_are_counted_in_the_summary_total():
    from webapp.solutions_script import build_solutions_script

    script = build_solutions_script('S', _chain(), _pivot_assignment())
    # One chain step plus one pivot step.
    assert '"2"' in script or ' "2"' in script
