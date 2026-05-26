import pytest

from webapp import app_backend


def test_flow_optional_inputs_excluded_from_effective_inputs(monkeypatch: pytest.MonkeyPatch):
    """Optional inputs should never be treated as missing prerequisites.

    Specifically: if a plugin-level requires token matches an input field declared
    with required=False, it must not appear in the assignment's effective `inputs`.
    """

    fake_gen = {
        "id": "opt_consumer",
        "name": "Optional Consumer",
        "language": "python",
        "_source_name": "test",
        "inputs": [
            {"name": "Credential(user, password)", "required": False},
        ],
        "outputs": [],
    }

    def fake_flag_generators_from_enabled_sources():
        return [fake_gen], []

    def fake_flag_node_generators_from_enabled_sources():
        return [], []

    def fake_enabled_plugin_contracts_by_id():
        return {
            "opt_consumer": {
                "plugin_id": "opt_consumer",
                "plugin_type": "flag-generator",
                "version": "1.0",
                "requires": ["Credential(user, password)"],
                "produces": [],
                "inputs": {},
            }
        }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", fake_flag_generators_from_enabled_sources)
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", fake_flag_node_generators_from_enabled_sources)
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", fake_enabled_plugin_contracts_by_id)

    preview = {
        "seed": 1,
        "hosts": [{"node_id": "h1", "name": "host-1", "role": "Docker", "vulnerabilities": [{"name": "v1"}]}],
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "host_router_map": {},
        "r2r_links_preview": [],
    }
    chain_nodes = [{"id": "h1", "name": "host-1", "type": "docker", "is_vuln": True}]

    fas = app_backend._flow_compute_flag_assignments(preview, chain_nodes, "zz-test")
    assert len(fas) == 1
    a0 = fas[0]

    # Optional field is recorded as optional, but is not treated as an effective required input.
    assert "Credential(user, password)" in (a0.get("input_fields_optional") or [])
    assert "Credential(user, password)" not in (a0.get("inputs") or [])

    # Strict ordering validation must not fail due to that optional token.
    ok, errors = app_backend._flow_validate_chain_order_by_requires_produces(chain_nodes, fas, scenario_label="zz-test")
    assert ok, errors


def test_enrich_saved_assignments_refreshes_stale_required_input_metadata(monkeypatch: pytest.MonkeyPatch):
    fake_gen = {
        "id": "ssh_desktop_creds",
        "name": "Sample: SSH Desktop Credentials",
        "language": "python",
        "_source_name": "test",
        "inputs": [
            {"name": "seed", "required": True},
            {"name": "node_name", "required": True},
            {"name": "Credential(user, password)", "required": True},
        ],
        "outputs": [],
    }

    def fake_flag_generators_from_enabled_sources():
        return [], []

    def fake_flag_node_generators_from_enabled_sources():
        return [fake_gen], []

    def fake_enabled_plugin_contracts_by_id():
        return {
            "ssh_desktop_creds": {
                "plugin_id": "ssh_desktop_creds",
                "plugin_type": "flag-node-generator",
                "version": "1.0",
                "requires": ["Knowledge(ip)", "Credential(user, password)"],
                "produces": [{"artifact": "Flag(flag_id)"}],
                "inputs": {},
            }
        }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", fake_flag_generators_from_enabled_sources)
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", fake_flag_node_generators_from_enabled_sources)
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", fake_enabled_plugin_contracts_by_id)

    stale_assignments = [{
        "node_id": "n1",
        "id": "ssh_desktop_creds",
        "name": "Sample: SSH Desktop Credentials",
        "type": "flag-node-generator",
        "input_fields": ["seed", "node_name", "Credential(user, password)"],
        "input_fields_required": ["seed", "node_name"],
        "input_fields_optional": ["Credential(user, password)"],
        "requires": ["Knowledge(ip)"],
        "inputs": ["Knowledge(ip)", "seed", "node_name"],
        "outputs": [],
    }]
    chain_nodes = [{"id": "n1", "name": "node-1", "type": "docker"}]

    enriched = app_backend._flow_enrich_saved_flag_assignments(
        stale_assignments,
        chain_nodes,
        scenario_label="zz-test",
    )

    assert len(enriched) == 1
    assignment = enriched[0]
    assert "Credential(user, password)" in (assignment.get("input_fields_required") or [])
    assert "Credential(user, password)" not in (assignment.get("input_fields_optional") or [])
    assert "Credential(user, password)" in (assignment.get("requires") or [])
    assert "Credential(user, password)" in (assignment.get("inputs") or [])
