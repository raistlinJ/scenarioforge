import pytest

from webapp import app_backend
from webapp.flow_prepare_preview_helpers import build_generator_run_config
from webapp.flow_prepare_preview_helpers import materialize_hint_file


def test_flow_first_optional_credential_is_chain_supplied(monkeypatch: pytest.MonkeyPatch):
    """A first-step optional credential must be made explicit and hinted.

    If a first generator can otherwise auto-generate credentials internally,
    participants would not know them. Flow supplies a deterministic credential
    instead and makes the field required in the sequence metadata.
    """

    fake_gen = {
        "id": "git-deploy-key-repo",
        "name": "Git Deploy Key Repo",
        "language": "python",
        "_source_name": "test",
        "inputs": [
            {"name": "Credential(user, password)", "required": False, "flow_supply_when_first": True},
        ],
        "outputs": [],
    }

    def fake_flag_generators_from_enabled_sources():
        return [fake_gen], []

    def fake_flag_node_generators_from_enabled_sources():
        return [], []

    def fake_enabled_plugin_contracts_by_id():
        return {
            "git-deploy-key-repo": {
                "plugin_id": "git-deploy-key-repo",
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

    assert "Credential(user, password)" in (a0.get("input_fields_required") or [])
    assert "Credential(user, password)" not in (a0.get("input_fields_optional") or [])
    assert "Credential(user, password)" in (a0.get("inputs") or [])
    assert "Credential(user, password)" in (a0.get("chain_supplied_inputs") or [])
    supplied = (a0.get("config_overrides") or {}).get("Credential(user, password)")
    assert isinstance(supplied, str) and ":" in supplied
    assert supplied == (a0.get("resolved_inputs") or {}).get("Credential(user, password)")
    assert any(supplied.replace(":", " / ") in str(hint) for hint in (a0.get("hints") or []))

    # Strict ordering validation must not fail due to the chain-supplied token.
    ok, errors = app_backend._flow_validate_chain_order_by_requires_produces(chain_nodes, fas, scenario_label="zz-test")
    assert ok, errors


def test_flow_first_marked_non_credential_input_is_chain_supplied(monkeypatch: pytest.MonkeyPatch):
    fake_gen = {
        "id": "invite-code-gate",
        "name": "Invite Code Gate",
        "language": "python",
        "_source_name": "test",
        "inputs": [
            {"name": "unlock_code", "type": "string", "required": True, "flow_supply_when_first": True},
        ],
        "outputs": [],
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([fake_gen], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {
        "invite-code-gate": {
            "plugin_id": "invite-code-gate",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": [],
            "produces": [],
            "inputs": {},
        }
    })

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
    assignment = fas[0]

    assert "unlock_code" in (assignment.get("input_fields_required") or [])
    assert "unlock_code" in (assignment.get("inputs") or [])
    assert "unlock_code" in (assignment.get("chain_supplied_inputs") or [])
    supplied = (assignment.get("config_overrides") or {}).get("unlock_code")
    assert isinstance(supplied, str) and supplied.startswith("code_")
    assert supplied == (assignment.get("resolved_inputs") or {}).get("unlock_code")
    assert any(f"unlock_code={supplied}" in str(hint) for hint in (assignment.get("hints") or []))

    ok, errors = app_backend._flow_validate_chain_order_by_requires_produces(chain_nodes, fas, scenario_label="zz-test")
    assert ok, errors


def test_flow_parallel_start_optional_credential_is_chain_supplied(monkeypatch: pytest.MonkeyPatch):
    fake_gen = {
        "id": "git-deploy-key-repo",
        "name": "Git Deploy Key Repo",
        "language": "python",
        "_source_name": "test",
        "inputs": [
            {"name": "Credential(user, password)", "required": False, "flow_supply_when_first": True},
        ],
        "outputs": [],
    }

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([fake_gen], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {
        "git-deploy-key-repo": {
            "plugin_id": "git-deploy-key-repo",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": ["Credential(user, password)"],
            "produces": [],
            "inputs": {},
        }
    })

    preview = {
        "seed": 1,
        "hosts": [
            {"node_id": "h1", "name": "host-1", "role": "Docker", "vulnerabilities": [{"name": "v1"}]},
            {"node_id": "h2", "name": "host-2", "role": "Docker", "vulnerabilities": [{"name": "v2"}]},
        ],
        "routers": [],
        "switches": [],
        "switches_detail": [],
        "host_router_map": {},
        "r2r_links_preview": [],
    }
    chain_nodes = [
        {"id": "h1", "name": "host-1", "type": "docker", "is_vuln": True},
        {"id": "h2", "name": "host-2", "type": "docker", "is_vuln": True},
    ]

    fas = app_backend._flow_compute_flag_assignments(preview, chain_nodes, "zz-test")
    assert len(fas) == 2

    first, second = fas
    assert "Credential(user, password)" in (first.get("input_fields_required") or [])
    assert "Credential(user, password)" in (first.get("chain_supplied_inputs") or [])
    assert "Credential(user, password)" in (second.get("input_fields_required") or [])
    assert "Credential(user, password)" in (second.get("chain_supplied_inputs") or [])
    assert second.get("chain_supplied_sequence_index") == 2
    assert second.get("chain_supplied_requirement_label") == "Seq 2 required"
    assert any("Sequence 2 required supplied input" in str(hint) for hint in (second.get("hints") or []))


def test_flow_dependent_non_start_optional_credential_stays_optional():
    gen_defs = {
        "producer": {
            "id": "producer",
            "inputs": [],
        },
        "git-deploy-key-repo": {
            "id": "git-deploy-key-repo",
            "inputs": [
                {"name": "Credential(user, password)", "required": False, "flow_supply_when_first": True},
            ],
        },
    }
    assignments = [
        {
            "node_id": "h1",
            "id": "producer",
            "produces": ["Token(service)"],
            "outputs": ["Token(service)"],
        },
        {
            "node_id": "h2",
            "id": "git-deploy-key-repo",
            "requires": ["Token(service)"],
            "inputs": ["Token(service)"],
            "input_fields": ["Credential(user, password)"],
            "input_fields_optional": ["Credential(user, password)"],
            "input_fields_required": [],
        },
    ]

    enriched = app_backend._flow_apply_first_step_chain_supplied_inputs_to_assignments(
        assignments,
        [{"id": "h1"}, {"id": "h2"}],
        scenario_label="zz-test",
        gen_defs_by_id=gen_defs,
    )

    second = enriched[1]
    assert "Credential(user, password)" in (second.get("input_fields_optional") or [])
    assert "Credential(user, password)" not in (second.get("chain_supplied_inputs") or [])
    assert not second.get("chain_supplied_input_hints")


def test_flow_non_deploy_key_optional_credential_stays_optional(monkeypatch: pytest.MonkeyPatch):
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

    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([fake_gen], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {
        "opt_consumer": {
            "plugin_id": "opt_consumer",
            "plugin_type": "flag-generator",
            "version": "1.0",
            "requires": ["Credential(user, password)"],
            "produces": [],
            "inputs": {},
        }
    })

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
    assignment = fas[0]
    assert "Credential(user, password)" in (assignment.get("input_fields_optional") or [])
    assert "Credential(user, password)" not in (assignment.get("inputs") or [])
    assert not assignment.get("chain_supplied_inputs")


def test_chain_supplied_input_hint_materializes_with_inject_files(tmp_path):
    run_dir = tmp_path / "flow-run"
    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(parents=True)

    hint = "Sequence 1 required supplied input: Credential(user, password)=user_demo / pass_demo."
    assignment = {
        "hints": [hint],
        "chain_supplied_input_hints": [hint],
        "inject_files": ["flag.txt -> /tmp"],
    }

    materialize_hint_file(
        assignment,
        flow_out_dir=str(run_dir),
        flow_run_remote=False,
        flow_core_cfg=None,
        backend=app_backend,
    )

    hint_path = artifacts_dir / "hint.txt"
    assert hint_path.exists()
    assert hint in hint_path.read_text(encoding="utf-8")


def test_flow_first_hints_include_low_hint_and_chain_supplied_input_hint():
    assignment = {
        "hint_levels": {"low": ["Target: 10.0.0.2"], "medium": [], "high": []},
        "chain_supplied_input_hints": ["Sequence 1 required supplied input: unlock_code=code_demo."],
        "hints": ["Target: 10.0.0.2"],
        "hint": "Target: 10.0.0.2",
    }

    assert app_backend._flow_first_hints_from_assignments([assignment]) == [
        "Target: 10.0.0.2",
        "Sequence 1 required supplied input: unlock_code=code_demo.",
    ]


def test_chain_supplied_credential_reaches_generator_run_config():
    assignment = {
        "id": "git-deploy-key-repo",
        "input_fields_required": ["Credential(user, password)"],
        "chain_supplied_input_values": {"Credential(user, password)": "user_demo:pass_demo"},
    }
    manifest = {
        "id": "git-deploy-key-repo",
        "inputs": [
            {"name": "Credential(user, password)", "required": False, "flow_supply_when_first": True},
        ],
        "requires": [],
    }

    _cfg_full, cfg, mismatch, _gen_def = build_generator_run_config(
        assignment,
        {"name": "docker-1"},
        preview={},
        preview_ip4="10.0.0.2",
        flow_context={},
        gen_by_id={"git-deploy-key-repo": manifest},
        flow_default_generator_config=lambda _assignment: {"seed": "seed-value"},
        backend=app_backend,
    )

    assert cfg["Credential(user, password)"] == "user_demo:pass_demo"
    assert mismatch.get("ok") is True


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
