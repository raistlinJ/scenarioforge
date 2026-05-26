from webapp.flow_prepare_preview_helpers import build_generator_run_config


class _BackendStub:
    @staticmethod
    def _flow_synthesized_inputs():
        return {
            "seed",
            "seed_ts",
            "secret",
            "flag_prefix",
            "flag_seed",
            "Knowledge(ip)",
            "target_ip",
            "host_ip",
            "ip4",
            "ipv4",
            "node_name",
        }


class _TimeStub:
    @staticmethod
    def time():
        return 1_700_000_000.0


def _load_manifest() -> dict:
    return {
        "id": "optional_flag_input_generator",
        "inputs": [
            {"name": "seed", "required": False},
            {"name": "flag_prefix", "required": False},
            {"name": "Flag(flag_id)", "required": False},
        ],
        "requires": [],
    }


def test_manifest_fixture_marks_flag_input_optional():
    manifest = _load_manifest()
    inputs = {str(item.get("name") or "").strip(): item for item in manifest.get("inputs") or []}

    assert inputs["Flag(flag_id)"]["required"] is False


def test_build_generator_run_config_does_not_autothread_optional_upstream_flag():
    manifest = _load_manifest()

    _cfg_full, cfg, _inputs_mismatch, _gen_def = build_generator_run_config(
        {"id": "optional_flag_input_generator"},
        {"name": "docker-2"},
        preview={},
        preview_ip4="10.0.0.2",
        flow_context={"Flag(flag_id)": "FLAG{UPSTREAM_VALUE}"},
        gen_by_id={"optional_flag_input_generator": manifest},
        flow_default_generator_config=lambda _assignment: {
            "seed": "seed-value",
            "secret": "secret-value",
            "flag_prefix": "FLAG",
        },
        backend=_BackendStub(),
        time_module=_TimeStub(),
    )

    assert cfg["flag_prefix"] == "FLAG"
    assert cfg["node_name"] == "docker-2"
    assert cfg["target_ip"] == "10.0.0.2"
    assert "Flag(flag_id)" not in cfg


def test_build_generator_run_config_does_not_autothread_optional_file_path():
    manifest = {
        "id": "formatted_ini_database_config",
        "inputs": [
            {"name": "seed", "required": False},
            {"name": "flag_prefix", "required": False},
            {"name": "File(path)", "required": False},
            {"name": "Flag(flag_id)", "required": False},
        ],
        "requires": [],
    }

    _cfg_full, cfg, _inputs_mismatch, _gen_def = build_generator_run_config(
        {"id": "formatted_ini_database_config", "type": "flag-generator", "requires": []},
        {"name": "docker-12"},
        preview={},
        preview_ip4="10.230.11.14",
        flow_context={"File(path)": "/tmp/vulns/flag_node_generators_runs/flow-newscenario2/01_node/docker-compose.yml"},
        gen_by_id={"formatted_ini_database_config": manifest},
        flow_default_generator_config=lambda _assignment: {
            "seed": "seed-value",
            "secret": "secret-value",
            "flag_prefix": "FLAG",
        },
        backend=_BackendStub(),
        time_module=_TimeStub(),
    )

    assert "File(path)" not in cfg


def test_build_generator_run_config_autothreads_required_file_path():
    manifest = {
        "id": "node_generator",
        "inputs": [
            {"name": "seed", "required": False},
            {"name": "File(path)", "required": True},
        ],
        "requires": ["File(path)"],
    }

    upstream_file = "/tmp/vulns/flag_generators_runs/flow-demo/01_source/artifacts/service-profile.json"
    _cfg_full, cfg, _inputs_mismatch, _gen_def = build_generator_run_config(
        {"id": "node_generator", "type": "flag-node-generator", "requires": ["File(path)"]},
        {"name": "docker-13"},
        preview={},
        preview_ip4="10.230.11.13",
        flow_context={"File(path)": upstream_file},
        gen_by_id={"node_generator": manifest},
        flow_default_generator_config=lambda _assignment: {
            "seed": "seed-value",
            "secret": "secret-value",
            "flag_prefix": "FLAG",
        },
        backend=_BackendStub(),
        time_module=_TimeStub(),
    )

    assert cfg["File(path)"] == upstream_file