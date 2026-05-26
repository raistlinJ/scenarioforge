import json
from types import SimpleNamespace

from webapp import flow_prepare_preview_helpers as helpers


class _Logger:
    def info(self, *_args, **_kwargs):
        pass

    def warning(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass


class _Backend:
    app = SimpleNamespace(logger=_Logger())

    @staticmethod
    def _first_valid_ipv4(value):
        text = str(value or "").split("/", 1)[0]
        parts = text.split(".")
        if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            return text
        return ""


def test_invoke_generator_run_accepts_flag_file_under_service_directory(tmp_path):
    run_dir = tmp_path / "run"
    service_dir = run_dir / "service" / "database"
    service_dir.mkdir(parents=True)
    (service_dir / "customer_exports.sql").write_text("SELECT 'FLAG{demo}';\n", encoding="utf-8")
    (run_dir / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    manifest_path = run_dir / "outputs.json"
    manifest_path.write_text(
        json.dumps(
            {
                "outputs": {
                    "Flag(flag_id)": "FLAG{demo}",
                    "FlagDelivery(mode)": "file",
                    "FlagFile(path)": "database/customer_exports.sql",
                    "File(path)": "docker-compose.yml",
                    "Directory(host, path)": "service",
                    "Endpoint(path)": "/database/customer_exports.sql",
                }
            }
        ),
        encoding="utf-8",
    )

    def _local_runner(*_args, **_kwargs):
        return True, "ok", str(manifest_path), "", ""

    result = helpers.invoke_generator_run(
        "postgres_customer_dump",
        flow_run_remote=False,
        flow_remote_repo_dir=None,
        flow_core_cfg=None,
        flow_out_dir=str(run_dir),
        cfg={},
        assignment_type="flag-node-generator",
        gen_timeout_s=120,
        effective_injects=None,
        flow_try_run_generator_remote=None,
        flow_try_run_generator=_local_runner,
    )

    assert result["ok_run"] is True
    assert result["note"] == "ok"


def test_invoke_generator_run_does_not_verify_binary_format_as_path(tmp_path):
    run_dir = tmp_path / "run"
    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(parents=True)
    (artifacts_dir / "sensor_firmware_v3.img").write_bytes(b"FWR1demo")

    manifest_path = run_dir / "outputs.json"
    manifest_path.write_text(
        json.dumps(
            {
                "outputs": {
                    "Flag(flag_id)": "FLAG{demo}",
                    "FlagDelivery(mode)": "embedded",
                    "File(path)": "artifacts/sensor_firmware_v3.img",
                    "Checksum(sha256)": "abc123",
                    "Binary(format)": "firmware-image",
                    "Version(service)": "relay-sensor/3.4.7",
                }
            }
        ),
        encoding="utf-8",
    )

    def _local_runner(*_args, **_kwargs):
        return True, "ok", str(manifest_path), "", ""

    result = helpers.invoke_generator_run(
        "binary_firmware_config_blob",
        flow_run_remote=False,
        flow_remote_repo_dir=None,
        flow_core_cfg=None,
        flow_out_dir=str(run_dir),
        cfg={},
        assignment_type="flag-generator",
        gen_timeout_s=120,
        effective_injects=None,
        flow_try_run_generator_remote=None,
        flow_try_run_generator=_local_runner,
    )

    assert result["ok_run"] is True
    assert result["note"] == "ok"
    assert helpers.flow_should_verify_output_path("File(path)", "artifacts/sensor_firmware_v3.img") is True
    assert helpers.flow_should_verify_output_path("Binary(format)", "firmware-image") is False
    assert helpers.flow_should_verify_output_path("Archive(format)", "zip") is False
    assert helpers.flow_should_verify_output_path("Encoded(value)", "abc/def") is False
    assert helpers.flow_should_verify_output_path("BackupArchive(file)", "bundle.tar.gz") is True


def test_process_generator_outputs_renders_inject_hint_without_staging_path(tmp_path):
    run_dir = tmp_path / "run"
    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(parents=True)
    (artifacts_dir / "sensor_firmware_v3.img").write_bytes(b"FWR1demo")

    outputs = {
        "Flag(flag_id)": "FLAG{demo}",
        "FlagDelivery(mode)": "embedded",
        "File(path)": "artifacts/sensor_firmware_v3.img",
        "Checksum(sha256)": "abc123",
        "Binary(format)": "firmware-image",
    }
    assignment = {
        "type": "flag-generator",
        "inject_files": ["File(path)"],
        "hints": ["Inspect /flow_injects/{{OUTPUT.File(path):basename}} on docker-13 @ 10.230.11.15."],
        "hint": "Inspect /flow_injects/{{OUTPUT.File(path):basename}} on docker-13 @ 10.230.11.15.",
    }

    result = helpers.process_generator_outputs(
        assignment,
        outputs,
        ok_run=True,
        note="ok",
        manifest_path=None,
        flow_out_dir=str(run_dir),
        assignment_type="flag-generator",
        gen_def={},
        flow_run_remote=False,
        preview_ip4="10.230.11.14",
        node_id="docker-12",
        generator_id="binary_firmware_config_blob",
        flow_context={},
        seen_flag_values=set(),
        redact_kv_for_ui=lambda value: value,
        apply_outputs_to_hint_text=helpers.apply_outputs_to_hint_text,
        apply_node_placeholders=helpers.apply_node_placeholders,
        backend=_Backend(),
    )

    assert result["ok_run"] is True
    assert assignment["hint"] == "Inspect /flow_injects/sensor_firmware_v3.img on docker-13 @ 10.230.11.15."
    assert str(run_dir) not in assignment["hint"]


def test_process_generator_outputs_accepts_remote_compose_paths():
    outputs = {
        "Flag(flag_id)": "FLAG{demo}",
        "FlagDelivery(mode)": "file",
        "FlagFile(path)": "/tmp/vulns/flag_node_generators_runs/flow-newscenario2/01_postgres_customer_dump_docker-13/service/database/customer_exports.sql",
        "File(path)": "/tmp/vulns/flag_node_generators_runs/flow-newscenario2/01_postgres_customer_dump_docker-13/docker-compose.yml",
        "Directory(host, path)": "/tmp/vulns/flag_node_generators_runs/flow-newscenario2/01_postgres_customer_dump_docker-13/service",
        "Endpoint(path)": "/database/customer_exports.sql",
    }
    assignment = {"hints": [], "hint": ""}

    result = helpers.process_generator_outputs(
        assignment,
        outputs,
        ok_run=True,
        note="ok",
        manifest_path="/tmp/vulns/flag_node_generators_runs/flow-newscenario2/01_postgres_customer_dump_docker-13/outputs.json",
        flow_out_dir="/tmp/vulns/flag_node_generators_runs/flow-newscenario2/01_postgres_customer_dump_docker-13",
        assignment_type="flag-node-generator",
        gen_def={"compose": {"file": "docker-compose.yml"}},
        flow_run_remote=True,
        preview_ip4="10.0.225.4",
        node_id="18",
        generator_id="postgres_customer_dump",
        flow_context={},
        seen_flag_values=set(),
        redact_kv_for_ui=lambda value: value,
        apply_outputs_to_hint_text=lambda text, _outputs: text,
        apply_node_placeholders=lambda text, **_kwargs: text,
        backend=_Backend(),
    )

    assert result["ok_run"] is True
    assert result["note"] == "ok"
    assert assignment["resolved_outputs"]["FlagFile(path)"].endswith("/service/database/customer_exports.sql")


def test_symbolic_file_inject_expands_from_current_outputs_not_prior_compose(tmp_path):
    prior_run = tmp_path / "prior-node-generator"
    prior_run.mkdir()
    (prior_run / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (prior_run / "outputs.json").write_text(
        json.dumps({"outputs": {"File(path)": "docker-compose.yml"}}),
        encoding="utf-8",
    )

    current_run = tmp_path / "current-formatted-generator"
    artifacts_dir = current_run / "artifacts"
    artifacts_dir.mkdir(parents=True)
    (artifacts_dir / "service-profile.json").write_text('{"flag":"FLAG{demo}"}\n', encoding="utf-8")
    manifest_path = current_run / "outputs.json"
    manifest_path.write_text(
        json.dumps(
            {
                "outputs": {
                    "Flag(flag_id)": "FLAG{demo}",
                    "FlagDelivery(mode)": "file",
                    "FlagFile(path)": "artifacts/service-profile.json",
                    "File(path)": "artifacts/service-profile.json",
                    "Format(name)": "json",
                    "APIKey(service)": "ak_demo",
                }
            }
        ),
        encoding="utf-8",
    )

    assignment = {"type": "flag-generator", "requires": [], "inject_files": ["File(path)"]}
    effective = helpers.resolve_and_stage_inject_files(
        assignment,
        artifact_context={},
        flow_context={},
        created_run_dirs=[str(prior_run), str(current_run)],
        flow_out_dir=str(current_run),
        flow_run_remote=True,
        run_index=2,
        backend=_Backend(),
    )

    assert effective is None
    assert assignment["inject_files"] == ["File(path)"]

    outputs = json.loads(manifest_path.read_text(encoding="utf-8"))["outputs"]
    processed = helpers.process_generator_outputs(
        assignment,
        outputs,
        ok_run=True,
        note="ok",
        manifest_path=str(manifest_path),
        flow_out_dir=str(current_run),
        assignment_type="flag-generator",
        gen_def={},
        flow_run_remote=False,
        preview_ip4="10.0.0.5",
        node_id="12",
        generator_id="formatted_json_profile_secret",
        flow_context={},
        seen_flag_values=set(),
        redact_kv_for_ui=lambda value: value,
        apply_outputs_to_hint_text=lambda text, _outputs: text,
        apply_node_placeholders=lambda text, **_kwargs: text,
        backend=_Backend(),
    )
    assert processed["ok_run"] is True

    finalized = helpers.finalize_generator_assignment_metadata(
        assignment,
        {},
        flow_out_dir=str(current_run),
        flow_run_remote=False,
        generator_catalog="repo",
        generator_id="formatted_json_profile_secret",
        assignment_type="flag-generator",
        cfg={},
        declared_output_keys=[],
        actual_output_keys=processed.get("actual_output_keys") or [],
        mismatch={},
        inputs_mismatch={},
        manifest_path=str(manifest_path),
        ok_run=bool(processed.get("ok_run")),
        note=str(processed.get("note") or ""),
        backend=_Backend(),
    )

    assert assignment["inject_files"] == ["service-profile.json"]
    assert "docker-compose.yml" not in json.dumps(assignment)
