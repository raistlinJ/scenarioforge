import hashlib
import io
import json
import xml.etree.ElementTree as ET
import zipfile

import pytest

from webapp.reproduction_bundle import (
    _safe_materialization_target,
    import_scenario_file,
)
from webapp import reproduction_bundle as reproduction_bundle_module
from webapp.app_backend import app
from webapp import app_backend as backend


def _bundle(tmp_path, *, artifact_bytes=b"FLAG-123\n"):
    source_path = "/tmp/vulns/flag_generators_runs/demo"
    root = ET.Element("Scenarios")
    ET.SubElement(
        root,
        "CoreConnection",
        {
            "ssh_host": "source-core.invalid",
            "ssh_username": "source-user",
            "ssh_password": "source-secret",
        },
    )
    scenario = ET.SubElement(root, "Scenario", {"name": "portable-demo"})
    editor = ET.SubElement(scenario, "ScenarioEditor")
    ET.SubElement(editor, "BaseScenario", {"filepath": ""})
    sequencing = ET.SubElement(editor, "FlagSequencing")
    state = ET.SubElement(sequencing, "FlowState")
    state.text = json.dumps(
        {
            "scenario": "portable-demo",
            "chain": [{"id": "7"}],
            "flag_assignments": [
                {
                    "id": "demo-generator",
                    "node_id": "7",
                    "artifacts_dir": source_path,
                    "outputs_manifest": f"{source_path}/outputs.json",
                    "resolved_outputs": {"Flag(flag_id)": "FLAG-123"},
                }
            ],
        }
    )
    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    manifest = {
        "format": "scenarioforge-reproduction",
        "version": 1,
        "fidelity": "portable-artifacts",
        "flow": {"scenario": "portable-demo"},
        "scenario": {
            "path": "scenario.xml",
            "sha256": hashlib.sha256(xml_bytes).hexdigest(),
        },
        "artifact_sources": [
            {
                "source_path": source_path,
                "archive_path": "artifacts/001",
                "bundled": True,
                "files": [
                    {
                        "path": "flag.txt",
                        "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                        "size": len(artifact_bytes),
                        "mode": 0o600,
                    }
                ],
            }
        ],
    }
    bundle = tmp_path / "portable.scenarioforge.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("scenario.xml", xml_bytes)
        archive.writestr("artifacts/001/flag.txt", artifact_bytes)
        archive.writestr("scenarioforge-reproduction.json", json.dumps(manifest))
    return bundle, source_path


def test_import_auto_detects_bundle_restores_artifacts_and_rewrites_xml(tmp_path):
    bundle, source_path = _bundle(tmp_path)
    upload_root = tmp_path / "uploads"

    imported = import_scenario_file(str(bundle), str(upload_root))

    assert imported.kind == "reproduction-bundle"
    assert imported.fidelity == "portable-artifacts"
    assert imported.bundled_artifact_sources == 1
    root = ET.parse(imported.xml_path).getroot()
    imported_core = root.find("CoreConnection")
    assert imported_core is not None
    assert imported_core.get("ssh_host") == "source-core.invalid"
    # Credentials are carried through import: downstream SSH operations
    # (Materialize, Validate) open connections from this XML, and a stripped
    # password left them stalling on an authentication they could not finish.
    assert imported_core.get("ssh_password") == "source-secret"
    flow = json.loads(root.find(".//FlowState").text)
    restored_dir = flow["reproduction_artifact_sources"][0]["restored_path"]
    assert restored_dir.startswith(str(upload_root.resolve()))
    assert open(f"{restored_dir}/flag.txt", "rb").read() == b"FLAG-123\n"
    assert flow["reproduction_artifact_sources"][0]["target_path"] == source_path
    assert flow["flag_assignments"][0]["artifacts_dir"] == source_path
    assert flow["flag_assignments"][0]["outputs_manifest"] == f"{source_path}/outputs.json"


def test_import_auto_detects_plain_xml_regardless_of_extension(tmp_path):
    source = tmp_path / "scenario.data"
    source.write_text('<Scenarios><Scenario name="demo" /></Scenarios>', encoding="utf-8")

    imported = import_scenario_file(str(source), str(tmp_path / "uploads"))

    assert imported.kind == "xml"
    assert imported.xml_path == str(source.resolve())


def test_import_rejects_bundle_path_traversal(tmp_path):
    bundle, _ = _bundle(tmp_path)
    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(unsafe, "w") as target:
        for info in source.infolist():
            target.writestr(info.filename, source.read(info.filename))
        target.writestr("../escape.txt", b"nope")

    with pytest.raises(ValueError, match="unsafe bundle member"):
        import_scenario_file(str(unsafe), str(tmp_path / "uploads"))


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("/tmp/vulns/flag_generators_runs/demo", "/tmp/vulns/flag_generators_runs/demo"),
        ("/tmp/vulns/flag_node_generators_runs/demo/", "/tmp/vulns/flag_node_generators_runs/demo"),
        ("/tmp/vulns/flag_generators_runs/../escape", ""),
        ("/tmp/vulns/flag_generators_runs/demo/../../escape", ""),
        ("/tmp/vulns/flag_generators_runs", ""),
        ("/tmp/vulns/other/demo", ""),
    ],
)
def test_materialization_target_is_confined_to_artifact_run_roots(target, expected):
    assert _safe_materialization_target(target) == expected


def test_load_xml_automatically_materializes_bundled_artifacts(tmp_path, monkeypatch):
    bundle, source_path = _bundle(tmp_path)
    upload_root = tmp_path / "uploads"
    put_calls = []

    class FakeSftp:
        def put(self, local, remote):
            put_calls.append((local, remote))

        def chmod(self, *_args):
            return None

        def close(self):
            return None

    class FakeClient:
        def __init__(self):
            self.sftp = FakeSftp()

        def open_sftp(self):
            return self.sftp

        def close(self):
            return None

    monkeypatch.setitem(app.config, "UPLOAD_FOLDER", str(upload_root))
    selected_configs = []
    monkeypatch.setattr(backend, "_webui_runtime_mode", lambda: "vm")
    monkeypatch.setattr(
        backend,
        "_core_config_from_xml_path",
        lambda *_args, **_kwargs: pytest.fail("VM import must not read credentials from imported XML"),
    )
    monkeypatch.setattr(
        backend,
        "_core_backend_defaults",
        lambda **_kwargs: {
            "ssh_host": "core.local",
            "ssh_username": "core",
            "ssh_password": "runtime-secret",
        },
    )
    monkeypatch.setattr(backend, "_require_core_ssh_credentials", lambda cfg: cfg)
    monkeypatch.setattr(
        backend,
        "_open_ssh_client",
        lambda cfg: selected_configs.append(dict(cfg)) or FakeClient(),
    )
    monkeypatch.setattr(backend, "_remote_mkdirs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, "_flow_assignment_missing_remote_paths", lambda *_args, **_kwargs: [])

    with app.test_client() as client:
        login = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login.status_code in (302, 303)
        response = client.post(
            "/load_xml",
            data={
                "scenarios_xml": (
                    io.BytesIO(bundle.read_bytes()),
                    "portable.scenarioforge.zip",
                ),
                "import_progress_id": "vmimportprogress1",
            },
            content_type="multipart/form-data",
        )
        progress_response = client.get("/api/scenario-import-progress/vmimportprogress1")

    assert response.status_code == 200
    assert len(put_calls) == 1
    assert put_calls[0][1] == f"{source_path}/flag.txt"
    assert len(selected_configs) == 1
    assert selected_configs[0]["ssh_host"] == "core.local"
    assert selected_configs[0]["ssh_username"] == "core"
    assert selected_configs[0]["ssh_password"] == "runtime-secret"
    assert b"automatically materialized" in response.data
    imported_xmls = list(upload_root.glob("*.xml"))
    assert imported_xmls
    rebound_root = ET.parse(imported_xmls[-1]).getroot()
    rebound_core = rebound_root.find("CoreConnection")
    assert rebound_core is not None
    assert rebound_core.get("ssh_host") == "core.local"
    assert rebound_core.get("ssh_username") == "core"
    assert "ssh_password" not in rebound_core.attrib
    scenario_core = rebound_root.find("./Scenario/ScenarioEditor/HardwareInLoop/CoreConnection")
    assert scenario_core is not None
    assert scenario_core.get("ssh_host") == "core.local"
    assert "ssh_password" not in scenario_core.attrib
    assert "source-core.invalid" not in imported_xmls[-1].read_text(encoding="utf-8")
    progress = progress_response.get_json()
    assert progress["status"] == "complete"
    assert progress["percent"] == 100
    steps = [event["step"] for event in progress["events"]]
    assert "Detecting scenario file type" in steps
    assert "Selecting materialization mode" in steps
    assert "Resolving CORE VM credentials" in steps
    assert "Connecting to CORE VM" in steps
    assert "Materializing bundled artifacts on CORE VM" in steps
    assert "Verifying CORE VM artifact paths" in steps
    assert steps[-1] == "Import complete"


def test_native_import_materializes_locally_without_resolving_credentials(tmp_path, monkeypatch):
    bundle, _source_path = _bundle(tmp_path)
    upload_root = tmp_path / "uploads"
    local_calls = []
    core_default_calls = []
    original_core_backend_defaults = backend._core_backend_defaults

    def tracked_core_backend_defaults(**kwargs):
        core_default_calls.append(dict(kwargs))
        assert kwargs.get("include_password") is not True, (
            "native import must not resolve secret SSH credentials"
        )
        return original_core_backend_defaults(**kwargs)

    monkeypatch.setitem(app.config, "UPLOAD_FOLDER", str(upload_root))
    monkeypatch.setattr(backend, "_webui_runtime_mode", lambda: "native")
    monkeypatch.setattr(backend, "_webui_local_mode", lambda: True)
    monkeypatch.setattr(backend, "_webui_running_in_docker", lambda: False)
    monkeypatch.setattr(
        backend,
        "_core_backend_defaults",
        tracked_core_backend_defaults,
    )
    monkeypatch.setattr(
        backend,
        "_open_ssh_client",
        lambda _cfg: pytest.fail("native import must not open SSH"),
    )
    monkeypatch.setattr(
        reproduction_bundle_module,
        "restore_bundled_artifacts_locally",
        lambda **kwargs: local_calls.append(kwargs) or 1,
    )

    with app.test_client() as client:
        login = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login.status_code in (302, 303)
        response = client.post(
            "/load_xml",
            data={
                "scenarios_xml": (
                    io.BytesIO(bundle.read_bytes()),
                    "portable.scenarioforge.zip",
                ),
                "import_progress_id": "nativeimportprogress1",
            },
            content_type="multipart/form-data",
        )
        progress_response = client.get("/api/scenario-import-progress/nativeimportprogress1")

    assert response.status_code == 200
    assert len(local_calls) == 1
    assert core_default_calls
    assert all(call.get("include_password") is not True for call in core_default_calls)
    assert local_calls[0]["upload_root"] == str(upload_root)
    assert b"automatically materialized" in response.data
    progress = progress_response.get_json()
    steps = [event["step"] for event in progress["events"]]
    assert "Selecting materialization mode" in steps
    assert "Resolving CORE VM credentials" not in steps
    selecting = [event for event in progress["events"] if event["step"] == "Selecting materialization mode"]
    assert selecting and "Native local CORE" in selecting[-1]["detail"]
    assert steps[-1] == "Import complete"


def test_native_remote_import_uses_one_time_prompt_password(tmp_path, monkeypatch):
    bundle, source_path = _bundle(tmp_path)
    upload_root = tmp_path / "uploads"
    selected_configs = []

    class FakeSftp:
        def put(self, _local, _remote):
            return None

        def chmod(self, *_args):
            return None

        def close(self):
            return None

    class FakeClient:
        def open_sftp(self):
            return FakeSftp()

        def close(self):
            return None

    def runtime_core_defaults(*, include_password=True):
        return {
            "host": "10.0.0.50",
            "ssh_host": "10.0.0.50",
            "ssh_username": "core",
        }

    monkeypatch.setitem(app.config, "UPLOAD_FOLDER", str(upload_root))
    monkeypatch.setattr(backend, "_webui_runtime_mode", lambda: "native")
    monkeypatch.setattr(backend, "_webui_local_mode", lambda: False)
    monkeypatch.setattr(backend, "_webui_running_in_docker", lambda: False)
    monkeypatch.setattr(backend, "_core_backend_defaults", runtime_core_defaults)
    monkeypatch.setattr(backend, "_require_core_ssh_credentials", lambda cfg: cfg)
    monkeypatch.setattr(
        backend,
        "_open_ssh_client",
        lambda cfg: selected_configs.append(dict(cfg)) or FakeClient(),
    )
    monkeypatch.setattr(backend, "_remote_mkdirs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, "_flow_assignment_missing_remote_paths", lambda *_args, **_kwargs: [])

    with app.test_client() as client:
        login = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login.status_code in (302, 303)
        response = client.post(
            "/load_xml",
            data={
                "scenarios_xml": (
                    io.BytesIO(bundle.read_bytes()),
                    "portable.scenarioforge.zip",
                ),
                "import_progress_id": "nativeremoteprogress1",
                "core_ssh_password": "prompt-secret",
            },
            content_type="multipart/form-data",
        )
        progress_response = client.get("/api/scenario-import-progress/nativeremoteprogress1")

    assert response.status_code == 200
    assert len(selected_configs) == 1
    assert selected_configs[0]["host"] == "10.0.0.50"
    assert selected_configs[0]["ssh_host"] == "10.0.0.50"
    assert selected_configs[0]["ssh_username"] == "core"
    assert selected_configs[0]["ssh_password"] == "prompt-secret"
    progress = progress_response.get_json()
    assert "prompt-secret" not in json.dumps(progress)
    steps = [event["step"] for event in progress["events"]]
    assert "Resolving remote CORE host credentials" in steps
    assert "Connecting to remote CORE host" in steps
    assert "Materializing bundled artifacts on remote CORE host" in steps
    assert progress["status"] == "complete"
    assert source_path.endswith("/demo")


def test_import_requirements_request_password_for_remote_destination(tmp_path, monkeypatch):
    monkeypatch.setattr(backend, "_webui_runtime_mode", lambda: "vm")
    monkeypatch.setattr(
        backend,
        "_core_backend_defaults",
        lambda **_kwargs: {
            "ssh_host": "core.local",
            "ssh_username": "core",
            "ssh_password": "",
        },
    )

    with app.test_client() as client:
        login = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login.status_code in (302, 303)
        response = client.get("/api/scenario-import-requirements")

    assert response.status_code == 200
    requirements = response.get_json()
    assert requirements["ok"] is True
    assert requirements["runtime_mode"] == "vm"
    assert requirements["transport"] == "ssh"
    assert requirements["destination_label"] == "CORE VM"
    assert requirements["password_required"] is True
    assert requirements["connection"]["ssh_host"] == "core.local"
    assert requirements["connection"]["ssh_username"] == "core"
    assert requirements["connection"]["core_host"] == "127.0.0.1"
    assert requirements["connection"]["core_port"] == 50051
    assert {item["field"] for item in requirements["missing_configuration"]} == {"ssh_password"}


def test_import_requirements_native_local_never_resolve_secret_credentials(monkeypatch):
    original_defaults = backend._core_backend_defaults

    def public_defaults_only(**kwargs):
        assert kwargs.get("include_password") is False
        return original_defaults(include_password=False)

    monkeypatch.setattr(backend, "_webui_runtime_mode", lambda: "native")
    monkeypatch.setattr(backend, "_webui_local_mode", lambda: True)
    monkeypatch.setattr(backend, "_webui_running_in_docker", lambda: False)
    monkeypatch.setattr(backend, "_core_backend_defaults", public_defaults_only)
    monkeypatch.setattr(
        backend,
        "_select_latest_core_secret_record",
        lambda _scenario=None: pytest.fail("native-local preflight must not load an access secret"),
    )

    with app.test_client() as client:
        login = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login.status_code in (302, 303)
        response = client.get("/api/scenario-import-requirements")

    requirements = response.get_json()
    assert requirements["transport"] == "local"
    assert requirements["password_required"] is False
    assert requirements["missing_configuration"] == []


def test_import_requirements_use_latest_validated_access_profile(monkeypatch):
    monkeypatch.setattr(backend, "_webui_runtime_mode", lambda: "native")
    monkeypatch.setattr(backend, "_webui_local_mode", lambda: False)
    monkeypatch.setattr(backend, "_webui_running_in_docker", lambda: False)
    monkeypatch.setattr(
        backend,
        "_core_backend_defaults",
        lambda **_kwargs: {
            "host": "10.0.0.50",
            "port": 50051,
            "ssh_host": "10.0.0.50",
            "ssh_port": 22,
            "ssh_username": "",
            "ssh_password": "",
        },
    )
    monkeypatch.setattr(
        backend,
        "_select_latest_core_secret_record",
        lambda _scenario=None: {
            "identifier": "profile-1",
            "host": "10.0.0.60",
            "port": 50052,
            "ssh_host": "10.0.0.60",
            "ssh_port": 2222,
            "ssh_username": "profile-user",
            "ssh_password_plain": "stored-secret",
            "vm_name": "Validated CORE",
        },
    )

    with app.test_client() as client:
        login = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login.status_code in (302, 303)
        response = client.get("/api/scenario-import-requirements")

    requirements = response.get_json()
    assert requirements["password_required"] is False
    assert requirements["missing_configuration"] == []
    assert requirements["profile"] == {
        "id": "profile-1",
        "label": "Validated CORE",
        "validated": True,
    }
    assert requirements["connection"]["core_host"] == "10.0.0.60"
    assert requirements["connection"]["core_port"] == 50052
    assert requirements["connection"]["ssh_host"] == "10.0.0.60"
    assert requirements["connection"]["ssh_port"] == 2222
    assert requirements["connection"]["ssh_username"] == "profile-user"


def test_import_connection_test_validates_explicit_native_remote_access(monkeypatch):
    selected_configs = []
    saved_profiles = []

    class FakeSftp:
        def close(self):
            return None

    class FakeClient:
        def open_sftp(self):
            return FakeSftp()

        def close(self):
            return None

    monkeypatch.setattr(backend, "_webui_runtime_mode", lambda: "native")
    monkeypatch.setattr(backend, "_webui_local_mode", lambda: False)
    monkeypatch.setattr(backend, "_webui_running_in_docker", lambda: False)
    monkeypatch.setattr(backend, "_core_backend_defaults", lambda **_kwargs: {})
    monkeypatch.setattr(backend, "_select_latest_core_secret_record", lambda _scenario=None: None)
    monkeypatch.setattr(backend, "_require_core_ssh_credentials", lambda cfg: cfg)
    monkeypatch.setattr(
        backend,
        "_open_ssh_client",
        lambda cfg: selected_configs.append(dict(cfg)) or FakeClient(),
    )
    monkeypatch.setattr(
        backend,
        "_save_core_credentials",
        lambda payload: saved_profiles.append(dict(payload)) or {
            "identifier": "saved-import-profile",
            "ssh_host": payload.get("ssh_host"),
        },
    )

    connection = {
        "core_host": "10.0.0.70",
        "core_port": 50051,
        "ssh_host": "10.0.0.70",
        "ssh_port": 2222,
        "ssh_username": "native-user",
        "ssh_password": "one-time-secret",
        "venv_bin": "/opt/core/venv/bin",
    }
    with app.test_client() as client:
        login = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login.status_code in (302, 303)
        response = client.post(
            "/api/scenario-import-connection/test",
            json={"connection": connection, "save_profile": True},
        )

    assert response.status_code == 200
    assert response.get_json()["message"] == "SSH and SFTP access validated."
    assert response.get_json()["profile_saved"] is True
    assert response.get_json()["profile"]["id"] == "saved-import-profile"
    assert len(selected_configs) == 1
    assert selected_configs[0]["host"] == "10.0.0.70"
    assert selected_configs[0]["port"] == 50051
    assert selected_configs[0]["ssh_host"] == "10.0.0.70"
    assert selected_configs[0]["ssh_port"] == 2222
    assert selected_configs[0]["ssh_username"] == "native-user"
    assert selected_configs[0]["ssh_password"] == "one-time-secret"
    assert len(saved_profiles) == 1
    assert saved_profiles[0]["ssh_password"] == "one-time-secret"


def test_vm_import_continues_and_reports_when_runtime_credentials_are_missing(tmp_path, monkeypatch):
    bundle, _source_path = _bundle(tmp_path)
    upload_root = tmp_path / "uploads"

    monkeypatch.setitem(app.config, "UPLOAD_FOLDER", str(upload_root))
    monkeypatch.setattr(backend, "_webui_runtime_mode", lambda: "vm")
    monkeypatch.setattr(
        backend,
        "_core_backend_defaults",
        lambda **_kwargs: {"ssh_host": "core.local", "ssh_username": "core"},
    )
    monkeypatch.setattr(
        backend,
        "_require_core_ssh_credentials",
        lambda _cfg: (_ for _ in ()).throw(RuntimeError("SSH password is required")),
    )
    monkeypatch.setattr(
        backend,
        "_open_ssh_client",
        lambda _cfg: pytest.fail("connection must not be attempted without credentials"),
    )

    with app.test_client() as client:
        login = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login.status_code in (302, 303)
        response = client.post(
            "/load_xml",
            data={
                "scenarios_xml": (
                    io.BytesIO(bundle.read_bytes()),
                    "portable.scenarioforge.zip",
                ),
                "import_progress_id": "missingcredentials1",
            },
            content_type="multipart/form-data",
        )
        progress_response = client.get("/api/scenario-import-progress/missingcredentials1")

    assert response.status_code == 200
    assert b"Automatic materialization error: SSH password is required" in response.data
    progress = progress_response.get_json()
    assert progress["status"] == "complete"
    attention = [
        event
        for event in progress["events"]
        if event["step"] == "Artifact materialization needs attention"
    ]
    assert len(attention) == 1
    assert "SSH password is required" in attention[0]["detail"]
    assert progress["events"][-1]["step"] == "Import complete"


def test_load_xml_skips_materialization_when_importer_declines(tmp_path, monkeypatch):
    """Declining materialization must not touch the CORE host at all.

    Copying bundled artifacts is the slow part of an import, so the choice has
    to actually skip the work -- not merely hide its result.
    """
    bundle, _source_path = _bundle(tmp_path)
    upload_root = tmp_path / "uploads"

    monkeypatch.setitem(app.config, "UPLOAD_FOLDER", str(upload_root))
    monkeypatch.setattr(backend, "_webui_runtime_mode", lambda: "vm")
    monkeypatch.setattr(
        backend,
        "_open_ssh_client",
        lambda _cfg: pytest.fail("declining materialization must not open SSH"),
    )
    monkeypatch.setattr(
        reproduction_bundle_module,
        "restore_bundled_artifacts_locally",
        lambda **_kwargs: pytest.fail("declining materialization must not restore locally"),
    )

    with app.test_client() as client:
        login = client.post("/login", data={"username": "coreadmin", "password": "coreadmin"})
        assert login.status_code in (302, 303)
        response = client.post(
            "/load_xml",
            data={
                "scenarios_xml": (
                    io.BytesIO(bundle.read_bytes()),
                    "portable.scenarioforge.zip",
                ),
                "import_progress_id": "declineprogress1",
                "import_materialize": "0",
            },
            content_type="multipart/form-data",
        )
        progress_response = client.get("/api/scenario-import-progress/declineprogress1")

    # The scenario still imports; only the artifact copy is skipped.
    assert response.status_code == 200
    assert b"not materialized" in response.data
    assert list(upload_root.glob("*.xml"))
    progress = progress_response.get_json()
    assert progress["status"] == "complete"
    steps = [event["step"] for event in progress["events"]]
    assert "Skipping artifact materialization" in steps
    assert "Materializing bundled artifacts on CORE VM" not in steps
    assert steps[-1] == "Import complete"
