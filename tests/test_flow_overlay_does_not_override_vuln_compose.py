from pathlib import Path

from scenarioforge.builders.topology import (
    _compose_record_for_docker_slot,
    _flow_flag_artifacts_overlay_from_host_metadata,
)
from scenarioforge.utils.vuln_process import prepare_compose_for_assignments


def test_flow_flag_generator_overlay_does_not_override_vuln_record_fields():
    # Simulate a host with Flow flag-generator metadata.
    hdata = {
        "metadata": {
            "flow_flag": {
                "type": "flag-generator",
                "artifacts_dir": "/tmp/vulns/flag_generators_runs/flow-x/01_gen/artifacts",
                "mount_path": "/flow_artifacts",
                "inject_files": ["File(path)"],
                "outputs_manifest": "outputs.json",
                "run_dir": "/tmp/vulns/flag_generators_runs/flow-x/01_gen",
            }
        }
    }

    overlay = _flow_flag_artifacts_overlay_from_host_metadata(hdata)
    assert overlay is not None
    assert overlay["ArtifactsMountPath"] == "/flow_artifacts"

    # Base vuln compose record (what docker_slot_plan should supply).
    vuln_rec = {
        "Type": "docker-compose",
        "Name": "airflow/CVE-2020-11981",
        "Path": "/tmp/vulns/catalog/vulhub/airflow/CVE-2020-11981/docker-compose.yml",
        "Vector": "vuln",
    }

    merged = {**vuln_rec, **overlay}

    # Ensure we kept vuln identity and only overlaid artifacts/inject fields.
    assert merged["Name"] == "airflow/CVE-2020-11981"
    assert merged["Path"].endswith("/airflow/CVE-2020-11981/docker-compose.yml")
    assert merged["Vector"] == "vuln"
    assert merged["ArtifactsDir"]


def test_flow_flag_node_generator_replaces_vulnerability_compose(tmp_path):
    run_dir = tmp_path / "git-deploy-key"
    run_dir.mkdir()
    generated_compose = run_dir / "docker-compose.yml"
    generated_compose.write_text(
        "services:\n  git:\n    image: alpine:3.19\n    ports: ['19418:19418']\n",
        encoding="utf-8",
    )
    hdata = {
        "metadata": {
            "flow_flag": {
                "type": "flag-node-generator",
                "generator_id": "git_deploy_key_repo",
                "run_dir": str(run_dir),
                "inject_files": ["service -> /flow_injects"],
            }
        }
    }
    vuln_rec = {
        "Type": "docker-compose",
        "Name": "yapi/mongodb-inj",
        "Path": "/catalog/yapi/docker-compose.yml",
        "Vector": "vuln",
    }

    selected = _compose_record_for_docker_slot(vuln_rec, hdata)

    assert selected["Path"] == str(generated_compose)
    assert selected["Vector"] == "flag-nodegen"
    assert selected["InjectFiles"] == ["service -> /flow_injects"]


def test_flag_node_generator_port_survives_core_compose_preparation(tmp_path, monkeypatch):
    import yaml

    run_dir = tmp_path / "flag_node_generators_runs" / "flow-scenario1" / "01_git_deploy_key_repo_docker-13"
    run_dir.mkdir(parents=True)
    service_dir = run_dir / "service" / "repo"
    service_dir.mkdir(parents=True)
    (service_dir / "deploy.env").write_text("DEPLOY_API_KEY=test\n", encoding="utf-8")
    source_compose = run_dir / "docker-compose.yml"
    source_compose.write_text(
        """
services:
  node:
    image: python:3.11-slim
    environment:
      SERVICE_PORT: "19418"
    ports:
      - "19418:19418"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CORETG_COMPOSE_FORCE_NO_NETWORK", "1")
    record = {
        "Type": "docker-compose",
        "Name": "Git: Deploy Key Repository",
        "Path": str(source_compose),
        "Vector": "flag-nodegen",
        "InjectSourceDir": str(run_dir),
        "InjectFiles": ["service -> /flow_injects"],
    }

    created = prepare_compose_for_assignments({"docker-13": record}, out_base=str(tmp_path / "prepared"))

    assert len(created) == 1
    rendered = yaml.safe_load(Path(created[0]).read_text(encoding="utf-8"))
    service = rendered["services"]["docker-13"]
    assert service["network_mode"] == "none"
    assert "19418" in [str(port) for port in service["expose"]]
    assert "ports" not in service
    assert "inject_copy" in service["depends_on"]
    assert "inject-flow-injects:/flow_injects" in service["volumes"]
    helper = rendered["services"]["inject_copy"]
    assert f"{run_dir}:/src:ro" in helper["volumes"]
    assert "inject-flow-injects:/dst/flow-injects" in helper["volumes"]
    assert rendered["volumes"]["inject-flow-injects"] in (None, {})
