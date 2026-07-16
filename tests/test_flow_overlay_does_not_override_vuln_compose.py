from scenarioforge.builders.topology import (
    _compose_record_for_docker_slot,
    _flow_flag_artifacts_overlay_from_host_metadata,
)


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
