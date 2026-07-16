from __future__ import annotations


def test_no_network_compose_keeps_inject_copy_dependency(tmp_path, monkeypatch):
    """CORE's selected-service startup must also run the flow-volume initializer."""
    try:
        import yaml  # type: ignore
    except Exception:
        return

    from scenarioforge.utils.vuln_process import prepare_compose_for_assignments

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  web:\n    image: alpine:3.19\n    command: [\"sh\", \"-lc\", \"sleep infinity\"]\n",
        encoding="utf-8",
    )
    inject_root = tmp_path / "flag_node_generators_runs" / "flow-bashbug" / "service"
    inject_root.mkdir(parents=True)
    (inject_root / "marker.txt").write_text("FLAG{test}\n", encoding="utf-8")

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_NO_NETWORK", raising=False)
    created = prepare_compose_for_assignments(
        {
            "docker-13": {
                "Type": "docker-compose",
                "Name": "bash/CVE-2014-6271",
                "Path": str(compose),
                "InjectSourceDir": str(inject_root.parent),
                "InjectFiles": ["service -> /flow_injects"],
            }
        },
        out_base=str(tmp_path / "out"),
    )

    assert created
    doc = yaml.safe_load((tmp_path / "out" / "docker-compose-docker-13.yml").read_text("utf-8"))
    target = doc["services"]["docker-13"]
    assert target["network_mode"] == "none"
    assert "inject_copy" in target["depends_on"]

