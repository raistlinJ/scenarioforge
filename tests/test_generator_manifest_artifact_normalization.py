from __future__ import annotations

from pathlib import Path

from scenarioforge.generator_manifests import discover_generator_manifests


def test_unquoted_flow_style_fact_names_are_repaired(tmp_path: Path):
    manifest_dir = tmp_path / "flag_node_generators" / "http" / "login_staff_portal"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "manifest.yaml").write_text(
        """
manifest_version: 1
id: http_login_staff_portal
kind: flag-node-generator
name: HTTP Login Staff Portal
runtime: {type: docker-compose, compose_file: docker-compose.yml, service: generator}
inputs:
  - {name: seed, type: string, required: true}
  - {name: Credential(user, password), type: string, required: true}
artifacts:
  requires: [Knowledge(ip), Credential(user, password)]
  optional_requires: [Directory(host, path)]
  produces: [Flag(flag_id), Credential(user, password), PortForward(host, port), Directory(host, path), Vulnerability(host, type)]
injects: [Credential(user, password)]
""".strip(),
        encoding="utf-8",
    )

    generators, plugins_by_id, errors = discover_generator_manifests(
        repo_root=tmp_path,
        kind="flag-node-generator",
    )

    assert errors == []
    assert len(generators) == 1

    generator = generators[0]
    input_names = {item.get("name") for item in generator.get("inputs", [])}
    output_names = {item.get("name") for item in generator.get("outputs", [])}

    assert "Credential(user, password)" in input_names
    assert "Credential(user, password)" in output_names
    assert "PortForward(host, port)" in output_names
    assert "Directory(host, path)" in output_names
    assert "Vulnerability(host, type)" in output_names
    assert generator.get("inject_files") == ["Credential(user, password)"]

    plugin = plugins_by_id["http_login_staff_portal"]
    assert plugin.get("requires") == ["Knowledge(ip)", "Credential(user, password)"]
    assert plugin.get("optional_requires") == ["Directory(host, path)"]
    assert [item.get("artifact") for item in plugin.get("produces", [])] == [
        "Flag(flag_id)",
        "Credential(user, password)",
        "PortForward(host, port)",
        "Directory(host, path)",
        "Vulnerability(host, type)",
    ]

    fragmented = {"Credential(user", "password)", "PortForward(host", "port)", "Directory(host", "path)"}
    assert not (fragmented & input_names)
    assert not (fragmented & output_names)
