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
  - {name: Credential(user, password), type: string, required: false, sensitive: true, flow_supply_when_first: true}
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
    credential_input = next(item for item in generator.get("inputs", []) if item.get("name") == "Credential(user, password)")
    assert credential_input.get("flow_supply_when_first") is True
    assert credential_input.get("sensitive") is True
    assert "Credential(user, password)" in output_names
    assert "PortForward(host, port)" in output_names
    assert "Directory(host, path)" in output_names
    assert "Vulnerability(host, type)" in output_names
    assert generator.get("inject_files") == ["Credential(user, password)"]

    plugin = plugins_by_id["http_login_staff_portal"]
    assert plugin.get("inputs", {}).get("Credential(user, password)", {}).get("flow_supply_when_first") is True
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


def test_manifest_loader_preserves_structured_hint_levels_and_readme(tmp_path: Path):
    manifest_dir = tmp_path / "flag_generators" / "web" / "basic_auth"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "README.md").write_text("# Basic Auth\n", encoding="utf-8")
    (manifest_dir / "manifest.yaml").write_text(
        """
manifest_version: 1
id: web_basic_auth
kind: flag-generator
name: Web Basic Auth
runtime: {type: docker-compose, compose_file: docker-compose.yml, service: generator}
artifacts:
  requires: [Knowledge(ip)]
  produces: [Flag(flag_id), PortForward(host, port)]
hint_templates:
  - "Next: {{NEXT_NODE_NAME}} @ {{NEXT_NODE_IP}}"
hint_levels:
  low:
    - "Target: {{NEXT_NODE_IP}}"
  medium:
    - "Port: {{OUTPUT.PortForward(host,port)}}"
  high:
    - "README: README.md"
""".strip(),
        encoding="utf-8",
    )

    generators, _plugins_by_id, errors = discover_generator_manifests(
        repo_root=tmp_path,
        kind="flag-generator",
    )

    assert errors == []
    assert len(generators) == 1
    generator = generators[0]
    assert generator.get("hint_levels") == {
        "low": ["Target: {{NEXT_NODE_IP}}"],
        "medium": ["Port: {{OUTPUT.PortForward(host,port)}}"],
        "high": ["README: README.md"],
    }
    assert generator.get("readme_path", "").endswith("README.md")
    assert generator.get("readme_rel_path") == "flag_generators/web/basic_auth/README.md"
