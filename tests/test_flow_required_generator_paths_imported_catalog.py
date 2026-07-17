import json
import os
from pathlib import Path

from webapp.app_backend import _flow_required_generator_repo_paths
import webapp.app_backend as app_backend


def _write_installed_generator(root: Path, *, kind_dir: str, source_id: str) -> Path:
    generator_dir = root / 'outputs' / 'installed_generators' / kind_dir / 'p_test__1'
    generator_dir.mkdir(parents=True)
    kind = 'flag-node-generator' if kind_dir == 'flag_node_generators' else 'flag-generator'
    (generator_dir / 'manifest.yaml').write_text(
        f"""manifest_version: 1
id: "1"
kind: {kind}
name: Imported Test Generator
runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator
inputs: []
artifacts:
  requires: []
  produces:
    - Flag(flag_id)
injects: []
""",
        encoding='utf-8',
    )
    (generator_dir / 'docker-compose.yml').write_text(
        'services:\n  generator:\n    image: python:3.11-slim\n    command: ["python", "-c", "print(1)"]\n',
        encoding='utf-8',
    )
    (generator_dir / '.coretg_pack.json').write_text(
        json.dumps({'generator_id': '1', 'source_generator_id': source_id, 'kind': kind}),
        encoding='utf-8',
    )
    return generator_dir


def test_flow_required_generator_paths_include_imported_flag_generator(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    repo_root.mkdir()
    generator_dir = _write_installed_generator(repo_root, kind_dir='flag_generators', source_id='imported_flag_generator')
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(repo_root / 'outputs' / 'installed_generators'))
    monkeypatch.setattr(app_backend, '_get_repo_root', lambda: str(repo_root))

    required = _flow_required_generator_repo_paths(
        repo_root=str(repo_root),
        flag_assignments=[
            {
                "flag_id": "flag_1",
                "generator_id": "imported_flag_generator",
            }
        ]
    )

    required_norm = {p.replace("\\", "/") for p in required}
    assert os.path.relpath(generator_dir, repo_root).replace('\\', '/') in required_norm


def test_flow_required_generator_paths_include_imported_node_generator(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    repo_root.mkdir()
    generator_dir = _write_installed_generator(repo_root, kind_dir='flag_node_generators', source_id='imported_node_generator')
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(repo_root / 'outputs' / 'installed_generators'))
    monkeypatch.setattr(app_backend, '_get_repo_root', lambda: str(repo_root))

    required = _flow_required_generator_repo_paths(
        repo_root=str(repo_root),
        flag_assignments=[
            {
                "flag_id": "flag_node_1",
                "generator_id": "imported_node_generator",
                "type": "flag-node-generator",
            }
        ],
    )

    required_norm = {p.replace("\\", "/") for p in required}
    assert os.path.relpath(generator_dir, repo_root).replace('\\', '/') in required_norm


def test_flow_required_generator_paths_do_not_sync_unavailable_generator(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    repo_root.mkdir()
    generator_dir = _write_installed_generator(repo_root, kind_dir='flag_node_generators', source_id='removed_generator')
    monkeypatch.setattr(app_backend, '_flag_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(app_backend, '_flag_node_generators_from_enabled_sources', lambda: ([], []))

    required = _flow_required_generator_repo_paths(
        repo_root=str(repo_root),
        flag_assignments=[{
            'generator_id': 'removed_generator',
            'type': 'flag-node-generator',
        }],
    )

    required_norm = {p.replace('\\', '/') for p in required}
    assert os.path.relpath(generator_dir, repo_root).replace('\\', '/') not in required_norm
    assert required_norm == {'scripts/run_flag_generator.py', 'scenarioforge'}
