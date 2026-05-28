from __future__ import annotations

from webapp import app_backend


def test_flow_compute_assignments_adds_default_vuln_injects(monkeypatch):
    monkeypatch.setattr(
        app_backend,
        "_flag_generators_from_enabled_sources",
        lambda: ([{"id": "gen-vuln", "name": "Gen Vuln", "inject_files": []}], []),
    )
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})

    preview = {
        "hosts": [
            {
                "node_id": 10,
                "vulnerabilities": ["xstream/CVE-2021-29505"],
            }
        ]
    }
    chain_nodes = [
        {
            "id": 10,
            "name": "docker-5",
            "role": "Docker",
            "vulnerabilities": ["xstream/CVE-2021-29505"],
        }
    ]

    assignments = app_backend._flow_compute_flag_assignments(preview, chain_nodes, "Anatest")

    assert isinstance(assignments, list) and len(assignments) == 1
    injects = assignments[0].get("inject_files") if isinstance(assignments[0], dict) else None
    assert injects == ["flag.txt -> /tmp"]


def test_flow_state_backfill_adds_default_vuln_injects(monkeypatch):
    monkeypatch.setattr(app_backend, "_flag_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))

    flow_state = {
        "flag_assignments": [
            {
                "node_id": "10",
                "id": "unknown",
                "vulnerabilities": ["xstream/CVE-2021-29505"],
            }
        ]
    }

    enriched = app_backend._backfill_flow_state_inject_files_from_catalog(flow_state)

    assignments = enriched.get("flag_assignments") if isinstance(enriched, dict) else None
    assert isinstance(assignments, list) and assignments
    assert assignments[0].get("inject_files") == ["flag.txt -> /tmp"]


def test_flow_compute_assignments_prefers_explicit_generator_injects_for_vuln_nodes(monkeypatch):
    monkeypatch.setattr(
        app_backend,
        "_flag_generators_from_enabled_sources",
        lambda: ([{"id": "gen-vuln", "name": "Gen Vuln", "inject_files": ["File(path)"]}], []),
    )
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})

    preview = {
        "hosts": [
            {
                "node_id": 10,
                "vulnerabilities": ["xstream/CVE-2021-29505"],
            }
        ]
    }
    chain_nodes = [
        {
            "id": 10,
            "name": "docker-5",
            "role": "Docker",
            "vulnerabilities": ["xstream/CVE-2021-29505"],
        }
    ]

    assignments = app_backend._flow_compute_flag_assignments(preview, chain_nodes, "Anatest")

    assert isinstance(assignments, list) and len(assignments) == 1
    injects = assignments[0].get("inject_files") if isinstance(assignments[0], dict) else None
    assert injects == ["File(path)"]


def test_flow_compute_assignments_preserves_inject_candidate_paths(monkeypatch):
    monkeypatch.setattr(
        app_backend,
        "_flag_generators_from_enabled_sources",
        lambda: ([
            {
                "id": "gen-vuln",
                "name": "Gen Vuln",
                "inject_files": ["File(path)"],
                "inject_candidate_paths": ["/opt/uploads", "relative/path", "/var/www/html/", "/bad/../path"],
            }
        ], []),
    )
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))
    monkeypatch.setattr(app_backend, "_flow_enabled_plugin_contracts_by_id", lambda: {})

    preview = {
        "hosts": [
            {
                "node_id": 10,
                "vulnerabilities": ["xstream/CVE-2021-29505"],
            }
        ]
    }
    chain_nodes = [
        {
            "id": 10,
            "name": "docker-5",
            "role": "Docker",
            "vulnerabilities": ["xstream/CVE-2021-29505"],
        }
    ]

    assignments = app_backend._flow_compute_flag_assignments(preview, chain_nodes, "Anatest")

    assert isinstance(assignments, list) and len(assignments) == 1
    assert assignments[0].get("inject_candidate_paths") == ["/opt/uploads", "/var/www/html"]


def test_flow_state_backfill_prefers_catalog_injects_for_vuln_nodes(monkeypatch):
    monkeypatch.setattr(
        app_backend,
        "_flag_generators_from_enabled_sources",
        lambda: ([{"id": "textfile_username_password", "inject_files": ["File(path)"]}], []),
    )
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))

    flow_state = {
        "flag_assignments": [
            {
                "node_id": "10",
                "id": "textfile_username_password",
                "vulnerabilities": ["xstream/CVE-2021-29505"],
                "inject_files": ["File(path)", "flag.txt -> /tmp"],
            }
        ]
    }

    enriched = app_backend._backfill_flow_state_inject_files_from_catalog(flow_state)

    assignments = enriched.get("flag_assignments") if isinstance(enriched, dict) else None
    assert isinstance(assignments, list) and assignments
    assert assignments[0].get("inject_files") == ["File(path)"]


def test_flow_state_backfill_adds_catalog_inject_candidate_paths(monkeypatch):
    monkeypatch.setattr(
        app_backend,
        "_flag_generators_from_enabled_sources",
        lambda: ([
            {
                "id": "textfile_username_password",
                "inject_files": ["File(path)"],
                "inject_candidate_paths": ["/opt/uploads", "/srv/share/"],
            }
        ], []),
    )
    monkeypatch.setattr(app_backend, "_flag_node_generators_from_enabled_sources", lambda: ([], []))

    flow_state = {
        "flag_assignments": [
            {
                "node_id": "10",
                "id": "textfile_username_password",
                "vulnerabilities": ["xstream/CVE-2021-29505"],
            }
        ]
    }

    enriched = app_backend._backfill_flow_state_inject_files_from_catalog(flow_state)

    assignments = enriched.get("flag_assignments") if isinstance(enriched, dict) else None
    assert isinstance(assignments, list) and assignments
    assert assignments[0].get("inject_candidate_paths") == ["/opt/uploads", "/srv/share"]
