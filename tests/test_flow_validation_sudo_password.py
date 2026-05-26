from webapp import app_backend as backend


def test_validate_session_nodes_and_injects_passes_sudo_password_to_remote_validator(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: [])

    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': 'docker-1',
                    'id': 'textfile_username_password',
                    'name': 'Textfile Username Password',
                    'type': 'flag-generator',
                    'run_dir': '/tmp/vulns/flag_generators_runs/flow-scenario1/01_textfile_username_password_docker-1',
                    'artifacts_dir': '/tmp/vulns/flag_generators_runs/flow-scenario1/01_textfile_username_password_docker-1',
                    'inject_source_dir': '/tmp/vulns/flag_generators_runs/flow-scenario1/01_textfile_username_password_docker-1/artifacts',
                    'outputs_manifest': '/tmp/vulns/flag_generators_runs/flow-scenario1/01_textfile_username_password_docker-1/outputs.json',
                    'inject_files': ['/tmp/vulns/flag_generators_runs/flow-scenario1/01_textfile_username_password_docker-1/artifacts/secrets.txt'],
                    'inject_files_detail': [],
                    'resolved_paths': {
                        'inject_sources': [
                            {
                                'path': '/tmp/vulns/flag_generators_runs/flow-scenario1/01_textfile_username_password_docker-1/artifacts/secrets.txt',
                                'is_remote': True,
                            }
                        ]
                    },
                }
            ]
        },
    )

    captured = {}

    def _fake_run_remote_python_json(_cfg, script, logger=None, label='', timeout=0):
        if label == 'flow.artifacts.validate':
            captured['script'] = script
            return {'ok': True, 'items': []}
        return {'ok': True, 'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_run_remote_python_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True, 'ssh_password': 'pw'},
        preview_plan_path=None,
        scenario_label='Scenario1',
    )

    assert isinstance(summary, dict)
    script = str(captured.get('script') or '')
    assert 'SUDO_PASSWORD = "pw"' in script
