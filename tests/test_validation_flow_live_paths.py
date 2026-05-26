from webapp import app_backend as backend


def _patch_validation_dependencies(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_run_remote_python_json', lambda *a, **k: {'items': []})


def test_validate_flow_live_paths_flags_local_missing(monkeypatch):
    _patch_validation_dependencies(monkeypatch)
    monkeypatch.setattr(backend.os.path, 'exists', lambda p: str(p).strip() == '/tmp/vulns/inject-ok')

    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '7',
                    'id': 'nfs_sensitive_file',
                    'resolved_paths': {
                        'artifacts_dir': {
                            'path': '/tmp/vulns/missing-artifacts',
                            'is_remote': False,
                        },
                        'inject_source_dir': {
                            'path': '/tmp/vulns/inject-ok',
                            'is_remote': False,
                        },
                        'inject_sources': [],
                    },
                }
            ]
        },
    )

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('flow_live_paths_checked') == 2
    assert summary.get('flow_live_paths_missing_count') == 1
    missing = summary.get('flow_live_paths_missing') or []
    assert any('artifacts_dir' in str(item) for item in missing)
    assert summary.get('ok') is False


def test_validate_flow_live_paths_ignores_remote_missing(monkeypatch):
    _patch_validation_dependencies(monkeypatch)
    monkeypatch.setattr(backend.os.path, 'exists', lambda p: False)

    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '9',
                    'id': 'remote_flow_gen',
                    'resolved_paths': {
                        'artifacts_dir': {
                            'path': '/tmp/vulns/remote-artifacts',
                            'is_remote': True,
                        },
                        'inject_source_dir': {
                            'path': '/tmp/vulns/remote-inject-source',
                            'is_remote': True,
                        },
                        'inject_sources': [
                            {
                                'path': '/tmp/vulns/remote-source',
                                'is_remote': True,
                            }
                        ],
                    },
                }
            ]
        },
    )

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('flow_live_paths_checked') == 3
    assert summary.get('flow_live_paths_missing_count') == 0
    assert summary.get('flow_live_paths_missing') == []
    assert summary.get('ok') is True


def test_validate_injects_missing_respects_per_node_expectations(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {5: {'name': 'docker-5'}})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {'docker-1': ['/tmp/secrets.txt']})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: ['/tmp'])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: ['/tmp/secrets.txt'])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-5'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: {5})
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *a, **k: {'flag_assignments': []})

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {
                        'container': 'docker-5',
                        'exists': True,
                        'running': True,
                        'inject_count': 0,
                        'inject_samples': [],
                        'inject_dirs_found': [],
                        'debug_logs': [],
                    }
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': []}
        if label == 'flow.artifacts.validate':
            return {'items': []}
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('injects_missing') == []


def test_validate_non_running_container_not_counted_as_missing_inject(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {3: {'name': 'docker-3'}})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {'docker-3': ['/tmp/challenge.txt']})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: ['/tmp'])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: ['/tmp/challenge.txt'])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-3'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: {3})
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *a, **k: {'flag_assignments': []})

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {
                        'container': 'docker-3',
                        'exists': True,
                        'running': False,
                        'state_status': 'exited',
                        'state_exit_code': 1,
                        'state_error': '',
                        'inject_count': 0,
                        'inject_samples': [
                            'Error response from daemon: container deadbeef is not running'
                        ],
                        'inject_dirs_found': [],
                        'debug_logs': [],
                    }
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': []}
        if label == 'flow.artifacts.validate':
            return {'items': []}
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('docker_not_running') == ['docker-3']
    details = summary.get('docker_not_running_details') or []
    assert details and details[0].get('container') == 'docker-3'
    assert details[0].get('status') == 'exited'
    assert details[0].get('exit_code') == 1
    assert summary.get('injects_missing') == []
    injects_detail = summary.get('injects_detail') or []
    assert any('docker-3: not running' in str(line) for line in injects_detail)
    assert not any('docker-3: 0 file(s)' in str(line) for line in injects_detail)


def test_validate_restarting_probe_not_counted_as_missing_inject(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {1: {'name': 'docker-1'}})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(
        backend,
        '_extract_inject_expected_by_node',
        lambda *a, **k: {'docker-1': ['/flow_injects/docker-compose.yml', '/flow_injects/site']},
    )
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: ['/flow_injects'])
    monkeypatch.setattr(
        backend,
        '_extract_inject_files_from_plan_xml',
        lambda *a, **k: ['/flow_injects/docker-compose.yml', '/flow_injects/site'],
    )
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: (['docker-1'], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-1'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: {1})
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *a, **k: {'flag_assignments': []})

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {
                        'container': 'docker-1',
                        'exists': True,
                        'running': True,
                        'state_status': 'running',
                        'state_exit_code': 0,
                        'state_error': '',
                        'inject_count': 0,
                        'inject_samples': [],
                        'inject_dirs_found': [],
                        'expected_present': [],
                        'expected_missing': ['/flow_injects/docker-compose.yml', '/flow_injects/site'],
                        'debug_logs': [
                            'Error response from daemon: Container abc is restarting, wait until the container is running'
                        ],
                    }
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': []}
        if label == 'flow.artifacts.validate':
            return {'items': []}
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('docker_not_running') == []
    assert summary.get('docker_start_pending') == ['docker-1']
    assert summary.get('injects_missing') == []
    assert not any('missing expected /flow_injects' in str(line) for line in summary.get('injects_detail') or [])


def test_validate_flow_enabled_without_per_node_expectations_does_not_require_all_nodes(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: ['/tmp'])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: ['/tmp/expected.txt'])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-1', 'docker-2', 'docker-4', 'docker-5'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: set())
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *a, **k: {'flag_assignments': []})

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {'container': 'docker-1', 'exists': True, 'running': True, 'inject_count': 0, 'inject_samples': [], 'inject_dirs_found': [], 'debug_logs': []},
                    {'container': 'docker-2', 'exists': True, 'running': True, 'inject_count': 0, 'inject_samples': [], 'inject_dirs_found': [], 'debug_logs': []},
                    {'container': 'docker-4', 'exists': True, 'running': True, 'inject_count': 0, 'inject_samples': [], 'inject_dirs_found': [], 'debug_logs': []},
                    {'container': 'docker-5', 'exists': True, 'running': True, 'inject_count': 0, 'inject_samples': [], 'inject_dirs_found': [], 'debug_logs': []},
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': []}
        if label == 'flow.artifacts.validate':
            return {'items': []}
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='NewScenario1',
        flow_enabled=True,
    )

    assert summary.get('injects_missing') == []


def test_validate_created_container_is_startup_pending_not_not_running(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {3: {'name': 'docker-3'}})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: ['/tmp'])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: ['/tmp/challenge.txt'])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: (['docker-3'], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-3'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: set())
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *a, **k: {'flag_assignments': []})

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {
                        'container': 'docker-3',
                        'exists': True,
                        'running': False,
                        'state_status': 'created',
                        'state_exit_code': 0,
                        'state_error': '',
                        'inject_count': 0,
                        'inject_samples': [],
                        'inject_dirs_found': [],
                        'debug_logs': [],
                    }
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': []}
        if label == 'flow.artifacts.validate':
            return {'items': []}
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('docker_not_running') == []
    assert summary.get('docker_start_pending') == ['docker-3']


def test_validate_inspect_no_such_container_is_startup_pending_not_missing(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {3: {'name': 'docker-3'}})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: ['/tmp'])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: ['/tmp/challenge.txt'])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: (['docker-3'], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-3'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: set())
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *a, **k: {'flag_assignments': []})

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {
                        'container': 'docker-3',
                        'exists': False,
                        'running': False,
                        'state_status': '',
                        'state_exit_code': None,
                        'state_error': '',
                        'inspect_error': 'Error: No such container: docker-3',
                        'inject_count': 0,
                        'inject_samples': [],
                        'inject_dirs_found': [],
                        'debug_logs': [],
                    }
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': []}
        if label == 'flow.artifacts.validate':
            return {'items': []}
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('docker_missing') == []
    assert summary.get('docker_not_running') == []
    assert summary.get('docker_start_pending') == ['docker-3']


def test_validate_inject_expected_sanitizes_mount_roots_and_optional_flag(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(
        backend,
        '_extract_inject_expected_by_node',
        lambda *a, **k: {
            'docker-1': ['/exports'],
            'docker-4': ['/flow_injects/secrets.txt', '/flow_injects/flag.txt'],
        },
    )
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: ['/exports'])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: ['/exports'])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-1', 'docker-4'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: set())
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *a, **k: {'flag_assignments': []})

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {
                        'container': 'docker-1',
                        'exists': True,
                        'running': True,
                        'inject_count': 0,
                        'inject_samples': [],
                        'inject_dirs_found': [],
                        'debug_logs': [],
                    },
                    {
                        'container': 'docker-4',
                        'exists': True,
                        'running': True,
                        'inject_count': 0,
                        'inject_samples': [],
                        'inject_dirs_found': [],
                        'debug_logs': [],
                    },
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': []}
        if label == 'flow.artifacts.validate':
            return {'items': []}
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('inject_dirs_expected') == ['/flow_injects']
    assert summary.get('inject_files_expected_by_node') == {'docker-4': ['/flow_injects/secrets.txt']}
    assert summary.get('injects_missing') == ['docker-4']


def test_validate_exact_container_inject_missing_survives_clean_generator_validation(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {3: {'name': 'docker-3'}})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {'docker-3': ['/flow_injects/site']})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: ['/flow_injects'])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: ['/flow_injects/site'])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-3'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: {3})
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'chain_ids': ['3'],
            'chain': [{'id': '3', 'name': 'docker-3'}],
            'flag_assignments': [
                {
                    'node_id': '3',
                    'id': 'site_bundle',
                    'type': 'flag-node-generator',
                    'artifacts_dir': '/tmp/vulns/site_bundle',
                    'resolved_outputs': {'Flag(flag_id)': 'FLAG{ok}'},
                    'inject_files': ['site -> /flow_injects'],
                }
            ],
        },
    )

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {
                        'container': 'docker-3',
                        'exists': True,
                        'running': True,
                        'inject_count': 1,
                        'inject_samples': ['/flow_injects/other.txt'],
                        'inject_dirs_found': ['/flow_injects'],
                        'expected_present': [],
                        'expected_missing': ['/flow_injects/site'],
                        'debug_logs': [],
                    }
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': []}
        if label == 'flow.artifacts.validate':
            return {
                'items': [
                    {
                        'node_id': '3',
                        'node_name': 'docker-3',
                        'container_name': 'docker-3',
                        'generator_id': 'site_bundle',
                        'outputs_missing': [],
                        'inject_missing': [],
                    }
                ]
            }
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='NewScenario1',
    )

    assert summary.get('injects_missing') == ['docker-3']
    assert summary.get('ok') is False
    assert any('missing expected /flow_injects/site' in str(line) for line in summary.get('injects_detail') or [])


def test_validate_generator_missing_filters_local_host_paths_and_bare_relative(monkeypatch):
    monkeypatch.setattr(backend, '_expected_from_plan_preview', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_parse_session_xml_for_compare', lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(backend, '_extract_inject_specs_from_flow_state', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_expected_by_node', lambda *a, **k: {})
    monkeypatch.setattr(backend, '_extract_inject_dirs_from_plan_xml', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_inject_files_from_plan_xml', lambda *a, **k: [])
    monkeypatch.setattr(backend, '_extract_expected_docker_and_vuln_nodes_from_plan_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(backend, '_session_docker_nodes_from_xml', lambda *a, **k: ['docker-1'])
    monkeypatch.setattr(backend, '_extract_inject_node_ids_from_flow_state', lambda *a, **k: set())
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '1',
                    'id': 'nfs_sensitive_file',
                    'name': 'nfs_sensitive_file',
                    'type': 'flag-node-generator',
                    'run_dir': '/tmp/vulns/flag_node_generators_runs/flow-anatest/01_nfs_sensitive_file_docker-1',
                    'artifacts_dir': '/tmp/vulns/flag_node_generators_runs/flow-anatest/01_nfs_sensitive_file_docker-1',
                    'inject_source_dir': '/tmp/vulns/flag_node_generators_runs/flow-anatest/01_nfs_sensitive_file_docker-1',
                    'outputs_manifest': '/Users/sampleuser/Documents/scenarioforge/outputs/flag_node_generators_runs/old/outputs.json',
                    'inject_files': ['exports'],
                }
            ]
        },
    )

    def _fake_remote_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'docker.exec.injects_status':
            return {
                'items': [
                    {
                        'container': 'docker-1',
                        'exists': True,
                        'running': True,
                        'inject_count': 1,
                        'inject_samples': ['/flow_injects/secrets.txt'],
                        'inject_dirs_found': ['/flow_injects'],
                        'debug_logs': [],
                    }
                ]
            }
        if label == 'docker.compose.assignments':
            return {'nodes': ['docker-1']}
        if label == 'flow.artifacts.validate':
            return {
                'items': [
                    {
                        'node_id': 'docker-1',
                        'generator_id': 'nfs_sensitive_file',
                        'outputs_missing': [
                            'missing manifest: /Users/sampleuser/Documents/scenarioforge/outputs/flag_node_generators_runs/old/outputs.json',
                        ],
                        'inject_missing': [
                            'secrets.txt',
                            '/Users/sampleuser/Documents/scenarioforge/outputs/flag_node_generators_runs/old/exports',
                            '/tmp/vulns/flag_node_generators_runs/flow-anatest/01_nfs_sensitive_file_docker-1/exports',
                        ],
                        'outputs_checked': [],
                        'inject_checked': [],
                    }
                ]
            }
        return {'items': []}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_remote_json)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='Anatest',
    )

    assert summary.get('generator_outputs_missing') == []
    assert summary.get('generator_injects_missing') == [
        'docker-1: /tmp/vulns/flag_node_generators_runs/flow-anatest/01_nfs_sensitive_file_docker-1/exports'
    ]


def test_validate_generator_validation_uses_chain_node_name_for_container_probe(monkeypatch):
    captured: dict[str, list[dict]] = {'items': []}

    _patch_validation_dependencies(monkeypatch)
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'chain_ids': ['3'],
            'chain': [{'id': '3', 'name': 'docker-1'}],
            'flag_assignments': [
                {
                    'node_id': '3',
                    'id': 'ssh_desktop_creds',
                    'name': 'Sample: SSH Desktop Credentials',
                    'type': 'flag-node-generator',
                    'run_dir': '/tmp/vulns/flag_node_generators_runs/flow-scenario1/02_ssh_desktop_creds_docker-1',
                    'artifacts_dir': '/tmp/vulns/flag_node_generators_runs/flow-scenario1/02_ssh_desktop_creds_docker-1',
                    'inject_source_dir': '/tmp/vulns/flag_node_generators_runs/flow-scenario1/02_ssh_desktop_creds_docker-1',
                    'outputs_manifest': '/tmp/vulns/flag_node_generators_runs/flow-scenario1/02_ssh_desktop_creds_docker-1/outputs.json',
                    'inject_files': ['desktop'],
                }
            ],
        },
    )

    def _capture_validation_script(check_items, scenario_label='', sudo_password=None):
        captured['items'] = list(check_items or [])
        return 'print({"ok": true, "items": []})'

    monkeypatch.setattr(backend, '_remote_flow_artifacts_validation_script', _capture_validation_script)

    summary = backend._validate_session_nodes_and_injects(
        scenario_xml_path='/tmp/scenario.xml',
        session_xml_path='/tmp/session.xml',
        core_cfg={'ssh_enabled': True},
        preview_plan_path=None,
        scenario_label='Scenario1',
    )

    assert summary.get('ok') is True
    assert captured['items']
    assert captured['items'][0].get('node_id') == '3'
    assert captured['items'][0].get('node_name') == 'docker-1'
