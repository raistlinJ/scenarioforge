import json

from webapp import app_backend as backend


def test_extract_inject_expected_by_node_maps_absolute_source_to_tmp(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '7',
                    'inject_files': ['/Users/me/project/exports', '/opt/data/seed.txt'],
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {7: {'name': 'docker-1'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-1' in out
    assert '/exports' in out['docker-1']
    assert '/flow_injects/seed.txt' in out['docker-1']
    assert all(not str(p).startswith('/Users/') for p in out['docker-1'])


def test_extract_inject_expected_by_node_normalizes_detail_absolute_paths(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '9',
                    'inject_files_detail': [
                        {'path': '/Users/me/project/File(path)'},
                        {'path': '/exports'},
                    ],
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {9: {'name': 'docker-9'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-9' in out
    assert '/tmp/File(path)' not in out['docker-9']
    assert '/exports' in out['docker-9']
    assert all(not str(p).startswith('/Users/') for p in out['docker-9'])


def test_extract_inject_expected_by_node_maps_tmp_vulns_source_to_tmp_basename(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '6',
                    'inject_files': ['File(path)'],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': '/tmp/vulns/flag_generators_runs/run1/artifacts/secrets.txt', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {6: {'name': 'docker-1'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-1' in out
    assert out['docker-1'] == ['/flow_injects/secrets.txt']


def test_extract_inject_expected_by_node_flag_generator_artifacts_source_root(monkeypatch):
    run_dir = '/tmp/vulns/flag_generators_runs/flow-scenario1/02_text_support_ticket_dump_docker-2'
    artifact_path = f'{run_dir}/artifacts/support_ticket_4172.txt'
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '7',
                    'id': 'text_support_ticket_dump',
                    'type': 'flag-generator',
                    'inject_source_dir': run_dir,
                    'artifacts_dir': run_dir,
                    'inject_files': [artifact_path],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': artifact_path, 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {7: {'name': 'docker-2'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'Scenario1')

    assert out['docker-2'] == ['/flow_injects/support_ticket_4172.txt']
    assert '/flow_injects/artifacts/support_ticket_4172.txt' not in out['docker-2']


def test_extract_inject_expected_by_node_preserves_dotfile_artifact_names(monkeypatch):
    run_dir = '/tmp/vulns/flag_generators_runs/flow-scenario1/01_text_env_backup_creds_docker-2'
    artifact_path = f'{run_dir}/artifacts/.env.backup'
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '7',
                    'id': 'text_env_backup_creds',
                    'type': 'flag-generator',
                    'inject_source_dir': run_dir,
                    'artifacts_dir': run_dir,
                    'inject_files': ['File(path)'],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': artifact_path, 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {7: {'name': 'docker-2'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'Scenario1')

    assert out['docker-2'] == ['/flow_injects/.env.backup']
    assert '/flow_injects/env.backup' not in out['docker-2']


def test_extract_inject_expected_by_node_preserves_run_relative_resolved_sources(monkeypatch):
    run_dir = '/tmp/vulns/flag_node_generators_runs/run123'
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '6',
                    'id': 'dep_api_key_admin_endpoint',
                    'type': 'flag-node-generator',
                    'inject_source_dir': run_dir,
                    'inject_files': ['FlagFile(path)', 'File(path)', 'site'],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': f'{run_dir}/site/private/dep_api_key_admin_endpoint-abc123.txt', 'is_remote': True},
                            {'path': f'{run_dir}/docker-compose.yml', 'is_remote': True},
                            {'path': f'{run_dir}/site', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {6: {'name': 'docker-1'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert out['docker-1'] == [
        '/flow_injects/site/private/dep_api_key_admin_endpoint-abc123.txt',
        '/flow_injects/docker-compose.yml',
        '/flow_injects/site',
    ]
    assert '/flow_injects/dep_api_key_admin_endpoint-abc123.txt' not in out['docker-1']


def test_extract_inject_expected_by_node_preserves_remote_run_relative_sources(monkeypatch):
    source_dir = '/home/sampleuser/Documents/scenarioforge/outputs/flag_node_generators_runs/run123'
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '6',
                    'id': 'dep_api_key_admin_endpoint',
                    'type': 'flag-node-generator',
                    'inject_source_dir': source_dir,
                    'inject_files': ['FlagFile(path)'],
                    'resolved_paths': {
                        'inject_sources': [
                            {
                                'path': '/tmp/vulns/flag_node_generators_runs/run123/site/private/dep_api_key_admin_endpoint-def456.txt',
                                'is_remote': True,
                            },
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {6: {'name': 'docker-1'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert out['docker-1'] == ['/flow_injects/site/private/dep_api_key_admin_endpoint-def456.txt']


def test_extract_inject_expected_by_node_prefers_resolved_runtime_sources(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '5',
                    'inject_files': ['exports'],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': '/exports', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {5: {'name': 'docker-5'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-5' in out
    assert '/exports' in out['docker-5']


def test_extract_inject_expected_by_node_resolved_sources_override_detail(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '5',
                    'inject_files': ['exports'],
                    'inject_files_detail': [
                        {'path': '/tmp/exports'},
                    ],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': '/exports', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {5: {'name': 'docker-5'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-5' in out
    assert out['docker-5'] == ['/exports']


def test_extract_inject_expected_by_node_preserves_explicit_inject_destinations(monkeypatch):
    run_dir = '/tmp/vulns/flag_node_generators_runs/run123'
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '6',
                    'id': 'git_deploy_key_repo',
                    'type': 'flag-node-generator',
                    'inject_source_dir': run_dir,
                    'inject_files': [
                        f'{run_dir}/service/private/deploy.key -> /srv/git/deploy.git',
                        f'{run_dir}/reports/summary.txt -> /opt/executive/reports',
                    ],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': f'{run_dir}/service/private/deploy.key', 'is_remote': True},
                            {'path': f'{run_dir}/reports/summary.txt', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {6: {'name': 'docker-1'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert out['docker-1'] == [
        '/srv/git/deploy.git/deploy.key',
        '/opt/executive/reports/summary.txt',
    ]


def test_extract_inject_expected_by_node_honors_inject_destination_override(monkeypatch):
    run_dir = '/tmp/vulns/flag_node_generators_runs/run123'
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '17',
                    'id': 'git_deploy_repo',
                    'type': 'flag-node-generator',
                    'inject_source_dir': run_dir,
                    'inject_files': ['service'],
                    'inject_files_override': ['service -> /home/git/repositories/deploy.git'],
                    'inject_files_detail': [
                        {'path': f'{run_dir}/service', 'resolved': 'service'},
                    ],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': f'{run_dir}/service', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {17: {'name': 'docker-17'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert out['docker-17'] == ['/home/git/repositories/deploy.git/service']
    assert '/flow_injects/service' not in out['docker-17']


def test_extract_inject_expected_by_node_maps_output_key_override_to_resolved_artifact(monkeypatch):
    run_dir = '/tmp/vulns/flag_generators_runs/flow-scenario1/03_shadow_fragment_docker-14'
    artifact_path = f'{run_dir}/artifacts/shadow.fragment'
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '14',
                    'id': 'text_shadow_fragment',
                    'type': 'flag-generator',
                    'inject_source_dir': run_dir,
                    'artifacts_dir': run_dir,
                    'inject_files': ['File(path)'],
                    'inject_files_override': ['File(path) -> /flow_injects'],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': artifact_path, 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {14: {'name': 'docker-14'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'Scenario1')

    assert out['docker-14'] == ['/flow_injects/shadow.fragment']
    assert '/flow_injects/artifacts/shadow.fragment' not in out['docker-14']


def test_extract_inject_expected_by_node_ignores_resolved_sources_without_inject_intent(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '5',
                    'inject_files': [],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': '/exports', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {5: {'name': 'docker-5'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-5' not in out


def test_extract_inject_expected_by_node_preserves_nested_bare_relative_path(monkeypatch):
    # A bare relative inject spec with subdirectories and no explicit dest and no
    # resolved_paths to resolve against: the real copy preserves the full nested
    # relative path under /flow_injects, so the expected path must too (regression
    # for a bug that truncated to just the basename).
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '3',
                    'type': 'flag-node-generator',
                    'inject_files': ['site/private/flag.txt'],
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {3: {'name': 'docker-3'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert out['docker-3'] == ['/flow_injects/site/private/flag.txt']
    assert '/flow_injects/flag.txt' not in out['docker-3']


def test_extract_inject_expected_by_node_preserves_nested_path_under_selected_candidate(monkeypatch):
    # When a user selects a non-default candidate destination in the UI, it is
    # persisted as an explicit 'src -> dest' override. With a nested relative src
    # and no resolved_paths, the expected path must be dest + full nested rel,
    # matching where _inject_copy_for_inject_files actually mounts the file.
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '4',
                    'type': 'flag-node-generator',
                    'inject_files': ['site/private/flag.txt'],
                    'inject_files_override': ['site/private/flag.txt -> /var/www/html'],
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {4: {'name': 'docker-4'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert out['docker-4'] == ['/var/www/html/site/private/flag.txt']
    assert '/var/www/html/flag.txt' not in out['docker-4']


def test_copy_destination_matches_validation_expected_for_selected_candidate(tmp_path, monkeypatch):
    # Parity guard: the container path where _inject_copy_for_inject_files actually
    # places a file must equal the path _extract_inject_expected_by_node checks, so
    # a correctly-injected file is never falsely reported missing. Exercises a
    # selected non-default candidate destination with a nested relative source.
    from scenarioforge.utils import vuln_process as vp

    run_dir = tmp_path / 'flag_node_generators_runs' / 'run1'
    (run_dir / 'site' / 'private').mkdir(parents=True)
    (run_dir / 'site' / 'private' / 'flag.txt').write_text('FLAG{demo}')

    override = 'site/private/flag.txt -> /var/www/html'

    compose = {'services': {'target': {'image': 'nginx', 'container_name': 'docker-3'}}}
    result = vp._inject_copy_for_inject_files(
        compose,
        inject_files=[override],
        source_dir=str(run_dir),
        prefer_service='target',
        inject_candidate_paths=['/var/www/html', '/srv/app/data'],
    )
    real_dest = '/var/www/html/site/private/flag.txt'
    # The real container destination must appear as a mount/copy target in the
    # generated compose (host source lives under tmp_path, so this string can only
    # be the container-side path).
    assert real_dest in json.dumps(result)

    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '3',
                    'type': 'flag-node-generator',
                    'inject_source_dir': str(run_dir),
                    'inject_files': ['site/private/flag.txt'],
                    'inject_files_override': [override],
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {3: {'name': 'docker-3'}},
    )
    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert out['docker-3'] == [real_dest]


def test_extract_inject_expected_by_node_ignores_node_generator_mount_root(monkeypatch):
    monkeypatch.setattr(
        backend,
        '_flow_state_from_xml_path',
        lambda *a, **k: {
            'flag_assignments': [
                {
                    'node_id': '5',
                    'id': 'nfs_sensitive_file',
                    'type': 'flag-node-generator',
                    'inject_files': ['/Users/me/project/exports'],
                    'resolved_paths': {
                        'inject_sources': [
                            {'path': '/exports', 'is_remote': True},
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(
        backend,
        '_expected_from_plan_preview',
        lambda *a, **k: {5: {'name': 'docker-5'}},
    )

    out = backend._extract_inject_expected_by_node('/tmp/scenario.xml', 'NewScenario1')

    assert 'docker-5' not in out
