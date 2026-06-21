import logging

import pytest

import scenarioforge.cli as cli
import scenarioforge.planning.orchestrator as orchestrator


def _patch_basic_cli_execute_dependencies(monkeypatch, *, flow_state=None):
    monkeypatch.setattr(cli, '_maybe_seed_docker_sudo_password_from_stdin', lambda: None)
    monkeypatch.setattr(cli, '_maybe_delegate_cli_to_remote', lambda *a, **k: None)
    monkeypatch.setattr(cli, '_export_flow_assignments_to_env', lambda *a, **k: None)
    monkeypatch.setattr(cli, 'parse_node_info', lambda *a, **k: (1, [('Host', 1.0)], [], []))
    monkeypatch.setattr(cli, 'parse_planning_metadata', lambda *a, **k: {})
    monkeypatch.setattr(cli, 'parse_hitl_info', lambda *a, **k: {'enabled': False, 'interfaces': []})
    monkeypatch.setattr(cli, 'compute_role_counts', lambda *a, **k: {'Host': 1})
    monkeypatch.setattr(cli, 'parse_routing_info', lambda *a, **k: (0.0, []))
    monkeypatch.setattr(cli, 'parse_segmentation_info', lambda *a, **k: (0.0, []))
    monkeypatch.setattr(cli, 'parse_traffic_info', lambda *a, **k: (0.0, []))
    monkeypatch.setattr(cli, 'parse_vulnerabilities_info', lambda *a, **k: (0.0, [], None))
    monkeypatch.setattr(cli, 'parse_pivoting_info', lambda *a, **k: (0.0, []))
    monkeypatch.setattr(cli, 'load_vuln_catalog', lambda *a, **k: [])
    monkeypatch.setattr(cli, 'assign_compose_to_nodes', lambda *a, **k: {})
    monkeypatch.setattr(
        cli,
        'collect_hitl_preview_ip_reservations',
        lambda *_a, **_k: {'ip_addresses': set(), 'network_cidrs': set()},
    )
    monkeypatch.setattr(cli, '_flow_state_from_xml', lambda *_a, **_k: flow_state)
    monkeypatch.setattr(cli, 'CORE_GRPC_AVAILABLE', False)

    def _fail_offline_report(*_a, **_k):
        pytest.fail('execute preflight should fail before offline report generation')

    monkeypatch.setattr(cli, '_run_offline_report', _fail_offline_report)


def test_cli_execute_saved_xml_rejects_stale_embedded_plan_preview(tmp_path, monkeypatch, caplog):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="s"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    flow_state = {
        'flag_assignments': [
            {
                'node_id': '1',
                'id': 'example_generator',
                'resolved_outputs': {'Flag(flag_id)': 'FLAG{abc}'},
            }
        ]
    }
    saved_preview = {
        'role_counts': {'Docker': 1},
        'hosts': [{'node_id': '1', 'role': 'Docker'}],
        'routers': [{'node_id': 'r1'}],
        'switches_detail': [{'node_id': 'sw1'}],
        'services_plan': {},
        'vulnerabilities_plan': {},
        'r2r_policy_preview': {},
        'r2s_policy_preview': {},
    }
    current_preview = {
        'role_counts': {'Host': 1},
        'hosts': [{'node_id': '1', 'role': 'Host'}],
        'routers': [],
        'switches_detail': [],
        'services_plan': {},
        'vulnerabilities_plan': {},
        'r2r_policy_preview': {},
        'r2s_policy_preview': {},
    }
    plan = {
        'routers_planned': 0,
        'role_counts': {'Host': 1},
        'service_plan': {},
        'vulnerability_plan': {},
        'traffic_plan': None,
        'breakdowns': {
            'router': {'simple_plan': {}},
            'segmentation': {'density': 0.0, 'raw_items_serialized': []},
        },
    }
    argv0 = cli.sys.argv[:]

    _patch_basic_cli_execute_dependencies(monkeypatch, flow_state=flow_state)
    monkeypatch.setattr(cli, '_load_preview_plan', lambda *_a, **_k: ({'metadata': {}}, saved_preview))
    monkeypatch.setattr(cli, 'build_full_preview', lambda *a, **k: current_preview)
    monkeypatch.setattr(orchestrator, 'compute_full_plan', lambda *a, **k: dict(plan))

    caplog.set_level(logging.ERROR)
    try:
        cli.sys.argv = ['scenarioforge.cli', '--xml', str(xml_path), '--scenario', 's']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    assert any('Saved PlanPreview does not match the current XML-derived plan' in rec.message for rec in caplog.records)
    assert any('PlanPreview mismatch:' in rec.message for rec in caplog.records)


def test_cli_execute_saved_xml_rejects_missing_flow_runtime_paths(tmp_path, monkeypatch, caplog):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="s"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    missing_artifacts = str(tmp_path / 'missing' / 'artifacts')
    missing_inject = str(tmp_path / 'missing' / 'inject' / 'exports.txt')
    flow_state = {
        'flag_assignments': [
            {
                'node_id': '7',
                'id': 'nfs_sensitive_file',
                'artifacts_dir': missing_artifacts,
                'inject_files': [f'{missing_inject} -> /tmp/seed'],
                'resolved_outputs': {'Flag(flag_id)': 'FLAG{abc}'},
            }
        ]
    }
    plan = {
        'routers_planned': 0,
        'role_counts': {'Docker': 1},
        'service_plan': {},
        'vulnerability_plan': {},
        'traffic_plan': None,
        'breakdowns': {
            'router': {'simple_plan': {}},
            'segmentation': {'density': 0.0, 'raw_items_serialized': []},
        },
    }
    argv0 = cli.sys.argv[:]

    _patch_basic_cli_execute_dependencies(monkeypatch, flow_state=flow_state)
    monkeypatch.setattr(cli, '_load_preview_plan', lambda *_a, **_k: ({'metadata': {}}, None))
    monkeypatch.setattr(orchestrator, 'compute_full_plan', lambda *a, **k: dict(plan))

    caplog.set_level(logging.ERROR)
    try:
        cli.sys.argv = ['scenarioforge.cli', '--xml', str(xml_path), '--scenario', 's']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    assert any('Execute requires pre-generated Flow values saved in the XML' in rec.message for rec in caplog.records)
    assert any('missing artifacts_dir' in rec.message for rec in caplog.records)
    assert any('missing inject_source' in rec.message for rec in caplog.records)