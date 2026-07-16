import logging
from types import SimpleNamespace

import pytest

import scenarioforge.cli as cli
import scenarioforge.planning.orchestrator as orchestrator


def _patch_basic_cli_execute_dependencies(monkeypatch, *, flow_state=None):
    monkeypatch.setattr(cli, '_maybe_seed_docker_sudo_password_from_stdin', lambda: None)
    monkeypatch.setattr(cli, '_maybe_delegate_cli_to_remote', lambda *a, **k: None)
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: None)
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
        'hosts': [{'node_id': '1', 'name': 'docker-1', 'role': 'Docker', 'ip4': '10.0.0.3/24'}],
        'routers': [{'node_id': 'r1'}],
        'switches_detail': [{
            'switch_id': 'sw1',
            'router_id': None,
            'lan_subnet': '10.0.0.0/24',
            'host_if_ips': {'1': '10.0.0.3/24'},
        }],
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


def test_cli_execute_requires_embedded_plan_preview(tmp_path, monkeypatch, caplog):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="s"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
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

    _patch_basic_cli_execute_dependencies(monkeypatch, flow_state=None)
    monkeypatch.setattr(cli, '_load_preview_plan', lambda *_a, **_k: ({'metadata': {}}, None))
    monkeypatch.setattr(orchestrator, 'compute_full_plan', lambda *a, **k: dict(plan))

    caplog.set_level(logging.ERROR)
    try:
        cli.sys.argv = ['scenarioforge.cli', '--xml', str(xml_path), '--scenario', 's']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    assert any('requires a valid PlanPreview embedded in the selected XML' in rec.message for rec in caplog.records)


def test_plan_summary_detects_host_address_drift():
    expected = cli._plan_summary_from_full_preview({
        'hosts': [{'node_id': 1, 'name': 'docker-1', 'ip4': '172.30.0.3/24'}],
    })
    actual = cli._plan_summary_from_full_preview({
        'hosts': [{'node_id': 1, 'name': 'docker-1', 'ip4': '10.0.0.3/24'}],
    })

    diffs = cli._diff_plan_summaries(expected, actual)

    assert any(item['field'] == 'host_addresses' for item in diffs)


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


def test_cli_execute_saved_xml_rejects_enabled_flow_without_resolved_assignments(tmp_path, monkeypatch, caplog):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="s"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    flow_state = {
        'flow_enabled': True,
        'chain_ids': ['1'],
        'flag_assignments': [],
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
    assert any(
        'Flow is enabled, but XML has no resolved Flow runtime values. Run Generate (resolve) and Save XML before Execute.' in rec.message
        for rec in caplog.records
    )


def test_validate_flow_state_for_cli_execute_allows_remote_runtime_paths():
    flow_state = {
        'flow_enabled': True,
        'flag_assignments': [
            {
                'node_id': '7',
                'id': 'nfs_sensitive_file',
                'artifacts_dir': '/tmp/remote/missing/artifacts',
                'inject_files': ['/tmp/remote/missing/exports.txt -> /tmp/seed'],
            }
        ],
    }

    ok, error, details = cli._validate_flow_state_for_cli_execute(
        flow_state,
        remote_execution_expected=True,
    )

    assert ok is True
    assert error is None
    assert details == []


def test_validate_flow_state_for_cli_execute_tmp_preview_requires_local_runtime_paths(tmp_path):
    missing_artifacts = str(tmp_path / 'missing' / 'artifacts')
    missing_inject = str(tmp_path / 'missing' / 'inject' / 'exports.txt')
    flow_state = {
        'flow_enabled': True,
        'flag_assignments': [
            {
                'node_id': '7',
                'id': 'nfs_sensitive_file',
                'artifacts_dir': missing_artifacts,
                'inject_files': [f'{missing_inject} -> /tmp/seed'],
                'resolved_outputs': {'Flag(flag_id)': 'FLAG{abc}'},
            }
        ],
    }

    ok, error, details = cli._validate_flow_state_for_cli_execute(
        flow_state,
        remote_execution_expected=True,
        require_local_runtime_paths=True,
    )

    assert ok is False
    assert error == 'Execute requires pre-generated Flow values saved in the XML. Run Generate (resolve) and save the XML before executing via CLI.'
    assert any(detail.get('reason') == 'missing artifacts_dir' for detail in details)
    assert any(detail.get('reason') == 'missing inject_source' for detail in details)


def test_cli_execute_remote_tmp_preview_xml_rejects_missing_flow_artifacts(tmp_path, monkeypatch, caplog):
    xml_path = tmp_path / 'outputs' / 'tmp-preview-06-18-26-00-34-51-ebe24f21' / 'Scenario1.xml'
    xml_path.parent.mkdir(parents=True, exist_ok=True)
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
    backend = SimpleNamespace(
        _resolve_preexecute_xml_path=lambda xml_arg, _scenario_name: str(xml_arg),
        _coerce_bool=lambda value: bool(value),
    )
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(cli, '_maybe_prepare_cli_execute_hitl_xml', lambda *_a, **_k: ([], []))
    monkeypatch.setattr(cli, '_resolve_cli_core_context', lambda *_a, **_k: ('s', {'ssh_enabled': True}, True))
    monkeypatch.setattr(cli, '_load_preview_plan', lambda *_a, **_k: ({'metadata': {}}, None))
    monkeypatch.setattr(orchestrator, 'compute_full_plan', lambda *a, **k: dict(plan))

    caplog.set_level(logging.ERROR)
    try:
        cli.sys.argv = ['scenarioforge.cli', 'execute', '--xml', str(xml_path), '--scenario', 's']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    assert any('temporary preview XML whose Flow artifacts are no longer present' in rec.message for rec in caplog.records)
    assert any('Temporary preview XML source:' in rec.message for rec in caplog.records)
    assert any('missing artifacts_dir' in rec.message for rec in caplog.records)
