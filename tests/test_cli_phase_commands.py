import io
import json
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest
from flask import Flask, jsonify, request

import scenarioforge.cli as cli
import scenarioforge.planning.orchestrator as orchestrator
from webapp import flow_prepare_preview_execute


class _FakeCoreClient:
    def connect(self):
        return None

    def get_sessions(self):
        return []


class _FakeSession:
    topo_stats = {'preview_realized': True}


class _FakeExecStdin:
    def __init__(self):
        self.sent = []

    def write(self, data):
        self.sent.append(data)

    def flush(self):
        return None

    def close(self):
        return None


class _FakeExecChannel:
    def __init__(self, exit_code=0):
        self.exit_code = exit_code

    def recv_exit_status(self):
        return self.exit_code


class _FakeExecStdout:
    def __init__(self, channel):
        self.channel = channel


class _FakeSshClient:
    def __init__(self, exit_code=0):
        self.stdin = _FakeExecStdin()
        self.channel = _FakeExecChannel(exit_code=exit_code)
        self.command = None

    def exec_command(self, command, get_pty=False, timeout=None):
        self.command = command
        return self.stdin, _FakeExecStdout(self.channel), object()

    def close(self):
        return None


class _CleanupCoreClient:
    def __init__(self, sessions=None):
        self._sessions = list(sessions or [])

    def get_sessions(self):
        return list(self._sessions)


def test_cli_preview_plan_phase_persists_preview_metadata(tmp_path, monkeypatch, capsys):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    fake_backend = SimpleNamespace(
        _scenario_names_from_xml=lambda _path: ['Scenario One'],
        _planner_persist_flow_plan=lambda **kwargs: {
            'xml_path': kwargs['xml_path'],
            'scenario': kwargs['scenario'],
            'seed': 42,
            'preview_plan_path': kwargs['xml_path'],
            'full_preview': {'seed': 42, 'hosts': [], 'routers': []},
            'plan': {'routers_planned': 0, 'role_counts': {'Host': 1}},
        },
    )
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: fake_backend)

    try:
        cli.sys.argv = ['scenarioforge.cli', 'preview-plan', '--xml', str(xml_path)]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True
    assert payload['phase'] == 'preview-plan'
    assert payload['scenario'] == 'Scenario One'
    assert payload['preview_plan_path'] == str(xml_path.resolve())


def test_load_preview_plan_from_xml_repairs_legacy_routing_placeholder(tmp_path):
    preview_payload = {
        'full_preview': {
            'routing_plan': {'Routing': 1},
            'r2s_grouping_preview': [{'protocol': 'Routing'}],
            'router_plan': {
                'simple_plan': {'Routing': 1},
                'items': [{'protocol': 'Routing'}],
            },
        },
    }
    xml_path = tmp_path / 'legacy-preview.xml'
    root = ET.Element('Scenarios')
    scenario_el = ET.SubElement(root, 'Scenario', {'name': 'Legacy'})
    editor_el = ET.SubElement(scenario_el, 'ScenarioEditor')
    plan_el = ET.SubElement(editor_el, 'PlanPreview')
    plan_el.text = json.dumps(preview_payload)
    ET.ElementTree(root).write(xml_path, encoding='utf-8', xml_declaration=True)

    payload, full_preview = cli._load_preview_plan(str(xml_path), 'Legacy')

    assert payload['full_preview'] == full_preview
    assert full_preview['routing_plan'] == {}
    assert full_preview['r2s_grouping_preview'][0]['protocol'] == ''
    assert full_preview['router_plan']['simple_plan'] == {}
    assert full_preview['router_plan']['items'][0]['protocol'] == ''


def test_cli_new_phase_writes_starter_xml(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'starter.xml'
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = ['scenarioforge.cli', 'new', '--xml', str(xml_path), '--scenario', 'My Scenario']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True
    assert payload['phase'] == 'new'
    assert payload['scenario'] == 'MyScenario'
    assert xml_path.exists()

    root = ET.parse(xml_path).getroot()
    assert root.tag == 'Scenarios'
    scenario_el = root.find('Scenario')
    assert scenario_el is not None
    assert scenario_el.get('name') == 'MyScenario'
    assert root.find('CoreConnection') is not None
    se = scenario_el.find('ScenarioEditor')
    assert se is not None
    section_names = [sec.get('name') for sec in se.findall('section')]
    assert 'Node Information' in section_names
    assert 'Routing' in section_names
    assert 'Vulnerabilities' in section_names


def test_cli_new_phase_persists_core_ssh_credentials_when_provided(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'starter.xml'
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli', 'new', '--xml', str(xml_path), '--scenario', 'CredScenario',
            '--host', '10.0.0.10', '--port', '50051',
            '--ssh-host', '10.0.0.11', '--ssh-port', '22',
            '--ssh-username', 'corevm', '--ssh-password', 'pw123',
            '--venv-bin', '/opt/core/venv/bin',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True

    root = ET.parse(xml_path).getroot()
    core_el = root.find('CoreConnection')
    assert core_el is not None
    assert core_el.get('host') == '10.0.0.10'
    assert core_el.get('ssh_host') == '10.0.0.11'
    assert core_el.get('ssh_username') == 'corevm'
    assert core_el.get('ssh_password') == 'pw123'
    assert core_el.get('venv_bin') == '/opt/core/venv/bin'


def test_cli_new_phase_uses_xml_stem_when_scenario_missing(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'starter.xml'
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = ['scenarioforge.cli', 'new', '--xml', str(xml_path)]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['scenario'] == 'starter'
    scenario_el = ET.parse(xml_path).getroot().find('Scenario')
    assert scenario_el is not None
    assert scenario_el.get('name') == 'starter'


def test_cli_new_phase_persists_density_count_when_provided(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend
    from scenarioforge.parsers.node_info import parse_node_info

    xml_path = tmp_path / 'density-count.xml'
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'new',
            '--xml',
            str(xml_path),
            '--scenario',
            'DensityCountScenario',
            '--density-count',
            '17',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True

    scenario_el = ET.parse(xml_path).getroot().find('Scenario')
    assert scenario_el is not None
    assert scenario_el.get('density_count') == '17'

    density_base, weight_items, count_items, services = parse_node_info(str(xml_path), 'DensityCountScenario')
    assert density_base == 17
    assert weight_items == []
    assert count_items == []
    assert services == []


def test_cli_execute_parser_defaults_enable_cleanup_actions():
    parser = cli._build_cli_parser()
    args = parser.parse_args(['execute', '--xml', '/tmp/scenario.xml'])

    assert args.core_cleanup_before_run is True
    assert args.docker_cleanup_before_run is True
    assert args.docker_remove_conflicts is True
    assert args.overwrite_existing_images is True
    assert args.docker_remove_all_containers is False


def test_cli_execute_parser_cleanup_opt_outs_disable_remove_actions():
    parser = cli._build_cli_parser()
    args = parser.parse_args([
        'execute',
        '--xml', '/tmp/scenario.xml',
        '--no-core-cleanup-before-run',
        '--no-docker-cleanup-before-run',
        '--no-docker-remove-conflicts',
        '--no-overwrite-existing-images',
    ])

    assert args.core_cleanup_before_run is False
    assert args.docker_cleanup_before_run is False
    assert args.docker_remove_conflicts is False
    assert args.overwrite_existing_images is False


@pytest.mark.parametrize(
    'option',
    ['-post-execution-validation', '--post-execution-validation'],
)
def test_cli_execute_parser_accepts_post_execution_validation_aliases(option):
    parser = cli._build_cli_parser()
    args = parser.parse_args(['execute', '--xml', '/tmp/scenario.xml', option])

    assert args.post_execution_validation is True


def test_post_execution_validation_summary_colors_errors_and_warnings(monkeypatch):
    stream = io.StringIO()
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setenv('FORCE_COLOR', '1')

    ok = cli._print_post_execution_validation_summary(
        {
            'ok': False,
            'missing_nodes': ['docker-9'],
            'injects_missing': ['docker-3'],
        },
        stream=stream,
    )

    output = stream.getvalue()
    assert ok is False
    assert '\033[31mERROR: Missing scenario nodes (1)\033[0m' in output
    assert '\033[33mWARNING: Missing container injects (1)\033[0m' in output
    assert 'VALIDATION_SUMMARY_JSON:' in output


def test_post_execution_validation_warning_does_not_fail_execute(monkeypatch):
    stream = io.StringIO()
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setenv('FORCE_COLOR', '1')

    ok = cli._print_post_execution_validation_summary(
        {'ok': False, 'injects_missing': ['docker-3']},
        stream=stream,
    )

    assert ok is True
    assert '\033[33mPASSED WITH WARNINGS\033[0m' in stream.getvalue()


def test_post_execution_validation_unclassified_failure_is_an_error():
    stream = io.StringIO()

    ok = cli._print_post_execution_validation_summary({'ok': False}, stream=stream)

    assert ok is False
    assert 'ERROR: Validation failed (1)' in stream.getvalue()


def test_post_execution_validation_flow_copy_failure_is_an_error():
    stream = io.StringIO()

    ok = cli._print_post_execution_validation_summary(
        {
            'ok': False,
            'flow_artifact_copy_error': 'copy incomplete',
        },
        stream=stream,
    )

    assert ok is False
    assert 'ERROR: Flow artifact copy failed (1)' in stream.getvalue()


def test_post_execution_validation_unavailable_emits_machine_summary():
    stream = io.StringIO()

    ok = cli._print_post_execution_validation_unavailable(
        'CORE session stayed in configuration',
        stream=stream,
        session_id=17,
        details=['core-daemon reported a service validation failure'],
    )

    assert ok is False
    summary = cli._extract_last_json_marker(
        stream.getvalue(),
        'VALIDATION_SUMMARY_JSON:',
    )
    assert summary is not None
    assert summary['ok'] is False
    assert summary['validation_unavailable'] is True
    assert summary['session_id'] == 17
    assert summary['validation_unavailable_details'] == [
        'core-daemon reported a service validation failure'
    ]


def test_remote_execute_failure_detail_prefers_start_validation_error():
    output = """
2026-06-22 ERROR root - CORE daemon runtime hint: service failed
2026-06-22 ERROR root - Start validation failed: CORE session stayed in "configuration"
[remote] cleanup complete
"""

    detail = cli._remote_execute_failure_detail(output)

    assert detail is not None
    assert 'Start validation failed' in detail


def test_cli_flag_sequencing_parser_defaults_enable_cleanup():
    parser = cli._build_cli_parser()
    args = parser.parse_args(['flag-sequencing', '--xml', '/tmp/scenario.xml'])

    assert args.flow_cleanup_before_run is True


def test_cli_flag_sequencing_parser_cleanup_opt_out_disables_cleanup():
    parser = cli._build_cli_parser()
    args = parser.parse_args([
        'flag-sequencing',
        '--xml', '/tmp/scenario.xml',
        '--no-flow-cleanup-before-run',
    ])

    assert args.flow_cleanup_before_run is False


def test_cli_flag_sequencing_parser_rejects_preview_mode():
    parser = cli._build_cli_parser()

    with pytest.raises(SystemExit):
        parser.parse_args([
            'flag-sequencing',
            '--xml', '/tmp/scenario.xml',
            '--flow-mode', 'preview',
        ])


def test_cli_execute_cleanup_runs_default_remove_actions(monkeypatch, caplog):
    args = SimpleNamespace(
        phase='execute',
        core_cleanup_before_run=True,
        docker_cleanup_before_run=True,
        overwrite_existing_images=True,
        docker_remove_all_containers=False,
    )
    core = _CleanupCoreClient([SimpleNamespace(id=7, state='runtime')])
    local_calls: list[list[str]] = []
    docker_calls: list[list[str]] = []

    monkeypatch.setattr(cli, '_run_local_cmd', lambda cmd, **kwargs: local_calls.append(list(cmd)) or SimpleNamespace(returncode=0, stdout='ok'))
    monkeypatch.setattr(cli, '_run_docker_cmd', lambda cmd, **kwargs: docker_calls.append(list(cmd)) or SimpleNamespace(returncode=0, stdout='ok'))
    monkeypatch.setattr(cli, '_cleanup_stale_vuln_temp_files', lambda: ['/tmp/vulns/docker-compose-old.yml'])
    monkeypatch.setattr(cli.shutil, 'which', lambda name: '/usr/bin/docker' if name == 'docker' else '/usr/bin/sudo')

    caplog.set_level('INFO')
    reconnect = cli._best_effort_cli_execute_cleanup(args, core)

    assert reconnect is True
    assert ['core-cleanup'] in local_calls
    assert ['docker', 'container', 'prune', '-f'] in docker_calls
    assert ['docker', 'image', 'prune', '-f'] in docker_calls
    assert any(cmd[:2] == ['sh', '-lc'] and 'coretg-gen-' in cmd[2] for cmd in local_calls)
    assert any(cmd[:2] == ['sh', '-lc'] and '_wrapper' in cmd[2] for cmd in local_calls)


def test_cli_flag_sequencing_cleanup_runs_default_remove_actions(monkeypatch, caplog):
    args = SimpleNamespace(
        phase='flag-sequencing',
        flow_mode='resolve',
        flow_cleanup_before_run=True,
    )
    local_calls: list[list[str]] = []
    docker_calls: list[list[str]] = []
    removed_roots: list[str] = []
    fake_backend = SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
    )

    monkeypatch.setattr(cli, '_run_local_cmd', lambda cmd, **kwargs: local_calls.append(list(cmd)) or SimpleNamespace(returncode=0, stdout='ok'))
    monkeypatch.setattr(cli, '_run_docker_cmd', lambda cmd, **kwargs: docker_calls.append(list(cmd)) or SimpleNamespace(returncode=0, stdout='ok'))
    monkeypatch.setattr(cli, '_cleanup_stale_vuln_temp_files', lambda: ['/tmp/vulns/docker-compose-old.yml'])
    monkeypatch.setattr(cli, '_remove_local_flow_scenario_roots', lambda scenario_norm: removed_roots.append(str(scenario_norm)) or ['/tmp/vulns/flag_generators_runs/flow-scenario-one'])
    monkeypatch.setattr(cli.shutil, 'which', lambda name: '/usr/bin/docker' if name == 'docker' else '/usr/bin/sudo')

    caplog.set_level('INFO')
    cli._best_effort_cli_flag_sequencing_cleanup(
        args,
        backend=fake_backend,
        core_cfg=None,
        scenario_name='Scenario One',
        run_remote=False,
    )

    assert removed_roots == ['scenario-one']
    assert ['docker', 'container', 'prune', '-f'] in docker_calls
    assert ['docker', 'image', 'prune', '-f'] in docker_calls
    assert any(cmd[:2] == ['sh', '-lc'] and 'coretg-gen-' in cmd[2] for cmd in local_calls)
    assert any(cmd[:2] == ['sh', '-lc'] and '_wrapper' in cmd[2] for cmd in local_calls)


def test_cli_new_phase_rejects_invalid_density_count(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'density-count-invalid.xml'
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'new',
            '--xml',
            str(xml_path),
            '--scenario',
            'DensityCountScenario',
            '--density-count',
            '-1',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    payload = json.loads(capsys.readouterr().err)
    assert payload['ok'] is False
    assert 'Invalid --density-count value' in payload['error']


def test_cli_new_phase_refuses_overwrite_without_force(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'starter.xml'
    xml_path.write_text('<Scenarios><Scenario name="existing" /></Scenarios>', encoding='utf-8')
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = ['scenarioforge.cli', 'new', '--xml', str(xml_path), '--scenario', 'My Scenario']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    payload = json.loads(capsys.readouterr().err)
    assert payload['ok'] is False
    assert 'already exists' in payload['error']
    assert 'existing' in xml_path.read_text(encoding='utf-8')


def test_cli_new_phase_seeds_basic_scenario_rows(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'myscen.xml'
    argv0 = cli.sys.argv[:]

    def _fake_concretize(scenarios, *, seed=None):
        scenario = dict((scenarios or [])[0])
        sections = dict(scenario.get('sections') or {})
        sections['Routing'] = {
            'density': 0.5,
            'items': [{'selected': 'OSPFv2', 'factor': 1.0, 'r2r_mode': 'Uniform'}],
        }
        sections['Traffic'] = {
            'density': 0.5,
            'items': [{
                'selected': 'TCP',
                'factor': 1.0,
                'pattern': 'periodic',
                'content_type': 'text',
                'rate_kbps': 128.0,
                'period_s': 2.0,
                'jitter_pct': 15.0,
            }],
        }
        sections['Vulnerabilities'] = {
            'density': 0.0,
            'flag_type': 'text',
            'items': [{
                'selected': 'Specific',
                'factor': 1.0,
                'v_metric': 'Count',
                'v_count': 1,
                'v_name': 'demo/random-vuln',
                'v_path': '/catalog/demo/random-vuln/docker-compose.yml',
            }],
        }
        scenario['sections'] = sections
        return [scenario]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(backend, '_concretize_scenarios_for_save', _fake_concretize)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'new',
            '--xml',
            str(xml_path),
            '--scenario',
            'myscen',
            '--seed-role',
            'Workstation=2',
            '--seed-role',
            'Docker=3',
            '--seed-routing',
            'Random',
            '--seed-traffic',
            'Random',
            '--seed-random-vulnerability-count',
            '1',
            '--seed',
            '42',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True
    assert payload['scenario'] == 'myscen'

    root = ET.parse(xml_path).getroot()
    scenario_el = root.find('Scenario')
    assert scenario_el is not None
    se = scenario_el.find('ScenarioEditor')
    assert se is not None

    node_section = se.find("section[@name='Node Information']")
    assert node_section is not None
    node_items = node_section.findall('item')
    assert len(node_items) == 2
    assert {(item.get('selected'), item.get('v_count')) for item in node_items} == {('Workstation', '2'), ('Docker', '3')}

    routing_section = se.find("section[@name='Routing']")
    assert routing_section is not None
    routing_item = routing_section.find('item')
    assert routing_item is not None
    assert routing_item.get('selected') == 'OSPFv2'

    traffic_section = se.find("section[@name='Traffic']")
    assert traffic_section is not None
    traffic_item = traffic_section.find('item')
    assert traffic_item is not None
    assert traffic_item.get('selected') == 'TCP'

    vuln_section = se.find("section[@name='Vulnerabilities']")
    assert vuln_section is not None
    vuln_item = vuln_section.find('item')
    assert vuln_item is not None
    assert vuln_item.get('selected') == 'Specific'
    assert vuln_item.get('v_name') == 'demo/random-vuln'


def test_cli_new_phase_supports_count_seed_specs_for_routing_and_traffic(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'count-seeds.xml'
    argv0 = cli.sys.argv[:]

    def _fake_concretize(scenarios, *, seed=None):
        scenario = dict((scenarios or [])[0])
        sections = dict(scenario.get('sections') or {})
        routing_section = dict(sections.get('Routing') or {})
        routing_items = list(routing_section.get('items') or [])
        if routing_items:
            routing_items[0] = dict(routing_items[0])
            routing_items[0]['selected'] = 'OSPFv2'
            routing_section['items'] = routing_items
            sections['Routing'] = routing_section

        traffic_section = dict(sections.get('Traffic') or {})
        traffic_items = list(traffic_section.get('items') or [])
        if traffic_items:
            traffic_items[0] = dict(traffic_items[0])
            traffic_items[0].update({
                'selected': 'TCP',
                'pattern': 'periodic',
                'content_type': 'text',
                'rate_kbps': 128.0,
                'period_s': 2.0,
                'jitter_pct': 15.0,
            })
            traffic_section['items'] = traffic_items
            sections['Traffic'] = traffic_section

        scenario['sections'] = sections
        return [scenario]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(backend, '_concretize_scenarios_for_save', _fake_concretize)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'new',
            '--xml',
            str(xml_path),
            '--scenario',
            'count-seeds',
            '--seed-routing',
            'OSPFv2=3',
            '--seed-traffic',
            'TCP=7',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True

    root = ET.parse(xml_path).getroot()
    scenario_el = root.find('Scenario')
    assert scenario_el is not None
    se = scenario_el.find('ScenarioEditor')
    assert se is not None

    routing_item = se.find("section[@name='Routing']/item")
    assert routing_item is not None
    assert routing_item.get('selected') == 'OSPFv2'
    assert routing_item.get('v_metric') == 'Count'
    assert routing_item.get('v_count') == '3'

    traffic_item = se.find("section[@name='Traffic']/item")
    assert traffic_item is not None
    assert traffic_item.get('selected') == 'TCP'
    assert traffic_item.get('v_metric') == 'Count'
    assert traffic_item.get('v_count') == '7'


def test_cli_new_phase_supports_density_seed_specs_for_routing_and_traffic(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'density-seeds.xml'
    argv0 = cli.sys.argv[:]

    def _fake_concretize(scenarios, *, seed=None):
        scenario = dict((scenarios or [])[0])
        sections = dict(scenario.get('sections') or {})
        routing_section = dict(sections.get('Routing') or {})
        routing_items = list(routing_section.get('items') or [])
        if routing_items:
            routing_items[0] = dict(routing_items[0])
            routing_items[0]['selected'] = 'OSPFv2'
            routing_section['items'] = routing_items
            sections['Routing'] = routing_section

        traffic_section = dict(sections.get('Traffic') or {})
        traffic_items = list(traffic_section.get('items') or [])
        if traffic_items:
            traffic_items[0] = dict(traffic_items[0])
            traffic_items[0].update({
                'selected': 'TCP',
                'pattern': 'periodic',
                'content_type': 'text',
                'rate_kbps': 128.0,
                'period_s': 2.0,
                'jitter_pct': 15.0,
            })
            traffic_section['items'] = traffic_items
            sections['Traffic'] = traffic_section

        scenario['sections'] = sections
        return [scenario]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(backend, '_concretize_scenarios_for_save', _fake_concretize)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'new',
            '--xml',
            str(xml_path),
            '--scenario',
            'density-seeds',
            '--seed-routing',
            'OSPFv2=density',
            '--seed-traffic',
            'TCP=density',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True

    root = ET.parse(xml_path).getroot()
    scenario_el = root.find('Scenario')
    assert scenario_el is not None
    se = scenario_el.find('ScenarioEditor')
    assert se is not None

    routing_item = se.find("section[@name='Routing']/item")
    assert routing_item is not None
    assert routing_item.get('selected') == 'OSPFv2'
    assert routing_item.get('v_metric') is None
    assert routing_item.get('v_count') is None

    traffic_item = se.find("section[@name='Traffic']/item")
    assert traffic_item is not None
    assert traffic_item.get('selected') == 'TCP'
    assert traffic_item.get('v_metric') is None
    assert traffic_item.get('v_count') is None


def test_cli_new_phase_rejects_invalid_count_seed_specs(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'invalid-count-seeds.xml'
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'new',
            '--xml',
            str(xml_path),
            '--scenario',
            'invalid-count-seeds',
            '--seed-routing',
            'OSPFv2=abc',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    payload = json.loads(capsys.readouterr().err)
    assert payload['ok'] is False
    assert 'Invalid --seed-routing value' in payload['error']


def test_cli_new_phase_supports_service_and_segmentation_seed_specs(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'service-seg-seeds.xml'
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(backend, '_concretize_scenarios_for_save', lambda scenarios, *, seed=None: scenarios)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'new',
            '--xml',
            str(xml_path),
            '--scenario',
            'service-seg-seeds',
            '--seed-service',
            'SSH=4',
            '--seed-segmentation',
            'Firewall=density',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True

    root = ET.parse(xml_path).getroot()
    scenario_el = root.find('Scenario')
    assert scenario_el is not None
    se = scenario_el.find('ScenarioEditor')
    assert se is not None

    service_item = se.find("section[@name='Services']/item")
    assert service_item is not None
    assert service_item.get('selected') == 'SSH'
    assert service_item.get('v_metric') == 'Count'
    assert service_item.get('v_count') == '4'

    segmentation_item = se.find("section[@name='Segmentation']/item")
    assert segmentation_item is not None
    assert segmentation_item.get('selected') == 'Firewall'
    assert segmentation_item.get('v_metric') is None
    assert segmentation_item.get('v_count') is None


def test_cli_new_phase_supports_specific_vulnerability_seed_specs(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'specific-vuln-seeds.xml'
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(backend, '_concretize_scenarios_for_save', lambda scenarios, *, seed=None: scenarios)
    monkeypatch.setattr(
        backend,
        '_load_backend_vuln_catalog_items',
        lambda: [
            {'Name': 'jboss/CVE-2017-12149', 'Path': '/catalog/jboss/CVE-2017-12149/docker-compose.yml'},
            {'Name': 'weblogic/CVE-2017-10271', 'Path': '/catalog/weblogic/CVE-2017-10271/docker-compose.yml'},
        ],
    )
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'new',
            '--xml',
            str(xml_path),
            '--scenario',
            'specific-vuln-seeds',
            '--seed-vulnerability',
            'jboss/CVE-2017-12149=2',
            '--seed-vulnerability',
            'weblogic/CVE-2017-10271=density',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True

    root = ET.parse(xml_path).getroot()
    scenario_el = root.find('Scenario')
    assert scenario_el is not None
    se = scenario_el.find('ScenarioEditor')
    assert se is not None

    vuln_items = se.findall("section[@name='Vulnerabilities']/item")
    assert len(vuln_items) == 2

    first = vuln_items[0]
    assert first.get('selected') == 'Specific'
    assert first.get('v_name') == 'jboss/CVE-2017-12149'
    assert first.get('v_path') == '/catalog/jboss/CVE-2017-12149/docker-compose.yml'
    assert first.get('v_metric') == 'Count'
    assert first.get('v_count') == '2'

    second = vuln_items[1]
    assert second.get('selected') == 'Specific'
    assert second.get('v_name') == 'weblogic/CVE-2017-10271'
    assert second.get('v_path') == '/catalog/weblogic/CVE-2017-10271/docker-compose.yml'
    assert second.get('v_metric') is None
    assert second.get('v_count') is None


def test_cli_new_phase_equalizes_multiple_density_seed_rows(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'multi-density-seeds.xml'
    argv0 = cli.sys.argv[:]

    def _fake_concretize(scenarios, *, seed=None):
        scenario = dict((scenarios or [])[0])
        sections = dict(scenario.get('sections') or {})

        traffic_section = dict(sections.get('Traffic') or {})
        traffic_items = list(traffic_section.get('items') or [])
        for item in traffic_items:
            if not isinstance(item, dict):
                continue
            item.update({
                'pattern': 'periodic',
                'content_type': 'text',
                'rate_kbps': 128.0,
                'period_s': 2.0,
                'jitter_pct': 15.0,
            })
        if traffic_items:
            traffic_section['items'] = traffic_items
            sections['Traffic'] = traffic_section

        scenario['sections'] = sections
        return [scenario]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(backend, '_concretize_scenarios_for_save', _fake_concretize)
    monkeypatch.setattr(
        backend,
        '_load_backend_vuln_catalog_items',
        lambda: [
            {'Name': 'jboss/CVE-2017-12149', 'Path': '/catalog/jboss/CVE-2017-12149/docker-compose.yml'},
            {'Name': 'weblogic/CVE-2017-10271', 'Path': '/catalog/weblogic/CVE-2017-10271/docker-compose.yml'},
        ],
    )
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'new',
            '--xml',
            str(xml_path),
            '--scenario',
            'multi-density-seeds',
            '--seed-routing',
            'OSPFv2',
            '--seed-routing',
            'BGP=density',
            '--seed-service',
            'SSH',
            '--seed-service',
            'HTTP=density',
            '--seed-traffic',
            'TCP',
            '--seed-traffic',
            'UDP=density',
            '--seed-segmentation',
            'Firewall',
            '--seed-segmentation',
            'NAT=density',
            '--seed-vulnerability',
            'jboss/CVE-2017-12149',
            '--seed-vulnerability',
            'weblogic/CVE-2017-10271=density',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True

    root = ET.parse(xml_path).getroot()
    se = root.find('./Scenario/ScenarioEditor')
    assert se is not None

    for section_name in ('Routing', 'Services', 'Traffic', 'Segmentation', 'Vulnerabilities'):
        items = se.findall(f"section[@name='{section_name}']/item")
        assert len(items) == 2
        factors = [float(item.get('factor') or 0.0) for item in items]
        assert factors == pytest.approx([0.5, 0.5])
        for item in items:
            assert item.get('v_metric') is None
            assert item.get('v_count') is None


def test_cli_new_phase_rejects_unknown_specific_vulnerability_seed(tmp_path, monkeypatch, capsys):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'unknown-specific-vuln-seed.xml'
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(backend, '_load_backend_vuln_catalog_items', lambda: [])
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'new',
            '--xml',
            str(xml_path),
            '--scenario',
            'unknown-specific-vuln-seed',
            '--seed-vulnerability',
            'jboss/CVE-2017-12149=1',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    payload = json.loads(capsys.readouterr().err)
    assert payload['ok'] is False
    assert 'Invalid --seed-vulnerability value' in payload['error']


def test_cli_new_phase_vm_mode_errors_when_vm_defaults_missing(tmp_path, monkeypatch, capsys):
    fake_backend = SimpleNamespace(
        _webui_runtime_mode=lambda: 'vm',
        _default_scenarios_payload_for_names=lambda names: {'scenarios': [{'name': list(names)[0], 'sections': {}, 'hitl': {'enabled': False, 'interfaces': []}}], 'core': {}},
        _core_backend_defaults=lambda include_password=True: {
            'host': '',
            'port': 0,
            'ssh_host': '',
            'ssh_port': 0,
            'ssh_username': '',
            'ssh_password': '' if include_password else '',
        },
        _normalize_core_config=lambda cfg, include_password=False: dict(cfg or {}),
        _webui_vm_mode_defaults=lambda include_password=False: {'hitl': {'enabled': True, 'interfaces': []}},
    )
    xml_path = tmp_path / 'starter.xml'
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: fake_backend)

    try:
        cli.sys.argv = ['scenarioforge.cli', 'new', '--xml', str(xml_path), '--scenario', 'vmtest']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    payload = json.loads(capsys.readouterr().err)
    assert payload['ok'] is False
    assert 'VM mode requires additional configuration' in payload['error']
    missing = payload.get('missing') if isinstance(payload.get('missing'), list) else []
    assert 'CORE_HOST / grpc host' in missing
    assert 'CORETG_VM_MODE_HITL_CORE_IFX_NAME (vm-mode HITL interface name)' in missing


def test_cli_flag_sequencing_vm_mode_requires_saved_core_connection(tmp_path, monkeypatch, capsys):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    fake_backend = SimpleNamespace(
        app=Flask(__name__),
        _scenario_names_from_xml=lambda _path: ['Scenario One'],
        _planner_persist_flow_plan=lambda **kwargs: {'xml_path': kwargs['xml_path'], 'scenario': kwargs['scenario']},
        _webui_runtime_mode=lambda: 'vm',
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda *_a, **_k: None,
        _merge_core_configs=lambda *configs, include_password=True: {'host': '', 'port': 0, 'ssh_host': '', 'ssh_port': 0, 'ssh_username': '', 'ssh_password': ''},
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: cfg,
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg or {}),
        _core_backend_defaults=lambda include_password=True: {'host': '', 'port': 0, 'ssh_host': '', 'ssh_port': 0, 'ssh_username': '', 'ssh_password': ''},
    )
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: fake_backend)

    try:
        cli.sys.argv = ['scenarioforge.cli', 'flag-sequencing', '--xml', str(xml_path), '--scenario', 'Scenario One']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    payload = json.loads(capsys.readouterr().err)
    assert payload['ok'] is False
    missing = payload.get('missing') if isinstance(payload.get('missing'), list) else []
    assert 'scenario XML is missing saved CORE VM connection data (CoreConnection or HardwareInLoop/CoreConnection)' in missing


def test_cli_vm_mode_execute_honors_xml_hitl_disabled_even_when_env_hitl_enabled():
    fake_backend = SimpleNamespace(
        _webui_runtime_mode=lambda: 'vm',
        _webui_vm_mode_defaults=lambda include_password=False: {
            'hitl': {
                'enabled': True,
                'interfaces': [{'name': 'ens19'}],
            },
        },
    )
    core_cfg = {
        'host': '127.0.0.1',
        'port': 50051,
        'ssh_host': '12.0.0.200',
        'ssh_port': 22,
        'ssh_username': 'core',
        'ssh_password': 'pw',
    }

    issues = cli._cli_vm_mode_config_issues(
        fake_backend,
        phase='execute',
        core_cfg=core_cfg,
        has_saved_core_source=True,
        hitl_config={'enabled': False, 'interfaces': []},
    )

    assert issues == []


def test_cli_vm_mode_execute_requires_interfaces_when_xml_hitl_enabled():
    fake_backend = SimpleNamespace(
        _webui_runtime_mode=lambda: 'vm',
        _webui_vm_mode_defaults=lambda include_password=False: {
            'hitl': {
                'enabled': False,
                'interfaces': [],
            },
        },
    )
    core_cfg = {
        'host': '127.0.0.1',
        'port': 50051,
        'ssh_host': '12.0.0.200',
        'ssh_port': 22,
        'ssh_username': 'core',
        'ssh_password': 'pw',
    }

    issues = cli._cli_vm_mode_config_issues(
        fake_backend,
        phase='execute',
        core_cfg=core_cfg,
        has_saved_core_source=True,
        hitl_config={'enabled': True, 'interfaces': []},
    )

    assert 'scenario XML HardwareInLoop interface configuration required by vm mode' in issues


def test_cli_vm_mode_execute_preflight_failure_emits_validation_summary(tmp_path, capsys):
    xml_path = tmp_path / 'scenario.xml'

    ret = cli._emit_vm_mode_cli_error(
        phase='execute',
        xml_path=str(xml_path),
        scenario_name='Scenario One',
        issues=['scenario XML is missing saved CORE VM connection data (CoreConnection or HardwareInLoop/CoreConnection)'],
        json_output=False,
        emit_validation_marker=True,
    )

    assert ret == 1
    summary = cli._extract_last_json_marker(capsys.readouterr().err, 'VALIDATION_SUMMARY_JSON:')
    assert summary is not None
    assert summary['ok'] is False
    assert summary['validation_unavailable'] is True
    assert summary['validation_unavailable_details'] == [
        'scenario XML is missing saved CORE VM connection data (CoreConnection or HardwareInLoop/CoreConnection)'
    ]


def test_cli_flag_sequencing_phase_invokes_backend_prepare_helper(tmp_path, monkeypatch, capsys):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    captured: dict[str, object] = {}
    app = Flask(__name__)

    sequence_calls: list[dict[str, object]] = []

    @app.route('/api/flag-sequencing/sequence_preview_plan', methods=['POST'])
    def api_flow_sequence_preview_plan():
        sequence_calls.append(request.get_json() or {})
        return jsonify({
            'ok': True,
            'chain': [{'id': 'node-a'}, {'id': 'node-b'}],
            'preview_plan_path': str(xml_path.resolve()),
        })

    def _fake_prepare(*, backend):
        captured['payload'] = request.get_json()
        return jsonify({'ok': True, 'flow_valid': True, 'flag_assignments': [], 'phase_result': 'resolved'})

    fake_backend = SimpleNamespace(
        app=app,
        _scenario_names_from_xml=lambda _path: ['Scenario One'],
        _planner_persist_flow_plan=lambda **kwargs: {
            'xml_path': kwargs['xml_path'],
            'scenario': kwargs['scenario'],
            'seed': 7,
            'preview_plan_path': kwargs['xml_path'],
            'full_preview': {},
            'plan': {},
        },
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda *_a, **_k: None,
        _merge_core_configs=lambda *configs, include_password=True: {},
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: cfg,
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg or {}),
    )
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: fake_backend)
    monkeypatch.setattr(flow_prepare_preview_execute, 'execute', _fake_prepare)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'flag-sequencing',
            '--xml',
            str(xml_path),
            '--flow-mode',
            'resolve',
            '--flow-length',
            '2',
            '--flow-chain-id',
            'node-a',
            '--flow-chain-id',
            'node-b',
            '--flow-run-local',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True
    assert payload['phase'] == 'flag-sequencing'
    sent = captured['payload']
    assert isinstance(sent, dict)
    assert sent['scenario'] == 'Scenario One'
    assert sent['preview_plan'] == str(xml_path.resolve())
    assert sent['mode'] == 'resolve'
    assert sent['length'] == 2
    assert sent['chain_ids'] == ['node-a', 'node-b']
    assert sent['run_local'] is True
    assert len(sequence_calls) == 1


def test_cli_flag_sequencing_phase_forces_remote_when_saved_remote_core_config_exists(tmp_path, monkeypatch, capsys):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    captured: dict[str, object] = {}
    app = Flask(__name__)

    @app.route('/api/flag-sequencing/sequence_preview_plan', methods=['POST'])
    def api_flow_sequence_preview_plan():
        return jsonify({
            'ok': True,
            'chain': [{'id': 'node-a'}],
            'preview_plan_path': str(xml_path.resolve()),
        })

    def _fake_prepare(*, backend):
        captured['payload'] = request.get_json()
        return jsonify({'ok': True, 'flow_valid': True, 'flag_assignments': [], 'phase_result': 'resolved'})

    fake_backend = SimpleNamespace(
        app=app,
        _scenario_names_from_xml=lambda _path: ['Scenario One'],
        _planner_persist_flow_plan=lambda **kwargs: {
            'xml_path': kwargs['xml_path'],
            'scenario': kwargs['scenario'],
            'seed': 7,
            'preview_plan_path': kwargs['xml_path'],
            'full_preview': {},
            'plan': {},
        },
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda *_a, **_k: {
            'host': '127.0.0.1',
            'port': 50051,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'ssh_enabled': True,
        },
        _select_core_config_for_page=lambda *_a, **_k: None,
        _load_run_history=lambda: [],
        _merge_core_configs=lambda *configs, include_password=True: {
            key: value for cfg in configs if isinstance(cfg, dict) for key, value in cfg.items()
        },
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: cfg,
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg or {}),
        _core_backend_defaults=lambda include_password=True: {},
    )
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: fake_backend)
    monkeypatch.setattr(flow_prepare_preview_execute, 'execute', _fake_prepare)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'flag-sequencing',
            '--xml',
            str(xml_path),
            '--flow-mode',
            'resolve',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True
    assert payload['generator_execution_requested'] is True
    assert payload['generator_execution_mode'] == 'remote'
    sent = captured['payload']
    assert isinstance(sent, dict)
    assert sent['run_remote'] is True


def test_cli_flag_sequencing_phase_runs_cleanup_by_default(tmp_path, monkeypatch, capsys):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    captured: dict[str, object] = {}
    cleanup_calls: list[dict[str, object]] = []
    app = Flask(__name__)

    @app.route('/api/flag-sequencing/sequence_preview_plan', methods=['POST'])
    def api_flow_sequence_preview_plan():
        return jsonify({
            'ok': True,
            'chain': [{'id': 'node-a'}],
            'preview_plan_path': str(xml_path.resolve()),
        })

    def _fake_prepare(*, backend):
        captured['payload'] = request.get_json()
        return jsonify({'ok': True, 'flow_valid': True, 'flag_assignments': [], 'phase_result': 'resolved'})

    fake_backend = SimpleNamespace(
        app=app,
        _scenario_names_from_xml=lambda _path: ['Scenario One'],
        _planner_persist_flow_plan=lambda **kwargs: {
            'xml_path': kwargs['xml_path'],
            'scenario': kwargs['scenario'],
            'seed': 7,
            'preview_plan_path': kwargs['xml_path'],
            'full_preview': {},
            'plan': {},
        },
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda *_a, **_k: {
            'host': '127.0.0.1',
            'port': 50051,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'ssh_enabled': True,
        },
        _select_core_config_for_page=lambda *_a, **_k: None,
        _load_run_history=lambda: [],
        _merge_core_configs=lambda *configs, include_password=True: {
            key: value for cfg in configs if isinstance(cfg, dict) for key, value in cfg.items()
        },
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: cfg,
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg or {}),
        _core_backend_defaults=lambda include_password=True: {},
    )
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: fake_backend)
    monkeypatch.setattr(flow_prepare_preview_execute, 'execute', _fake_prepare)
    monkeypatch.setattr(
        cli,
        '_best_effort_cli_flag_sequencing_cleanup',
        lambda args, **kwargs: cleanup_calls.append({'phase': args.phase, **kwargs}),
    )
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'flag-sequencing',
            '--xml',
            str(xml_path),
            '--flow-mode',
            'resolve',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True
    assert cleanup_calls
    assert cleanup_calls[0]['run_remote'] is True


def test_cli_flag_sequencing_phase_uses_explicit_xml_for_remote_core_config(tmp_path, monkeypatch, capsys):
    raw_xml_path = tmp_path / 'raw.xml'
    latest_xml_path = tmp_path / 'latest.xml'
    raw_xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    latest_xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    captured: dict[str, object] = {}
    persist_calls: list[str] = []
    app = Flask(__name__)

    @app.route('/api/flag-sequencing/sequence_preview_plan', methods=['POST'])
    def api_flow_sequence_preview_plan():
        return jsonify({
            'ok': True,
            'chain': [{'id': 'node-a'}],
            'preview_plan_path': str(latest_xml_path.resolve()),
        })

    def _fake_prepare(*, backend):
        captured['payload'] = request.get_json()
        return jsonify({'ok': True, 'flow_valid': True, 'flag_assignments': [], 'phase_result': 'resolved'})

    fake_backend = SimpleNamespace(
        app=app,
        _resolve_preexecute_xml_path=lambda _xml_path, _scenario: str(latest_xml_path.resolve()),
        _scenario_names_from_xml=lambda _path: ['Scenario One'],
        _planner_persist_flow_plan=lambda **kwargs: persist_calls.append(str(kwargs['xml_path'])) or {
            'xml_path': kwargs['xml_path'],
            'scenario': kwargs['scenario'],
            'seed': 7,
            'preview_plan_path': kwargs['xml_path'],
            'full_preview': {},
            'plan': {},
        },
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda xml_path, *_a, **_k: {
            'host': '127.0.0.1',
            'port': 50051,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
            'ssh_enabled': True,
        } if str(xml_path) == str(raw_xml_path.resolve()) else None,
        _select_core_config_for_page=lambda *_a, **_k: None,
        _load_run_history=lambda: [],
        _merge_core_configs=lambda *configs, include_password=True: {
            key: value for cfg in configs if isinstance(cfg, dict) for key, value in cfg.items()
        },
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: cfg,
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg or {}),
        _core_backend_defaults=lambda include_password=True: {},
    )
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: fake_backend)
    monkeypatch.setattr(flow_prepare_preview_execute, 'execute', _fake_prepare)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'flag-sequencing',
            '--xml',
            str(raw_xml_path),
            '--flow-mode',
            'resolve',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True
    assert persist_calls == [str(raw_xml_path.resolve())]
    sent = captured['payload']
    assert isinstance(sent, dict)
    assert sent['preview_plan'] == str(latest_xml_path.resolve())
    assert sent['run_remote'] is True


def test_cli_flag_sequencing_phase_bypasses_login_gate_for_internal_sequence_route(tmp_path, monkeypatch, capsys):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    captured: dict[str, object] = {}
    app = Flask(__name__)

    @app.before_request
    def _block_api_requests():
        return jsonify({'ok': False, 'error': 'Login required'}), 401

    @app.route('/api/flag-sequencing/sequence_preview_plan', methods=['POST'])
    def api_flow_sequence_preview_plan():
        return jsonify({
            'ok': True,
            'chain': [{'id': 'node-a'}],
            'preview_plan_path': str(xml_path.resolve()),
        })

    def _fake_prepare(*, backend):
        captured['payload'] = request.get_json()
        return jsonify({'ok': True, 'flow_valid': True, 'flag_assignments': [], 'phase_result': 'resolved'})

    fake_backend = SimpleNamespace(
        app=app,
        _scenario_names_from_xml=lambda _path: ['Scenario One'],
        _planner_persist_flow_plan=lambda **kwargs: {
            'xml_path': kwargs['xml_path'],
            'scenario': kwargs['scenario'],
            'seed': 7,
            'preview_plan_path': kwargs['xml_path'],
            'full_preview': {},
            'plan': {},
        },
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda *_a, **_k: None,
        _merge_core_configs=lambda *configs, include_password=True: {},
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: cfg,
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg or {}),
    )
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: fake_backend)
    monkeypatch.setattr(flow_prepare_preview_execute, 'execute', _fake_prepare)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'flag-sequencing',
            '--xml',
            str(xml_path),
            '--flow-mode',
            'resolve',
            '--flow-run-local',
        ]
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True
    sent = captured['payload']
    assert isinstance(sent, dict)
    assert sent['scenario'] == 'Scenario One'


def test_cli_topo_phase_stops_after_topology_build(tmp_path, monkeypatch, capsys):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="s"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    argv0 = cli.sys.argv[:]

    monkeypatch.setattr(cli, '_maybe_seed_docker_sudo_password_from_stdin', lambda: None)
    monkeypatch.setattr(cli, '_maybe_delegate_cli_to_remote', lambda *a, **k: None)
    monkeypatch.setattr(cli, '_export_flow_assignments_to_env', lambda *a, **k: None)
    monkeypatch.setattr(cli, 'parse_node_info', lambda *a, **k: (1, [('Host', 1.0)], [], []))
    monkeypatch.setattr(cli, 'parse_planning_metadata', lambda *a, **k: {})
    monkeypatch.setattr(cli, 'parse_hitl_info', lambda *a, **k: {'enabled': False, 'interfaces': []})
    monkeypatch.setattr(cli, 'compute_role_counts', lambda *a, **k: {'Host': 1})
    monkeypatch.setattr(cli, 'parse_routing_info', lambda *a, **k: (0.1, []))
    monkeypatch.setattr(cli, 'parse_segmentation_info', lambda *a, **k: (0.0, []))
    monkeypatch.setattr(cli, 'parse_traffic_info', lambda *a, **k: (0.0, []))
    monkeypatch.setattr(cli, 'parse_vulnerabilities_info', lambda *a, **k: (0.0, [], None))
    monkeypatch.setattr(cli, 'parse_pivoting_info', lambda *a, **k: (0.0, []))
    monkeypatch.setattr(cli, 'load_vuln_catalog', lambda *a, **k: [])
    monkeypatch.setattr(cli, 'assign_compose_to_nodes', lambda *a, **k: {})
    monkeypatch.setattr(cli, '_flow_state_from_xml', lambda *a, **k: None)
    monkeypatch.setattr(cli, 'collect_hitl_preview_ip_reservations', lambda *_a, **_k: {'ip_addresses': set(), 'network_cidrs': set()})
    monkeypatch.setattr(cli, 'build_full_preview', lambda *a, **k: {'hosts': [], 'routers': [], 'switches_detail': []})
    monkeypatch.setattr(cli, 'attach_hitl_rj45_nodes', lambda *a, **k: {'enabled': False, 'interfaces': []})
    monkeypatch.setattr(cli, '_core_session_id', lambda *_a, **_k: 77)
    monkeypatch.setattr(cli, 'write_report', lambda *a, **k: pytest.fail('topo phase should stop before report generation'))
    monkeypatch.setattr(cli, 'CORE_GRPC_AVAILABLE', True)
    monkeypatch.setattr(cli, 'client', SimpleNamespace(CoreGrpcClient=lambda address: _FakeCoreClient()))
    monkeypatch.setattr(
        cli,
        'build_segmented_topology',
        lambda *a, **k: (
            _FakeSession(),
            [SimpleNamespace(node_id=1)],
            [SimpleNamespace(node_id=2)],
            {'2': ['HTTP']},
            {'1': ['OSPF']},
            {'docker-1': {'Type': 'docker-compose'}},
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        'compute_full_plan',
        lambda *a, **k: {
            'routers_planned': 1,
            'role_counts': {'Host': 1},
            'service_plan': {},
            'vulnerability_plan': {},
            'traffic_plan': None,
            'breakdowns': {
                'router': {'simple_plan': {}},
                'segmentation': {'density': 0.0, 'raw_items_serialized': []},
            },
        },
    )

    try:
        cli.sys.argv = ['scenarioforge.cli', 'topo', '--xml', str(xml_path), '--scenario', 's']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True
    assert payload['phase'] == 'topo'
    assert payload['scenario'] == 's'
    assert payload['session_id'] == 77
    assert payload['session_started'] is False
    assert payload['routers_count'] == 1
    assert payload['hosts_count'] == 1
    assert payload['docker_nodes'] == ['docker-1']


def test_cli_topo_phase_uses_explicit_xml_as_ground_truth(tmp_path, monkeypatch, capsys):
    raw_xml_path = tmp_path / 'raw.xml'
    latest_xml_path = tmp_path / 'latest.xml'
    raw_xml_path.write_text('<Scenarios><Scenario name="s"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    latest_xml_path.write_text('<Scenarios><Scenario name="s"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    argv0 = cli.sys.argv[:]
    captured: dict[str, str] = {}

    fake_backend = SimpleNamespace(
        _resolve_preexecute_xml_path=lambda _xml_path, _scenario: str(latest_xml_path.resolve()),
        _scenario_names_from_xml=lambda _path: ['s'],
        _sanitize_hitl_config=lambda cfg, *_args: cfg,
    )

    def _capture_parse_node_info(xml_path, *args, **kwargs):
        captured['xml_path'] = str(xml_path)
        return (1, [('Host', 1.0)], [], [])

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: fake_backend)
    monkeypatch.setattr(cli, '_maybe_seed_docker_sudo_password_from_stdin', lambda: None)
    monkeypatch.setattr(cli, '_maybe_delegate_cli_to_remote', lambda *a, **k: None)
    monkeypatch.setattr(cli, '_export_flow_assignments_to_env', lambda *a, **k: None)
    monkeypatch.setattr(cli, 'parse_node_info', _capture_parse_node_info)
    monkeypatch.setattr(cli, 'parse_planning_metadata', lambda *a, **k: {})
    monkeypatch.setattr(cli, 'parse_hitl_info', lambda *a, **k: {'enabled': False, 'interfaces': []})
    monkeypatch.setattr(cli, 'compute_role_counts', lambda *a, **k: {'Host': 1})
    monkeypatch.setattr(cli, 'parse_routing_info', lambda *a, **k: (0.1, []))
    monkeypatch.setattr(cli, 'parse_segmentation_info', lambda *a, **k: (0.0, []))
    monkeypatch.setattr(cli, 'parse_traffic_info', lambda *a, **k: (0.0, []))
    monkeypatch.setattr(cli, 'parse_vulnerabilities_info', lambda *a, **k: (0.0, [], None))
    monkeypatch.setattr(cli, 'parse_pivoting_info', lambda *a, **k: (0.0, []))
    monkeypatch.setattr(cli, 'load_vuln_catalog', lambda *a, **k: [])
    monkeypatch.setattr(cli, 'assign_compose_to_nodes', lambda *a, **k: {})
    monkeypatch.setattr(cli, '_flow_state_from_xml', lambda *a, **k: None)
    monkeypatch.setattr(cli, 'collect_hitl_preview_ip_reservations', lambda *_a, **_k: {'ip_addresses': set(), 'network_cidrs': set()})
    monkeypatch.setattr(cli, 'build_full_preview', lambda *a, **k: {'hosts': [], 'routers': [], 'switches_detail': []})
    monkeypatch.setattr(cli, 'attach_hitl_rj45_nodes', lambda *a, **k: {'enabled': False, 'interfaces': []})
    monkeypatch.setattr(cli, '_core_session_id', lambda *_a, **_k: 77)
    monkeypatch.setattr(cli, 'write_report', lambda *a, **k: pytest.fail('topo phase should stop before report generation'))
    monkeypatch.setattr(cli, 'CORE_GRPC_AVAILABLE', True)
    monkeypatch.setattr(cli, 'client', SimpleNamespace(CoreGrpcClient=lambda address: _FakeCoreClient()))
    monkeypatch.setattr(
        cli,
        'build_segmented_topology',
        lambda *a, **k: (
            _FakeSession(),
            [SimpleNamespace(node_id=1)],
            [SimpleNamespace(node_id=2)],
            {'2': ['HTTP']},
            {'1': ['OSPF']},
            {'docker-1': {'Type': 'docker-compose'}},
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        'compute_full_plan',
        lambda *a, **k: {
            'routers_planned': 1,
            'role_counts': {'Host': 1},
            'service_plan': {},
            'vulnerability_plan': {},
            'traffic_plan': None,
            'breakdowns': {
                'router': {'simple_plan': {}},
                'segmentation': {'density': 0.0, 'raw_items_serialized': []},
            },
        },
    )

    try:
        cli.sys.argv = ['scenarioforge.cli', 'topo', '--xml', str(raw_xml_path), '--scenario', 's']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok'] is True
    assert captured['xml_path'] == str(raw_xml_path.resolve())
    assert payload['xml_path'] == str(raw_xml_path.resolve())


def test_cli_execute_phase_validates_hitl_interfaces_before_remote_delegate(tmp_path, monkeypatch):
    from webapp import app_backend as backend

    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario A"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    argv0 = cli.sys.argv[:]
    captured: dict[str, str] = {}

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(cli, '_maybe_seed_docker_sudo_password_from_stdin', lambda: None)
    monkeypatch.setattr(backend, '_resolve_preexecute_xml_path', lambda path, _scenario: str(path))
    monkeypatch.setattr(backend, '_scenario_names_from_xml', lambda _path: ['Scenario A'])
    monkeypatch.setattr(
        backend,
        '_parse_scenarios_xml',
        lambda _path: {
            'scenarios': [
                {
                    'name': 'Scenario A',
                    'hitl': {
                        'enabled': True,
                        'interfaces': [
                            {'name': 'net1', 'proxmox_target': {'interface_id': 'net1'}},
                        ],
                    },
                }
            ],
            'core': {'ssh_enabled': True},
        },
    )
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *_a, **_k: {'ssh_enabled': True, 'core_secret_id': 'core-secret-1'})
    monkeypatch.setattr(backend, '_select_core_config_for_page', lambda *_a, **_k: {'ssh_enabled': True, 'ssh_password': 'pw'})
    monkeypatch.setattr(
        backend,
        '_merge_core_configs',
        lambda *configs, include_password=True: {k: v for cfg in configs if isinstance(cfg, dict) for k, v in cfg.items()},
    )
    monkeypatch.setattr(backend, '_prefer_explicit_or_ssh_core_host', lambda cfg, *_a, **_k: cfg)
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, _norm: dict(cfg))
    monkeypatch.setattr(backend, '_normalize_core_config', lambda cfg, include_password=True: dict(cfg))
    monkeypatch.setattr(backend, '_outputs_dir', lambda: str(tmp_path))
    monkeypatch.setattr(
        backend,
        '_validate_hitl_interface_names_for_execute',
        lambda _hitl_cfg, _core_cfg: (
            {
                'enabled': True,
                'interfaces': [
                    {'name': 'ens19', 'proxmox_target': {'interface_id': 'net1'}},
                ],
            },
            [],
            [{'index': 0, 'from': 'net1', 'to': 'ens19', 'selector': 'net1'}],
        ),
    )

    def _capture_delegate(args, *, backend, scenario_name):
        captured['xml_path'] = str(args.xml)
        return 0

    monkeypatch.setattr(cli, '_maybe_delegate_cli_to_remote', _capture_delegate)

    try:
        cli.sys.argv = ['scenarioforge.cli', 'execute', '--xml', str(xml_path), '--scenario', 'Scenario A']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    assert captured['xml_path'] != str(xml_path.resolve())
    rewritten_text = open(captured['xml_path'], 'r', encoding='utf-8').read()
    assert 'name="ens19"' in rewritten_text


def test_cli_execute_remote_delegated_skips_repeat_hitl_validation(tmp_path, monkeypatch):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario A"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    argv0 = cli.sys.argv[:]

    fake_backend = SimpleNamespace(
        _resolve_preexecute_xml_path=lambda path, _scenario: str(path),
        _scenario_names_from_xml=lambda _path: ['Scenario A'],
    )

    def _fail_repeat_hitl(*args, **kwargs):
        raise AssertionError('remote delegated CLI should not repeat HITL validation')

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: fake_backend)
    monkeypatch.setattr(cli, '_maybe_seed_docker_sudo_password_from_stdin', lambda: None)
    monkeypatch.setattr(cli, '_maybe_prepare_cli_execute_hitl_xml', _fail_repeat_hitl)
    monkeypatch.setattr(cli, '_maybe_delegate_cli_to_remote', lambda *a, **k: 0)
    monkeypatch.setattr(cli, 'parse_hitl_info', lambda *a, **k: {'enabled': False, 'interfaces': []})
    monkeypatch.setenv('CORETG_CLI_REMOTE_DELEGATED', '1')

    try:
        cli.sys.argv = ['scenarioforge.cli', 'execute', '--xml', str(xml_path), '--scenario', 'Scenario A']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0
        monkeypatch.delenv('CORETG_CLI_REMOTE_DELEGATED', raising=False)

    assert ret == 0


def test_cli_execute_remote_delegated_skips_repeat_saved_xml_resolution(tmp_path, monkeypatch):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario A"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    argv0 = cli.sys.argv[:]

    fake_backend = SimpleNamespace(
        _scenario_names_from_xml=lambda _path: ['Scenario A'],
        _resolve_preexecute_xml_path=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError('remote delegated CLI should not repeat saved XML resolution')),
    )

    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: fake_backend)
    monkeypatch.setattr(cli, '_maybe_seed_docker_sudo_password_from_stdin', lambda: None)
    monkeypatch.setattr(cli, '_maybe_prepare_cli_execute_hitl_xml', lambda *a, **k: ([], []))
    monkeypatch.setattr(cli, '_maybe_delegate_cli_to_remote', lambda *a, **k: 0)
    monkeypatch.setattr(cli, 'parse_hitl_info', lambda *a, **k: {'enabled': False, 'interfaces': []})
    monkeypatch.setenv('CORETG_CLI_REMOTE_DELEGATED', '1')

    try:
        cli.sys.argv = ['scenarioforge.cli', 'execute', '--xml', str(xml_path), '--scenario', 'Scenario A']
        ret = cli.main()
    finally:
        cli.sys.argv = argv0
        monkeypatch.delenv('CORETG_CLI_REMOTE_DELEGATED', raising=False)

    assert ret == 0


def test_cli_resolve_core_context_uses_saved_xml_core_and_cli_overrides(tmp_path):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')

    def _merge_core_configs(*configs, include_password=True):
        merged = {}
        for cfg in configs:
            if isinstance(cfg, dict):
                merged.update(cfg)
        return merged

    fake_backend = SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda *_a, **_k: {
            'host': '10.0.0.9',
            'port': 50051,
            'ssh_host': '12.0.0.100',
            'ssh_port': 9001,
            'ssh_username': 'core',
            'core_secret_id': 'sec-1',
        },
        _select_core_config_for_page=lambda *_a, **_k: {
            'host': '127.0.0.1',
            'port': 50052,
            'ssh_host': 'saved.example.test',
            'ssh_port': 2222,
            'ssh_username': 'saved-user',
            'ssh_password': 'pw',
            'venv_bin': '/opt/core/venv/bin',
            'core_secret_id': 'saved-secret',
            'vm_key': 'saved::vm',
        },
        _load_run_history=lambda: [],
        _merge_core_configs=_merge_core_configs,
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: dict(cfg, ssh_password=cfg.get('ssh_password') or 'pw'),
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg),
    )
    args = SimpleNamespace(xml=str(xml_path), host='198.51.100.4', port=50051)
    argv0 = cli.sys.argv[:]

    try:
        cli.sys.argv = ['scenarioforge.cli', 'execute', '--xml', str(xml_path), '--host', '198.51.100.4']
        scenario_norm, cfg, has_saved_core_source = cli._resolve_cli_core_context(
            args,
            backend=fake_backend,
            scenario_name='Scenario One',
        )
    finally:
        cli.sys.argv = argv0

    assert scenario_norm == 'scenario-one'
    assert has_saved_core_source is True
    assert cfg['host'] == '198.51.100.4'
    assert cfg['port'] == 50051
    assert cfg['ssh_host'] == '12.0.0.100'
    assert cfg['ssh_port'] == 9001
    assert cfg['ssh_username'] == 'core'
    assert cfg['ssh_password'] == 'pw'
    assert cfg['core_secret_id'] == 'sec-1'
    assert cfg.get('vm_key') is None


def test_cli_execute_delegates_to_remote_cli_for_saved_remote_core_config(tmp_path, monkeypatch, capsys):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    fake_client = _FakeSshClient(exit_code=0)
    custom_service_installs = []
    validation_calls = []
    copy_calls = []

    def _merge_core_configs(*configs, include_password=True):
        merged = {}
        for cfg in configs:
            if isinstance(cfg, dict):
                merged.update(cfg)
        return merged

    fake_backend = SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda *_a, **_k: {
            'host': '127.0.0.1',
            'port': 50051,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        _select_core_config_for_page=lambda *_a, **_k: {},
        _load_run_history=lambda: [],
        _merge_core_configs=_merge_core_configs,
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: dict(cfg),
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg),
        _require_core_ssh_credentials=lambda cfg: dict(cfg),
        _open_ssh_client=lambda cfg: fake_client,
        _install_custom_services_to_core_vm=lambda client, **kwargs: custom_service_installs.append(
            (client, kwargs.get('sudo_password'))
        ),
        _prepare_remote_cli_context=lambda **kwargs: {
            'xml_path': '/tmp/remote/scenario.xml',
            'preview_plan_path': None,
            'repo_dir': '/tmp/remote/repo',
            'base_dir': '/tmp/remote',
        },
        _select_remote_python_interpreter=lambda *_a, **_k: '/opt/core/venv/bin/python',
        _remote_core_target_host=lambda *_a, **_k: '127.0.0.1',
        _coerce_bool=lambda value: bool(value),
        _relay_remote_channel_to_log=lambda _channel, handle, redact_tokens=None: handle.write(
            'CORE_SESSION_ID: 41\nREMOTE CLI OK\n'
        ),
        _extract_session_id_from_text=lambda text: 41 if 'CORE_SESSION_ID: 41' in text else None,
        _list_active_core_sessions_via_remote_python=lambda *_a, **_k: [
            {'id': 41, 'state': 'RUNTIME', 'nodes': 3}
        ],
        _grpc_save_current_session_xml_with_config=lambda _cfg, _out_dir, session_id=None: str(
            tmp_path / f'session-{session_id}.xml'
        ),
        _validate_session_nodes_and_injects=lambda **kwargs: (
            validation_calls.append(kwargs)
            or (
                {
                    'ok': False,
                    'injects_missing': ['docker-3'],
                    'expected_nodes': ['router-1', 'docker-3'],
                    'docker_running': ['docker-3'],
                }
                if len(validation_calls) == 1
                else {
                    'ok': True,
                    'injects_missing': [],
                    'expected_nodes': ['router-1', 'docker-3'],
                    'docker_running': ['docker-3'],
                }
            )
        ),
        _maybe_copy_flow_artifacts_into_containers=lambda meta, **kwargs: (
            copy_calls.append((meta, kwargs)),
            meta.__setitem__('flow_artifacts_copied', True),
        ),
    )
    args = SimpleNamespace(
        phase='execute',
        xml=str(xml_path),
        preview_plan=None,
        scenario='Scenario One',
        host='localhost',
        port=50051,
        post_execution_validation=True,
    )
    argv0 = cli.sys.argv[:]
    monkeypatch.setattr(
        cli,
        '_flow_state_from_xml',
        lambda *_a, **_k: {
            'flow_enabled': True,
            'chain_ids': ['3'],
            'flag_assignments': [{'node_id': '3', 'inject_files': ['service']}],
        },
    )

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'execute',
            '--xml',
            str(xml_path),
            '--scenario',
            'Scenario One',
            '-post-execution-validation',
        ]
        ret = cli._maybe_delegate_cli_to_remote(args, backend=fake_backend, scenario_name='Scenario One')
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    assert custom_service_installs == [(fake_client, 'pw')]
    assert fake_client.command is not None
    assert 'CORETG_CLI_REMOTE_DELEGATED=1' in fake_client.command
    assert 'scenarioforge.cli execute --xml /tmp/remote/scenario.xml' in fake_client.command
    assert '--host 127.0.0.1' in fake_client.command
    assert '--port 50051' in fake_client.command
    assert 'post-execution-validation' not in fake_client.command
    assert fake_client.stdin.sent == ['pw\n']
    assert len(validation_calls) == 2
    assert len(copy_calls) == 2
    assert copy_calls[0][1]['stage'] == 'cli-postrun'
    assert copy_calls[1][1]['stage'] == 'cli-validation-retry'
    assert validation_calls[0]['scenario_xml_path'] == str(xml_path.resolve())
    assert validation_calls[0]['session_xml_path'].endswith('session-41.xml')
    validation_artifact = tmp_path / 'core-post' / 'validation-session-41.json'
    assert validation_artifact.exists()
    validation_payload = json.loads(validation_artifact.read_text(encoding='utf-8'))
    assert validation_payload['injects_missing'] == []
    assert validation_payload['flow_copy_retried_after_validation'] is True
    captured = capsys.readouterr()
    assert '[remote] Preparing remote workspace and uploads...' in captured.out
    assert '[remote] Refreshing custom CORE services...' in captured.out
    assert '[remote] Starting CLI execution...' in captured.out
    assert '[remote] Verified CORE session 41 is RUNTIME' in captured.out
    assert 'REMOTE CLI OK' in captured.out
    assert 'Missing injects detected after copy; repairing once and revalidating' in captured.out
    assert 'Post-execution validation: PASSED' in captured.out


def test_cli_remote_execute_start_failure_emits_validation_summary(tmp_path, monkeypatch, capsys):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text(
        '<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>',
        encoding='utf-8',
    )
    fake_client = _FakeSshClient(exit_code=1)

    def _merge_core_configs(*configs, include_password=True):
        merged = {}
        for cfg in configs:
            if isinstance(cfg, dict):
                merged.update(cfg)
        return merged

    fake_backend = SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda *_a, **_k: {
            'host': '127.0.0.1',
            'port': 50051,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        _select_core_config_for_page=lambda *_a, **_k: {},
        _load_run_history=lambda: [],
        _merge_core_configs=_merge_core_configs,
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: dict(cfg),
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg),
        _require_core_ssh_credentials=lambda cfg: dict(cfg),
        _open_ssh_client=lambda cfg: fake_client,
        _prepare_remote_cli_context=lambda **kwargs: {
            'xml_path': '/tmp/remote/scenario.xml',
            'preview_plan_path': None,
            'repo_dir': '/tmp/remote/repo',
            'base_dir': '/tmp/remote',
        },
        _select_remote_python_interpreter=lambda *_a, **_k: '/opt/core/venv/bin/python',
        _remote_core_target_host=lambda *_a, **_k: '127.0.0.1',
        _coerce_bool=lambda value: bool(value),
        _relay_remote_channel_to_log=lambda _channel, handle, redact_tokens=None: handle.write(
            'CORE_SESSION_ID: 41\n'
            '2026-06-22 ERROR root - Start validation failed: '
            'CORE session stayed in "configuration"\n'
        ),
    )
    args = SimpleNamespace(
        phase='execute',
        xml=str(xml_path),
        preview_plan=None,
        scenario='Scenario One',
        host='localhost',
        port=50051,
        post_execution_validation=True,
    )
    argv0 = cli.sys.argv[:]

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'execute',
            '--xml',
            str(xml_path),
            '--scenario',
            'Scenario One',
            '--post-execution-validation',
        ]
        ret = cli._maybe_delegate_cli_to_remote(
            args,
            backend=fake_backend,
            scenario_name='Scenario One',
        )
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    output = capsys.readouterr().out
    summary = cli._extract_last_json_marker(output, 'VALIDATION_SUMMARY_JSON:')
    assert summary is not None
    assert summary['validation_unavailable'] is True
    assert 'CORE session stayed in' in summary['error']


def test_cli_remote_parent_accepts_child_validated_configuration_session(tmp_path, monkeypatch, capsys):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text(
        '<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>',
        encoding='utf-8',
    )
    fake_client = _FakeSshClient(exit_code=0)

    def _merge_core_configs(*configs, include_password=True):
        merged = {}
        for cfg in configs:
            if isinstance(cfg, dict):
                merged.update(cfg)
        return merged

    fake_backend = SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda *_a, **_k: {
            'host': '127.0.0.1',
            'port': 50051,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        _select_core_config_for_page=lambda *_a, **_k: {},
        _load_run_history=lambda: [],
        _merge_core_configs=_merge_core_configs,
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: dict(cfg),
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg),
        _require_core_ssh_credentials=lambda cfg: dict(cfg),
        _open_ssh_client=lambda cfg: fake_client,
        _prepare_remote_cli_context=lambda **kwargs: {
            'xml_path': '/tmp/remote/scenario.xml',
            'preview_plan_path': None,
            'repo_dir': '/tmp/remote/repo',
            'base_dir': '/tmp/remote',
        },
        _select_remote_python_interpreter=lambda *_a, **_k: '/opt/core/venv/bin/python',
        _remote_core_target_host=lambda *_a, **_k: '127.0.0.1',
        _coerce_bool=lambda value: bool(value),
        _relay_remote_channel_to_log=lambda _channel, handle, redact_tokens=None: handle.write(
            'CORE_SESSION_ID: 42\n'
            'CORE_SESSION_VALIDATION_JSON: '
            '{"configuration_tolerated":true,"runtime_ok":false,'
            '"session_id":42,"state":"configuration","validation_ok":true}\n'
        ),
        _extract_session_id_from_text=lambda text: 42,
        _list_active_core_sessions_via_remote_python=lambda *_a, **_k: [
            {'id': 42, 'state': 'CONFIGURATION', 'nodes': 2}
        ],
    )
    args = SimpleNamespace(
        phase='execute',
        xml=str(xml_path),
        preview_plan=None,
        scenario='Scenario One',
        host='localhost',
        port=50051,
        post_execution_validation=False,
    )
    argv0 = cli.sys.argv[:]

    try:
        cli.sys.argv = [
            'scenarioforge.cli',
            'execute',
            '--xml',
            str(xml_path),
            '--scenario',
            'Scenario One',
        ]
        ret = cli._maybe_delegate_cli_to_remote(
            args,
            backend=fake_backend,
            scenario_name='Scenario One',
        )
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    assert 'Verified CORE session 42 is CONFIGURATION' in capsys.readouterr().out


def test_cli_execute_remote_delegate_includes_resolved_scenario_and_preview_plan(tmp_path, monkeypatch):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    fake_client = _FakeSshClient(exit_code=0)

    def _merge_core_configs(*configs, include_password=True):
        merged = {}
        for cfg in configs:
            if isinstance(cfg, dict):
                merged.update(cfg)
        return merged

    fake_backend = SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda *_a, **_k: {
            'host': '127.0.0.1',
            'port': 50051,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        _select_core_config_for_page=lambda *_a, **_k: {},
        _load_run_history=lambda: [],
        _merge_core_configs=_merge_core_configs,
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: dict(cfg),
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg),
        _require_core_ssh_credentials=lambda cfg: dict(cfg),
        _open_ssh_client=lambda cfg: fake_client,
        _prepare_remote_cli_context=lambda **kwargs: {
            'xml_path': '/tmp/remote/scenario.xml',
            'preview_plan_path': '/tmp/remote/preview.xml',
            'repo_dir': '/tmp/remote/repo',
            'base_dir': '/tmp/remote',
        },
        _select_remote_python_interpreter=lambda *_a, **_k: '/opt/core/venv/bin/python',
        _remote_core_target_host=lambda *_a, **_k: '127.0.0.1',
        _coerce_bool=lambda value: bool(value),
        _relay_remote_channel_to_log=lambda _channel, handle, redact_tokens=None: handle.write(
            'CORE_SESSION_ID: 42\nREMOTE CLI OK\n'
        ),
        _extract_session_id_from_text=lambda text: 42 if 'CORE_SESSION_ID: 42' in text else None,
        _list_active_core_sessions_via_remote_python=lambda *_a, **_k: [
            {'id': 42, 'state': 'RUNTIME', 'nodes': 3}
        ],
    )
    args = SimpleNamespace(
        phase='execute',
        xml=str(xml_path),
        preview_plan=None,
        scenario='Scenario One',
        host='localhost',
        port=50051,
        _resolved_preview_plan_path=str(xml_path),
    )
    argv0 = cli.sys.argv[:]

    try:
        cli.sys.argv = ['scenarioforge.cli', 'execute', '--xml', str(xml_path)]
        ret = cli._maybe_delegate_cli_to_remote(args, backend=fake_backend, scenario_name='Scenario One')
    finally:
        cli.sys.argv = argv0

    assert ret == 0
    assert fake_client.command is not None
    assert '--scenario ' in fake_client.command
    assert 'Scenario One' in fake_client.command
    assert '--preview-plan /tmp/remote/preview.xml' in fake_client.command


def test_cli_execute_vm_mode_requires_saved_xml_core_config_even_when_env_remote_exists(tmp_path, monkeypatch, caplog, capsys):
    xml_path = tmp_path / 'scenario.xml'
    xml_path.write_text('<Scenarios><Scenario name="Scenario One"><ScenarioEditor /></Scenario></Scenarios>', encoding='utf-8')
    fake_client = _FakeSshClient(exit_code=0)

    def _merge_core_configs(*configs, include_password=True):
        merged = {
            'host': '127.0.0.1',
            'port': 50051,
            'ssh_host': '12.0.0.200',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        }
        for cfg in configs:
            if isinstance(cfg, dict):
                merged.update(cfg)
        return merged

    fake_backend = SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower().replace(' ', '-'),
        _core_config_from_xml_path=lambda *_a, **_k: None,
        _core_backend_defaults=lambda include_password=True: {
            'host': '127.0.0.1',
            'port': 50051,
            'ssh_host': '12.0.0.200',
            'ssh_port': 22,
            'ssh_username': 'core',
            'ssh_password': 'pw',
        },
        _select_core_config_for_page=lambda *_a, **_k: {},
        _load_run_history=lambda: [],
        _merge_core_configs=_merge_core_configs,
        _prefer_explicit_or_ssh_core_host=lambda cfg, *_a, **_k: cfg,
        _apply_core_secret_to_config=lambda cfg, _norm: dict(cfg),
        _normalize_core_config=lambda cfg, include_password=True: dict(cfg),
        _require_core_ssh_credentials=lambda cfg: dict(cfg),
        _open_ssh_client=lambda cfg: fake_client,
        _prepare_remote_cli_context=lambda **kwargs: {
            'xml_path': '/tmp/remote-env/scenario.xml',
            'preview_plan_path': None,
            'repo_dir': '/tmp/remote-env/repo',
            'base_dir': '/tmp/remote-env',
        },
        _select_remote_python_interpreter=lambda *_a, **_k: '/opt/core/venv/bin/python',
        _remote_core_target_host=lambda *_a, **_k: '127.0.0.1',
        _coerce_bool=lambda value: bool(value),
        _relay_remote_channel_to_log=lambda _channel, handle, redact_tokens=None: handle.write('REMOTE ENV CLI OK\n'),
        _webui_runtime_mode=lambda: 'vm',
    )
    args = SimpleNamespace(
        phase='execute',
        xml=str(xml_path),
        preview_plan=None,
        host='localhost',
        port=50051,
        post_execution_validation=True,
    )
    argv0 = cli.sys.argv[:]

    try:
        caplog.set_level('ERROR')
        cli.sys.argv = ['scenarioforge.cli', 'execute', '--xml', str(xml_path), '--scenario', 'Scenario One']
        ret = cli._maybe_delegate_cli_to_remote(args, backend=fake_backend, scenario_name='Scenario One')
    finally:
        cli.sys.argv = argv0

    assert ret == 1
    summary = cli._extract_last_json_marker(capsys.readouterr().err, 'VALIDATION_SUMMARY_JSON:')
    assert summary is not None
    assert summary['validation_unavailable'] is True
    assert any('VM mode requires additional configuration before the execute phase can run.' in rec.message for rec in caplog.records)
    assert any('scenario XML is missing saved CORE VM connection data' in rec.message for rec in caplog.records)
