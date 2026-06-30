import contextlib
import io
import json
import os
import shutil
import tempfile
import uuid

from webapp.app_backend import app
from webapp import app_backend as backend


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def _seed_xml_plan(scenario: str, full_preview: dict, flow_meta: dict) -> tuple[str, str]:
    tmp_dir = tempfile.mkdtemp(prefix='coretg-flow-gve-')
    xml_path = os.path.join(tmp_dir, f'{scenario}.xml')
    xml = f"""<Scenarios>
  <Scenario name=\"{scenario}\">
    <ScenarioEditor>
      <section name=\"Node Information\">
        <item selected=\"Docker\" v_metric=\"Count\" v_count=\"2\"/>
      </section>
      <section name=\"Routing\" density=\"0.0\"></section>
      <section name=\"Services\" density=\"0.0\"></section>
      <section name=\"Vulnerabilities\" density=\"0.0\"></section>
      <section name=\"Segmentation\" density=\"0.0\"></section>
      <section name=\"Traffic\" density=\"0.0\"></section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""
    with open(xml_path, 'w', encoding='utf-8') as f:
        f.write(xml)

    payload = {
        'full_preview': full_preview,
        'metadata': {
            'xml_path': xml_path,
            'scenario': scenario,
            'seed': full_preview.get('seed'),
            'flow': flow_meta,
        },
    }
    ok, err = backend._update_plan_preview_in_xml(xml_path, scenario, payload)
    assert ok, err
    ok2, err2 = backend._update_flow_state_in_xml(xml_path, scenario, flow_meta)
    assert ok2, err2
    return xml_path, tmp_dir


class _NoRunThread:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        return None


class _DoneProc:
    def poll(self):
        return 0


class _FakeSftp:
    def stat(self, path):
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        return object()

    def close(self):
        return None


class _FakeSsh:
    def open_sftp(self):
        return _FakeSftp()

    def close(self):
        return None


def _postgres_customer_dump_nodegen_def():
    return {
        'id': 'postgres_customer_dump',
        'name': 'PostgreSQL Customer Dump',
        'language': 'python',
        'type': 'flag-node-generator',
        'generator_catalog': 'flag_node_generators',
        'source_path': 'flag_node_generators/database/_variant_runtime',
        'source': {'path': 'flag_node_generators/database/_variant_runtime'},
        'runtime': {'type': 'docker-compose'},
        'compose': {'file': 'docker-compose.yml', 'service': 'generator'},
        'inject_files': [],
        'inputs': [],
        'outputs': [
            {'name': 'Flag(flag_id)'},
            {'name': 'FlagDelivery(mode)'},
            {'name': 'FlagFile(path)'},
            {'name': 'File(path)'},
            {'name': 'Directory(host, path)'},
            {'name': 'Endpoint(path)'},
            {'name': 'PortForward(host, port)'},
        ],
        '_source_name': 'test',
    }


def _write_fake_remote_generator_repo(tmp_dir: str) -> str:
    repo_dir = os.path.join(tmp_dir, 'remote-repo')
    scripts_dir = os.path.join(repo_dir, 'scripts')
    os.makedirs(scripts_dir, exist_ok=True)
    runner_path = os.path.join(scripts_dir, 'run_flag_generator.py')
    runner = r'''
import argparse
import json
import os

parser = argparse.ArgumentParser()
parser.add_argument('--kind')
parser.add_argument('--generator-id')
parser.add_argument('--out-dir', required=True)
parser.add_argument('--config')
parser.add_argument('--repo-root')
args = parser.parse_args()

os.makedirs(args.out_dir, exist_ok=True)
service_dir = os.path.join(args.out_dir, 'service')
database_dir = os.path.join(service_dir, 'database')
os.makedirs(database_dir, exist_ok=True)
compose_path = os.path.join(args.out_dir, 'docker-compose.yml')
flag_path = os.path.join(database_dir, 'customer_exports.sql')
with open(compose_path, 'w', encoding='utf-8') as handle:
    handle.write('services:\n  db:\n    image: postgres:16\n')
with open(flag_path, 'w', encoding='utf-8') as handle:
    handle.write('COPY customers FROM stdin;\nFLAG{postgres_customer_dump}\n')

outputs = {
    'Flag(flag_id)': 'FLAG{postgres_customer_dump}',
    'FlagDelivery(mode)': 'file',
    'FlagFile(path)': 'database/customer_exports.sql',
    'File(path)': 'docker-compose.yml',
    'Directory(host, path)': 'service',
    'Endpoint(path)': '/database/customer_exports.sql',
    'PortForward(host, port)': '5432',
}
with open(os.path.join(args.out_dir, 'outputs.json'), 'w', encoding='utf-8') as handle:
    json.dump({'outputs': outputs}, handle)
'''
    with open(runner_path, 'w', encoding='utf-8') as handle:
        handle.write(runner)
    return repo_dir


def _execute_embedded_remote_script(_cfg, script, logger=None, label='', timeout=0):
    stdout = io.StringIO()
    stderr = io.StringIO()
    namespace = {'__name__': '__main__'}
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exec(compile(script, '<remote-flow-test>', 'exec'), namespace)
    for line in reversed(stdout.getvalue().splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    raise AssertionError(f'no JSON payload returned for {label}: stdout={stdout.getvalue()} stderr={stderr.getvalue()}')


def test_remote_service_node_generator_prepare_persists_execute_ready_flow(monkeypatch):
    app.config['TESTING'] = True
    client = app.test_client()
    _login(client)

    scenario = f'zz-remote-service-node-{uuid.uuid4().hex[:8]}'
    full_preview = {
        'seed': 319,
        'hosts': [
            {
                'id': 'docker-13',
                'node_id': 'docker-13',
                'name': 'docker-13',
                'role': 'Docker',
                'type': 'docker',
                'is_vuln': False,
                'vulnerabilities': [],
                'ip4': '10.0.225.13/24',
            },
        ],
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'host_router_map': {},
        'r2r_links_preview': [],
    }
    flow_meta = {'scenario': scenario, 'length': 1, 'chain_ids': ['docker-13'], 'flags_enabled': True}
    xml_path, tmp_dir = _seed_xml_plan(scenario, full_preview, flow_meta)
    remote_repo = _write_fake_remote_generator_repo(tmp_dir)
    remote_cfg = {
        'ssh_enabled': True,
        'ssh_host': 'core.example.test',
        'ssh_username': 'sampleuser',
        'ssh_password': 'pw',
        'ssh_port': 22,
        'host': 'localhost',
        'port': 50051,
        'grpc_host': 'localhost',
        'grpc_port': 50051,
    }
    nodegen_def = _postgres_customer_dump_nodegen_def()

    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([nodegen_def], []))
    monkeypatch.setattr(backend, '_flow_enabled_plugin_contracts_by_id', lambda: {})
    monkeypatch.setattr(backend, '_flow_validate_chain_order_by_requires_produces', lambda *a, **k: (True, []))
    monkeypatch.setattr(backend, '_build_topology_graph_from_preview_plan', lambda _preview: (full_preview['hosts'], [], {}))
    monkeypatch.setattr(backend, '_flow_compose_docker_stats', lambda _nodes: {'docker_nodes': 1, 'vulnerability_nodes': 0})
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *a, **k: dict(remote_cfg))
    monkeypatch.setattr(backend, '_select_core_config_for_page', lambda *a, **k: dict(remote_cfg))
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_a, **_k: dict(cfg or {}))
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: dict(cfg or remote_cfg, ssh_enabled=True, ssh_password='pw'))
    monkeypatch.setattr(backend, '_open_ssh_client', lambda _cfg: _FakeSsh())
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda *_a, **_k: remote_repo)
    monkeypatch.setattr(backend, '_remote_path_join', lambda *parts: os.path.join(*[str(part) for part in parts if str(part or '').strip()]))
    monkeypatch.setattr(backend, '_push_repo_to_remote', lambda *a, **k: None)
    monkeypatch.setattr(backend, '_flow_required_installed_generator_outputs', lambda *_a, **_k: [])
    monkeypatch.setattr(backend, '_flow_required_generator_repo_paths', lambda *_a, **_k: ['scripts'])
    monkeypatch.setattr(backend, '_run_remote_python_json', _execute_embedded_remote_script)
    monkeypatch.setattr(backend, '_summary_from_preview_plan_path', lambda *_a, **_k: ({}, {}))
    monkeypatch.setattr(backend, '_summary_from_xml_plan', lambda *_a, **_k: ({}, None))
    monkeypatch.setattr(backend, '_diff_plan_summaries', lambda *_a, **_k: [])

    def _fake_flow_assignments(_preview, chain_nodes, _scenario, **_kwargs):
        assert [node.get('id') for node in chain_nodes] == ['docker-13']
        return [
            {
                'node_id': 'docker-13',
                'id': 'postgres_customer_dump',
                'name': 'PostgreSQL Customer Dump',
                'type': 'flag-node-generator',
                'generator_catalog': 'flag_node_generators',
                'inject_files': [],
                'outputs': [
                    'Flag(flag_id)',
                    'FlagDelivery(mode)',
                    'FlagFile(path)',
                    'File(path)',
                    'Directory(host, path)',
                    'Endpoint(path)',
                    'PortForward(host, port)',
                ],
            },
        ]

    monkeypatch.setattr(backend, '_flow_compute_flag_assignments', _fake_flow_assignments)

    try:
        prepare_resp = client.post(
            '/api/flag-sequencing/prepare_preview_for_execute',
            json={
                'scenario': scenario,
                'preview_plan': xml_path,
                'mode': 'resolve',
                'length': 1,
                'chain_ids': ['docker-13'],
                'run_remote': True,
                'best_effort': False,
                'timeout_s': 10,
            },
        )
        assert prepare_resp.status_code == 200, prepare_resp.get_json()
        prepare_data = prepare_resp.get_json() or {}
        assert prepare_data.get('ok') is True
        assert prepare_data.get('flow_valid') is True
        assert prepare_data.get('generation_failures') == []

        assignments = prepare_data.get('flag_assignments') if isinstance(prepare_data.get('flag_assignments'), list) else []
        assert len(assignments) == 1
        assignment = assignments[0]
        assert assignment.get('generated') is True
        assert assignment.get('generation_note') == 'ok'
        resolved_outputs = assignment.get('resolved_outputs') if isinstance(assignment.get('resolved_outputs'), dict) else {}
        flag_file = str(resolved_outputs.get('FlagFile(path)') or '')
        assert flag_file.endswith('/service/database/customer_exports.sql')
        assert str(resolved_outputs.get('Directory(host, path)') or '').endswith('/service')
        assert resolved_outputs.get('Endpoint(path)') == '/database/customer_exports.sql'

        saved_flow = backend._flow_state_from_xml_path(xml_path, scenario)
        saved_assignments = saved_flow.get('flag_assignments') if isinstance(saved_flow, dict) else []
        assert len(saved_assignments) == 1
        saved_assignment = saved_assignments[0]
        assert saved_assignment.get('generated') is True
        saved_outputs = saved_assignment.get('resolved_outputs') if isinstance(saved_assignment.get('resolved_outputs'), dict) else {}
        assert str(saved_outputs.get('FlagFile(path)') or '').endswith('/service/database/customer_exports.sql')

        monkeypatch.setattr(backend.threading, 'Thread', _NoRunThread)
        execute_resp = client.post(
            '/run_cli_async',
            data={
                'xml_path': xml_path,
                'scenario': scenario,
                'preview_plan': xml_path,
                'flow_enabled': '1',
                'core_json': json.dumps(remote_cfg),
                'hitl_core_json': json.dumps(remote_cfg),
            },
        )
        assert execute_resp.status_code == 202, execute_resp.get_json()
        run_id = str((execute_resp.get_json() or {}).get('run_id') or '').strip()
        assert run_id
        assert backend.RUNS[run_id].get('flow_enabled') is True
    finally:
        try:
            for run_dir in prepare_data.get('created_run_dirs') or []:
                run_dir = str(run_dir or '')
                if run_dir.startswith('/tmp/vulns/'):
                    shutil.rmtree(run_dir, ignore_errors=True)
        except Exception:
            pass
        try:
            if 'run_id' in locals() and run_id:
                backend.RUNS.pop(run_id, None)
        except Exception:
            pass
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


def test_generate_validate_execute_flow_copy_for_both_generator_kinds(monkeypatch):
    app.config['TESTING'] = True
    client = app.test_client()
    _login(client)

    scenario = f'zz-gve-copy-{uuid.uuid4().hex[:8]}'
    full_preview = {
        'seed': 77,
        'hosts': [
            {
                'id': 'h1',
                'node_id': 'h1',
                'name': 'h1',
                'role': 'Workstation',
                'type': 'workstation',
                'is_vuln': True,
                'vulnerabilities': ['CVE-TEST-1'],
                'ip4': '10.0.0.11',
            },
            {
                'id': 'h2',
                'node_id': 'h2',
                'name': 'h2',
                'role': 'Docker',
                'type': 'docker',
                'is_vuln': False,
                'vulnerabilities': [],
                'ip4': '10.0.0.12',
            },
        ],
        'routers': [],
        'switches': [],
        'switches_detail': [],
        'host_router_map': {},
        'r2r_links_preview': [],
    }

    flow_meta = {
        'scenario': scenario,
        'length': 2,
    }

    xml_path, tmp_dir = _seed_xml_plan(scenario, full_preview, flow_meta)

    fg_def = {
        'id': 'fg_test',
        'name': 'FG Test',
        'language': 'python',
        'inputs': [],
        'outputs': [{'name': 'Flag(flag_id)'}, {'name': 'File(path)'}],
        'hint_levels': {'low': ['hint']},
        '_source_name': 'test',
    }
    fng_def = {
        'id': 'fng_test',
        'name': 'FNG Test',
        'language': 'python',
        'inputs': [],
        'outputs': [{'name': 'Flag(flag_id)'}, {'name': 'File(path)'}],
        'hint_levels': {'low': ['hint']},
        '_source_name': 'test',
    }

    monkeypatch.setattr(backend, '_flag_generators_from_enabled_sources', lambda: ([fg_def], []))
    monkeypatch.setattr(backend, '_flag_node_generators_from_enabled_sources', lambda: ([fng_def], []))
    monkeypatch.setattr(backend, '_flow_enabled_plugin_contracts_by_id', lambda: {})
    monkeypatch.setattr(backend, '_flow_validate_chain_order_by_requires_produces', lambda *a, **k: (True, []))
    monkeypatch.setattr(backend, '_core_config_from_xml_path', lambda *a, **k: {'ssh_enabled': False, 'ssh_password': 'pw'})
    monkeypatch.setattr(backend, '_apply_core_secret_to_config', lambda cfg, *_a, **_k: cfg)
    monkeypatch.setattr(backend, '_build_topology_graph_from_preview_plan', lambda _preview: (full_preview['hosts'], [], {}))
    monkeypatch.setattr(backend, '_flow_compose_docker_stats', lambda _nodes: {'docker_nodes': 1, 'vulnerability_nodes': 1})
    monkeypatch.setattr(backend, '_pick_flag_chain_nodes', lambda _nodes, _adj, length=2: full_preview['hosts'][:length])

    def _fake_flow_assignments(_preview, chain_nodes, _scenario, **_kwargs):
        nodes = [n for n in (chain_nodes or []) if isinstance(n, dict)]
        assert len(nodes) >= 2
        return [
            {
                'node_id': str(nodes[0].get('id') or 'h1'),
                'id': 'fg_test',
                'name': 'FG Test',
                'type': 'flag-generator',
                'generator_catalog': 'flag_generators',
                'inject_files': [],
                'outputs': ['Flag(flag_id)', 'File(path)'],
            },
            {
                'node_id': str(nodes[1].get('id') or 'h2'),
                'id': 'fng_test',
                'name': 'FNG Test',
                'type': 'flag-node-generator',
                'generator_catalog': 'flag_node_generators',
                'inject_files': ['File(path)'],
                'outputs': ['Flag(flag_id)', 'File(path)'],
            },
        ]

    monkeypatch.setattr(backend, '_flow_compute_flag_assignments', _fake_flow_assignments)

    generator_calls: list[dict] = []

    def _fake_subprocess_run(cmd, cwd=None, check=False, capture_output=False, text=False, timeout=None, env=None):
        generator_id = ''
        generator_kind = ''
        out_dir = ''
        if isinstance(cmd, list):
            if '--generator-id' in cmd:
                i = cmd.index('--generator-id')
                if i + 1 < len(cmd):
                    generator_id = str(cmd[i + 1])
            if '--kind' in cmd:
                i = cmd.index('--kind')
                if i + 1 < len(cmd):
                    generator_kind = str(cmd[i + 1])
            if '--out-dir' in cmd:
                i = cmd.index('--out-dir')
                if i + 1 < len(cmd):
                    out_dir = str(cmd[i + 1])

        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            art_dir = os.path.join(out_dir, 'artifacts')
            os.makedirs(art_dir, exist_ok=True)
            outputs = {'Flag(flag_id)': f'FLAG{{{generator_id}}}', 'flag': f'FLAG{{{generator_id}}}'}

            if generator_id == 'fg_test':
                export_path = os.path.join(art_dir, 'exports.txt')
                with open(export_path, 'w', encoding='utf-8') as f:
                    f.write('seed-data')
                outputs['File(path)'] = 'artifacts/exports.txt'
            else:
                compose_path = os.path.join(out_dir, 'docker-compose.yml')
                with open(compose_path, 'w', encoding='utf-8') as f:
                    f.write('services: {}\n')
                outputs['File(path)'] = 'docker-compose.yml'

            manifest_path = os.path.join(out_dir, 'outputs.json')
            with open(manifest_path, 'w', encoding='utf-8') as mf:
                json.dump({'outputs': outputs}, mf)

        inject_raw = None
        if isinstance(env, dict):
            inject_raw = env.get('CORETG_INJECT_FILES_JSON')
        inject_files_override = []
        if isinstance(inject_raw, str) and inject_raw.strip():
            try:
                parsed = json.loads(inject_raw)
                if isinstance(parsed, list):
                    inject_files_override = [str(x) for x in parsed]
            except Exception:
                inject_files_override = [inject_raw]

        generator_calls.append({
            'id': generator_id,
            'kind': generator_kind,
            'out_dir': out_dir,
            'inject_files_override': inject_files_override,
        })

        class _Result:
            def __init__(self):
                self.returncode = 0
                self.stdout = ''
                self.stderr = ''

        return _Result()

    monkeypatch.setattr(backend.subprocess, 'run', _fake_subprocess_run)

    captured_revalidate_items = {'items': []}

    def _fake_validation_script(check_items, scenario_label=''):
        captured_revalidate_items['items'] = list(check_items or [])
        return 'print("ok")'

    def _fake_run_remote_python_json(_cfg, _script, logger=None, label='', timeout=0):
        if label == 'flow.revalidate.artifacts':
            items = []
            for it in captured_revalidate_items['items']:
                out_checked = []
                run_dir = str(it.get('run_dir') or '').strip()
                if run_dir:
                    out_checked.append(run_dir)
                inject_checked = []
                inj = it.get('inject_files') if isinstance(it.get('inject_files'), list) else []
                for raw in inj:
                    src = str(raw).split('->', 1)[0].strip()
                    if src:
                        inject_checked.append(src)
                items.append({
                    'outputs_checked': out_checked,
                    'inject_checked': inject_checked,
                    'outputs_missing': [],
                    'inject_missing': [],
                })
            return {'ok': True, 'items': items}
        if str(label).startswith('docker.copy_flow_artifacts'):
            return {
                'ok': True,
                'assignments_count': 2,
                'assignments_keys': ['h1', 'h2'],
                'items': [
                    {'node': 'h1', 'ok': True, 'src': '/tmp/vulns/flag_generators_runs/x', 'dest': '/flow_artifacts', 'targets': ['h1']},
                    {'node': 'h2', 'ok': True, 'src': '/tmp/vulns/flag_node_generators_runs/x', 'dest': '/flow_artifacts', 'targets': ['h2']},
                ],
            }
        if str(label).startswith('docker.exec.verify_flow_artifacts'):
            return {'ok': True, 'items': []}
        if str(label).startswith('remote.vulns_inventory'):
            return {'ok': True, 'items': []}
        return {'ok': True, 'items': []}

    monkeypatch.setattr(backend, '_remote_flow_artifacts_validation_script', _fake_validation_script)
    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_run_remote_python_json)
    monkeypatch.setattr(backend, '_require_core_ssh_credentials', lambda cfg: dict(cfg or {}, ssh_enabled=True, ssh_password='pw'))

    try:
        prepare_resp = client.post(
            '/api/flag-sequencing/prepare_preview_for_execute',
            json={
                'scenario': scenario,
                'preview_plan': xml_path,
                'length': 2,
                'best_effort': False,
                'timeout_s': 10,
            },
        )
        assert prepare_resp.status_code == 200, prepare_resp.get_json()
        prepare_data = prepare_resp.get_json() or {}
        assert prepare_data.get('ok') is True

        assignments = prepare_data.get('flag_assignments') if isinstance(prepare_data.get('flag_assignments'), list) else []
        assert len(assignments) == 2
        types = {str(a.get('type') or '') for a in assignments if isinstance(a, dict)}
        assert 'flag-generator' in types
        assert 'flag-node-generator' in types

        second = next(a for a in assignments if str(a.get('id') or '') == 'fng_test')
        second_injects = second.get('inject_files') if isinstance(second.get('inject_files'), list) else []
        assert any(os.path.isabs(str(v).split('->', 1)[0].strip()) for v in second_injects)

        assert any(c.get('id') == 'fg_test' and c.get('kind') == 'flag-generator' for c in generator_calls)
        assert any(c.get('id') == 'fng_test' and c.get('kind') == 'flag-node-generator' for c in generator_calls)
        assert any(
            c.get('id') == 'fng_test'
            and any(os.path.isabs(str(x).split('->', 1)[0].strip()) for x in (c.get('inject_files_override') or []))
            for c in generator_calls
        )

        revalidate_resp = client.post(
            '/api/flag-sequencing/revalidate_flow',
            json={
                'scenario': scenario,
                'xml_path': xml_path,
                'flag_assignments': assignments,
            },
        )
        assert revalidate_resp.status_code == 200
        revalidate_data = revalidate_resp.get_json() or {}
        assert revalidate_data.get('ok') is True
        assert revalidate_data.get('missing') == []

        validated_types = {
            str(it.get('generator_type') or '')
            for it in (captured_revalidate_items.get('items') or [])
            if isinstance(it, dict)
        }
        assert 'flag-generator' in validated_types
        assert 'flag-node-generator' in validated_types

        monkeypatch.setattr(backend.threading, 'Thread', _NoRunThread)
        execute_resp = client.post(
            '/run_cli_async',
            data={
                'xml_path': xml_path,
                'scenario': scenario,
                'preview_plan': xml_path,
                'flow_enabled': '1',
            },
        )
        assert execute_resp.status_code == 202, execute_resp.get_json()
        execute_data = execute_resp.get_json() or {}
        run_id = str(execute_data.get('run_id') or '').strip()
        assert run_id

        run_meta = backend.RUNS[run_id]
        run_meta.update({
            'proc': _DoneProc(),
            'returncode': None,
            'done': False,
            'history_added': True,
            'remote': True,
            'core_cfg': {'ssh_password': 'pw'},
        })

        status_resp = client.get(f'/run_status/{run_id}')
        assert status_resp.status_code == 200
        assert backend.RUNS[run_id].get('flow_artifacts_copied') is True
    finally:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


def test_maybe_copy_flow_artifacts_retries_after_zero_success_attempt(monkeypatch):
    meta = {
        'remote': True,
        'core_cfg': {'ssh_password': 'pw'},
    }

    payloads = iter([
        {
            'ok': True,
            'assignments_count': 2,
            'assignments_keys': ['docker-1', 'docker-4'],
            'items': [
                {'node': 'docker-1', 'ok': False, 'error': 'container not found'},
                {'node': 'docker-4', 'ok': False, 'error': 'container not found'},
            ],
        },
        {
            'ok': True,
            'assignments_count': 2,
            'assignments_keys': ['docker-1', 'docker-4'],
            'items': [
                {'node': 'docker-1', 'ok': True, 'src': '/tmp/a', 'dest': '/flow_artifacts', 'targets': ['docker-1']},
                {'node': 'docker-4', 'ok': True, 'src': '/tmp/b', 'dest': '/flow_artifacts', 'targets': ['docker-4']},
            ],
        },
    ])
    labels: list[str] = []

    monkeypatch.setattr(backend, '_log_remote_vulns_inventory', lambda *a, **k: None)
    monkeypatch.setattr(backend, '_append_async_run_log_line', lambda _meta, line: labels.append(str(line)))

    def _fake_run_remote_python_json(_cfg, _script, logger=None, label='', timeout=0):
        if str(label).startswith('docker.copy_flow_artifacts'):
            return next(payloads)
        if str(label).startswith('docker.exec.verify_flow_artifacts'):
            return {'ok': True, 'items': []}
        if str(label).startswith('docker.exec.listener_snapshot'):
            return {'ok': True, 'items': []}
        raise AssertionError(label)

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_run_remote_python_json)

    backend._maybe_copy_flow_artifacts_into_containers(meta, stage='postrun')
    assert meta.get('flow_artifacts_copied') is not True
    assert any('pending retry ok=0 total=2' in line for line in labels)

    backend._maybe_copy_flow_artifacts_into_containers(meta, stage='postrun')
    assert meta.get('flow_artifacts_copied') is True


def test_maybe_copy_flow_artifacts_requires_at_least_one_target_when_requested(monkeypatch):
    meta = {
        'remote': True,
        'core_cfg': {'ssh_password': 'pw'},
        'flow_copy_required': True,
    }

    monkeypatch.setattr(backend, '_log_remote_vulns_inventory', lambda *a, **k: None)
    monkeypatch.setattr(backend, '_append_async_run_log_line', lambda *a, **k: None)
    monkeypatch.setattr(
        backend,
        '_run_remote_python_json',
        lambda *_a, **_k: {
            'ok': True,
            'assignments_count': 0,
            'candidate_count': 0,
            'items': [],
        },
    )

    backend._maybe_copy_flow_artifacts_into_containers(meta, stage='cli-postrun')

    assert meta.get('flow_artifacts_copied') is not True
    assert meta.get('flow_artifact_copy_error') == 'no Flow artifact copy targets were found'


def test_maybe_copy_flow_artifacts_includes_first_copy_failure_detail(monkeypatch):
    meta = {
        'remote': True,
        'core_cfg': {'ssh_password': 'pw'},
        'flow_copy_required': True,
    }

    monkeypatch.setattr(backend, '_log_remote_vulns_inventory', lambda *a, **k: None)
    monkeypatch.setattr(backend, '_append_async_run_log_line', lambda *a, **k: None)

    def _fake_run_remote_python_json(_cfg, _script, logger=None, label='', timeout=0):
        if str(label).startswith('docker.copy_flow_artifacts'):
            return {
                'ok': False,
                'assignments_count': 1,
                'candidate_count': 1,
                'items': [
                    {
                        'node': 'docker-2',
                        'ok': False,
                        'errors': [
                            'docker-2: source missing for /flow_injects/service: /tmp/vulns/missing/service'
                        ],
                    }
                ],
            }
        if str(label).startswith('docker.exec.verify_flow_artifacts'):
            return {'ok': True, 'items': []}
        if str(label).startswith('docker.exec.listener_snapshot'):
            return {'ok': True, 'items': []}
        raise AssertionError(label)

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_run_remote_python_json)

    backend._maybe_copy_flow_artifacts_into_containers(meta, stage='cli-postrun')

    assert meta.get('flow_artifacts_copied') is not True
    error = str(meta.get('flow_artifact_copy_error') or '')
    assert 'only 0 of 1 Flow artifact copy targets succeeded' in error
    assert 'first_error=docker-2: source missing for /flow_injects/service' in error


def test_maybe_copy_flow_artifacts_reports_non_warning_failure_detail(monkeypatch):
    meta = {
        'remote': True,
        'core_cfg': {'ssh_password': 'pw'},
        'flow_copy_required': True,
    }

    monkeypatch.setattr(backend, '_log_remote_vulns_inventory', lambda *a, **k: None)
    monkeypatch.setattr(backend, '_append_async_run_log_line', lambda *a, **k: None)

    def _fake_run_remote_python_json(_cfg, _script, logger=None, label='', timeout=0):
        if str(label).startswith('docker.copy_flow_artifacts'):
            return {
                'ok': True,
                'assignments_count': 1,
                'candidate_count': 1,
                'items': [
                    {
                        'node': 'docker-12',
                        'ok': False,
                        'errors': [
                            'abcd1234: warning: container stopped during or after copy, verification may fail',
                            'abcd1234: docker cp failed for /flow_injects/support_runbook.html via /flow_injects/support_runbook.html: container is restarting',
                        ],
                    }
                ],
            }
        if str(label).startswith('docker.exec.verify_flow_artifacts'):
            return {'ok': True, 'items': []}
        if str(label).startswith('docker.exec.listener_snapshot'):
            return {'ok': True, 'items': []}
        raise AssertionError(label)

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_run_remote_python_json)

    backend._maybe_copy_flow_artifacts_into_containers(meta, stage='cli-postrun')

    error = str(meta.get('flow_artifact_copy_error') or '')
    assert 'first_error=abcd1234: docker cp failed for /flow_injects/support_runbook.html' in error
    assert 'first_error=abcd1234: warning:' not in error


def test_remote_flow_copy_ignores_original_compose_backups():
    script = backend._remote_copy_flow_artifacts_into_containers_script('pw')

    assert "if text.endswith('.orig.yml'):" in script
