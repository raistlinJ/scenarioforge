import io
import json
import subprocess
from contextlib import redirect_stdout
from pathlib import Path

from webapp import app_backend as backend


def _run_validation_script(assignments):
    script = backend._remote_flow_artifacts_validation_script(assignments, scenario_label='LiveTopologySmoke')
    ns = {'__name__': '__main__'}
    out = io.StringIO()
    with redirect_stdout(out):
        exec(script, ns, ns)
    payload = json.loads(out.getvalue().strip())
    return payload


def test_remote_validator_resolves_relative_outputs_in_artifacts_and_outputs_dirs(tmp_path):
    run_dir = tmp_path / 'flow-run'
    artifacts_dir = run_dir / 'artifacts'
    outputs_dir = run_dir / 'outputs'
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    secret_path = artifacts_dir / 'secrets.txt'
    secret_path.write_text('demo-secret', encoding='utf-8')

    compose_path = outputs_dir / 'docker-compose.yml'
    compose_path.write_text('services: {}\n', encoding='utf-8')

    manifest_flag = run_dir / 'outputs_flag.json'
    manifest_flag.write_text(
        json.dumps({'outputs': {'secret_file': 'secrets.txt'}}),
        encoding='utf-8',
    )

    manifest_node = run_dir / 'outputs_node.json'
    manifest_node.write_text(
        json.dumps({'outputs': {'File(path)': 'docker-compose.yml'}}),
        encoding='utf-8',
    )

    payload = _run_validation_script(
        [
            {
                'node_id': 'docker-34',
                'generator_id': 'textfile_username_password',
                'generator_type': 'flag-generator',
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                'outputs_manifest': str(manifest_flag),
                'inject_files_detail': [],
                'inject_files': [],
            },
            {
                'node_id': 'docker-31',
                'generator_id': 'nfs_sensitive_file',
                'generator_type': 'flag-node-generator',
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                'outputs_manifest': str(manifest_node),
                'inject_files_detail': [],
                'inject_files': [],
            },
        ]
    )

    items = payload.get('items') or []
    by_id = {str(it.get('generator_id')): it for it in items if isinstance(it, dict)}

    fg_item = by_id.get('textfile_username_password')
    assert fg_item is not None
    assert fg_item.get('outputs_missing') == []
    assert str(secret_path) in (fg_item.get('outputs_checked') or [])

    node_item = by_id.get('nfs_sensitive_file')
    assert node_item is not None
    assert node_item.get('outputs_missing') == []
    assert str(compose_path) in (node_item.get('outputs_checked') or [])


def test_remote_validator_resolves_flag_file_below_service_directory(tmp_path):
    run_dir = tmp_path / 'flow-run'
    service_dir = run_dir / 'service' / 'database'
    service_dir.mkdir(parents=True, exist_ok=True)
    (service_dir / 'customer_exports.sql').write_text("SELECT 'FLAG{demo}';\n", encoding='utf-8')
    (run_dir / 'docker-compose.yml').write_text('services: {}\n', encoding='utf-8')

    outputs_manifest = run_dir / 'outputs.json'
    outputs_manifest.write_text(
        json.dumps(
            {
                'outputs': {
                    'FlagDelivery(mode)': 'file',
                    'FlagFile(path)': 'database/customer_exports.sql',
                    'File(path)': 'docker-compose.yml',
                    'Directory(host, path)': 'service',
                    'Endpoint(path)': '/database/customer_exports.sql',
                }
            }
        ),
        encoding='utf-8',
    )

    payload = _run_validation_script(
        [
            {
                'node_id': 'docker-13',
                'node_name': 'docker-13',
                'generator_id': 'postgres_customer_dump',
                'generator_type': 'flag-node-generator',
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                'outputs_manifest': str(outputs_manifest),
                'inject_files_detail': [],
                'inject_files': [],
            }
        ]
    )

    item = (payload.get('items') or [])[0]
    assert item.get('outputs_missing') == []
    assert item.get('inject_missing') == []
    assert str(service_dir / 'customer_exports.sql') in (item.get('outputs_checked') or [])


def test_listener_snapshot_script_includes_tcp_udp_and_ss_checks():
    script = backend._remote_docker_exec_listener_snapshot_script(
        containers=['docker-40'],
        sudo_password='pw',
    )

    assert '/proc/net/tcp' in script
    assert '/proc/net/tcp6' in script
    assert '/proc/net/udp' in script
    assert '/proc/net/udp6' in script
    assert 'ss -lntu' in script
    assert 'docker-40' in script


def test_remote_copy_flow_artifacts_script_prefers_node_alias_over_compose_sidecars():
    script = backend._remote_copy_flow_artifacts_into_containers_script(sudo_password='pw')

    assert "if node_name in names:" in script
    assert "targets = [node_name]" in script
    assert script.index("if node_name in names:") < script.index("ids = _compose_container_ids(project, yml)")


def test_remote_copy_flow_artifacts_script_falls_back_to_resolved_inject_sources():
    script = backend._remote_copy_flow_artifacts_into_containers_script(sudo_password='pw')

    assert "resolved_value = _entry_get('resolved_paths', 'ResolvedPaths')" in script
    assert "resolved_items = resolved_paths.get('inject_sources')" in script
    assert "out.append({'src': src_path, 'dest': flow_default_dest})" in script


def test_remote_copy_flow_artifacts_script_defaults_flow_assignment_injects_to_flow_injects(tmp_path, monkeypatch):
    base_dir = tmp_path / 'remote-base'
    assign_dir = base_dir / 'vulns'
    assign_dir.mkdir(parents=True, exist_ok=True)

    source_dir = tmp_path / 'flag_node_generators_runs' / 'flow-scenario1' / '02_ssh_desktop_creds_docker-1'
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / 'desktop').write_text('demo', encoding='utf-8')

    compose_path = assign_dir / 'docker-compose-docker-1.yml'
    compose_path.write_text('services:\n  docker-1:\n    image: demo\n', encoding='utf-8')

    assignments_path = assign_dir / 'compose_assignments.json'
    assignments_path.write_text(
        json.dumps(
            {
                'assignments': {
                    'docker-1': {
                        'InjectFiles': ['desktop'],
                        'InjectSourceDir': str(source_dir),
                    }
                }
            }
        ),
        encoding='utf-8',
    )

    calls: list[list[str]] = []

    def _fake_subprocess_run(cmd, stdout=None, stderr=None, text=None, timeout=None, input=None):
        cmd_list = [str(part) for part in cmd]
        try:
            docker_idx = cmd_list.index('docker')
        except ValueError:
            raise AssertionError(cmd_list)
        docker_cmd = cmd_list[docker_idx + 1:]

        if docker_cmd[:3] == ['ps', '-a', '--format']:
            return subprocess.CompletedProcess(cmd_list, 0, stdout='docker-1\n')
        if docker_cmd[:2] == ['exec', 'docker-1']:
            calls.append(docker_cmd)
            if '/usr/local/coretg/bin/busybox' in docker_cmd:
                return subprocess.CompletedProcess(cmd_list, 1, stdout='')
            return subprocess.CompletedProcess(cmd_list, 0, stdout='')
        if docker_cmd[:1] == ['cp']:
            calls.append(docker_cmd)
            return subprocess.CompletedProcess(cmd_list, 0, stdout='')
        raise AssertionError(docker_cmd)

    monkeypatch.setenv('CORE_REMOTE_BASE_DIR', str(base_dir))
    monkeypatch.setattr(subprocess, 'run', _fake_subprocess_run)

    script = backend._remote_copy_flow_artifacts_into_containers_script(sudo_password='pw')
    ns = {'__name__': '__main__'}
    out = io.StringIO()
    with redirect_stdout(out):
        exec(script, ns, ns)
    payload = json.loads(out.getvalue().strip())

    assert payload.get('ok') is True
    items = payload.get('items') or []
    assert items and items[0].get('ok') is True
    cp_calls = [entry for entry in calls if entry[:1] == ['cp']]
    assert cp_calls
    assert cp_calls[0][-1] == 'docker-1:/flow_injects/desktop'


def test_remote_copy_flow_artifacts_script_rewrites_local_outputs_paths_to_remote_runs(tmp_path, monkeypatch):
    base_dir = tmp_path / 'remote-base'
    assign_dir = base_dir / 'vulns'
    assign_dir.mkdir(parents=True, exist_ok=True)

    compose_path = assign_dir / 'docker-compose-docker-1.yml'
    compose_path.write_text('services:\n  docker-1:\n    image: demo\n', encoding='utf-8')

    stale_source_dir = '/Users/sampleuser/Documents/scenarioforge/outputs/flag_node_generators_runs/flow-scenario1/02_git_deploy_key_repo_docker-1'

    assignments_path = assign_dir / 'compose_assignments.json'
    assignments_path.write_text(
        json.dumps(
            {
                'assignments': {
                    'docker-1': {
                        'InjectFiles': ['service -> /flow_injects'],
                        'InjectSourceDir': stale_source_dir,
                    }
                }
            }
        ),
        encoding='utf-8',
    )

    calls: list[list[str]] = []

    def _fake_subprocess_run(cmd, stdout=None, stderr=None, text=None, timeout=None, input=None):
        cmd_list = [str(part) for part in cmd]
        docker_idx = cmd_list.index('docker')
        docker_cmd = cmd_list[docker_idx + 1:]
        if docker_cmd[:3] == ['ps', '-a', '--format']:
            return subprocess.CompletedProcess(cmd_list, 0, stdout='docker-1\n')
        if docker_cmd[:2] == ['exec', 'docker-1']:
            calls.append(docker_cmd)
            if '/usr/local/coretg/bin/busybox' in docker_cmd:
                return subprocess.CompletedProcess(cmd_list, 1, stdout='')
            return subprocess.CompletedProcess(cmd_list, 0, stdout='')
        if docker_cmd[:1] == ['cp']:
            calls.append(docker_cmd)
            return subprocess.CompletedProcess(cmd_list, 0, stdout='')
        raise AssertionError(docker_cmd)

    monkeypatch.setenv('CORE_REMOTE_BASE_DIR', str(base_dir))
    monkeypatch.setattr(subprocess, 'run', _fake_subprocess_run)

    script = backend._remote_copy_flow_artifacts_into_containers_script(sudo_password='pw')
    ns = {'__name__': '__main__'}
    out = io.StringIO()
    with redirect_stdout(out):
        exec(script, ns, ns)
    payload = json.loads(out.getvalue().strip())

    assert payload.get('ok') is True
    cp_calls = [entry for entry in calls if entry[:1] == ['cp']]
    assert cp_calls
    assert cp_calls[0][-2] == '/tmp/vulns/flag_node_generators_runs/flow-scenario1/02_git_deploy_key_repo_docker-1/service'
    assert cp_calls[0][-1] == 'docker-1:/flow_injects/service'


def test_remote_copy_flow_artifacts_script_recovers_stale_flow_injects_source(tmp_path, monkeypatch):
    base_dir = tmp_path / 'remote-base'
    assign_dir = base_dir / 'vulns'
    assign_dir.mkdir(parents=True, exist_ok=True)

    source_dir = tmp_path / 'flag_node_generators_runs' / 'flow-scenario1' / '02_ssh_dual_incident_response_docker-1'
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / 'workspace').mkdir(parents=True, exist_ok=True)
    (source_dir / 'workspace' / 'case.txt').write_text('demo', encoding='utf-8')

    compose_path = assign_dir / 'docker-compose-docker-1.yml'
    compose_path.write_text('services:\n  docker-1:\n    image: demo\n', encoding='utf-8')

    assignments_path = assign_dir / 'compose_assignments.json'
    assignments_path.write_text(
        json.dumps(
            {
                'assignments': {
                    'docker-1': {
                        'InjectFiles': ['/flow_injects/workspace'],
                        'InjectSourceDir': str(source_dir),
                    }
                }
            }
        ),
        encoding='utf-8',
    )

    calls: list[list[str]] = []

    def _fake_subprocess_run(cmd, stdout=None, stderr=None, text=None, timeout=None, input=None):
        cmd_list = [str(part) for part in cmd]
        docker_idx = cmd_list.index('docker')
        docker_cmd = cmd_list[docker_idx + 1:]
        if docker_cmd[:3] == ['ps', '-a', '--format']:
            return subprocess.CompletedProcess(cmd_list, 0, stdout='docker-1\n')
        if docker_cmd[:2] == ['exec', 'docker-1']:
            calls.append(docker_cmd)
            if '/usr/local/coretg/bin/busybox' in docker_cmd:
                return subprocess.CompletedProcess(cmd_list, 1, stdout='')
            return subprocess.CompletedProcess(cmd_list, 0, stdout='')
        if docker_cmd[:1] == ['cp']:
            calls.append(docker_cmd)
            return subprocess.CompletedProcess(cmd_list, 0, stdout='')
        raise AssertionError(docker_cmd)

    monkeypatch.setenv('CORE_REMOTE_BASE_DIR', str(base_dir))
    monkeypatch.setattr(subprocess, 'run', _fake_subprocess_run)

    script = backend._remote_copy_flow_artifacts_into_containers_script(sudo_password='pw')
    ns = {'__name__': '__main__'}
    out = io.StringIO()
    with redirect_stdout(out):
        exec(script, ns, ns)
    payload = json.loads(out.getvalue().strip())

    assert payload.get('ok') is True
    cp_calls = [entry for entry in calls if entry[:1] == ['cp']]
    assert cp_calls
    assert cp_calls[0][-2] == str(source_dir / 'workspace')
    assert cp_calls[0][-1] == 'docker-1:/flow_injects/workspace'


def test_remote_copy_flow_artifacts_script_maps_source_side_detail_to_flow_injects(tmp_path, monkeypatch):
    base_dir = tmp_path / 'remote-base'
    assign_dir = base_dir / 'vulns'
    assign_dir.mkdir(parents=True, exist_ok=True)

    source_dir = tmp_path / 'flag_node_generators_runs' / 'flow-scenario1' / '02_http_login_staff_portal_docker-1'
    site_dir = source_dir / 'site'
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / 'index.html').write_text('demo', encoding='utf-8')

    compose_path = assign_dir / 'docker-compose-docker-1.yml'
    compose_path.write_text('services:\n  docker-1:\n    image: demo\n', encoding='utf-8')

    assignments_path = assign_dir / 'compose_assignments.json'
    assignments_path.write_text(
        json.dumps(
            {
                'assignments': {
                    'docker-1': {
                        'InjectFilesDetail': [
                            {'path': str(site_dir)},
                        ],
                        'InjectSourceDir': str(source_dir),
                    }
                }
            }
        ),
        encoding='utf-8',
    )

    calls: list[list[str]] = []

    def _fake_subprocess_run(cmd, stdout=None, stderr=None, text=None, timeout=None, input=None):
        cmd_list = [str(part) for part in cmd]
        docker_idx = cmd_list.index('docker')
        docker_cmd = cmd_list[docker_idx + 1:]
        if docker_cmd[:3] == ['ps', '-a', '--format']:
            return subprocess.CompletedProcess(cmd_list, 0, stdout='docker-1\n')
        if docker_cmd[:2] == ['exec', 'docker-1']:
            calls.append(docker_cmd)
            if '/usr/local/coretg/bin/busybox' in docker_cmd:
                return subprocess.CompletedProcess(cmd_list, 1, stdout='')
            return subprocess.CompletedProcess(cmd_list, 0, stdout='')
        if docker_cmd[:1] == ['cp']:
            calls.append(docker_cmd)
            return subprocess.CompletedProcess(cmd_list, 0, stdout='')
        raise AssertionError(docker_cmd)

    monkeypatch.setenv('CORE_REMOTE_BASE_DIR', str(base_dir))
    monkeypatch.setattr(subprocess, 'run', _fake_subprocess_run)

    script = backend._remote_copy_flow_artifacts_into_containers_script(sudo_password='pw')
    ns = {'__name__': '__main__'}
    out = io.StringIO()
    with redirect_stdout(out):
        exec(script, ns, ns)
    payload = json.loads(out.getvalue().strip())

    assert payload.get('ok') is True
    cp_calls = [entry for entry in calls if entry[:1] == ['cp']]
    assert cp_calls
    assert cp_calls[0][-2] == str(site_dir)
    assert cp_calls[0][-1] == 'docker-1:/flow_injects/site'


def test_remote_validator_maps_numeric_node_id_to_docker_alias():
    script = backend._remote_flow_artifacts_validation_script([
        {'node_id': '4', 'generator_id': 'binary_embed_text'}
    ], scenario_label='LiveTopologySmoke')

    assert "elif node_id and node_id.isdigit() and f\"docker-{node_id}\" in docker_names:" in script
    assert "target_container = f\"docker-{node_id}\"" in script


def test_remote_validator_does_not_add_generic_container_probe_fallback():
    script = backend._remote_flow_artifacts_validation_script([
        {'node_id': '4', 'generator_id': 'binary_embed_text'}
    ], scenario_label='LiveTopologySmoke')

    assert "container_dest_paths.append('/flow_injects')" not in script
    assert "container_dest_paths.append('/flow_artifacts')" not in script


def test_remote_validator_prefers_resolved_inject_sources_and_skips_legacy_tmp_flag_txt(tmp_path):
    run_dir = tmp_path / 'flow-run'
    run_dir.mkdir(parents=True, exist_ok=True)
    real_inject = run_dir / 'flag.txt'
    real_inject.write_text('FLAG{demo}', encoding='utf-8')

    payload = _run_validation_script(
        [
            {
                'node_id': 'docker-1',
                'generator_id': 'textfile_username_password',
                'generator_type': 'flag-generator',
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                # Legacy/stale path that should not be treated as required host source.
                'inject_files': ['/tmp/flag.txt'],
                # Authoritative generation-time resolved source should be used.
                'resolved_paths': {
                    'inject_sources': [
                        {'path': str(real_inject), 'is_remote': True},
                    ]
                },
            }
        ]
    )

    items = payload.get('items') or []
    assert len(items) == 1
    item = items[0]

    assert item.get('inject_missing') == []
    checked = item.get('inject_checked') or []
    assert (str(real_inject) in checked) or (checked == [])
    assert '/tmp/flag.txt' not in (item.get('inject_missing') or [])


def test_remote_validator_skips_legacy_tmp_flag_when_resolved_source_is_run_dir_flag_missing(tmp_path):
    run_dir = tmp_path / 'flow-run'
    run_dir.mkdir(parents=True, exist_ok=True)
    compose_file = run_dir / 'artifacts' / 'docker-compose.yml'
    compose_file.parent.mkdir(parents=True, exist_ok=True)
    compose_file.write_text('services: {}\n', encoding='utf-8')

    payload = _run_validation_script(
        [
            {
                'node_id': 'docker-2',
                'generator_id': 'binary_embed_text',
                'generator_type': 'flag-generator',
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                'inject_files': ['/tmp/flag.txt'],
                'resolved_paths': {
                    'inject_sources': [
                        {'path': str(compose_file), 'is_remote': True},
                        {'path': str(run_dir / 'flag.txt'), 'is_remote': True},
                    ]
                },
            }
        ]
    )

    items = payload.get('items') or []
    assert len(items) == 1
    item = items[0]
    missing = item.get('inject_missing') or []
    checked = item.get('inject_checked') or []

    assert str(compose_file) in checked
    assert str(run_dir / 'flag.txt') not in missing


def test_remote_validator_mirrored_generators_respect_delivery_contract(tmp_path):
    mirror_specs = [
        ('embedded_artifact_generator', 'flag-generator'),
        ('service_node_generator', 'flag-node-generator'),
        ('credential_file_generator', 'flag-generator'),
    ]

    assignments = []
    for generator_id, generator_type in mirror_specs:
        mirror_dir = tmp_path / f'mirror_{generator_id}'
        mirror_dir.mkdir()

        run_dir = mirror_dir / 'run'
        artifacts_dir = run_dir / 'artifacts'
        outputs_dir = run_dir / 'outputs'
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        outputs_dir.mkdir(parents=True, exist_ok=True)

        outputs_payload = {'outputs': {}}
        inject_files = []

        if generator_id == 'embedded_artifact_generator':
            (artifacts_dir / 'payload.bin').write_bytes(b'ELFMOCK')
            outputs_payload['outputs'] = {
                'FlagDelivery(mode)': 'embedded',
                'Binary(path)': 'payload.bin',
            }
            inject_files = ['/tmp/flag.txt']
        elif generator_id == 'service_node_generator':
            (outputs_dir / 'docker-compose.yml').write_text('services: {}\n', encoding='utf-8')
            (artifacts_dir / 'exports').mkdir(parents=True, exist_ok=True)
            (artifacts_dir / 'exports' / 'flag.txt').write_text('FLAG{nfs}\n', encoding='utf-8')
            outputs_payload['outputs'] = {
                'FlagDelivery(mode)': 'file',
                'FlagFile(path)': 'exports/flag.txt',
                'File(path)': 'docker-compose.yml',
            }
            inject_files = ['exports/flag.txt->/flow_injects']
        else:
            (artifacts_dir / 'flag.txt').write_text('FLAG{text}\n', encoding='utf-8')
            outputs_payload['outputs'] = {
                'FlagDelivery(mode)': 'file',
                'FlagFile(path)': 'flag.txt',
                'Secret(path)': 'flag.txt',
            }
            inject_files = ['flag.txt->/flow_injects']

        outputs_manifest = run_dir / 'outputs.json'
        outputs_manifest.write_text(json.dumps(outputs_payload), encoding='utf-8')

        assignments.append(
            {
                'node_id': f'docker-{len(assignments) + 1}',
                'generator_id': generator_id,
                'generator_type': generator_type,
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                'inject_source_dir': str(artifacts_dir),
                'outputs_manifest': str(outputs_manifest),
                'inject_files': inject_files,
            }
        )

    payload = _run_validation_script(assignments)
    assert payload.get('ok') is True

    items = payload.get('items') or []
    by_id = {str(item.get('generator_id')): item for item in items if isinstance(item, dict)}

    embed_item = by_id.get('embedded_artifact_generator')
    assert embed_item is not None
    assert embed_item.get('flag_delivery_mode') == 'embedded'
    assert embed_item.get('flag_file_path') in ('', None)
    assert embed_item.get('outputs_missing') == []
    assert embed_item.get('inject_missing') == []

    nfs_item = by_id.get('service_node_generator')
    assert nfs_item is not None
    assert nfs_item.get('flag_delivery_mode') == 'file'
    assert str(nfs_item.get('flag_file_path') or '').endswith('/exports/flag.txt')
    assert nfs_item.get('outputs_missing') == []
    assert nfs_item.get('inject_missing') == []

    text_item = by_id.get('credential_file_generator')
    assert text_item is not None
    assert text_item.get('flag_delivery_mode') == 'file'
    assert str(text_item.get('flag_file_path') or '').endswith('/flag.txt')
    assert text_item.get('outputs_missing') == []
    assert text_item.get('inject_missing') == []
