import io
import json
from pathlib import Path

import pytest

from webapp import app_backend as backend


class _FakeSFTP:
    def __init__(self, existing_paths):
        self._existing_paths = set(existing_paths)
        self.put_calls = []
        self.uploaded_bytes = {}

    def put(self, localpath, remotepath):
        local_path = Path(localpath)
        remote_path = str(remotepath)
        self.put_calls.append((str(local_path), remote_path))
        self.uploaded_bytes[remote_path] = local_path.read_bytes()
        self._existing_paths.add(remote_path)

    def stat(self, path):
        if str(path) not in self._existing_paths:
            raise FileNotFoundError(str(path))
        return object()

    def close(self):
        return None


class _FakeSSHClient:
    def __init__(self, sftp):
        self._sftp = sftp

    def open_sftp(self):
        return self._sftp


def test_prepare_remote_cli_context_keeps_rewritten_xml_when_preview_matches_xml(tmp_path, monkeypatch):
    wrapper_dir = tmp_path / 'docker-wrap-vuln-test-1-vuln-test-1'
    wrapper_dir.mkdir()
    (wrapper_dir / 'Dockerfile').write_text('FROM alpine:3.19\n', encoding='utf-8')

    compose_path = tmp_path / 'docker-compose-docker-1.yml'
    compose_path.write_text(
        '\n'.join(
            [
                'services:',
                '  app:',
                '    image: coretg/vuln-test-1-vuln-test-1:iproute2',
                '    labels:',
                f'      coretg.wrapper_build_context: {wrapper_dir}',
                '      coretg.wrapper_build_dockerfile: Dockerfile',
            ]
        )
        + '\n',
        encoding='utf-8',
    )

    xml_path = tmp_path / 'ephemeral.xml'
    xml_path.write_text(
        '\n'.join(
            [
                '<?xml version="1.0" encoding="utf-8"?>',
                '<Scenarios>',
                '  <Scenario name="demo">',
                '    <ScenarioEditor>',
                '      <Section name="Vulnerabilities">',
                f'        <item v_path="{compose_path}" />',
                '      </Section>',
                '    </ScenarioEditor>',
                '  </Scenario>',
                '</Scenarios>',
            ]
        ),
        encoding='utf-8',
    )

    remote_repo = '/remote/repo'
    fake_sftp = _FakeSFTP(
        {
            remote_repo,
            f'{remote_repo}/scenarioforge',
            f'{remote_repo}/scenarioforge/__init__.py',
        }
    )
    client = _FakeSSHClient(fake_sftp)

    monkeypatch.setattr(backend, '_remote_base_dir', lambda _sftp: '/remote/base')
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda _sftp: remote_repo)
    monkeypatch.setattr(backend, '_remote_mkdirs', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_upload_flow_artifacts_for_plan_to_remote', lambda **_kwargs: None)
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path / 'empty-repo'))

    log_handle = io.StringIO()

    context = backend._prepare_remote_cli_context(
        client=client,
        run_id='run-123',
        xml_path=str(xml_path),
        preview_plan_path=str(xml_path),
        log_handle=log_handle,
    )

    remote_xml_path = context['xml_path']
    assert context['preview_plan_path'] == remote_xml_path

    uploaded_xml = fake_sftp.uploaded_bytes[remote_xml_path].decode('utf-8')
    assert str(compose_path) not in uploaded_xml
    assert '/remote/base/runs/run-123/docker-compose-docker-1.yml' in uploaded_xml

    remote_compose_path = '/remote/base/runs/run-123/docker-compose-docker-1.yml'
    uploaded_compose = fake_sftp.uploaded_bytes[remote_compose_path].decode('utf-8')
    assert str(wrapper_dir) not in uploaded_compose
    assert '/remote/base/runs/run-123/docker-wrap-vuln-test-1-vuln-test-1' in uploaded_compose

    remote_wrapper_dockerfile = '/remote/base/runs/run-123/docker-wrap-vuln-test-1-vuln-test-1/Dockerfile'
    assert fake_sftp.uploaded_bytes[remote_wrapper_dockerfile].decode('utf-8') == 'FROM alpine:3.19\n'

    xml_upload_count = sum(1 for _local, remote in fake_sftp.put_calls if remote == remote_xml_path)
    assert xml_upload_count == 1


def test_prepare_remote_cli_context_rewrites_local_compose_build_contexts(tmp_path, monkeypatch):
    build_dir = tmp_path / 'httpd-cve-2017-15715'
    build_dir.mkdir()
    (build_dir / 'Dockerfile').write_text('FROM httpd:2.4\n', encoding='utf-8')
    (build_dir / 'index.html').write_text('hello\n', encoding='utf-8')

    compose_path = tmp_path / 'docker-compose-docker-1.yml'
    compose_path.write_text(
        '\n'.join(
            [
                'services:',
                '  apache:',
                '    build:',
                f'      context: {build_dir}',
                '    image: local/httpd-test:latest',
            ]
        )
        + '\n',
        encoding='utf-8',
    )

    xml_path = tmp_path / 'ephemeral.xml'
    xml_path.write_text(
        '\n'.join(
            [
                '<?xml version="1.0" encoding="utf-8"?>',
                '<Scenarios>',
                '  <Scenario name="demo">',
                '    <ScenarioEditor>',
                '      <Section name="Vulnerabilities">',
                f'        <item v_path="{compose_path}" />',
                '      </Section>',
                '    </ScenarioEditor>',
                '  </Scenario>',
                '</Scenarios>',
            ]
        ),
        encoding='utf-8',
    )

    remote_repo = '/remote/repo'
    fake_sftp = _FakeSFTP(
        {
            remote_repo,
            f'{remote_repo}/scenarioforge',
            f'{remote_repo}/scenarioforge/__init__.py',
        }
    )
    client = _FakeSSHClient(fake_sftp)

    monkeypatch.setattr(backend, '_remote_base_dir', lambda _sftp: '/remote/base')
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda _sftp: remote_repo)
    monkeypatch.setattr(backend, '_remote_mkdirs', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_upload_flow_artifacts_for_plan_to_remote', lambda **_kwargs: None)
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path / 'empty-repo'))

    backend._prepare_remote_cli_context(
        client=client,
        run_id='run-456',
        xml_path=str(xml_path),
        preview_plan_path=str(xml_path),
        log_handle=io.StringIO(),
    )

    remote_compose_path = '/remote/base/runs/run-456/docker-compose-docker-1.yml'
    uploaded_compose = fake_sftp.uploaded_bytes[remote_compose_path].decode('utf-8')
    assert str(build_dir) not in uploaded_compose
    assert '/remote/base/runs/run-456/httpd-cve-2017-15715' in uploaded_compose

    remote_dockerfile = '/remote/base/runs/run-456/httpd-cve-2017-15715/Dockerfile'
    remote_index = '/remote/base/runs/run-456/httpd-cve-2017-15715/index.html'
    assert fake_sftp.uploaded_bytes[remote_dockerfile].decode('utf-8') == 'FROM httpd:2.4\n'
    assert fake_sftp.uploaded_bytes[remote_index].decode('utf-8') == 'hello\n'


def test_prepare_remote_cli_context_uploads_env_file_assets(tmp_path, monkeypatch):
    env_path = tmp_path / 'config.env'
    env_path.write_text('DB_PASSWORD=secret\n', encoding='utf-8')

    compose_path = tmp_path / 'docker-compose-docker-1.yml'
    compose_path.write_text(
        '\n'.join(
            [
                'services:',
                '  jumpserver:',
                '    image: vulhub/jumpserver:3.6.3',
                '    env_file: config.env',
            ]
        )
        + '\n',
        encoding='utf-8',
    )

    xml_path = tmp_path / 'ephemeral.xml'
    xml_path.write_text(
        '\n'.join(
            [
                '<?xml version="1.0" encoding="utf-8"?>',
                '<Scenarios>',
                '  <Scenario name="demo">',
                '    <ScenarioEditor>',
                '      <Section name="Vulnerabilities">',
                f'        <item v_path="{compose_path}" />',
                '      </Section>',
                '    </ScenarioEditor>',
                '  </Scenario>',
                '</Scenarios>',
            ]
        ),
        encoding='utf-8',
    )

    remote_repo = '/remote/repo'
    fake_sftp = _FakeSFTP(
        {
            remote_repo,
            f'{remote_repo}/scenarioforge',
            f'{remote_repo}/scenarioforge/__init__.py',
        }
    )
    client = _FakeSSHClient(fake_sftp)

    monkeypatch.setattr(backend, '_remote_base_dir', lambda _sftp: '/remote/base')
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda _sftp: remote_repo)
    monkeypatch.setattr(backend, '_remote_mkdirs', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_upload_flow_artifacts_for_plan_to_remote', lambda **_kwargs: None)
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path / 'empty-repo'))

    backend._prepare_remote_cli_context(
        client=client,
        run_id='run-789',
        xml_path=str(xml_path),
        preview_plan_path=str(xml_path),
        log_handle=io.StringIO(),
    )

    remote_compose_path = '/remote/base/runs/run-789/docker-compose-docker-1.yml'
    uploaded_compose = fake_sftp.uploaded_bytes[remote_compose_path].decode('utf-8')
    assert 'env_file: /remote/base/runs/run-789/config.env' in uploaded_compose

    remote_env_path = '/remote/base/runs/run-789/config.env'
    assert fake_sftp.uploaded_bytes[remote_env_path].decode('utf-8') == 'DB_PASSWORD=secret\n'


def test_prepare_remote_cli_context_syncs_core_runtime_package(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    (repo_root / 'scenarioforge' / 'builders').mkdir(parents=True)
    (repo_root / 'scenarioforge' / 'utils').mkdir(parents=True)
    (repo_root / 'scripts').mkdir(parents=True)
    (repo_root / 'scenarioforge' / '__init__.py').write_text('', encoding='utf-8')
    (repo_root / 'scenarioforge' / 'cli.py').write_text('CLI = True\n', encoding='utf-8')
    (repo_root / 'scenarioforge' / 'generator_manifests.py').write_text('MANIFESTS = {}\n', encoding='utf-8')
    (repo_root / 'scenarioforge' / 'builders' / 'topology.py').write_text('PRE = True\n', encoding='utf-8')
    (repo_root / 'scenarioforge' / 'utils' / 'vuln_process.py').write_text('INJECT = True\n', encoding='utf-8')
    (repo_root / 'scripts' / 'run_flag_generator.py').write_text('print("runner")\n', encoding='utf-8')

    xml_path = tmp_path / 'ephemeral.xml'
    xml_path.write_text('<Scenarios />\n', encoding='utf-8')

    remote_repo = '/remote/repo'
    fake_sftp = _FakeSFTP(
        {
            remote_repo,
            f'{remote_repo}/scenarioforge',
            f'{remote_repo}/scenarioforge/__init__.py',
        }
    )
    client = _FakeSSHClient(fake_sftp)

    monkeypatch.setattr(backend, '_remote_base_dir', lambda _sftp: '/remote/base')
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda _sftp: remote_repo)
    monkeypatch.setattr(backend, '_remote_mkdirs', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_upload_flow_artifacts_for_plan_to_remote', lambda **_kwargs: None)
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(repo_root))

    backend._prepare_remote_cli_context(
        client=client,
        run_id='run-sync',
        xml_path=str(xml_path),
        preview_plan_path=str(xml_path),
        log_handle=io.StringIO(),
    )

    uploaded_remote_paths = {remote for _local, remote in fake_sftp.put_calls}
    assert f'{remote_repo}/scenarioforge/cli.py' in uploaded_remote_paths
    assert f'{remote_repo}/scenarioforge/builders/topology.py' in uploaded_remote_paths
    assert f'{remote_repo}/scenarioforge/utils/vuln_process.py' in uploaded_remote_paths
    assert f'{remote_repo}/scripts/run_flag_generator.py' in uploaded_remote_paths


def test_prepare_remote_cli_context_reports_missing_preview_plan_path(tmp_path, monkeypatch):
    xml_path = tmp_path / 'ephemeral.xml'
    xml_path.write_text('<Scenarios />\n', encoding='utf-8')
    missing_preview = tmp_path / 'missing-preview.xml'

    remote_repo = '/remote/repo'
    fake_sftp = _FakeSFTP(
        {
            remote_repo,
            f'{remote_repo}/scenarioforge',
            f'{remote_repo}/scenarioforge/__init__.py',
        }
    )
    client = _FakeSSHClient(fake_sftp)

    monkeypatch.setattr(backend, '_remote_base_dir', lambda _sftp: '/remote/base')
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda _sftp: remote_repo)
    monkeypatch.setattr(backend, '_remote_mkdirs', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_upload_flow_artifacts_for_plan_to_remote', lambda **_kwargs: None)
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path / 'empty-repo'))

    with pytest.raises(FileNotFoundError, match='preview plan XML local file missing') as excinfo:
        backend._prepare_remote_cli_context(
            client=client,
            run_id='run-missing-preview',
            xml_path=str(xml_path),
            preview_plan_path=str(missing_preview),
            log_handle=io.StringIO(),
        )

    assert str(missing_preview) in str(excinfo.value)


def test_repo_push_excludes_root_nginx_but_not_template_nginx_files() -> None:
    assert backend._should_exclude_repo_member('nginx/certs/server.key') is True
    assert backend._should_exclude_repo_member('nginx/nginx.conf') is True
    assert backend._should_exclude_repo_member('flag_templates/flag_web_basic_auth_flag/nginx.conf') is False


def test_repo_rsync_filters_exclude_root_nginx_dir() -> None:
    filters = backend._repo_rsync_filters(allowed_outputs=[])

    assert '- nginx/' in filters
    assert '- **/nginx/' in filters


def test_extract_flow_artifact_dirs_from_plan_includes_flow_state_sources(tmp_path, monkeypatch):
    xml_path = tmp_path / 'preview.xml'
    xml_path.write_text('<Scenarios />\n', encoding='utf-8')

    preview_payload = {
        'full_preview': {
            'hosts': [
                {
                    'artifacts_dir': '/tmp/vulns/flow-demo/artifacts',
                }
            ]
        },
        'metadata': {
            'flow': {},
        },
    }
    flow_state = {
        'flag_assignments': [
            {
                'run_dir': '/tmp/vulns/flow-demo',
                'inject_source_dir': '/tmp/vulns/flow-demo/exports',
                'outputs_manifest': '/tmp/vulns/flow-demo/meta/outputs.json',
                'resolved_paths': {
                    'inject_sources': [
                        {'path': '/tmp/vulns/flow-demo/exports/secrets.txt'},
                    ]
                },
            }
        ]
    }

    monkeypatch.setattr(backend, '_load_plan_preview_from_xml', lambda *_a, **_k: preview_payload)
    monkeypatch.setattr(backend, '_flow_state_from_xml_path', lambda *_a, **_k: flow_state)

    dirs = backend._extract_flow_artifact_dirs_from_plan(str(xml_path))

    assert '/tmp/vulns/flow-demo/artifacts' in dirs
    assert '/tmp/vulns/flow-demo/exports' in dirs
    assert '/tmp/vulns/flow-demo' in dirs
    assert '/tmp/vulns/flow-demo/meta' in dirs


def test_prepare_remote_cli_context_rewrites_and_uploads_flaggen_run_artifacts(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    run_dir = repo_root / 'outputs' / 'flag_generators_runs' / 'run-abc'
    artifacts_dir = run_dir / 'artifacts'
    artifacts_dir.mkdir(parents=True)
    artifact_path = artifacts_dir / 'ops_logs.tar'
    artifact_path.write_bytes(b'tar-bytes')
    manifest_path = run_dir / 'outputs.json'
    manifest_path.write_text(
        json.dumps({'outputs': {'File(path)': 'artifacts/ops_logs.tar'}}),
        encoding='utf-8',
    )
    flow_state = {
        'scenario': 'demo',
        'flag_assignments': [
            {
                'node_id': '1',
                'id': 'archive_tar_log_bundle',
                'type': 'flag-generator',
                'run_dir': str(run_dir),
                'artifacts_dir': str(run_dir),
                'outputs_manifest': str(manifest_path),
                'inject_files': [f'{artifact_path} -> /flow_injects'],
                'resolved_paths': {
                    'inject_sources': [{'path': str(artifact_path)}],
                },
            }
        ],
        'flow_enabled': True,
    }
    xml_path = run_dir / 'ephemeral_execute.xml'
    xml_path.write_text(
        '\n'.join(
            [
                '<?xml version="1.0" encoding="utf-8"?>',
                '<Scenarios>',
                '  <Scenario name="demo">',
                '    <ScenarioEditor>',
                '      <FlagSequencing>',
                f'        <FlowState>{json.dumps(flow_state, separators=(",", ":"))}</FlowState>',
                '      </FlagSequencing>',
                '    </ScenarioEditor>',
                '  </Scenario>',
                '</Scenarios>',
            ]
        ),
        encoding='utf-8',
    )

    remote_repo = '/remote/repo'
    fake_sftp = _FakeSFTP(
        {
            remote_repo,
            f'{remote_repo}/scenarioforge',
            f'{remote_repo}/scenarioforge/__init__.py',
        }
    )
    client = _FakeSSHClient(fake_sftp)

    monkeypatch.setattr(backend, '_remote_base_dir', lambda _sftp: '/remote/base')
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda _sftp: remote_repo)
    monkeypatch.setattr(backend, '_remote_mkdirs', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(repo_root))

    log_handle = io.StringIO()
    context = backend._prepare_remote_cli_context(
        client=client,
        run_id='run-abc',
        xml_path=str(xml_path),
        preview_plan_path=str(xml_path),
        log_handle=log_handle,
    )

    remote_artifact_root = '/tmp/vulns/flag_generators_runs/run-abc'
    uploaded_xml = fake_sftp.uploaded_bytes[context['xml_path']].decode('utf-8')
    assert str(run_dir) not in uploaded_xml
    assert remote_artifact_root in uploaded_xml
    assert fake_sftp.uploaded_bytes[f'{remote_artifact_root}/outputs.json'] == manifest_path.read_bytes()
    assert fake_sftp.uploaded_bytes[f'{remote_artifact_root}/artifacts/ops_logs.tar'] == b'tar-bytes'
    assert 'rewrote ' in log_handle.getvalue()
    assert f'flow.artifacts.uploaded dir={run_dir} -> {remote_artifact_root}' in log_handle.getvalue()


def test_upload_flow_artifacts_resolves_remote_tmp_vulns_to_local_outputs(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    local_run_dir = repo_root / 'outputs' / 'flag_generators_runs' / 'flow-demo' / '01_text'
    artifacts_dir = local_run_dir / 'artifacts'
    artifacts_dir.mkdir(parents=True)
    manifest_path = local_run_dir / 'outputs.json'
    manifest_path.write_text(json.dumps({'outputs': {'File(path)': 'artifacts/secret.txt'}}), encoding='utf-8')
    artifact_path = artifacts_dir / 'secret.txt'
    artifact_path.write_text('secret\n', encoding='utf-8')

    remote_run_dir = '/tmp/vulns/flag_generators_runs/flow-demo/01_text'
    flow_state = {
        'flag_assignments': [
            {
                'id': 'text_secret',
                'type': 'flag-generator',
                'node_id': 'docker-1',
                'run_dir': remote_run_dir,
                'artifacts_dir': remote_run_dir,
                'outputs_manifest': f'{remote_run_dir}/outputs.json',
                'inject_files': [f'{remote_run_dir}/artifacts/secret.txt -> /flow_injects'],
            }
        ]
    }
    xml_path = tmp_path / 'preview.xml'
    xml_path.write_text(
        '\n'.join(
            [
                '<Scenarios>',
                '  <Scenario name="demo">',
                '    <ScenarioEditor>',
                '      <FlagSequencing>',
                f'        <FlowState>{json.dumps(flow_state, separators=(",", ":"))}</FlowState>',
                '      </FlagSequencing>',
                '    </ScenarioEditor>',
                '  </Scenario>',
                '</Scenarios>',
            ]
        ),
        encoding='utf-8',
    )

    fake_sftp = _FakeSFTP(set())
    client = _FakeSSHClient(fake_sftp)

    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(repo_root))
    monkeypatch.setattr(backend, '_remote_mkdirs', lambda *_args, **_kwargs: None)

    log_handle = io.StringIO()
    backend._upload_flow_artifacts_for_plan_to_remote(
        client=client,
        sftp=fake_sftp,
        preview_plan_path=str(xml_path),
        log_handle=log_handle,
    )

    assert fake_sftp.uploaded_bytes[f'{remote_run_dir}/outputs.json'] == manifest_path.read_bytes()
    assert fake_sftp.uploaded_bytes[f'{remote_run_dir}/artifacts/secret.txt'] == b'secret\n'
    assert f'resolved from {remote_run_dir}' in log_handle.getvalue()


def test_prepare_remote_cli_context_regenerates_missing_remote_flow_artifacts_from_resolved_inputs(tmp_path, monkeypatch):
    remote_repo = '/remote/repo'
    remote_run_dir = '/tmp/vulns/flag_generators_runs/flow-demo/01_text'
    remote_artifact = f'{remote_run_dir}/artifacts/secret.txt'
    flow_state = {
        'flag_assignments': [
            {
                'id': 'text_secret',
                'type': 'flag-generator',
                'node_id': 'docker-1',
                'run_dir': remote_run_dir,
                'artifacts_dir': remote_run_dir,
                'outputs_manifest': f'{remote_run_dir}/outputs.json',
                'inject_files': [f'{remote_artifact} -> /flow_injects'],
                'resolved_paths': {'inject_sources': [{'path': remote_artifact}]},
                'resolved_inputs': {'seed': 'demo-seed', 'custom_input': 'kept'},
            }
        ]
    }
    xml_path = tmp_path / 'preview.xml'
    xml_path.write_text(
        '\n'.join(
            [
                '<Scenarios>',
                '  <Scenario name="demo">',
                '    <ScenarioEditor>',
                '      <FlagSequencing>',
                f'        <FlowState>{json.dumps(flow_state, separators=(",", ":"))}</FlowState>',
                '      </FlagSequencing>',
                '    </ScenarioEditor>',
                '  </Scenario>',
                '</Scenarios>',
            ]
        ),
        encoding='utf-8',
    )

    fake_sftp = _FakeSFTP(
        {
            remote_repo,
            f'{remote_repo}/scenarioforge',
            f'{remote_repo}/scenarioforge/__init__.py',
        }
    )
    client = _FakeSSHClient(fake_sftp)
    run_calls = []

    def fake_run_remote_python_json(_core_cfg, script, **_kwargs):
        run_calls.append(script)
        fake_sftp._existing_paths.update(
            {
                remote_run_dir,
                f'{remote_run_dir}/outputs.json',
                remote_artifact,
            }
        )
        return {'ok': True, 'out_dir': remote_run_dir, 'manifest_exists': True}

    monkeypatch.setattr(backend, '_remote_base_dir', lambda _sftp: '/remote/base')
    monkeypatch.setattr(backend, '_remote_static_repo_dir', lambda _sftp: remote_repo)
    monkeypatch.setattr(backend, '_remote_mkdirs', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(backend, '_get_repo_root', lambda: str(tmp_path / 'empty-repo'))
    monkeypatch.setattr(backend, '_run_remote_python_json', fake_run_remote_python_json)

    log_handle = io.StringIO()
    backend._prepare_remote_cli_context(
        client=client,
        run_id='run-regenerate',
        xml_path=str(xml_path),
        preview_plan_path=str(xml_path),
        log_handle=log_handle,
        core_cfg={'ssh_enabled': True, 'ssh_host': 'core.local', 'ssh_username': 'core', 'ssh_password': 'pw'},
    )

    assert len(run_calls) == 1
    assert 'text_secret' in run_calls[0]
    assert 'demo-seed' in run_calls[0]
    assert 'custom_input' in run_calls[0]
    assert 'flow.artifacts.regenerate complete count=1' in log_handle.getvalue()


def test_remote_flow_regenerate_script_compiles() -> None:
    script = backend._remote_flow_regenerate_script(
        assignment={
            'config': {'seed': 'demo'},
            'inject_files': ['/tmp/vulns/flag_generators_runs/flow-demo/01_text/artifacts/secret.txt -> /flow_injects'],
        },
        remote_repo='/tmp/scenarioforge',
        out_dir='/tmp/vulns/flag_generators_runs/flow-demo/01_text',
        kind='flag-generator',
        generator_id='text_secret',
        sudo_password='',
    )

    compile(script, '<remote-flow-regenerate>', 'exec')


def test_remote_flow_regenerate_failure_raises_concise_user_message(tmp_path, monkeypatch):
    remote_repo = '/remote/repo'
    remote_run_dir = '/tmp/vulns/flag_generators_runs/flow-demo/01_text'
    remote_artifact = f'{remote_run_dir}/artifacts/secret.txt'
    flow_state = {
        'flag_assignments': [
            {
                'id': 'text_secret',
                'type': 'flag-generator',
                'node_id': 'docker-1',
                'run_dir': remote_run_dir,
                'outputs_manifest': f'{remote_run_dir}/outputs.json',
                'inject_files': [f'{remote_artifact} -> /flow_injects'],
                'resolved_inputs': {'seed': 'demo-seed'},
            }
        ]
    }
    xml_path = tmp_path / 'preview.xml'
    xml_path.write_text(
        '\n'.join(
            [
                '<Scenarios>',
                '  <Scenario name="demo">',
                '    <ScenarioEditor>',
                '      <FlagSequencing>',
                f'        <FlowState>{json.dumps(flow_state, separators=(",", ":"))}</FlowState>',
                '      </FlagSequencing>',
                '    </ScenarioEditor>',
                '  </Scenario>',
                '</Scenarios>',
            ]
        ),
        encoding='utf-8',
    )

    monkeypatch.setattr(
        backend,
        '_run_remote_python_json',
        lambda *_args, **_kwargs: {'ok': False, 'stderr': 'very long internal regenerate failure'},
    )

    log_handle = io.StringIO()
    with pytest.raises(RuntimeError, match='Challenges and Flow Data not found on CORE VM') as excinfo:
        backend._regenerate_missing_remote_flow_artifacts_for_plan(
            sftp=_FakeSFTP(set()),
            preview_plan_path=str(xml_path),
            remote_repo=remote_repo,
            core_cfg={'ssh_enabled': True, 'ssh_host': 'core.local', 'ssh_username': 'core'},
            log_handle=log_handle,
        )

    assert str(excinfo.value) == backend.FLOW_REMOTE_ARTIFACTS_MISSING_MESSAGE
    assert 'flow.artifacts.regenerate failed details' in log_handle.getvalue()
    assert 'very long internal regenerate failure' in log_handle.getvalue()


def test_remote_flow_regenerate_can_defer_postcheck_to_revalidate(tmp_path, monkeypatch):
    remote_repo = '/remote/repo'
    remote_run_dir = '/tmp/vulns/flag_generators_runs/flow-demo/01_text'
    remote_artifact = f'{remote_run_dir}/artifacts/secret.txt'
    flow_state = {
        'flag_assignments': [
            {
                'id': 'text_secret',
                'type': 'flag-generator',
                'node_id': 'docker-1',
                'run_dir': remote_run_dir,
                'outputs_manifest': f'{remote_run_dir}/outputs.json',
                'inject_files': [f'{remote_artifact} -> /flow_injects'],
                'resolved_inputs': {'seed': 'demo-seed'},
            }
        ]
    }
    xml_path = tmp_path / 'preview.xml'
    xml_path.write_text(
        '\n'.join(
            [
                '<Scenarios>',
                '  <Scenario name="demo">',
                '    <ScenarioEditor>',
                '      <FlagSequencing>',
                f'        <FlowState>{json.dumps(flow_state, separators=(",", ":"))}</FlowState>',
                '      </FlagSequencing>',
                '    </ScenarioEditor>',
                '  </Scenario>',
                '</Scenarios>',
            ]
        ),
        encoding='utf-8',
    )

    monkeypatch.setattr(
        backend,
        '_run_remote_python_json',
        lambda *_args, **_kwargs: {'ok': True, 'out_dir': remote_run_dir, 'manifest_exists': True},
    )

    log_handle = io.StringIO()
    backend._regenerate_missing_remote_flow_artifacts_for_plan(
        sftp=_FakeSFTP(set()),
        preview_plan_path=str(xml_path),
        remote_repo=remote_repo,
        core_cfg={'ssh_enabled': True, 'ssh_host': 'core.local', 'ssh_username': 'core'},
        log_handle=log_handle,
        verify_after=False,
    )

    assert 'flow.artifacts.regenerate complete count=1' in log_handle.getvalue()
