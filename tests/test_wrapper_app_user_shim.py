import json
import subprocess
from pathlib import Path

import yaml

from scenarioforge.builders import topology
from scenarioforge.utils import vuln_process


def test_wrapper_dockerfile_contains_user_probe_and_shim(tmp_path, monkeypatch):
    monkeypatch.delenv('CORETG_IPROUTE2_WRAPPER_STRATEGY', raising=False)
    path = vuln_process._write_iproute2_wrapper(str(tmp_path), 'vulhub/kibana:6.5.4')
    txt = Path(path).read_text(encoding='utf-8')
    assert 'AS coretg_userprobe' in txt
    assert '/usr/local/coretg/base_user' in txt
    assert vuln_process.CORETG_APP_USER_SHIM_PATH in txt
    assert 'setuidgid' in txt


def test_wrapper_dockerfile_packages_strategy_ships_busybox_shim(tmp_path, monkeypatch):
    monkeypatch.setenv('CORETG_IPROUTE2_WRAPPER_STRATEGY', 'packages')
    path = vuln_process._write_iproute2_wrapper(str(tmp_path), 'vulhub/kibana:6.5.4')
    txt = Path(path).read_text(encoding='utf-8')
    assert 'AS coretg_userprobe' in txt
    assert 'COPY --from=coretg_iptools /bin/busybox /usr/local/coretg/bin/busybox' in txt
    assert vuln_process.CORETG_APP_USER_SHIM_PATH in txt


def _write_compose(tmp_path, *, entrypoint=None, command=None):
    svc = {
        'image': 'coretg/scenario-node:iproute2',
        'user': '0:0',
        'labels': {
            'coretg.wrapper_build_context': str(tmp_path / 'wrap-ctx'),
            'coretg.wrapper_base_image': 'vulhub/kibana:6.5.4',
        },
    }
    if entrypoint is not None:
        svc['entrypoint'] = entrypoint
    if command is not None:
        svc['command'] = command
    compose = {'services': {'kibana': svc}}
    p = tmp_path / 'docker-compose.yml'
    p.write_text(yaml.safe_dump(compose, sort_keys=False), encoding='utf-8')
    return p


def _fake_run_factory(config):
    calls = []

    def run(args, timeout=None):
        calls.append([str(a) for a in args])
        if 'inspect' in args:
            return 0, json.dumps(config)
        return 0, ''

    return run, calls


def test_app_user_shim_rewrites_nonroot_base(tmp_path):
    p = _write_compose(tmp_path)
    run, calls = _fake_run_factory({
        'User': 'kibana',
        'Entrypoint': ['/usr/local/bin/dumb-init', '--'],
        'Cmd': ['/usr/local/bin/kibana-docker'],
    })
    topology._apply_wrapper_app_user_entrypoints(str(p), docker_cmd=['docker'], run=run, node_name='n1')
    obj = yaml.safe_load(p.read_text(encoding='utf-8'))
    svc = obj['services']['kibana']
    assert svc['entrypoint'] == [topology._CORETG_APP_USER_SHIM, '/usr/local/bin/dumb-init', '--']
    assert svc['command'] == ['/usr/local/bin/kibana-docker']
    # docker exec must keep running as root for CORE service files.
    assert svc['user'] == '0:0'
    assert any('inspect' in c for c in calls)


def test_app_user_shim_skips_root_base(tmp_path):
    p = _write_compose(tmp_path)
    before = p.read_text(encoding='utf-8')
    run, _calls = _fake_run_factory({'User': '', 'Entrypoint': None, 'Cmd': ['nginx', '-g', 'daemon off;']})
    topology._apply_wrapper_app_user_entrypoints(str(p), docker_cmd=['docker'], run=run, node_name='n1')
    assert p.read_text(encoding='utf-8') == before


def test_app_user_shim_wraps_existing_entrypoint_and_is_idempotent(tmp_path):
    p = _write_compose(tmp_path, entrypoint='sh', command=['-lc', 'airflow initdb && airflow webserver'])
    run, _calls = _fake_run_factory({'User': 'airflow', 'Entrypoint': ['airflow'], 'Cmd': None})
    topology._apply_wrapper_app_user_entrypoints(str(p), docker_cmd=['docker'], run=run, node_name='n1')
    obj = yaml.safe_load(p.read_text(encoding='utf-8'))
    svc = obj['services']['kibana']
    assert svc['entrypoint'] == [topology._CORETG_APP_USER_SHIM, 'sh']
    assert svc['command'] == ['-lc', 'airflow initdb && airflow webserver']

    topology._apply_wrapper_app_user_entrypoints(str(p), docker_cmd=['docker'], run=run, node_name='n1')
    obj2 = yaml.safe_load(p.read_text(encoding='utf-8'))
    assert obj2['services']['kibana']['entrypoint'] == [topology._CORETG_APP_USER_SHIM, 'sh']


def test_preflight_applies_app_user_shim(tmp_path, monkeypatch):
    wrap_ctx = tmp_path / 'wrap-ctx'
    wrap_ctx.mkdir()
    (wrap_ctx / 'Dockerfile').write_text('FROM vulhub/kibana:6.5.4\n', encoding='utf-8')
    compose_path = tmp_path / 'docker-compose-docker-1.yml'
    compose_path.write_text(
        yaml.safe_dump(
            {
                'services': {
                    'docker-1': {
                        'image': 'coretg/scenario-docker-1:iproute2',
                        'pull_policy': 'never',
                        'user': '0:0',
                        'labels': {
                            'coretg.wrapper_build_context': str(wrap_ctx),
                            'coretg.wrapper_build_dockerfile': 'Dockerfile',
                            'coretg.wrapper_base_image': 'vulhub/kibana:6.5.4',
                        },
                    },
                },
            },
            sort_keys=False,
        ),
        encoding='utf-8',
    )

    config = {
        'User': 'kibana',
        'Entrypoint': ['/usr/local/bin/dumb-init', '--'],
        'Cmd': ['/usr/local/bin/kibana-docker'],
    }

    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        call = [str(arg) for arg in args]
        if call[:3] == ['docker', 'image', 'inspect']:
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(config) + '\n')
        if call[:2] == ['docker', 'inspect']:
            return subprocess.CompletedProcess(args, 0, stdout='123 running\n')
        return subprocess.CompletedProcess(args, 0, stdout='')

    monkeypatch.setattr(topology, '_docker_compose_cmd', lambda: ['docker', 'compose'])
    monkeypatch.setattr(topology, '_docker_cmd', lambda: ['docker'])
    monkeypatch.setattr(topology, '_docker_sudo_password', lambda: None)
    monkeypatch.setattr(topology.subprocess, 'run', fake_run)
    topology._PREFLIGHTED_DOCKER_NODE_COMPOSES.clear()

    topology._docker_compose_preflight(str(compose_path), node_name='docker-1')

    obj = yaml.safe_load(compose_path.read_text(encoding='utf-8'))
    svc = obj['services']['docker-1']
    assert svc['entrypoint'] == [topology._CORETG_APP_USER_SHIM, '/usr/local/bin/dumb-init', '--']
    assert svc['command'] == ['/usr/local/bin/kibana-docker']
    assert svc['user'] == '0:0'


def _ip_repair_harness(monkeypatch, *, has_ip, fail_create=False):
    """Fake docker `run` plus host filesystem state for the ip repair."""
    calls = []
    state = {'linked': False, 'host_busybox': False}

    def run(args, timeout=None):
        call = [str(a) for a in args]
        calls.append(call)
        is_exec = 'exec' in call
        if is_exec and call[-3:] in (['ip', 'link', 'show'], ['/sbin/ip', 'link', 'show']):
            return (0, '1: lo') if (has_ip or state['linked']) else (127, 'not found')
        if is_exec and 'ln' in call:
            state['linked'] = True
            return 0, ''
        if call[1] == 'inspect' and any('{{.Image}}' in part for part in call):
            return 0, 'sha256:abc123'
        if call[1:3] == ['image', 'inspect']:
            return 0, 'linux|amd64|'
        if call[1] == 'create':
            return (1, 'boom') if fail_create else (0, 'cid')
        if call[1] == 'cp':
            # Extracting busybox out of the source container populates the host cache.
            if ':/bin/busybox' in call[-2]:
                state['host_busybox'] = True
            return 0, ''
        return 0, ''

    monkeypatch.setattr(topology.os.path, 'isfile', lambda p: state['host_busybox'])
    monkeypatch.setattr(topology.os, 'chmod', lambda *a, **k: None)
    return run, calls


def test_ip_repair_noop_when_ip_present(monkeypatch):
    run, calls = _ip_repair_harness(monkeypatch, has_ip=True)
    assert topology._ensure_container_ip_tooling('c1', docker_cmd=['docker'], run=run, node_name='n1') is True
    assert not any(c[1] == 'cp' for c in calls)


def test_ip_repair_injects_busybox_when_missing(monkeypatch):
    run, calls = _ip_repair_harness(monkeypatch, has_ip=False)
    assert topology._ensure_container_ip_tooling('c1', docker_cmd=['docker'], run=run, node_name='n1') is True
    # Must fetch a busybox matching the container image architecture.
    create = next(c for c in calls if c[1] == 'create')
    assert '--platform' in create and 'linux/amd64' in create
    # Must land at a path named exactly `busybox` for applet dispatch.
    cp_into = next(c for c in calls if c[1] == 'cp' and c[-1].startswith('c1:'))
    assert cp_into[-1] == 'c1:/busybox'
    assert any('/sbin/ip' in c for c in calls if 'ln' in c)


def test_ip_repair_reports_failure_when_busybox_unavailable(monkeypatch):
    run, _calls = _ip_repair_harness(monkeypatch, has_ip=False, fail_create=True)
    assert topology._ensure_container_ip_tooling('c1', docker_cmd=['docker'], run=run, node_name='n1') is False


def test_container_image_platform_includes_variant():
    def run(args, timeout=None):
        call = [str(a) for a in args]
        if call[1] == 'inspect':
            return 0, 'sha256:deadbeef'
        return 0, 'linux|arm64|v8'

    assert topology._container_image_platform('c1', docker_cmd=['docker'], run=run) == 'linux/arm64/v8'
