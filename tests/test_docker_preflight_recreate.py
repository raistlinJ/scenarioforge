from pathlib import Path

import scenarioforge.builders.topology as topo


class _Proc:
    def __init__(self, returncode: int, stdout: str = ''):
        self.returncode = returncode
        self.stdout = stdout


def test_docker_compose_preflight_force_recreates_stale_restarting_container(tmp_path, monkeypatch):
    compose_path = tmp_path / 'docker-compose.yml'
    compose_path.write_text(
        'services:\n'
        '  docker-3:\n'
        '    image: alpine:3.20\n'
        '    container_name: docker-3\n',
        encoding='utf-8',
    )

    calls = []
    inspect_calls = {'count': 0}

    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        calls.append(argv)

        if argv[:3] == ['docker', 'compose', '-p']:
            if argv[-1:] == ['build']:
                return _Proc(0, '')
            if 'pull' in argv:
                return _Proc(0, '')
            if argv[-2:] == ['up', '--no-start']:
                return _Proc(0, '')
            if argv[-4:] == ['up', '-d', '--no-build', 'docker-3']:
                return _Proc(0, '')
            if argv[-5:] == ['up', '-d', '--force-recreate', '--no-build', 'docker-3']:
                return _Proc(0, '')
            if argv[-4:] == ['rm', '-f', '-s', 'docker-3']:
                return _Proc(0, '')
        if argv[:3] == ['docker', 'inspect', '--format']:
            fmt = argv[3]
            if fmt == '{{.State.Pid}} {{.State.Status}}':
                inspect_calls['count'] += 1
                if inspect_calls['count'] <= 5:
                    return _Proc(0, '0 restarting')
                return _Proc(0, '123 running')
            if fmt == '{{json .State}}':
                return _Proc(0, '{"Status":"running","Pid":123}')
        if argv[:3] == ['docker', 'rm', '-f']:
            return _Proc(0, '')
        raise AssertionError(f'unexpected args: {argv}')

    monkeypatch.setattr(topo, '_docker_compose_cmd', lambda: ['docker', 'compose'])
    monkeypatch.setattr(topo, '_docker_cmd', lambda: ['docker'])
    monkeypatch.setattr(topo.subprocess, 'run', fake_run)
    monkeypatch.setattr(topo.time, 'sleep', lambda _s: None)
    monkeypatch.setenv('CORETG_DOCKER_PREFLIGHT_WAIT_SECONDS', '1')
    monkeypatch.setenv('CORETG_DOCKER_PREFLIGHT_POLL_SECONDS', '1')
    topo._PREFLIGHTED_DOCKER_NODE_COMPOSES.discard(str(Path(compose_path).resolve()))

    topo._docker_compose_preflight(str(compose_path), node_name='docker-3')

    assert ['docker', 'rm', '-f', 'docker-3'] in calls
    assert ['docker', 'compose', '-p', 'docker-3conf', '-f', str(compose_path), 'up', '-d', '--force-recreate', '--no-build', 'docker-3'] in calls


def test_docker_compose_preflight_builds_build_only_dependency_without_explicit_image(tmp_path, monkeypatch):
    compose_path = tmp_path / 'docker-compose.yml'
    wrapper_ctx = tmp_path / 'wrapper'
    wrapper_ctx.mkdir()
    (wrapper_ctx / 'Dockerfile').write_text('FROM alpine:3.20\n', encoding='utf-8')

    smtpd_ctx = tmp_path / 'smtpd'
    smtpd_ctx.mkdir()
    (smtpd_ctx / 'Dockerfile').write_text('FROM alpine:3.20\n', encoding='utf-8')

    compose_path.write_text(
        (
            'services:\n'
            '  docker-1:\n'
            '    image: coretg/test-jira:iproute2\n'
            '    container_name: docker-1\n'
            '    labels:\n'
            f'      coretg.wrapper_build_context: {wrapper_ctx}\n'
            '    depends_on:\n'
            '      - smtpd\n'
            '  smtpd:\n'
            '    build: smtpd\n'
        ),
        encoding='utf-8',
    )

    calls = []

    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        calls.append(argv)

        if argv[:2] == ['docker', 'build']:
            return _Proc(0, '')
        if argv[:3] == ['docker', 'compose', '-p']:
            if argv[-2:] == ['pull', '--ignore-buildable']:
                return _Proc(0, '')
            if argv[-3:] == ['up', '--no-start', '--no-build']:
                return _Proc(0, '')
            if argv[-4:] == ['up', '-d', '--no-build', 'docker-1']:
                return _Proc(0, '')
        if argv[:3] == ['docker', 'inspect', '--format']:
            if argv[3] == '{{.State.Pid}} {{.State.Status}}':
                return _Proc(0, '123 running')
        raise AssertionError(f'unexpected args: {argv}')

    monkeypatch.setattr(topo, '_docker_compose_cmd', lambda: ['docker', 'compose'])
    monkeypatch.setattr(topo, '_docker_cmd', lambda: ['docker'])
    monkeypatch.setattr(topo.subprocess, 'run', fake_run)
    topo._PREFLIGHTED_DOCKER_NODE_COMPOSES.discard(str(Path(compose_path).resolve()))

    topo._docker_compose_preflight(str(compose_path), node_name='docker-1')

    assert [
        'docker',
        'build',
        '--network',
        'host',
        '-t',
        'coretg/test-jira:iproute2',
        '-f',
        str(wrapper_ctx / 'Dockerfile'),
        str(wrapper_ctx),
    ] in calls
    assert [
        'docker',
        'build',
        '--network',
        'host',
        '-t',
        'docker-1conf-smtpd',
        '-f',
        str(smtpd_ctx / 'Dockerfile'),
        str(smtpd_ctx),
    ] in calls
    assert ['docker', 'compose', '-p', 'docker-1conf', '-f', str(compose_path), 'build'] not in calls


def test_docker_compose_preflight_fails_on_wrapper_build_failure(tmp_path, monkeypatch):
    compose_path = tmp_path / 'docker-compose.yml'
    wrapper_ctx = tmp_path / 'wrapper'
    wrapper_ctx.mkdir()
    (wrapper_ctx / 'Dockerfile').write_text('FROM vulhub/appweb:7.0.1\n', encoding='utf-8')

    compose_path.write_text(
        (
            'services:\n'
            '  docker-7:\n'
            '    image: coretg/unique-flow-chain-docker-7:iproute2\n'
            '    container_name: docker-7\n'
            '    labels:\n'
            f'      coretg.wrapper_build_context: {wrapper_ctx}\n'
        ),
        encoding='utf-8',
    )

    calls = []

    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        calls.append(argv)
        if argv[:2] == ['docker', 'build']:
            return _Proc(1, 'base image pull failed')
        raise AssertionError(f'unexpected args after wrapper build failure: {argv}')

    monkeypatch.setattr(topo, '_docker_compose_cmd', lambda: ['docker', 'compose'])
    monkeypatch.setattr(topo, '_docker_cmd', lambda: ['docker'])
    monkeypatch.setattr(topo.subprocess, 'run', fake_run)
    monkeypatch.delenv('CORETG_DOCKER_STRICT_PULL', raising=False)
    topo._PREFLIGHTED_DOCKER_NODE_COMPOSES.discard(str(Path(compose_path).resolve()))

    try:
        topo._docker_compose_preflight(str(compose_path), node_name='docker-7')
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError('expected wrapper build failure to abort preflight')

    assert 'docker wrapper image build failed' in message
    assert 'coretg/unique-flow-chain-docker-7:iproute2' in message
    assert 'base image pull failed' in message
    assert calls == [
        [
            'docker',
            'build',
            '--network',
            'host',
            '-t',
            'coretg/unique-flow-chain-docker-7:iproute2',
            '-f',
            str(wrapper_ctx / 'Dockerfile'),
            str(wrapper_ctx),
        ]
    ]


def test_docker_compose_preflight_runs_inject_helpers_before_target_service(tmp_path, monkeypatch):
    compose_path = tmp_path / 'docker-compose.yml'
    compose_path.write_text(
        'services:\n'
        '  docker-1:\n'
        '    image: alpine:3.20\n'
        '    container_name: docker-1\n'
        '  inject_copy:\n'
        '    image: alpine:3.20\n',
        encoding='utf-8',
    )

    calls = []

    def fake_run(args, stdout=None, stderr=None, text=None, timeout=None, input=None):
        argv = list(args)
        calls.append(argv)

        if argv[:3] == ['docker', 'compose', '-p']:
            if argv[-1:] == ['build']:
                return _Proc(0, '')
            if 'pull' in argv:
                return _Proc(0, '')
            if argv[-2:] == ['up', '--no-start']:
                return _Proc(0, '')
            if argv[-3:] == ['up', '--no-build', 'inject_copy']:
                return _Proc(0, 'inject_copy exited with code 0')
            if argv[-4:] == ['ps', '--all', '-q', 'inject_copy']:
                return _Proc(0, 'helper-container-id\n')
            if argv[-4:] == ['up', '-d', '--no-build', 'docker-1']:
                return _Proc(0, '')
        if argv[:3] == ['docker', 'inspect', '--format']:
            if argv[3] == '{{.State.ExitCode}} {{.State.Status}}':
                return _Proc(0, '0 exited')
            if argv[3] == '{{.State.Pid}} {{.State.Status}}':
                return _Proc(0, '123 running')
        raise AssertionError(f'unexpected args: {argv}')

    monkeypatch.setattr(topo, '_docker_compose_cmd', lambda: ['docker', 'compose'])
    monkeypatch.setattr(topo, '_docker_cmd', lambda: ['docker'])
    monkeypatch.setattr(topo.subprocess, 'run', fake_run)
    topo._PREFLIGHTED_DOCKER_NODE_COMPOSES.discard(str(Path(compose_path).resolve()))

    topo._docker_compose_preflight(str(compose_path), node_name='docker-1')

    helper_up = [
        'docker',
        'compose',
        '-p',
        'docker-1conf',
        '-f',
        str(compose_path),
        'up',
        '--no-build',
        'inject_copy',
    ]
    target_up = [
        'docker',
        'compose',
        '-p',
        'docker-1conf',
        '-f',
        str(compose_path),
        'up',
        '-d',
        '--no-build',
        'docker-1',
    ]
    assert helper_up in calls
    assert target_up in calls
    assert calls.index(helper_up) < calls.index(target_up)
