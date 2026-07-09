from __future__ import annotations

import time
from typing import Any, Callable

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    login_required: Callable[[Callable[..., Any]], Callable[..., Any]],
    normalize_scenario_label: Callable[[str], str],
    select_core_config_for_page: Callable[..., dict[str, Any]],
    open_ssh_client: Callable[[dict[str, Any]], Any],
    collect_remote_core_daemon_pids: Callable[[Any], list[int]],
    stop_remote_core_daemon_conflict: Callable[..., Any],
) -> None:
    if not begin_route_registration(app, 'core_daemon_admin_routes'):
        return

    def _restart_core_daemon_view():
        scenario_norm = normalize_scenario_label(request.args.get('scenario', ''))
        core_cfg = select_core_config_for_page(scenario_norm, include_password=True)
        payload = request.get_json(silent=True) or {}
        force_kill = bool(payload.get('force_kill_existing'))

        if not core_cfg.get('ssh_host'):
            return jsonify({'error': 'No CORE VM configured via SSH.'}), 400

        try:
            app.logger.info('[core.daemon] Attempting restart via SSH')
            client = open_ssh_client(core_cfg)
            daemon_pids = collect_remote_core_daemon_pids(client)

            if daemon_pids and not force_kill:
                return jsonify({
                    'ok': False,
                    'error': (
                        'core-daemon is already running on the CORE VM. '
                        f'PIDs: {", ".join(str(pid) for pid in daemon_pids)}.'
                    ),
                    'daemon_running': True,
                    'daemon_pids': daemon_pids,
                    'can_stop_daemons': bool(core_cfg.get('ssh_password')),
                    'code': 'core_daemon_running',
                }), 409

            if daemon_pids and force_kill:
                if not core_cfg.get('ssh_password'):
                    return jsonify({
                        'ok': False,
                        'error': 'Stopping core-daemon requires sudo; provide an SSH password.',
                        'can_stop_daemons': False,
                    }), 400
                stop_remote_core_daemon_conflict(
                    client,
                    sudo_password=core_cfg.get('ssh_password'),
                    pids=daemon_pids,
                    logger=app.logger,
                )
                time.sleep(1.0)
                daemon_pids = collect_remote_core_daemon_pids(client)
                if len(daemon_pids) > 1:
                    return jsonify({
                        'ok': False,
                        'error': (
                            'Multiple core-daemon processes are still running after stop attempt. '
                            f'PIDs: {", ".join(str(pid) for pid in daemon_pids)}.'
                        ),
                        'daemon_conflict': True,
                        'daemon_pids': daemon_pids,
                        'can_stop_daemons': bool(core_cfg.get('ssh_password')),
                        'code': 'core_daemon_conflict',
                    }), 409

            def _sudo_exec(cmd: str, *, timeout: float = 40.0) -> tuple[int, str, str]:
                from webapp.app_backend import _scrub_password_echo
                sudo_password = core_cfg.get('ssh_password')
                wrapped = f"sh -c 'timeout {int(max(5, timeout))}s {cmd.strip()}'"
                sudo_cmd = f"sudo -S -p '' {wrapped}" if sudo_password else f"sudo -n {wrapped}"
                stdin = stdout = stderr = None
                try:
                    stdin, stdout, stderr = client.exec_command(sudo_cmd, timeout=timeout + 5.0, get_pty=True)
                    if sudo_password:
                        try:
                            stdin.write(str(sudo_password) + '\n')
                            stdin.flush()
                        except Exception:
                            pass
                    out_bytes = stdout.read() if stdout else b''
                    err_bytes = stderr.read() if stderr else b''
                    try:
                        code = stdout.channel.recv_exit_status() if (stdout and hasattr(stdout, 'channel')) else 0
                    except Exception:
                        code = 0
                    out_text = _scrub_password_echo(out_bytes.decode('utf-8', 'ignore') if isinstance(out_bytes, (bytes, bytearray)) else str(out_bytes or ''), sudo_password)
                    err_text = _scrub_password_echo(err_bytes.decode('utf-8', 'ignore') if isinstance(err_bytes, (bytes, bytearray)) else str(err_bytes or ''), sudo_password)
                    return int(code), out_text, err_text
                finally:
                    try:
                        if stdin:
                            stdin.close()
                    except Exception:
                        pass

            exit_code, _out, err = _sudo_exec('systemctl restart core-daemon || systemctl start core-daemon', timeout=40.0)
            if exit_code != 0:
                err = (err or '').strip()
                return jsonify({'error': f'Restart failed (exit {exit_code}): {err}'}), 500

            daemon_pids = collect_remote_core_daemon_pids(client)
            if len(daemon_pids) > 1:
                return jsonify({
                    'ok': False,
                    'error': (
                        'Restart resulted in multiple core-daemon processes. '
                        f'PIDs: {", ".join(str(pid) for pid in daemon_pids)}.'
                    ),
                    'daemon_conflict': True,
                    'daemon_pids': daemon_pids,
                    'can_stop_daemons': bool(core_cfg.get('ssh_password')),
                    'code': 'core_daemon_conflict',
                }), 409

            if len(daemon_pids) == 0:
                chk_code, _, _ = _sudo_exec('systemctl is-active core-daemon', timeout=10.0)
                if chk_code != 0:
                    return jsonify({'error': 'Restart command succeeded but service is not active.'}), 500

            if len(daemon_pids) == 1:
                app.logger.info('[core.daemon] Restart successful (pid=%s)', daemon_pids[0])
            elif len(daemon_pids) == 0:
                app.logger.info('[core.daemon] Restart successful (service active; pid discovery unavailable)')

            time.sleep(2.0)
            return jsonify({'status': 'ok', 'message': 'CORE daemon restarted successfully.', 'daemon_pids': daemon_pids})
        except Exception as exc:
            app.logger.error('Failed to restart CORE daemon: %s', exc, exc_info=True)
            msg = str(exc)
            if 'Authentication failed' in msg:
                msg = 'SSH authentication failed. Check your credentials in Scenarios > Config.'
            return jsonify({'error': msg}), 500
        finally:
            try:
                if 'client' in locals() and client is not None:
                    client.close()
            except Exception:
                pass

    app.add_url_rule(
        '/core/restart_core_daemon',
        endpoint='restart_core_daemon',
        view_func=login_required(_restart_core_daemon_view),
        methods=['POST'],
    )
    mark_routes_registered(app, 'core_daemon_admin_routes')