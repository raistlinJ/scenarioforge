from __future__ import annotations

import json
from typing import Any, Callable

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    merge_core_configs: Callable[..., dict[str, Any]],
    apply_core_secret_to_config: Callable[[dict[str, Any], str], dict[str, Any]],
    require_core_ssh_credentials: Callable[[dict[str, Any]], dict[str, Any]],
    open_ssh_client: Callable[[dict[str, Any]], Any],
    remote_core_service_names: Callable[..., set[str]],
    install_custom_services_to_core_vm: Callable[..., dict[str, Any]],
    local_custom_service_names: Callable[[], list[str]],
) -> None:
    if not begin_route_registration(app, 'core_custom_services_routes'):
        return

    def _payload_core_config(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str, tuple[dict[str, Any], int] | None]:
        scenario_name = str(payload.get('scenario_name') or payload.get('scenario') or '').strip()
        core_cfg = payload.get('core')
        if not isinstance(core_cfg, dict):
            try:
                core_json = payload.get('core_json')
                if core_json:
                    core_cfg = json.loads(core_json)
            except Exception:
                core_cfg = None
        if not isinstance(core_cfg, dict):
            return None, scenario_name, ({'ok': False, 'error': 'core config missing'}, 400)
        try:
            core_cfg = merge_core_configs(core_cfg, include_password=True)
            core_cfg = apply_core_secret_to_config(core_cfg, scenario_name)
            core_cfg = require_core_ssh_credentials(core_cfg)
        except Exception as exc:
            return None, scenario_name, ({'ok': False, 'error': str(exc)}, 400)
        return core_cfg, scenario_name, None

    def _check_custom_services_view():
        raw_payload = request.get_json(silent=True) or {}
        payload = raw_payload if isinstance(raw_payload, dict) else {}
        core_cfg, _scenario_name, error = _payload_core_config(payload)
        if error:
            body, status = error
            return jsonify(body), status
        required = local_custom_service_names()
        if not required:
            return jsonify({'ok': False, 'error': 'No local custom CORE services found.'}), 500

        install_requested = bool(payload.get('install'))
        client = None
        install_meta = None
        try:
            client = open_ssh_client(core_cfg or {})
            discovered = sorted(
                remote_core_service_names(client, core_cfg=core_cfg, require_custom_services_dir=True),
                key=str.lower,
            )
            missing = sorted([name for name in required if name not in set(discovered)], key=str.lower)
            if install_requested and missing:
                install_meta = install_custom_services_to_core_vm(
                    client,
                    sudo_password=(core_cfg or {}).get('ssh_password'),
                    logger=app.logger,
                    core_cfg=core_cfg,
                )
                discovered = sorted(
                    remote_core_service_names(client, core_cfg=core_cfg, require_custom_services_dir=True),
                    key=str.lower,
                )
                missing = sorted([name for name in required if name not in set(discovered)], key=str.lower)
            if install_requested and missing:
                return jsonify(
                    {
                        'ok': False,
                        'installed': bool(install_meta),
                        'missing_services': missing,
                        'required_services': required,
                        'discovered_services': discovered,
                        'install_custom_services': install_meta,
                        'error': 'Custom CORE services are still missing after install.',
                    }
                ), 409
            return jsonify(
                {
                    'ok': True,
                    'installed': bool(install_meta),
                    'missing_services': missing,
                    'required_services': required,
                    'discovered_services': discovered,
                    'install_custom_services': install_meta,
                }
            )
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 500
        finally:
            try:
                if client:
                    client.close()
            except Exception:
                pass

    app.add_url_rule('/core/custom_services/check', endpoint='core_custom_services_check', view_func=_check_custom_services_view, methods=['POST'])
    mark_routes_registered(app, 'core_custom_services_routes')
