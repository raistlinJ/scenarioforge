from __future__ import annotations

import json
from typing import Any, Callable, Optional

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    core_config_for_request: Callable[..., dict[str, Any]],
    latest_session_id_for_scenario: Callable[[str], Optional[int]] | None = None,
    init_artifact_check_progress: Callable[..., None],
    schedule_artifact_checks: Callable[..., None],
    get_artifact_check_progress: Callable[[str], Optional[dict[str, Any]]],
    uuid_hex: Callable[[], str],
) -> None:
    if not begin_route_registration(app, 'core_artifact_checks_routes'):
        return

    def _request_field(*names: str) -> str:
        if request.form:
            for name in names:
                value = request.form.get(name)
                if value not in (None, ''):
                    return str(value).strip()
        payload = request.get_json(silent=True)
        if isinstance(payload, dict):
            for name in names:
                value = payload.get(name)
                if value not in (None, ''):
                    return str(value).strip()
        return ''

    def _start_view():
        session_raw = _request_field('session_id')
        xml_path = _request_field('xml_path', 'path')
        scenario = _request_field('scenario', 'scenario_name')
        if not xml_path:
            return jsonify({'ok': False, 'error': 'The session scenario XML path is required.'}), 400

        session_id: Any = None
        if session_raw:
            try:
                session_id = int(session_raw)
            except Exception:
                session_id = session_raw
        elif scenario and latest_session_id_for_scenario:
            # Callers such as the Execution Summary know the scenario they just
            # ran but not its session id.
            session_id = latest_session_id_for_scenario(scenario)
        if session_id in (None, ''):
            return jsonify({
                'ok': False,
                'error': 'No running session id was given, and none is recorded for this scenario.',
            }), 400

        try:
            core_cfg = core_config_for_request(include_password=True)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Could not resolve CORE connection: {exc}'}), 400

        check_id = uuid_hex()
        try:
            init_artifact_check_progress(check_id, session_id=session_id, scenario=scenario)
            schedule_artifact_checks(
                check_id, core_cfg,
                session_id=session_id, xml_path=xml_path,
                scenario_label=scenario or None, logger=app.logger,
            )
        except Exception as exc:
            try:
                app.logger.exception('[check_artifacts] failed to start')
            except Exception:
                pass
            return jsonify({'ok': False, 'error': f'Failed to start artifact checks: {exc}', 'check_id': check_id}), 500
        return jsonify({'ok': True, 'check_id': check_id})

    def _status_view(check_id: str):
        payload = get_artifact_check_progress(check_id)
        if not payload:
            return jsonify({'ok': False, 'check_id': check_id, 'status': 'unknown'}), 404
        payload = dict(payload)
        payload['ok'] = True
        return jsonify(payload)

    app.add_url_rule('/core/check_artifacts/start', endpoint='core_check_artifacts_start',
                     view_func=_start_view, methods=['POST'])
    app.add_url_rule('/core/check_artifacts/status/<check_id>', endpoint='core_check_artifacts_status',
                     view_func=_status_view, methods=['GET'])

    mark_routes_registered(app, 'core_artifact_checks_routes')
