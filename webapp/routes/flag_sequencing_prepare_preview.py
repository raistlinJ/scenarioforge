from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any

from flask import Response, jsonify, request, stream_with_context

from webapp import flow_prepare_preview_execute
from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_prepare_preview_routes'):
        return

    backend = backend_module

    # Resolving can run generators and persist the resolved Flow state.  Send
    # an immediate response byte plus periodic heartbeats so an idle HTTP
    # connection is not dropped while that work runs.  A retry carrying the
    # same request id attaches to this worker instead of running generators a
    # second time or writing the plan concurrently.
    _resolve_jobs_lock = threading.Lock()
    _resolve_jobs: dict[str, dict[str, Any]] = {}

    def _resolve_job_key(payload: dict[str, Any]) -> str:
        request_id = str((payload or {}).get('resolve_request_id') or '').strip()
        if request_id:
            return f'request:{request_id}'
        stable_payload = dict(payload or {})
        stable_payload.pop('progress_id', None)
        try:
            encoded = json.dumps(stable_payload, sort_keys=True, separators=(',', ':'), default=str)
        except Exception:
            encoded = repr(sorted((str(key), repr(value)) for key, value in stable_payload.items()))
        return hashlib.sha256(encoded.encode('utf-8', errors='ignore')).hexdigest()

    @app.route('/api/flag-sequencing/prepare_preview_for_execute', methods=['POST'])
    def api_flow_prepare_preview_for_execute():
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            payload = {}
        key = _resolve_job_key(payload)
        now = time.monotonic()

        with _resolve_jobs_lock:
            # Retain completed results just long enough for a browser retry to
            # retrieve them.  This also bounds the in-memory job cache.
            stale_keys = [
                job_key for job_key, job in _resolve_jobs.items()
                if job.get('done').is_set() and (now - float(job.get('completed_at') or now)) > 600
            ]
            for stale_key in stale_keys:
                _resolve_jobs.pop(stale_key, None)

            job = _resolve_jobs.get(key)
            if job is None:
                job = {
                    'done': threading.Event(),
                    'payload': dict(payload),
                    'body': b'',
                    'completed_at': 0.0,
                }
                _resolve_jobs[key] = job

                def _run_job(job_ref=job) -> None:
                    try:
                        with app.app_context():
                            response = app.make_response(
                                flow_prepare_preview_execute.execute(
                                    backend=backend,
                                    payload=job_ref['payload'],
                                )
                            )
                            job_ref['body'] = response.get_data()
                    except Exception as exc:
                        try:
                            app.logger.exception('Flow resolve worker failed.')
                        except Exception:
                            pass
                        with app.app_context():
                            job_ref['body'] = jsonify({
                                'ok': False,
                                'error': f'Internal error preparing preview for execution: {exc}',
                            }).get_data()
                    finally:
                        job_ref['completed_at'] = time.monotonic()
                        job_ref['done'].set()

                threading.Thread(
                    target=_run_job,
                    name=f'flow-resolve-{key[-8:]}',
                    daemon=True,
                ).start()

        def _stream_result():
            # JSON accepts leading/interstitial whitespace.  The first chunk
            # flushes headers immediately; subsequent chunks keep VM/proxy
            # idle timeouts from severing a long resolve request.
            yield b' \n'
            while not job['done'].wait(timeout=1):
                yield b' \n'
            yield job['body']

        return Response(
            stream_with_context(_stream_result()),
            status=200,
            content_type='application/json; charset=utf-8',
            headers={'Cache-Control': 'no-store'},
        )

    mark_routes_registered(app, 'flag_sequencing_prepare_preview_routes')
