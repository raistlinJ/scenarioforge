from __future__ import annotations

import os
from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered
from webapp.routes.vuln_catalog_batch import _item_matches_query, _prefer_explicit_or_ssh_core_host


_CACHE_LOG_LINE_LIMIT = 500
_CACHE_RUN_KINDS = ('vuln_image_cache',)


def _append_cache_log(meta: dict[str, Any], message: str) -> None:
    if not isinstance(meta, dict):
        return
    lines = meta.get('log_lines')
    if not isinstance(lines, list):
        lines = []
    text = str(message or '').strip()
    if not text:
        return
    lines.append(text)
    if len(lines) > _CACHE_LOG_LINE_LIMIT:
        lines = lines[-_CACHE_LOG_LINE_LIMIT:]
    meta['log_lines'] = lines


def _summarize_cache_run(meta: dict[str, Any]) -> dict[str, int]:
    items = meta.get('selected_items') if isinstance(meta.get('selected_items'), list) else []
    total = len(items)
    results = meta.get('results') if isinstance(meta.get('results'), list) else []
    ok = len([r for r in results if isinstance(r, dict) and r.get('ok')])
    failed = len([r for r in results if isinstance(r, dict) and not r.get('ok')])
    return {
        'total': total,
        'completed': len(results),
        'ok': ok,
        'failed': failed,
        'pending': max(0, total - len(results)),
    }


def _run_cache_job(backend: Any, meta: dict[str, Any], core_cfg: dict[str, Any]) -> None:
    mode = str(meta.get('mode') or 'pull')
    items = meta.get('selected_items') if isinstance(meta.get('selected_items'), list) else []
    total = len(items)
    catalog_id = str(meta.get('catalog_id') or '')
    core_host = str(core_cfg.get('ssh_host') or core_cfg.get('host') or '')
    sudo = backend._coerce_bool(core_cfg.get('docker_use_sudo', True))
    pw = str(core_cfg.get('ssh_password') or '')

    meta['status'] = 'running'
    _append_cache_log(meta, f"[cache] {mode}: queued {total} item(s)")

    try:
        push_result = backend._push_repo_to_remote(core_cfg, upload_only_injected_artifacts=True)
        remote_repo_dir = str((push_result or {}).get('repo_path') or '').strip()
        _append_cache_log(meta, f"[cache] repo sync complete (repo_path={remote_repo_dir or 'unknown'})")
    except Exception as exc:
        remote_repo_dir = ''
        _append_cache_log(meta, f"[cache] repo sync failed: {exc}")

    client = None
    try:
        client = backend._open_ssh_client(core_cfg)
    except Exception as exc:
        _append_cache_log(meta, f"[cache] SSH connect failed: {exc}")
        meta['status'] = 'failed'
        meta['done'] = True
        meta['finished_at'] = backend._local_timestamp_display()
        return

    repo_root = os.path.abspath(backend._get_repo_root())
    results: list[dict[str, Any]] = []

    try:
        for index, item in enumerate(items):
            if meta.get('stop_requested'):
                break
            item_id = int(item.get('id') or 0)
            item_name = backend._vuln_catalog_item_display_name(item)
            meta['active_item_id'] = item_id
            meta['active_item_name'] = item_name
            meta['active_index'] = index + 1
            _append_cache_log(meta, f"[cache] {index + 1}/{total}: #{item_id} {item_name}")

            result: dict[str, Any] = {
                'item_id': item_id,
                'item_name': item_name,
                'ok': False,
                'cached': None,
                'missing_images': [],
                'error': None,
            }

            local_path = None
            try:
                local_path = backend._vuln_catalog_item_abs_compose_path(catalog_id=catalog_id, item=item)
            except Exception as exc:
                result['error'] = f'invalid compose path: {exc}'

            remote_yml = ''
            if local_path and os.path.isfile(local_path) and remote_repo_dir:
                try:
                    rel = os.path.relpath(local_path, repo_root).replace(os.sep, '/')
                except Exception:
                    rel = ''
                if rel and not rel.startswith('..'):
                    remote_yml = backend._remote_path_join(remote_repo_dir, rel)

            if not remote_yml:
                result['error'] = result['error'] or 'compose file not found or not under repo root'
                results.append(result)
                meta['results'] = results
                continue

            try:
                rc, out, _err = backend._exec_ssh_command(
                    client, f"[ -f {backend.shlex.quote(remote_yml)} ] && echo present || echo missing",
                    timeout=15.0, check=False,
                )
                if 'present' not in (out or ''):
                    result['error'] = 'compose file not synced to CORE VM yet'
                    results.append(result)
                    meta['results'] = results
                    continue
            except Exception as exc:
                result['error'] = f'remote existence check failed: {exc}'
                results.append(result)
                meta['results'] = results
                continue

            if mode == 'pull':
                cmd = f"docker compose -f {backend.shlex.quote(remote_yml)} pull"
                try:
                    if sudo:
                        rc, out, err = backend._exec_ssh_sudo_command(client, cmd, password=pw, timeout=600.0)
                    else:
                        rc, out, err = backend._exec_ssh_command(client, cmd, timeout=600.0, check=False)
                    result['ok'] = rc == 0
                    result['cached'] = rc == 0
                    if rc != 0:
                        result['error'] = (str(err or out or 'docker compose pull failed').strip())[-1000:]
                except Exception as exc:
                    result['error'] = str(exc)
                _append_cache_log(meta, f"[cache] pull #{item_id}: {'ok' if result['ok'] else 'failed'}")
            else:
                try:
                    images_cmd = f"docker compose -f {backend.shlex.quote(remote_yml)} config --images 2>/dev/null"
                    rc, out, _err = backend._exec_ssh_command(client, images_cmd, timeout=60.0, check=False)
                    images = [line.strip() for line in (out or '').splitlines() if line.strip()]
                    missing: list[str] = []
                    for image_ref in images:
                        irc, _iout, _ierr = backend._exec_ssh_command(
                            client, f"docker image inspect {backend.shlex.quote(image_ref)}",
                            timeout=30.0, check=False,
                        )
                        if irc != 0:
                            missing.append(image_ref)
                    result['ok'] = True
                    result['cached'] = bool(images) and not missing
                    result['missing_images'] = missing
                except Exception as exc:
                    result['error'] = str(exc)
                _append_cache_log(
                    meta,
                    f"[cache] status #{item_id}: cached={result.get('cached')} missing={len(result.get('missing_images') or [])}",
                )

            try:
                backend._update_vuln_catalog_item_cache_state(
                    catalog_id=catalog_id,
                    item_id=item_id,
                    cached=result.get('cached'),
                    missing_images=result.get('missing_images') or [],
                    error=result.get('error'),
                    core_host=core_host,
                )
            except Exception:
                pass

            results.append(result)
            meta['results'] = results
            meta['active_item_id'] = None
            meta['active_item_name'] = None
    finally:
        try:
            client.close()
        except Exception:
            pass

    if meta.get('stop_requested'):
        meta['status'] = 'stopped'
        _append_cache_log(meta, '[cache] stopped')
    else:
        meta['status'] = 'completed'
        _append_cache_log(meta, f"[cache] {mode} completed")

    meta['done'] = True
    meta['finished_at'] = backend._local_timestamp_display()


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'vuln_catalog_cache_routes'):
        return

    backend = backend_module

    def _find_cache_meta(run_id: str) -> dict[str, Any] | None:
        target = str(run_id or '').strip()
        if target:
            meta = backend.RUNS.get(target)
            if isinstance(meta, dict) and meta.get('kind') in _CACHE_RUN_KINDS:
                return meta
            return None
        active = None
        for candidate in backend.RUNS.values():
            if not isinstance(candidate, dict) or candidate.get('kind') not in _CACHE_RUN_KINDS:
                continue
            if not candidate.get('done'):
                return candidate
            active = candidate
        return active

    def _start_cache_run(mode: str):
        backend._require_builder_or_admin()
        payload = request.get_json(silent=True) or {}

        for existing in backend.RUNS.values():
            if isinstance(existing, dict) and existing.get('kind') in _CACHE_RUN_KINDS and not existing.get('done'):
                return jsonify({'ok': False, 'error': 'An image cache run is already active'}), 409

        state = backend._load_vuln_catalogs_state()
        entry = backend._get_active_vuln_catalog_entry(state)
        if not entry:
            return jsonify({'ok': False, 'error': 'No active catalog pack'}), 404

        items = backend._normalize_vuln_catalog_items(entry)
        item_ids_raw = payload.get('item_ids') if isinstance(payload.get('item_ids'), list) else None
        query = str(payload.get('query') or '').strip()
        include_disabled = backend._coerce_bool(payload.get('include_disabled')) if 'include_disabled' in payload else False
        limit = None
        try:
            limit_raw = payload.get('limit')
            if limit_raw not in (None, '', False):
                limit = max(1, min(int(limit_raw), 500))
        except Exception:
            limit = None

        if item_ids_raw:
            wanted = set()
            for value in item_ids_raw:
                try:
                    wanted.add(int(value))
                except Exception:
                    continue
            selected_items = [item for item in items if int(item.get('id') or 0) in wanted]
        else:
            selected_items = []
            for item in items:
                if not include_disabled and bool(item.get('disabled')):
                    continue
                if not _item_matches_query(item, query):
                    continue
                selected_items.append(item)

        if limit is not None:
            selected_items = selected_items[:limit]
        if not selected_items:
            return jsonify({'ok': False, 'error': 'No catalog items matched the selection'}), 400

        try:
            core_cfg = backend._merge_core_configs(payload.get('core'), include_password=True)
            runtime_mode = str(getattr(backend, '_webui_runtime_mode', lambda: 'native')() or 'native').strip().lower()
            core_cfg = _prefer_explicit_or_ssh_core_host(payload.get('core'), core_cfg, runtime_mode=runtime_mode)
            if not core_cfg.get('host'):
                core_cfg['host'] = core_cfg.get('ssh_host') or '127.0.0.1'
            if not core_cfg.get('port'):
                core_cfg['port'] = backend.CORE_PORT
            core_cfg = backend._require_core_ssh_credentials(core_cfg)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'CORE VM SSH config required: {exc}'}), 400

        run_id = str(backend.uuid.uuid4())[:12]
        meta = {
            'kind': 'vuln_image_cache',
            'run_id': run_id,
            'mode': mode,
            'done': False,
            'status': 'queued',
            'catalog_id': str(entry.get('id') or '').strip(),
            'catalog_label': str(entry.get('label') or '').strip() or str(entry.get('id') or '').strip(),
            'query': query,
            'include_disabled': include_disabled,
            'limit': limit,
            'selected_items': [dict(item) for item in selected_items],
            'results': [],
            'log_lines': [],
            'active_item_id': None,
            'active_item_name': None,
            'stop_requested': False,
            'started_at': backend._local_timestamp_display(),
            'finished_at': None,
        }
        backend.RUNS[run_id] = meta

        try:
            backend.threading.Thread(
                target=_run_cache_job,
                args=(backend, meta, core_cfg),
                name=f'vuln-cache-{run_id[:8]}',
                daemon=True,
            ).start()
        except Exception as exc:
            backend.RUNS.pop(run_id, None)
            return jsonify({'ok': False, 'error': f'failed to start cache run: {exc}'}), 500

        return jsonify({'ok': True, 'run_id': run_id, 'mode': mode, 'selected_count': len(selected_items)})

    @app.route('/vuln_catalog_items/cache/start', methods=['POST'])
    def vuln_catalog_items_cache_start():
        return _start_cache_run('pull')

    @app.route('/vuln_catalog_items/cache/refresh/start', methods=['POST'])
    def vuln_catalog_items_cache_refresh_start():
        return _start_cache_run('status')

    @app.route('/vuln_catalog_items/cache/status')
    def vuln_catalog_items_cache_status():
        backend._require_builder_or_admin()
        run_id = str(request.args.get('run_id') or '').strip()
        meta = _find_cache_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        return jsonify({
            'ok': True,
            'run_id': str(meta.get('run_id') or ''),
            'mode': str(meta.get('mode') or ''),
            'done': bool(meta.get('done')),
            'status': str(meta.get('status') or ''),
            'stop_requested': bool(meta.get('stop_requested')),
            'started_at': meta.get('started_at'),
            'finished_at': meta.get('finished_at'),
            'catalog': {
                'id': str(meta.get('catalog_id') or ''),
                'label': str(meta.get('catalog_label') or ''),
            },
            'progress': _summarize_cache_run(meta),
            'active_item': (
                {'id': meta.get('active_item_id'), 'name': meta.get('active_item_name')}
                if meta.get('active_item_id') else None
            ),
            'results': meta.get('results') if isinstance(meta.get('results'), list) else [],
            'log_lines': list(meta.get('log_lines') if isinstance(meta.get('log_lines'), list) else []),
        })

    @app.route('/vuln_catalog_items/cache/stop', methods=['POST'])
    def vuln_catalog_items_cache_stop():
        backend._require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        run_id = str(payload.get('run_id') or '').strip()
        meta = _find_cache_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        meta['stop_requested'] = True
        _append_cache_log(meta, '[cache] stop requested')
        return jsonify({'ok': True, 'run_id': str(meta.get('run_id') or ''), 'stop_requested': True})

    mark_routes_registered(app, 'vuln_catalog_cache_routes')
