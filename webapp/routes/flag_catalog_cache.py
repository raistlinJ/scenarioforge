from __future__ import annotations

import os
import re
from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


_CACHE_LOG_LINE_LIMIT = 500
_CACHE_RUN_KINDS = ('flag_image_cache',)

# Generator compose files commonly interpolate these into volume bind-mount
# specs (e.g. `${INPUTS_DIR}:/inputs:ro`). A cache run only pulls/inspects
# images and never starts a container, so the paths don't need to exist -
# they just need to be non-empty or Compose rejects the spec as malformed.
_CACHE_COMPOSE_ENV_PREFIX = "INPUTS_DIR=/tmp OUTPUTS_DIR=/tmp ARTIFACT_VARIANT_ID=cache-check"

_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')


def _parse_compose_image_refs(raw: str) -> list[str]:
    """Parse `docker compose config --images` output into image references.

    Over an SSH+sudo session with a PTY allocated (needed for the sudo password
    prompt), stdout and stderr get merged, so Compose's own log/warning lines
    (e.g. "the attribute `version` is obsolete") can end up mixed in with the
    real image names. Docker image references never contain whitespace, so any
    line that still has whitespace after stripping ANSI color codes is log
    noise, not an image reference.
    """
    images: list[str] = []
    for line in (raw or '').splitlines():
        text = _ANSI_ESCAPE_RE.sub('', line).strip()
        if not text or any(ch.isspace() for ch in text):
            continue
        images.append(text)
    return images


def _parse_image_size(raw: str) -> int | None:
    """Parse `docker image inspect --format '{{.Size}}'` output into bytes.

    Same PTY stdout/stderr-merging concern as _parse_compose_image_refs: take
    the last purely-numeric line, ignoring any log noise mixed into stdout.
    """
    size: int | None = None
    for line in (raw or '').splitlines():
        text = _ANSI_ESCAPE_RE.sub('', line).strip()
        if text.isdigit():
            size = int(text)
    return size


def _kind_label(kind: str) -> str:
    return 'Flag-Node-Generators' if str(kind or '').strip().lower() == 'flag-node-generator' else 'Flag-Generators'


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


def _collect_catalog_items(backend: Any, kind: str) -> list[dict[str, Any]]:
    loader = (
        backend._flag_node_generators_from_all_installed_sources
        if kind == 'flag-node-generator'
        else backend._flag_generators_from_all_installed_sources
    )
    try:
        generators, _errors = loader()
    except Exception:
        return []
    try:
        generators = backend._annotate_disabled_state(generators, kind=kind)
    except Exception:
        pass
    return [g for g in (generators or []) if isinstance(g, dict)]


def _item_matches_query(item: dict[str, Any], query: str) -> bool:
    needle = str(query or '').strip().lower()
    if not needle:
        return True
    fields = [str(item.get('id') or ''), str(item.get('name') or '')]
    return any(needle in str(value).lower() for value in fields)


def _run_cache_job(backend: Any, meta: dict[str, Any], core_cfg: dict[str, Any]) -> None:
    mode = str(meta.get('mode') or 'pull')
    kind = str(meta.get('kind_name') or 'flag-generator')
    items = meta.get('selected_items') if isinstance(meta.get('selected_items'), list) else []
    total = len(items)
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

    def _run_docker_cmd(cmd: str, *, timeout: float, cancel_check: Any) -> tuple[int, str, str]:
        # `docker`/`docker compose` need daemon access, which typically requires sudo
        # unless the SSH user is already in the `docker` group.
        if sudo:
            return backend._exec_ssh_sudo_command(client, cmd, password=pw, timeout=timeout, cancel_check=cancel_check)
        return backend._exec_ssh_command(client, cmd, timeout=timeout, check=False, cancel_check=cancel_check)

    def _check_images_and_sizes(remote_yml: str, cancel_check: Any) -> tuple[list[str], list[str], int | None]:
        """Resolve a compose file's images and check presence + on-disk size.

        Returns (images, missing, total_size_bytes). total_size_bytes is None if
        any image is missing or its size couldn't be determined.
        """
        images_cmd = (
            f"{_CACHE_COMPOSE_ENV_PREFIX} "
            f"docker compose -f {backend.shlex.quote(remote_yml)} config --images"
        )
        rc, out, err = _run_docker_cmd(images_cmd, timeout=60.0, cancel_check=cancel_check)
        if rc != 0:
            raise RuntimeError((str(err or out or 'docker compose config --images failed')).strip()[-1000:])
        images = _parse_compose_image_refs(out)
        missing: list[str] = []
        total_size = 0
        for image_ref in images:
            if meta.get('stop_requested'):
                break
            irc, iout, _ierr = _run_docker_cmd(
                f"docker image inspect --format '{{{{.Size}}}}' {backend.shlex.quote(image_ref)}",
                timeout=30.0, cancel_check=cancel_check,
            )
            if irc != 0:
                missing.append(image_ref)
                continue
            size = _parse_image_size(iout)
            if size is None:
                missing.append(image_ref)
            else:
                total_size += size
        return images, missing, (None if missing else total_size)

    try:
        for index, item in enumerate(items):
            if meta.get('stop_requested'):
                break
            item_id = str(item.get('id') or '').strip()
            item_name = str(item.get('name') or item_id)
            meta['active_item_id'] = item_id
            meta['active_item_name'] = item_name
            meta['active_index'] = index + 1

            result: dict[str, Any] = {
                'item_id': item_id,
                'item_name': item_name,
                'ok': False,
                'cached': None,
                'missing_images': [],
                'cache_size_bytes': None,
                'error': None,
            }

            local_path = backend._generator_item_abs_compose_path(item)
            if not local_path:
                # Plain script generators have no compose runtime; nothing to cache.
                result['ok'] = True
                result['error'] = 'no compose runtime (skipped)'
                results.append(result)
                meta['results'] = results
                continue
            if not os.path.isfile(local_path):
                result['error'] = 'compose file not found locally'
                results.append(result)
                meta['results'] = results
                continue

            _append_cache_log(meta, f"[cache] {index + 1}/{total}: {item_id} {item_name}")

            remote_yml = ''
            if remote_repo_dir:
                try:
                    rel = os.path.relpath(local_path, repo_root).replace(os.sep, '/')
                except Exception:
                    rel = ''
                if rel and not rel.startswith('..'):
                    remote_yml = backend._remote_path_join(remote_repo_dir, rel)

            if not remote_yml:
                result['error'] = 'compose file not found or not under repo root'
                results.append(result)
                meta['results'] = results
                continue

            cancel_check = lambda: bool(meta.get('stop_requested'))

            try:
                rc, out, _err = backend._exec_ssh_command(
                    client, f"[ -f {backend.shlex.quote(remote_yml)} ] && echo present || echo missing",
                    timeout=15.0, check=False, cancel_check=cancel_check,
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

            # Create empty placeholders for any `env_file:` the compose
            # references but that doesn't exist (older Docker Compose builds
            # hard-error on a missing env_file even for config/pull/build).
            # Harmless: caching never runs a container.
            try:
                env_refs = backend._compose_env_file_relpaths(local_path)
                if env_refs:
                    remote_dir = backend.posixpath.dirname(remote_yml)
                    for ref in env_refs:
                        remote_env = backend._remote_path_join(remote_dir, ref)
                        q = backend.shlex.quote(remote_env)
                        backend._exec_ssh_command(
                            client, f"[ -e {q} ] || : > {q}",
                            timeout=15.0, check=False, cancel_check=cancel_check,
                        )
            except Exception:
                pass

            if mode == 'pull':
                # `pull` only fetches registry images; generators built from a local
                # Dockerfile (`build:`) are silently skipped ("No image to be pulled")
                # and never actually cached unless we also build them here.
                pull_cmd = f"{_CACHE_COMPOSE_ENV_PREFIX} docker compose -f {backend.shlex.quote(remote_yml)} pull"
                build_cmd = f"{_CACHE_COMPOSE_ENV_PREFIX} docker compose -f {backend.shlex.quote(remote_yml)} build"
                try:
                    pull_rc, pull_out, pull_err = _run_docker_cmd(pull_cmd, timeout=600.0, cancel_check=cancel_check)
                    if meta.get('stop_requested'):
                        result['error'] = 'cancelled before build step'
                    else:
                        build_rc, build_out, build_err = _run_docker_cmd(build_cmd, timeout=600.0, cancel_check=cancel_check)
                        result['ok'] = pull_rc == 0 and build_rc == 0
                        result['cached'] = result['ok']
                        if not result['ok']:
                            errors = []
                            if pull_rc != 0:
                                errors.append(f"pull: {(str(pull_err or pull_out or 'failed')).strip()[:400]}")
                            if build_rc != 0:
                                errors.append(f"build: {(str(build_err or build_out or 'failed')).strip()[:400]}")
                            result['error'] = '; '.join(errors)[:1000]
                        elif not meta.get('stop_requested'):
                            try:
                                _images, _missing, size = _check_images_and_sizes(remote_yml, cancel_check)
                                result['cache_size_bytes'] = size
                            except Exception:
                                pass
                except Exception as exc:
                    result['error'] = str(exc)
                _append_cache_log(meta, f"[cache] pull {item_id}: {'ok' if result['ok'] else 'failed'}")
            elif mode == 'clear':
                try:
                    images_cmd = (
                        f"{_CACHE_COMPOSE_ENV_PREFIX} "
                        f"docker compose -f {backend.shlex.quote(remote_yml)} config --images"
                    )
                    rc, out, err = _run_docker_cmd(images_cmd, timeout=60.0, cancel_check=cancel_check)
                    if rc != 0:
                        result['error'] = (str(err or out or 'docker compose config --images failed').strip())[-1000:]
                    else:
                        images = _parse_compose_image_refs(out)
                        removed: list[str] = []
                        errors: list[str] = []
                        for image_ref in images:
                            if meta.get('stop_requested'):
                                break
                            rrc, rout, rerr = _run_docker_cmd(
                                f"docker rmi -f {backend.shlex.quote(image_ref)}",
                                timeout=60.0, cancel_check=cancel_check,
                            )
                            combined = str(rerr or rout or '')
                            if rrc == 0 or 'no such image' in combined.lower():
                                removed.append(image_ref)
                            else:
                                errors.append(f"{image_ref}: {combined.strip()[:200]}")
                        result['ok'] = not errors
                        result['cached'] = False
                        result['missing_images'] = []
                        if errors:
                            result['error'] = '; '.join(errors)[:1000]
                except Exception as exc:
                    result['error'] = str(exc)
                _append_cache_log(meta, f"[cache] clear {item_id}: {'ok' if result['ok'] else 'failed'}")
            else:
                try:
                    images, missing, size = _check_images_and_sizes(remote_yml, cancel_check)
                    result['ok'] = True
                    result['cached'] = bool(images) and not missing
                    result['missing_images'] = missing
                    result['cache_size_bytes'] = size
                except Exception as exc:
                    result['error'] = str(exc)
                _append_cache_log(
                    meta,
                    f"[cache] status {item_id}: cached={result.get('cached')} missing={len(result.get('missing_images') or [])}",
                )

            try:
                backend._update_generator_item_cache_state(
                    kind=kind,
                    generator_id=item_id,
                    cached=result.get('cached'),
                    missing_images=result.get('missing_images') or [],
                    cache_size_bytes=result.get('cache_size_bytes'),
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
    if not begin_route_registration(app, 'flag_catalog_cache_routes'):
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

    def _resolve_cache_core_cfg(payload: dict[str, Any]) -> dict[str, Any]:
        core_cfg = backend._merge_core_configs(payload.get('core'), include_password=True)
        core_cfg = backend._prefer_explicit_or_ssh_core_host(core_cfg, payload.get('core'))
        if not core_cfg.get('host'):
            core_cfg['host'] = core_cfg.get('ssh_host') or '127.0.0.1'
        if not core_cfg.get('port'):
            core_cfg['port'] = backend.CORE_PORT
        return backend._require_core_ssh_credentials(core_cfg)

    def _start_cache_run(mode: str):
        backend._require_builder_or_admin()
        payload = request.get_json(silent=True) or {}

        for existing in backend.RUNS.values():
            if isinstance(existing, dict) and existing.get('kind') in _CACHE_RUN_KINDS and not existing.get('done'):
                return jsonify({'ok': False, 'error': 'An image cache run is already active'}), 409

        kind = str(payload.get('kind') or 'flag-generator').strip().lower()
        if kind not in ('flag-generator', 'flag-node-generator'):
            kind = 'flag-generator'

        items = _collect_catalog_items(backend, kind)
        item_ids_raw = payload.get('generator_ids') if isinstance(payload.get('generator_ids'), list) else None
        query = str(payload.get('query') or '').strip()
        include_disabled = backend._coerce_bool(payload.get('include_disabled')) if 'include_disabled' in payload else False
        scope = str(payload.get('scope') or 'all').strip().lower()
        if scope not in ('all', 'uncached', 'failed'):
            scope = 'all'
        limit = None
        try:
            limit_raw = payload.get('limit')
            if limit_raw not in (None, '', False):
                limit = max(1, min(int(limit_raw), 500))
        except Exception:
            limit = None

        if item_ids_raw:
            wanted = {str(v or '').strip() for v in item_ids_raw}
            selected_items = [item for item in items if str(item.get('id') or '').strip() in wanted]
        else:
            selected_items = []
            for item in items:
                if not include_disabled and bool(item.get('_disabled')):
                    continue
                if not item.get('compose'):
                    continue
                if not _item_matches_query(item, query):
                    continue
                if scope == 'uncached' and item.get('_cached') is True:
                    continue
                if scope == 'failed' and not item.get('_cache_error'):
                    continue
                selected_items.append(item)

        if mode == 'clear':
            # Persistent items are never touched by any cleanup-style action.
            selected_items = [item for item in selected_items if not item.get('_persistent')]

        if limit is not None:
            selected_items = selected_items[:limit]
        if not selected_items:
            return jsonify({'ok': False, 'error': 'No generators matched the selection'}), 400

        try:
            core_cfg = _resolve_cache_core_cfg(payload)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'CORE VM SSH config required: {exc}'}), 400

        run_id = str(backend.uuid.uuid4())[:12]
        meta = {
            'kind': 'flag_image_cache',
            'kind_name': kind,
            'run_id': run_id,
            'mode': mode,
            'done': False,
            'status': 'queued',
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
                name=f'flag-cache-{run_id[:8]}',
                daemon=True,
            ).start()
        except Exception as exc:
            backend.RUNS.pop(run_id, None)
            return jsonify({'ok': False, 'error': f'failed to start cache run: {exc}'}), 500

        return jsonify({'ok': True, 'run_id': run_id, 'mode': mode, 'kind': kind, 'selected_count': len(selected_items)})

    @app.route('/flag_catalog_items/cache/precheck', methods=['POST'])
    def flag_catalog_items_cache_precheck():
        backend._require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        stop_running = backend._coerce_bool(payload.get('stop_running'))

        try:
            core_cfg = _resolve_cache_core_cfg(payload)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'CORE VM SSH config required: {exc}'}), 400

        core_host = str(core_cfg.get('ssh_host') or core_cfg.get('host') or '')
        core_port = core_cfg.get('ssh_port') or core_cfg.get('port')

        try:
            client = backend._open_ssh_client(core_cfg)
        except Exception as exc:
            return jsonify({
                'ok': False, 'error': f'SSH connect failed: {exc}',
                'core_host': core_host, 'core_port': core_port,
            }), 502

        try:
            try:
                names = backend._list_remote_running_containers(core_cfg, client=client)
            except Exception as exc:
                return jsonify({
                    'ok': False, 'error': f'Unable to list running containers: {exc}',
                    'core_host': core_host, 'core_port': core_port,
                }), 502

            if not names:
                return jsonify({
                    'ok': True, 'active': False, 'container_names': [], 'container_count': 0, 'stopped': False,
                    'core_host': core_host, 'core_port': core_port,
                })

            if not stop_running:
                return jsonify({
                    'ok': True,
                    'active': True,
                    'container_names': names,
                    'container_count': len(names),
                    'stopped': False,
                    'core_host': core_host,
                    'core_port': core_port,
                })

            stopped, errors = backend._stop_remote_containers(core_cfg, names, client=client)
            if errors:
                return jsonify({
                    'ok': False,
                    'error': errors[0],
                    'active': True,
                    'container_names': names,
                    'stopped_names': stopped,
                    'errors': errors,
                    'core_host': core_host,
                    'core_port': core_port,
                }), 409

            return jsonify({
                'ok': True,
                'active': True,
                'container_names': names,
                'container_count': len(names),
                'stopped': True,
                'stopped_names': stopped,
                'core_host': core_host,
                'core_port': core_port,
            })
        finally:
            try:
                client.close()
            except Exception:
                pass

    @app.route('/flag_catalog_items/cache/start', methods=['POST'])
    def flag_catalog_items_cache_start():
        return _start_cache_run('pull')

    @app.route('/flag_catalog_items/cache/refresh/start', methods=['POST'])
    def flag_catalog_items_cache_refresh_start():
        return _start_cache_run('status')

    @app.route('/flag_catalog_items/cache/clear/start', methods=['POST'])
    def flag_catalog_items_cache_clear_start():
        return _start_cache_run('clear')

    @app.route('/flag_catalog_items/cache/status')
    def flag_catalog_items_cache_status():
        backend._require_builder_or_admin()
        run_id = str(request.args.get('run_id') or '').strip()
        meta = _find_cache_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        return jsonify({
            'ok': True,
            'run_id': str(meta.get('run_id') or ''),
            'mode': str(meta.get('mode') or ''),
            'kind': str(meta.get('kind_name') or ''),
            'kind_label': _kind_label(str(meta.get('kind_name') or '')),
            'done': bool(meta.get('done')),
            'status': str(meta.get('status') or ''),
            'stop_requested': bool(meta.get('stop_requested')),
            'started_at': meta.get('started_at'),
            'finished_at': meta.get('finished_at'),
            'progress': _summarize_cache_run(meta),
            'active_item': (
                {'id': meta.get('active_item_id'), 'name': meta.get('active_item_name')}
                if meta.get('active_item_id') else None
            ),
            'results': meta.get('results') if isinstance(meta.get('results'), list) else [],
            'log_lines': list(meta.get('log_lines') if isinstance(meta.get('log_lines'), list) else []),
        })

    @app.route('/flag_catalog_items/cache/stop', methods=['POST'])
    def flag_catalog_items_cache_stop():
        backend._require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        run_id = str(payload.get('run_id') or '').strip()
        meta = _find_cache_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        meta['stop_requested'] = True
        _append_cache_log(meta, '[cache] stop requested')
        return jsonify({'ok': True, 'run_id': str(meta.get('run_id') or ''), 'stop_requested': True})

    mark_routes_registered(app, 'flag_catalog_cache_routes')
