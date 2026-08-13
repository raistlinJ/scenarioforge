from __future__ import annotations

import re
from typing import Any, Callable

from flask import flash, jsonify, redirect, request, send_file, url_for
from werkzeug.utils import secure_filename

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    install_generator_pack_or_bundle: Callable[..., tuple[bool, str]],
    load_installed_generator_packs_state: Callable[[], dict],
    save_installed_generator_packs_state: Callable[[dict], None],
    installed_generators_root: Callable[[], str],
    get_repo_root: Callable[[], str],
    local_timestamp_display: Callable[[], str],
    local_timestamp_safe: Callable[[], str],
    compute_next_numeric_generator_id: Callable[..., int],
    install_generator_pack_payload: Callable[..., tuple[bool, str, list[dict[str, Any]], int, list[dict[str, Any]]]],
    download_zip_from_url: Callable[[str], bytes],
    pack_to_zip_bytes: Callable[[dict], bytes],
    os_module: Any,
    tempfile_module: Any,
    uuid_module: Any,
    shutil_module: Any,
    io_module: Any,
    zipfile_module: Any,
    catalog_packs_for_export: Callable[[], list[dict[str, Any]]] | None = None,
    cleanup_remote_pack: Callable[[dict[str, Any]], tuple[bool, str]] | None = None,
) -> None:
    if not begin_route_registration(app, 'generator_pack_routes'):
        return

    def _folder_upload_path(raw_path: str) -> str:
        normalized = str(raw_path or '').replace('\\', '/').strip()
        if not normalized or '\x00' in normalized:
            raise ValueError('Repository upload contains an empty file path.')
        if normalized.startswith('/') or re.match(r'^[A-Za-z]:/', normalized):
            raise ValueError(f'Repository upload contains an absolute path: {normalized}')
        parts = [part for part in normalized.split('/') if part not in ('', '.')]
        if not parts or any(part == '..' for part in parts):
            raise ValueError(f'Repository upload contains an unsafe path: {normalized}')
        return '/'.join(parts)

    def _repository_folder_to_zip(repo_files: list[Any], repo_paths: list[str], zip_path: str) -> None:
        if not repo_files:
            raise ValueError('No repository folder selected.')
        if len(repo_files) > 10000:
            raise ValueError('Repository folder contains more than 10,000 files; upload a ZIP instead.')
        if len(repo_paths) != len(repo_files):
            raise ValueError(
                'The browser did not provide repository-relative paths. '
                'Try a current Chrome, Edge, Firefox, or Safari browser, or upload a ZIP instead.'
            )

        normalized_paths: list[str] = []
        seen_paths: set[str] = set()
        for raw_path in repo_paths:
            normalized = _folder_upload_path(raw_path)
            if normalized in seen_paths:
                raise ValueError(f'Repository upload contains a duplicate path: {normalized}')
            seen_paths.add(normalized)
            normalized_paths.append(normalized)

        with zipfile_module.ZipFile(zip_path, 'w', zipfile_module.ZIP_DEFLATED) as archive:
            for file_obj, relative_path in zip(repo_files, normalized_paths):
                with archive.open(relative_path, 'w') as destination:
                    shutil_module.copyfileobj(file_obj.stream, destination, length=1024 * 1024)

    def _latest_pack_success_payload(note: str) -> dict[str, Any]:
        warnings: list[dict[str, Any]] = []
        installed_generators: list[dict[str, Any]] = []
        grouped: list[dict[str, Any]] = []
        pack_id = ''
        pack_label = ''
        pack_origin = ''
        try:
            state = load_installed_generator_packs_state()
            packs = state.get('packs') if isinstance(state, dict) else None
            if isinstance(packs, list) and packs:
                last = packs[-1] if isinstance(packs[-1], dict) else {}
                pack_id = str(last.get('id') or '').strip()
                pack_label = str(last.get('label') or '').strip()
                pack_origin = str(last.get('origin') or '').strip()
                ww = last.get('warnings') if isinstance(last, dict) else None
                if isinstance(ww, list):
                    warnings = [item for item in ww if isinstance(item, dict)]
                raw_installed = last.get('installed') if isinstance(last, dict) else None
                if isinstance(raw_installed, list):
                    for item in raw_installed:
                        if not isinstance(item, dict):
                            continue
                        record = dict(item)
                        try:
                            marker_path = os_module.path.join(str(record.get('path') or '').strip(), '.coretg_pack.json')
                            if marker_path and os_module.path.exists(marker_path) and os_module.path.isfile(marker_path):
                                import json

                                with open(marker_path, 'r', encoding='utf-8') as handle:
                                    marker = json.load(handle)
                                if isinstance(marker, dict):
                                    source_id = str(marker.get('source_generator_id') or '').strip()
                                    if source_id:
                                        record['source_id'] = source_id
                        except Exception:
                            pass
                        installed_generators.append(record)
        except Exception:
            warnings = []
            installed_generators = []

        grouped_map: dict[str, list[str]] = {}
        for item in installed_generators:
            kind = str(item.get('kind') or '').strip() or 'generator'
            gid = str(item.get('source_id') or item.get('id') or '').strip()
            if not gid:
                continue
            grouped_map.setdefault(kind, []).append(gid)
        grouped = [
            {'kind': kind, 'count': len(ids), 'ids': ids}
            for kind, ids in grouped_map.items()
        ]
        installed_ids = [
            str(item.get('source_id') or item.get('id') or '').strip()
            for item in installed_generators
            if str(item.get('source_id') or item.get('id') or '').strip()
        ]
        if len(installed_ids) == 1:
            confirmation_text = f'Added to catalog as {installed_ids[0]}.'
        elif installed_ids:
            confirmation_text = f'Added to catalog as {", ".join(installed_ids)}.'
        elif pack_label:
            confirmation_text = f'Added generator pack {pack_label} to the catalog.'
        else:
            confirmation_text = 'Generator pack added to catalog.'
        return {
            'ok': True,
            'message': note,
            'warnings': warnings,
            'import_summary': {
                'installed_generator_count': len(installed_generators),
                'generator_kind_count': len(grouped),
                'warning_count': len(warnings),
            },
            'confirmation_text': confirmation_text,
            'confirmation_detail': note,
            'installed_as': {
                'pack_id': pack_id,
                'pack_label': pack_label,
                'origin': pack_origin,
                'generators': installed_generators,
                'grouped': grouped,
            },
        }

    @app.route('/generator_packs/upload', methods=['POST'])
    def generator_packs_upload():
        is_xhr = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        file_obj = request.files.get('zip_file')
        repo_files = [
            item for item in request.files.getlist('repo_files')
            if item and str(item.filename or '').strip()
        ]
        if (not file_obj or file_obj.filename == '') and not repo_files:
            if is_xhr:
                return jsonify({'ok': False, 'error': 'No repository folder or ZIP selected.'}), 400
            flash('No repository folder or ZIP selected.')
            return redirect(url_for('flag_catalog_page'))
        if file_obj and file_obj.filename and repo_files:
            if is_xhr:
                return jsonify({'ok': False, 'error': 'Select either a repository folder or a ZIP, not both.'}), 400
            flash('Select either a repository folder or a ZIP, not both.')
            return redirect(url_for('flag_catalog_page'))

        if repo_files:
            raw_label = str(request.form.get('repo_label') or 'repository').strip()
            filename = secure_filename(raw_label) or 'repository'
            suffix = '-' + filename + '.zip'
            label = filename
            pack_origin = 'folder-upload'
        else:
            filename = secure_filename(file_obj.filename)
            if not filename.lower().endswith('.zip'):
                if is_xhr:
                    return jsonify({'ok': False, 'error': 'Only .zip files are accepted for ZIP upload.'}), 400
                flash('Only .zip files are accepted for ZIP upload.')
                return redirect(url_for('flag_catalog_page'))
            suffix = '-' + filename
            label = filename[:-4]
            pack_origin = 'upload'

        fd, tmp_path = tempfile_module.mkstemp(prefix='coretg_pack_', suffix=suffix)
        os_module.close(fd)
        try:
            if repo_files:
                repo_paths = [str(path or '') for path in request.form.getlist('repo_paths')]
                _repository_folder_to_zip(repo_files, repo_paths, tmp_path)
            else:
                file_obj.save(tmp_path)
            ok, note = install_generator_pack_or_bundle(
                zip_path=tmp_path,
                pack_label=label,
                pack_origin=pack_origin,
            )
            if is_xhr:
                if ok:
                    return jsonify(_latest_pack_success_payload(note)), 200
                return jsonify({'ok': False, 'error': f'Pack install failed: {note}'}), 400
            if ok:
                payload = _latest_pack_success_payload(note)
                flash(f"{payload.get('confirmation_text') or note} {payload.get('confirmation_detail') or ''}".strip())
            else:
                flash(f'Pack install failed: {note}')
        except ValueError as exc:
            if is_xhr:
                return jsonify({'ok': False, 'error': str(exc)}), 400
            flash(str(exc))
        finally:
            try:
                os_module.remove(tmp_path)
            except Exception:
                pass
        return redirect(url_for('flag_catalog_page'))

    @app.route('/generator_packs/import_url', methods=['POST'])
    def generator_packs_import_url():
        is_xhr = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        url = str(request.form.get('zip_url') or '').strip()
        if not url:
            if is_xhr:
                return jsonify({'ok': False, 'error': 'Missing URL.'}), 400
            flash('Missing URL.')
            return redirect(url_for('flag_catalog_page'))
        try:
            data = download_zip_from_url(url)
            fd, tmp_path = tempfile_module.mkstemp(prefix='coretg_pack_url_', suffix='.zip')
            os_module.close(fd)
            try:
                with open(tmp_path, 'wb') as fh:
                    fh.write(data)
                ok, note = install_generator_pack_or_bundle(zip_path=tmp_path, pack_label=url, pack_origin='url')
                if is_xhr:
                    if ok:
                        return jsonify(_latest_pack_success_payload(note)), 200
                    return jsonify({'ok': False, 'error': f'Pack install failed: {note}'}), 400
                if ok:
                    payload = _latest_pack_success_payload(note)
                    flash(f"{payload.get('confirmation_text') or note} {payload.get('confirmation_detail') or ''}".strip())
                else:
                    flash(f'Pack install failed: {note}')
            finally:
                try:
                    os_module.remove(tmp_path)
                except Exception:
                    pass
        except Exception as exc:
            if is_xhr:
                return jsonify({'ok': False, 'error': f'URL import failed: {exc}'}), 400
            flash(f'URL import failed: {exc}')
        return redirect(url_for('flag_catalog_page'))

    @app.route('/generator_packs/delete/<pack_id>', methods=['POST'])
    def generator_packs_delete(pack_id: str):
        is_xhr = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in str(request.headers.get('Accept') or '')

        def _delete_response(*, ok: bool, message: str, status: int = 200, **extra: Any):
            if is_xhr:
                return jsonify({'ok': ok, 'message': message, **extra}), status
            flash(message)
            return redirect(url_for('flag_catalog_page'))

        pid = str(pack_id or '').strip()
        if not pid:
            return _delete_response(ok=False, message='Missing pack id.', status=400)

        installed_root = os_module.path.abspath(installed_generators_root())
        state = load_installed_generator_packs_state()
        packs = state.get('packs') or []
        if not isinstance(packs, list):
            packs = []

        target = None
        kept = []
        for pack in packs:
            if isinstance(pack, dict) and str(pack.get('id') or '') == pid:
                target = pack
                continue
            kept.append(pack)

        if not target:
            return _delete_response(ok=False, message='Pack not found.', status=404, pack_id=pid)

        remote_cleanup_note = ''
        if target.get('repo_local') is not True and cleanup_remote_pack is not None:
            try:
                remote_ok, remote_cleanup_note = cleanup_remote_pack(target)
            except Exception as exc:
                remote_ok, remote_cleanup_note = False, str(exc)
            if not remote_ok:
                return _delete_response(
                    ok=False,
                    message=f'Uninstall aborted: failed removing the CORE runtime copy: {remote_cleanup_note}',
                    status=409,
                    pack_id=pid,
                    stage='remote_cleanup',
                )

        if isinstance(target, dict) and target.get('repo_local') is True:
            target = dict(target)
            target['disabled'] = True
            target['uninstalled'] = True
            target['uninstalled_at'] = local_timestamp_display()
            state['packs'] = kept + [target]
            save_installed_generator_packs_state(state)
            return _delete_response(
                ok=True,
                message=f'Uninstalled pack {pid}; repo-local files remain in the workspace.',
                pack_id=pid,
                removed=0,
                repo_local=True,
            )

        removed = 0
        failures: list[str] = []
        for item in (target.get('installed') or []):
            if not isinstance(item, dict):
                continue
            path = str(item.get('path') or '').strip()
            if not path:
                continue
            abs_path = os_module.path.abspath(path)
            try:
                if os_module.path.commonpath([installed_root, abs_path]) != installed_root:
                    failures.append(f'refused to delete outside installed root: {abs_path}')
                    continue
            except Exception:
                failures.append(f'refused to delete path: {abs_path}')
                continue

            try:
                if os_module.path.isdir(abs_path):
                    shutil_module.rmtree(abs_path, ignore_errors=False)
                    removed += 1
                elif os_module.path.exists(abs_path):
                    os_module.remove(abs_path)
                    removed += 1
            except Exception as exc:
                failures.append(f'failed deleting {abs_path}: {exc}')

        state['packs'] = kept
        save_installed_generator_packs_state(state)

        if failures:
            message = f'Uninstalled pack {pid} with warnings: removed={removed}; {failures[0]}'
        else:
            suffix = f'; {remote_cleanup_note}' if remote_cleanup_note else ''
            message = f'Uninstalled pack {pid} (removed {removed} item(s)){suffix}'
        return _delete_response(
            ok=True,
            message=message,
            pack_id=pid,
            removed=removed,
            warnings=failures,
            remote_cleanup=remote_cleanup_note,
        )

    @app.route('/generator_packs/download/<pack_id>')
    def generator_packs_download(pack_id: str):
        pid = str(pack_id or '').strip()
        state = load_installed_generator_packs_state()
        packs = state.get('packs') or []
        if not isinstance(packs, list):
            packs = []
        target = None
        for pack in packs:
            if isinstance(pack, dict) and str(pack.get('id') or '') == pid:
                target = pack
                break
        if not target:
            flash('Pack not found')
            return redirect(url_for('flag_catalog_page'))

        data = pack_to_zip_bytes(target)
        label = secure_filename(str(target.get('label') or '')).strip() or 'pack'
        download_name = f'generator-pack-{pid}-{label}.zip'
        return send_file(io_module.BytesIO(data), as_attachment=True, download_name=download_name)

    @app.route('/generator_packs/export_all')
    def generator_packs_export_all():
        if catalog_packs_for_export is not None:
            try:
                packs = catalog_packs_for_export()
            except Exception:
                packs = []
        else:
            state = load_installed_generator_packs_state()
            packs = state.get('packs') or []
            if not isinstance(packs, list):
                packs = []

        mem = io_module.BytesIO()
        with zipfile_module.ZipFile(mem, 'w', zipfile_module.ZIP_DEFLATED) as zf:
            for pack in packs:
                if not isinstance(pack, dict):
                    continue
                if pack.get('uninstalled') is True:
                    continue
                pid = str(pack.get('id') or '').strip()
                if not pid:
                    continue
                label = secure_filename(str(pack.get('label') or '')).strip() or 'pack'
                arcname = f'packs/{pid}-{label}.zip'
                try:
                    zf.writestr(arcname, pack_to_zip_bytes(pack))
                except Exception:
                    continue
        mem.seek(0)
        resp = send_file(mem, as_attachment=True, download_name='flag_catalog.zip')
        token = ''.join(ch for ch in str(request.args.get('download_token') or '').strip() if ch.isalnum() or ch in '._-')[:128]
        if token:
            resp.set_cookie('coretg_catalog_download_token', token, max_age=60, path='/', samesite='Lax')
        return resp

    mark_routes_registered(app, 'generator_pack_routes')
