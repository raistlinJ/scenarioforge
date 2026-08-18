from __future__ import annotations

import copy
import re
import shutil
import threading
import time
import zipfile
from typing import Any, Callable

from flask import flash, jsonify, redirect, request, url_for

from webapp.routes._registration import begin_route_registration, mark_routes_registered


MAX_FOLDER_UPLOAD_FILES = 10000


# Discovery walks every compose directory in the pack, which for a large
# catalog is minutes of work inside one blocking POST. The client polls this
# store so it can name the vulnerability being validated instead of cycling
# canned messages. Mirrors the scenario-import progress store in
# webapp/routes/xml_editor_io.py.
_PROGRESS_LOCK = threading.Lock()
_PROGRESS: dict[str, dict[str, Any]] = {}
_PROGRESS_TTL_SECONDS = 15 * 60
PROGRESS_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,80}$")

# The discovery loop lives in app_backend, several frames below the route and
# behind an injected callable that tests replace with their own fakes. A
# thread-local sink lets it report progress without changing that signature.
_ACTIVE = threading.local()


def _expire_progress() -> None:
    cutoff = time.time() - _PROGRESS_TTL_SECONDS
    with _PROGRESS_LOCK:
        for progress_id in list(_PROGRESS):
            if float(_PROGRESS[progress_id].get('updated_at') or 0) < cutoff:
                _PROGRESS.pop(progress_id, None)


def update_progress(
    progress_id: str,
    *,
    step: str,
    detail: str = '',
    current: int = 0,
    total: int = 0,
    status: str = 'running',
) -> None:
    if not progress_id or not PROGRESS_ID_RE.fullmatch(str(progress_id)):
        return
    now = time.time()
    percent = 0
    if total > 0:
        percent = max(0, min(100, int(round((current / total) * 100))))
    with _PROGRESS_LOCK:
        _PROGRESS[progress_id] = {
            'id': progress_id,
            'step': str(step or ''),
            'detail': str(detail or ''),
            'current': int(current),
            'total': int(total),
            'percent': percent,
            'status': status,
            'updated_at': now,
        }


def progress_snapshot(progress_id: str) -> dict[str, Any] | None:
    _expire_progress()
    with _PROGRESS_LOCK:
        state = _PROGRESS.get(progress_id)
        return copy.deepcopy(state) if isinstance(state, dict) else None


def set_active_progress_id(progress_id: str | None) -> None:
    _ACTIVE.progress_id = progress_id if (progress_id and PROGRESS_ID_RE.fullmatch(str(progress_id))) else None


def set_active_architecture_scan(enabled: bool | None) -> None:
    """Per-import override for the architecture scan.

    The scan resolves each image's architectures, falling back to a
    `docker manifest inspect` registry round trip for anything this host has
    not pulled. That is the slow part of an import -- minutes for a large
    catalog -- so the operator chooses per import. None restores the
    environment default.
    """
    _ACTIVE.architecture_scan = None if enabled is None else bool(enabled)


def active_architecture_scan() -> bool | None:
    return getattr(_ACTIVE, 'architecture_scan', None)


def _requested_architecture_scan() -> bool | None:
    """The Import dialog's validation choice for this request.

    None when the field is absent, which keeps the deployment's configured
    default and leaves scripted POSTs written before the dialog unaffected.
    """
    raw = str(request.form.get('validate_architectures') or '').strip().lower()
    if raw in ('1', 'true', 'yes', 'on'):
        return True
    if raw in ('0', 'false', 'no', 'off'):
        return False
    return None


def report_discovery_item(current: int, total: int, name: str) -> None:
    """Called from the discovery loop. A no-op when no import is being tracked."""
    progress_id = getattr(_ACTIVE, 'progress_id', None)
    if not progress_id:
        return
    update_progress(
        progress_id,
        step='Discovering and validating vulnerabilities',
        detail=str(name or ''),
        current=current,
        total=total,
    )


def _folder_upload_path(raw_path: str) -> str:
    normalized = str(raw_path or '').replace('\\', '/').strip()
    if not normalized or '\x00' in normalized:
        raise ValueError('Folder upload contains an empty file path.')
    if normalized.startswith('/') or re.match(r'^[A-Za-z]:/', normalized):
        raise ValueError(f'Folder upload contains an absolute path: {normalized}')
    parts = [part for part in normalized.split('/') if part not in ('', '.')]
    if not parts or any(part == '..' for part in parts):
        raise ValueError(f'Folder upload contains an unsafe path: {normalized}')
    return '/'.join(parts)


def _folder_upload_to_zip(repo_files: list[Any], repo_paths: list[str], zip_path: str) -> None:
    if not repo_files:
        raise ValueError('No vulnerability catalog folder selected.')
    if len(repo_files) > MAX_FOLDER_UPLOAD_FILES:
        raise ValueError('Vulnerability catalog folder contains more than 10,000 files; upload a ZIP instead.')
    if len(repo_paths) != len(repo_files):
        raise ValueError(
            'The browser did not provide folder-relative paths. '
            'Try a current Chrome, Edge, Firefox, or Safari browser, or upload a ZIP instead.'
        )

    normalized_paths: list[str] = []
    seen_paths: set[str] = set()
    for raw_path in repo_paths:
        normalized = _folder_upload_path(raw_path)
        if normalized in seen_paths:
            raise ValueError(f'Folder upload contains a duplicate path: {normalized}')
        seen_paths.add(normalized)
        normalized_paths.append(normalized)

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for file_obj, relative_path in zip(repo_files, normalized_paths):
            with archive.open(relative_path, 'w') as destination:
                shutil.copyfileobj(file_obj.stream, destination, length=1024 * 1024)


def register(
    app,
    *,
    require_builder_or_admin: Callable[[], None],
    install_vuln_catalog_zip_file: Callable[..., dict[str, Any]],
    install_vuln_catalog_zip_bytes: Callable[..., dict[str, Any]],
    is_safe_remote_zip_url: Callable[[str], tuple[bool, str]],
    download_zip_from_url: Callable[[str], bytes],
    request_entity_too_large_type: type[Exception],
    secure_filename_func: Callable[[str], str],
    tempfile_module: Any,
    os_module: Any,
    urlparse_func: Callable[[str], Any],
) -> None:
    if not begin_route_registration(app, 'vuln_catalog_pack_ingest_routes'):
        return

    @app.get('/api/vuln-catalog-import-progress/<progress_id>')
    def vuln_catalog_import_progress(progress_id: str):
        if not PROGRESS_ID_RE.fullmatch(str(progress_id or '')):
            return jsonify({'ok': False, 'error': 'Invalid import progress id.'}), 400
        snapshot = progress_snapshot(progress_id)
        if snapshot is None:
            return jsonify({'ok': True, 'status': 'waiting', 'percent': 0})
        return jsonify({'ok': True, **snapshot})

    @app.route('/vuln_catalog_packs/upload', methods=['POST'])
    def vuln_catalog_packs_upload():
        require_builder_or_admin()
        is_ajax = str(request.headers.get('X-Requested-With') or '').lower() == 'xmlhttprequest' or 'application/json' in str(request.headers.get('Accept') or '')

        max_upload_bytes = 1024 * 1024 * 1024
        try:
            max_upload_bytes = int(os_module.getenv('CORETG_VULN_PACK_MAX_BYTES') or max_upload_bytes)
        except Exception:
            max_upload_bytes = 1024 * 1024 * 1024

        # Flask 3.1 defaults MAX_FORM_PARTS to 1,000. Folder uploads send one
        # file part and one repo_paths field per file, so otherwise a catalog
        # with about 500 files is rejected before this route can validate it.
        # Keep the override local to this endpoint and aligned with our own
        # explicit file-count and byte limits.
        #
        # These are set in separate try blocks on purpose. On Flask 3.0.x
        # `max_content_length` is a read-only property, so assigning it raises
        # AttributeError; sharing one try block let that failure skip the
        # `max_form_parts` assignment underneath it, silently leaving the
        # 1,000-part default in place and rejecting every folder upload of
        # more than ~500 files.
        try:
            request.max_form_parts = (MAX_FOLDER_UPLOAD_FILES * 2) + 10
        except Exception:
            pass
        try:
            request.max_content_length = max_upload_bytes
        except Exception:
            pass

        try:
            upload_file = request.files.get('zip_file')
            repo_files = [
                item for item in request.files.getlist('repo_files')
                if item and str(item.filename or '').strip()
            ]
        except request_entity_too_large_type:
            msg = (
                'Upload exceeds the vulnerability catalog limits '
                f'(max {max_upload_bytes // (1024 * 1024)}MB or {MAX_FOLDER_UPLOAD_FILES:,} folder files).'
            )
            if is_ajax:
                return jsonify({'ok': False, 'error': msg}), 413
            flash(msg)
            return redirect(url_for('vuln_catalog_page'))

        progress_id = str(request.form.get('import_progress_id') or '').strip()
        if not PROGRESS_ID_RE.fullmatch(progress_id):
            progress_id = ''

        validate_architectures = _requested_architecture_scan()

        if not upload_file and not repo_files:
            # A folder upload that reaches here sent a body the parser accepted
            # but that carried no usable file parts. Report what actually
            # arrived: the difference between "no parts at all", "parts under
            # an unexpected field name", and "parts whose filename was blank"
            # points at three completely different causes, and none of them is
            # distinguishable from the bare message.
            msg = 'No vulnerability catalog folder or ZIP selected.'
            try:
                raw_repo_files = request.files.getlist('repo_files')
                blank_named = sum(
                    1 for item in raw_repo_files
                    if not str(getattr(item, 'filename', '') or '').strip()
                )
                detail = (
                    f'Request carried {len(raw_repo_files)} repo_files part(s) '
                    f'({blank_named} with a blank filename), '
                    f'{len(request.form.getlist("repo_paths"))} repo_paths field(s); '
                    f'file fields={sorted(set(request.files.keys()))}, '
                    f'form fields={sorted(set(request.form.keys()))}, '
                    f'content_length={request.content_length}, '
                    f'content_type={(request.content_type or "")[:80]!r}.'
                )
                msg = f'{msg} {detail}'
            except Exception:
                pass
            if is_ajax:
                return jsonify({'ok': False, 'error': msg}), 400
            flash(msg)
            return redirect(url_for('vuln_catalog_page'))
        if upload_file and repo_files:
            msg = 'Select either a vulnerability catalog folder or a ZIP, not both.'
            if is_ajax:
                return jsonify({'ok': False, 'error': msg}), 400
            flash(msg)
            return redirect(url_for('vuln_catalog_page'))

        try:
            req_len = request.content_length
            if isinstance(req_len, int) and req_len > max_upload_bytes:
                msg = f'File too large (max {max_upload_bytes // (1024 * 1024)}MB).'
                if is_ajax:
                    return jsonify({'ok': False, 'error': msg}), 413
                flash(msg)
                return redirect(url_for('vuln_catalog_page'))
        except Exception:
            pass

        tmp_path = ''
        uploaded_file_count = 0
        uploaded_compose_count = 0
        try:
            try:
                with tempfile_module.NamedTemporaryFile(prefix='vuln-upload-', suffix='.zip', delete=False) as tmp:
                    tmp_path = tmp.name
                if repo_files:
                    repo_paths = [str(path or '') for path in request.form.getlist('repo_paths')]
                    _folder_upload_to_zip(repo_files, repo_paths, tmp_path)
                else:
                    upload_file.save(tmp_path)
            except request_entity_too_large_type:
                msg = 'File too large for this server upload limit.'
                if is_ajax:
                    return jsonify({'ok': False, 'error': msg}), 413
                flash(msg)
                return redirect(url_for('vuln_catalog_page'))

            if repo_files:
                label = secure_filename_func(str(request.form.get('repo_label') or '').strip()) or 'vuln-catalog'
                origin = 'folder-upload'
            else:
                label = secure_filename_func(getattr(upload_file, 'filename', '') or '') or 'vuln-catalog'
                origin = 'upload'
            try:
                with zipfile.ZipFile(tmp_path, 'r') as archive:
                    uploaded_names = [name for name in archive.namelist() if name and not name.endswith('/')]
                uploaded_file_count = len(uploaded_names)
                uploaded_compose_count = sum(
                    1 for name in uploaded_names
                    if name == 'docker-compose.yml' or name.endswith('/docker-compose.yml')
                )
            except Exception:
                uploaded_file_count = 0
                uploaded_compose_count = 0

            set_active_progress_id(progress_id)
            set_active_architecture_scan(validate_architectures)
            update_progress(
                progress_id,
                step='Extracting catalog',
                detail=f'{uploaded_file_count:,} file(s) received',
            )
            try:
                entry = install_vuln_catalog_zip_file(zip_file_path=tmp_path, label=label, origin=origin)
            finally:
                set_active_progress_id(None)
                set_active_architecture_scan(None)
            update_progress(
                progress_id,
                step='Installing catalog',
                detail='Writing catalog index',
                current=1,
                total=1,
                status='complete',
            )
            try:
                os_module.remove(tmp_path)
            except Exception:
                pass
            bundle_count = 0
            try:
                bundle_count = int(entry.get('bundle_count') or 0) if isinstance(entry, dict) else 0
            except Exception:
                bundle_count = 0
            message = 'Vulnerability catalog pack installed.'
            if bundle_count > 0:
                message = f'Installed {bundle_count} vulnerability catalog pack(s) from bundle.'
            missing_required_file_count = 0
            try:
                missing_required_file_count = int(entry.get('missing_required_file_count') or 0) if isinstance(entry, dict) else 0
            except Exception:
                missing_required_file_count = 0
            if missing_required_file_count > 0:
                message = f'{message} Missing {missing_required_file_count} compose support file(s).'
            if is_ajax:
                return jsonify({
                    'ok': True,
                    'message': message,
                    'catalog_id': str(entry.get('id') or ''),
                    'import_method': origin,
                    'uploaded_file_count': uploaded_file_count,
                    'discovered_compose_count': uploaded_compose_count,
                    'installed_catalog_count': bundle_count or 1,
                    'installed_vulnerability_count': int(entry.get('compose_count') or uploaded_compose_count or 0),
                    'missing_required_file_count': missing_required_file_count,
                    'bundle_failures': list(entry.get('bundle_failures') or []),
                })
            flash(message)
        except Exception as exc:
            set_active_progress_id(None)
            set_active_architecture_scan(None)
            update_progress(progress_id, step='Import failed', detail=str(exc), status='failed')
            try:
                if tmp_path:
                    os_module.remove(tmp_path)
            except Exception:
                pass
            if is_ajax:
                return jsonify({'ok': False, 'error': f'Failed to install vulnerability catalog pack: {exc}'}), 400
            flash(f'Failed to install vulnerability catalog pack: {exc}')
        return redirect(url_for('vuln_catalog_page'))

    @app.route('/vuln_catalog_packs/import_url', methods=['POST'])
    def vuln_catalog_packs_import_url():
        require_builder_or_admin()
        is_ajax = str(request.headers.get('X-Requested-With') or '').lower() == 'xmlhttprequest' or 'application/json' in str(request.headers.get('Accept') or '')
        url = str(request.form.get('zip_url') or '').strip()
        ok, msg = is_safe_remote_zip_url(url)
        if not ok:
            if is_ajax:
                return jsonify({'ok': False, 'error': f'Blocked URL: {msg}'}), 400
            flash(f'Blocked URL: {msg}')
            return redirect(url_for('vuln_catalog_page'))
        try:
            data = download_zip_from_url(url)
            label = os_module.path.basename(urlparse_func(url).path) or 'vuln-catalog'
            set_active_architecture_scan(_requested_architecture_scan())
            try:
                entry = install_vuln_catalog_zip_bytes(zip_bytes=data, label=label, origin=url)
            finally:
                set_active_architecture_scan(None)
            bundle_count = int(entry.get('bundle_count') or 0)
            missing_count = int(entry.get('missing_required_file_count') or 0)
            message = 'Vulnerability catalog pack installed from URL.'
            if bundle_count:
                message = f'Installed {bundle_count} vulnerability catalog pack(s) from URL bundle.'
            if is_ajax:
                return jsonify({
                    'ok': True,
                    'message': message,
                    'catalog_id': str(entry.get('id') or ''),
                    'import_method': 'url',
                    'downloaded_bytes': len(data),
                    'installed_catalog_count': bundle_count or 1,
                    'installed_vulnerability_count': int(entry.get('compose_count') or 0),
                    'missing_required_file_count': missing_count,
                    'bundle_failures': list(entry.get('bundle_failures') or []),
                })
            flash('Vulnerability catalog pack installed from URL.')
        except Exception as exc:
            if is_ajax:
                return jsonify({'ok': False, 'error': f'Failed to import vulnerability catalog pack: {exc}'}), 400
            flash(f'Failed to import vulnerability catalog pack: {exc}')
        return redirect(url_for('vuln_catalog_page'))

    mark_routes_registered(app, 'vuln_catalog_pack_ingest_routes')
