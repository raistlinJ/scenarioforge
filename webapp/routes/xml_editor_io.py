from __future__ import annotations

import copy
import json
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable

from flask import Response, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

try:
    from lxml import etree as LET  # type: ignore
except Exception:  # pragma: no cover
    LET = None  # type: ignore


_IMPORT_PROGRESS_LOCK = threading.Lock()
_IMPORT_PROGRESS: dict[str, dict[str, Any]] = {}
_IMPORT_PROGRESS_TTL_SECONDS = 15 * 60
_IMPORT_PROGRESS_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,80}$")


def _expire_import_progress() -> None:
    cutoff = time.time() - _IMPORT_PROGRESS_TTL_SECONDS
    with _IMPORT_PROGRESS_LOCK:
        for progress_id in list(_IMPORT_PROGRESS):
            if float(_IMPORT_PROGRESS[progress_id].get('updated_at') or 0) < cutoff:
                _IMPORT_PROGRESS.pop(progress_id, None)


def _update_import_progress(
    progress_id: str,
    step: str,
    percent: int,
    detail: str = '',
    *,
    status: str = 'running',
) -> None:
    if not progress_id or not _IMPORT_PROGRESS_ID_RE.fullmatch(progress_id):
        return
    now = time.time()
    event = {
        'step': str(step or 'Importing scenario'),
        'detail': str(detail or ''),
        'percent': max(0, min(100, int(percent))),
        'status': status,
        'timestamp': now,
    }
    with _IMPORT_PROGRESS_LOCK:
        state = _IMPORT_PROGRESS.setdefault(
            progress_id,
            {'id': progress_id, 'status': 'running', 'percent': 0, 'events': [], 'updated_at': now},
        )
        events = state.setdefault('events', [])
        if not events or any(events[-1].get(key) != event.get(key) for key in ('step', 'detail', 'status')):
            events.append(event)
            del events[:-60]
        state.update({
            'status': status,
            'step': event['step'],
            'detail': event['detail'],
            'percent': event['percent'],
            'updated_at': now,
        })


def _import_progress_snapshot(progress_id: str) -> dict[str, Any] | None:
    _expire_import_progress()
    with _IMPORT_PROGRESS_LOCK:
        state = _IMPORT_PROGRESS.get(progress_id)
        return copy.deepcopy(state) if isinstance(state, dict) else None


def register(
    app,
    *,
    current_user_getter: Callable[[], dict[str, Any] | None],
    allowed_file_func: Callable[[str], bool],
    parse_scenarios_xml: Callable[[str], dict[str, Any]],
    default_core_dict: Callable[[], dict[str, Any]],
    attach_base_upload: Callable[[dict[str, Any]], Any],
    hydrate_base_upload_from_disk: Callable[[dict[str, Any]], Any],
    enumerate_host_interfaces: Callable[[], list[dict[str, Any]]],
    save_base_upload_state: Callable[[dict[str, Any]], Any],
    prepare_payload_for_index: Callable[..., dict[str, Any]],
    persist_editor_state_snapshot: Callable[..., Any],
    load_editor_state_snapshot: Callable[..., dict[str, Any] | None],
    normalize_core_config: Callable[..., dict[str, Any]],
    normalize_scenario_names_strict: Callable[[list[Any]], Any],
    local_timestamp_safe: Callable[[], str],
    outputs_dir: Callable[[], str],
    sanitize_scenario_name_strict: Callable[[str, str], str],
    build_scenarios_xml: Callable[[dict[str, Any]], ET.ElementTree],
    persist_scenario_catalog: Callable[..., Any],
    ui_build_id: str,
    logger=None,
) -> None:
    """Register XML editor load/save/render routes extracted from app_backend."""

    log = logger or getattr(app, 'logger', None)

    def _concretize_scenarios_for_save(scenarios_payload: Any, *, seed: Any = None) -> list[Any]:
        from webapp import app_backend as backend

        return backend._concretize_scenarios_for_save(scenarios_payload, seed=seed)

    def _scenario_for_output_path(scenario: Any, output_path: str, scenario_name: str) -> Any:
        """Rebase embedded preview metadata onto the XML snapshot being written."""
        if not isinstance(scenario, dict):
            return scenario
        preview_key = 'plan_preview' if isinstance(scenario.get('plan_preview'), dict) else 'planPreview'
        preview = scenario.get(preview_key)
        if not isinstance(preview, dict) or not preview:
            return scenario
        out = copy.deepcopy(scenario)
        preview_out = copy.deepcopy(preview)
        metadata = preview_out.get('metadata') if isinstance(preview_out.get('metadata'), dict) else {}
        metadata = dict(metadata)
        metadata['xml_path'] = os.path.abspath(output_path)
        metadata['scenario'] = str(scenario_name or '').strip()
        if metadata.get('seed') in (None, ''):
            full_preview = preview_out.get('full_preview') if isinstance(preview_out.get('full_preview'), dict) else {}
            if full_preview.get('seed') not in (None, ''):
                metadata['seed'] = full_preview.get('seed')
        metadata.setdefault('origin', 'planner')
        preview_out['metadata'] = metadata
        out['plan_preview'] = preview_out
        if preview_key != 'plan_preview':
            out.pop(preview_key, None)
        return out

    def _import_connection_overrides(raw: Any) -> dict[str, Any]:
        source = raw if isinstance(raw, dict) else {}
        mapping = {
            'core_host': 'host',
            'core_port': 'port',
            'ssh_host': 'ssh_host',
            'ssh_port': 'ssh_port',
            'ssh_username': 'ssh_username',
            'ssh_password': 'ssh_password',
            'venv_bin': 'venv_bin',
        }
        overrides: dict[str, Any] = {}
        for source_key, target_key in mapping.items():
            value = source.get(source_key)
            if value in (None, ''):
                continue
            if target_key in {'port', 'ssh_port'}:
                try:
                    parsed = int(value)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f'{source_key.replace("_", " ")} must be a number') from exc
                if parsed < 1 or parsed > 65535:
                    raise ValueError(f'{source_key.replace("_", " ")} must be between 1 and 65535')
                overrides[target_key] = parsed
            else:
                overrides[target_key] = str(value).strip()
        if 'host' in overrides:
            overrides['grpc_host'] = overrides['host']
        if 'port' in overrides:
            overrides['grpc_port'] = overrides['port']
        overrides['ssh_enabled'] = True
        return overrides

    def _core_secret_record_config(record: Any, *, include_password: bool) -> dict[str, Any]:
        if not isinstance(record, dict):
            return {}
        cfg = {
            'host': record.get('host') or record.get('grpc_host'),
            'grpc_host': record.get('grpc_host') or record.get('host'),
            'port': record.get('port') or record.get('grpc_port'),
            'grpc_port': record.get('grpc_port') or record.get('port'),
            'ssh_host': record.get('ssh_host') or record.get('host') or record.get('grpc_host'),
            'ssh_port': record.get('ssh_port') or 22,
            'ssh_username': record.get('ssh_username'),
            'ssh_enabled': True,
            'venv_bin': record.get('venv_bin'),
            'core_secret_id': record.get('identifier'),
            'vm_key': record.get('vm_key'),
            'vm_name': record.get('vm_name'),
            'vm_node': record.get('vm_node'),
            'vmid': record.get('vmid'),
            'proxmox_secret_id': record.get('proxmox_secret_id'),
            'proxmox_target': record.get('proxmox_target'),
            'validated': True,
        }
        if include_password:
            cfg['ssh_password'] = (
                record.get('ssh_password_plain') or record.get('password_plain') or ''
            )
        return {key: value for key, value in cfg.items() if value not in (None, '')}

    def _import_materialization_destination(
        *,
        connection_overrides: Any = None,
        profile_id: str = '',
        include_password: bool = False,
        scenario_norm: str = '',
    ) -> dict[str, Any]:
        """Resolve local/remote transport and a destination-owned CORE configuration."""
        from webapp import app_backend as backend

        runtime_mode = backend._webui_runtime_mode()
        runtime_cfg = backend._core_backend_defaults(include_password=include_password)
        overrides = _import_connection_overrides(connection_overrides)

        def is_native_local(cfg: dict[str, Any]) -> bool:
            if runtime_mode != 'native':
                return False
            grpc_host = str(cfg.get('grpc_host') or cfg.get('host') or '').strip().lower()
            ssh_host = str(cfg.get('ssh_host') or grpc_host or '').strip().lower()
            local_names = {'localhost', '127.0.0.1', '::1'}
            return not bool(backend._webui_running_in_docker()) and (
                bool(backend._webui_local_mode())
                or (grpc_host in local_names and ssh_host in local_names)
            )

        initial_cfg = dict(runtime_cfg)
        initial_cfg.update(overrides)
        initially_local = is_native_local(initial_cfg)
        resolved_profile = None
        requested_profile_id = str(profile_id or '').strip()
        if requested_profile_id:
            resolved_profile = backend._load_core_credentials(requested_profile_id)
            if not resolved_profile:
                raise ValueError('The selected destination VM/Access profile is no longer available.')
        else:
            runtime_required = (
                initial_cfg.get('host') or initial_cfg.get('grpc_host'),
                initial_cfg.get('port') or initial_cfg.get('grpc_port'),
                initial_cfg.get('ssh_host') or initial_cfg.get('host'),
                initial_cfg.get('ssh_port'),
                initial_cfg.get('ssh_username'),
            )
            runtime_has_password = bool(str(initial_cfg.get('ssh_password') or '')) if include_password else True
            if not initially_local and (not all(runtime_required) or not runtime_has_password):
                resolved_profile = backend._select_latest_core_secret_record(scenario_norm or None)

        combined = dict(runtime_cfg)
        profile_cfg = _core_secret_record_config(resolved_profile, include_password=include_password)
        combined.update(profile_cfg)
        profile_conflict = False
        if profile_cfg and overrides:
            for field in ('host', 'port', 'ssh_host', 'ssh_port', 'ssh_username'):
                if field not in overrides:
                    continue
                if str(overrides.get(field) or '') != str(profile_cfg.get(field) or ''):
                    profile_conflict = True
                    break
            if str(overrides.get('ssh_password') or ''):
                profile_conflict = True
        combined.update(overrides)
        if profile_conflict:
            for metadata_key in (
                'core_secret_id', 'vm_key', 'vm_name', 'vm_node', 'vmid',
                'proxmox_secret_id', 'proxmox_target', 'validated',
            ):
                combined.pop(metadata_key, None)
        public_core_cfg = backend._normalize_core_config(combined, include_password=include_password)
        for metadata_key in (
            'core_secret_id', 'vm_key', 'vm_name', 'vm_node', 'vmid',
            'proxmox_secret_id', 'proxmox_target', 'validated',
        ):
            if combined.get(metadata_key) not in (None, ''):
                public_core_cfg[metadata_key] = combined.get(metadata_key)
        local_materialization = is_native_local(public_core_cfg)
        return {
            'runtime_mode': runtime_mode,
            'local_materialization': local_materialization,
            'public_core_cfg': public_core_cfg,
            'profile': {
                'id': str(public_core_cfg.get('core_secret_id') or ''),
                'label': str(
                    public_core_cfg.get('vm_name')
                    or public_core_cfg.get('vm_key')
                    or public_core_cfg.get('ssh_host')
                    or ''
                ),
                'validated': bool(public_core_cfg.get('validated')),
            },
        }

    def _auto_materialize_imported_bundle(
        imported: Any,
        parsed_payload: Any,
        progress: Callable[[str, int, str], None] | None = None,
        connection_overrides: Any = None,
        profile_id: str = '',
        requested: bool = True,
    ) -> dict[str, Any]:
        from webapp import app_backend as backend
        from webapp.reproduction_bundle import (
            _safe_materialization_target,
            restore_bundled_artifacts_locally,
            restore_bundled_artifacts_to_core,
        )

        if imported.kind != 'reproduction-bundle' or imported.bundled_artifact_sources < 1:
            return {'attempted': False, 'ok': True, 'restored_sources': 0, 'missing': []}
        if not requested:
            # The importer declined materialization: it copies every bundled
            # artifact to the CORE host, which is the slow part of an import.
            # The scenario still imports fully; its artifacts are simply not on
            # the host yet, and a later execute regenerates what it needs.
            if progress:
                progress(
                    'Skipping artifact materialization',
                    88,
                    'Not requested; bundled artifacts were not copied to the CORE host.',
                )
            return {
                'attempted': False,
                'ok': True,
                'restored_sources': 0,
                'missing': [],
                'declined': True,
            }
        flow_state = backend._flow_state_from_xml_path(imported.xml_path, None)
        if not isinstance(flow_state, dict):
            return {
                'attempted': True,
                'ok': False,
                'restored_sources': 0,
                'missing': [],
                'error': 'The imported bundle does not contain a readable saved FlowState.',
            }
        scenario_label = str(flow_state.get('scenario') or '').strip()
        if not scenario_label and isinstance(parsed_payload, dict):
            scenarios = parsed_payload.get('scenarios')
            if isinstance(scenarios, list) and scenarios and isinstance(scenarios[0], dict):
                scenario_label = str(scenarios[0].get('name') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        destination = _import_materialization_destination(
            connection_overrides=connection_overrides,
            profile_id=profile_id,
            include_password=False,
            scenario_norm=scenario_norm,
        )
        if not destination.get('local_materialization'):
            destination = _import_materialization_destination(
                connection_overrides=connection_overrides,
                profile_id=profile_id,
                include_password=True,
                scenario_norm=scenario_norm,
            )
        runtime_mode = str(destination.get('runtime_mode') or 'native')
        local_materialization = bool(destination.get('local_materialization'))
        if progress:
            if local_materialization:
                mode_detail = 'Native local CORE: guarded local filesystem, no SSH credentials'
            elif runtime_mode == 'native':
                mode_detail = 'Native remote CORE: runtime-managed SSH credentials'
            else:
                mode_detail = 'VM mode: runtime-managed CORE SSH credentials'
            progress(
                "Selecting materialization mode",
                58,
                mode_detail,
            )
        records = flow_state.get('reproduction_artifact_sources')
        records = records if isinstance(records, list) else []
        remote_records = [
            record
            for record in records
            if isinstance(record, dict)
            and _safe_materialization_target(record.get('target_path'))
        ]
        local_ready = sum(
            1
            for record in records
            if isinstance(record, dict)
            and str(record.get('target_path') or '') == str(record.get('restored_path') or '')
            and os.path.isdir(str(record.get('restored_path') or ''))
        )
        if not remote_records:
            return {
                'attempted': True,
                'ok': local_ready == imported.bundled_artifact_sources,
                'restored_sources': local_ready,
                'missing': [],
                'runtime_mode': runtime_mode,
                'credential_source': 'none',
            }

        log_handle = backend.io.StringIO()
        if local_materialization:
            try:
                restored_native = restore_bundled_artifacts_locally(
                    flow_state=flow_state,
                    upload_root=app.config['UPLOAD_FOLDER'],
                    log_handle=log_handle,
                    progress=progress,
                )
                restored_sources = local_ready + restored_native
                if progress:
                    progress(
                        "Verifying native artifact paths",
                        90,
                        f"Restored {restored_sources}/{imported.bundled_artifact_sources} artifact sources",
                    )
                return {
                    'attempted': True,
                    'ok': restored_sources == imported.bundled_artifact_sources,
                    'restored_sources': restored_sources,
                    'missing': [],
                    'runtime_mode': runtime_mode,
                    'materialization_transport': 'local',
                    'credential_source': 'none',
                    'log': log_handle.getvalue()[-4000:],
                }
            except Exception as exc:
                return {
                    'attempted': True,
                    'ok': False,
                    'restored_sources': local_ready,
                    'missing': [],
                    'runtime_mode': runtime_mode,
                    'materialization_transport': 'local',
                    'credential_source': 'none',
                    'error': str(exc),
                    'log': log_handle.getvalue()[-4000:],
                }

        client = None
        sftp = None
        remote_label = 'CORE VM' if runtime_mode == 'vm' else 'remote CORE host'
        override_cfg = connection_overrides if isinstance(connection_overrides, dict) else {}
        credential_source = (
            'prompt'
            if str(override_cfg.get('ssh_password') or '')
            else ('profile' if str((destination.get('profile') or {}).get('id') or '') else 'runtime')
        )
        try:
            if progress:
                progress(
                    f"Resolving {remote_label} credentials",
                    62,
                    "Using destination runtime configuration or the one-time import password; "
                    "imported credentials are ignored",
                )
            core_cfg = dict(destination.get('public_core_cfg') or {})
            core_cfg = backend._require_core_ssh_credentials(core_cfg)
            if progress:
                progress(
                    f"Connecting to {remote_label}",
                    66,
                    f"SSH target {core_cfg.get('ssh_host') or core_cfg.get('host') or '(configured host)'}",
                )
            client = backend._open_ssh_client(core_cfg)
            sftp = client.open_sftp()
            restored_remote = restore_bundled_artifacts_to_core(
                backend=backend,
                client=client,
                sftp=sftp,
                flow_state=flow_state,
                upload_root=app.config['UPLOAD_FOLDER'],
                log_handle=log_handle,
                progress=progress,
                destination_label=remote_label,
            )
            assignments = flow_state.get('flag_assignments')
            assignments = assignments if isinstance(assignments, list) else []
            missing: list[str] = []
            for assignment in assignments:
                if not isinstance(assignment, dict):
                    continue
                missing.extend(
                    str(path)
                    for path in backend._flow_assignment_missing_remote_paths(sftp, assignment)
                    if str(path).strip()
                )
            restored_sources = local_ready + restored_remote
            if progress:
                progress(
                    f"Verifying {remote_label} artifact paths",
                    90,
                    f"Restored {restored_sources}/{imported.bundled_artifact_sources}; missing paths {len(set(missing))}",
                )
            return {
                'attempted': True,
                'ok': restored_sources == imported.bundled_artifact_sources and not missing,
                'restored_sources': restored_sources,
                'missing': sorted(set(missing)),
                'runtime_mode': runtime_mode,
                'materialization_transport': 'ssh',
                'credential_source': credential_source,
                'log': log_handle.getvalue()[-4000:],
            }
        except Exception as exc:
            return {
                'attempted': True,
                'ok': False,
                'restored_sources': local_ready,
                'missing': [],
                'runtime_mode': runtime_mode,
                'materialization_transport': 'ssh',
                'credential_source': credential_source,
                'error': str(exc),
                'log': log_handle.getvalue()[-4000:],
            }
        finally:
            try:
                if sftp:
                    sftp.close()
            except Exception:
                pass
            try:
                if client:
                    client.close()
            except Exception:
                pass

    @app.get('/api/scenario-import-progress/<progress_id>')
    def scenario_import_progress(progress_id: str):
        if not _IMPORT_PROGRESS_ID_RE.fullmatch(str(progress_id or '')):
            return jsonify({'ok': False, 'error': 'Invalid import progress id.'}), 400
        snapshot = _import_progress_snapshot(progress_id)
        if snapshot is None:
            return jsonify({'ok': True, 'status': 'waiting', 'percent': 0, 'events': []})
        return jsonify({'ok': True, **snapshot})

    @app.get('/api/scenario-import-requirements')
    def scenario_import_requirements():
        current_user = current_user_getter() or {}
        can_save_profile = str(current_user.get('role') or '').strip().lower() == 'admin'
        destination = _import_materialization_destination(include_password=False)
        if not destination.get('local_materialization'):
            destination = _import_materialization_destination(include_password=True)
        runtime_mode = str(destination.get('runtime_mode') or 'native')
        core_cfg = destination.get('public_core_cfg') or {}
        connection = {
            'core_host': str(core_cfg.get('grpc_host') or core_cfg.get('host') or ''),
            'core_port': core_cfg.get('grpc_port') or core_cfg.get('port') or '',
            'ssh_host': str(core_cfg.get('ssh_host') or ''),
            'ssh_port': core_cfg.get('ssh_port') or '',
            'ssh_username': str(core_cfg.get('ssh_username') or ''),
            'venv_bin': str(core_cfg.get('venv_bin') or ''),
            'profile_id': str((destination.get('profile') or {}).get('id') or ''),
        }
        if destination.get('local_materialization'):
            return jsonify({
                'ok': True,
                'runtime_mode': runtime_mode,
                'transport': 'local',
                'password_required': False,
                'missing_configuration': [],
                'connection': connection,
                'profile': destination.get('profile') or {},
                'can_save_profile': can_save_profile,
            })

        required_fields = {
            'core_host': 'CORE host',
            'core_port': 'CORE port',
            'ssh_host': 'SSH host',
            'ssh_port': 'SSH port',
            'ssh_username': 'SSH username',
        }
        missing_configuration = [
            {'field': field, 'label': label}
            for field, label in required_fields.items()
            if connection.get(field) in (None, '')
        ]
        ssh_password = str(core_cfg.get('ssh_password') or '')
        if not ssh_password:
            missing_configuration.append({'field': 'ssh_password', 'label': 'SSH password'})
        return jsonify({
            'ok': True,
            'runtime_mode': runtime_mode,
            'transport': 'ssh',
            'destination_label': 'CORE VM' if runtime_mode == 'vm' else 'remote CORE host',
            'password_required': not bool(ssh_password),
            'missing_configuration': missing_configuration,
            'connection': connection,
            'profile': destination.get('profile') or {},
            'can_save_profile': can_save_profile,
        })

    @app.post('/api/scenario-import-connection/test')
    def scenario_import_connection_test():
        from webapp import app_backend as backend

        payload = request.get_json(silent=True) or {}
        connection = payload.get('connection') if isinstance(payload.get('connection'), dict) else {}
        profile_id = str(connection.get('profile_id') or '').strip()
        try:
            destination = _import_materialization_destination(
                connection_overrides=connection,
                profile_id=profile_id,
                include_password=False,
            )
            if destination.get('local_materialization'):
                return jsonify({
                    'ok': True,
                    'transport': 'local',
                    'message': 'Native local CORE uses the local filesystem; SSH validation is not required.',
                    'connection': connection,
                    'profile': destination.get('profile') or {},
                })
            destination = _import_materialization_destination(
                connection_overrides=connection,
                profile_id=profile_id,
                include_password=True,
            )
            core_cfg = backend._require_core_ssh_credentials(
                dict(destination.get('public_core_cfg') or {})
            )
            client = None
            sftp = None
            try:
                client = backend._open_ssh_client(core_cfg)
                sftp = client.open_sftp()
            finally:
                try:
                    if sftp:
                        sftp.close()
                except Exception:
                    pass
                try:
                    if client:
                        client.close()
                except Exception:
                    pass
            profile = destination.get('profile') or {}
            save_profile = bool(payload.get('save_profile'))
            current_user = current_user_getter() or {}
            if save_profile and str(current_user.get('role') or '').strip().lower() != 'admin':
                return jsonify({'ok': False, 'error': 'Admin privileges are required to save an access profile.'}), 403
            if save_profile:
                stored_meta = backend._save_core_credentials({
                    'scenario_name': 'Imported scenarios',
                    'grpc_host': core_cfg.get('grpc_host') or core_cfg.get('host'),
                    'grpc_port': core_cfg.get('grpc_port') or core_cfg.get('port'),
                    'ssh_host': core_cfg.get('ssh_host'),
                    'ssh_port': core_cfg.get('ssh_port'),
                    'ssh_username': core_cfg.get('ssh_username'),
                    'ssh_password': core_cfg.get('ssh_password'),
                    'ssh_enabled': True,
                    'venv_bin': core_cfg.get('venv_bin'),
                    'vm_key': core_cfg.get('vm_key'),
                    'vm_name': core_cfg.get('vm_name'),
                    'vm_node': core_cfg.get('vm_node'),
                    'vmid': core_cfg.get('vmid'),
                    'proxmox_secret_id': core_cfg.get('proxmox_secret_id'),
                    'proxmox_target': core_cfg.get('proxmox_target'),
                })
                profile = {
                    'id': str(stored_meta.get('identifier') or ''),
                    'label': str(
                        stored_meta.get('vm_name')
                        or stored_meta.get('vm_key')
                        or stored_meta.get('ssh_host')
                        or ''
                    ),
                    'validated': True,
                }
            return jsonify({
                'ok': True,
                'transport': 'ssh',
                'message': 'SSH and SFTP access validated.',
                'destination_label': (
                    'CORE VM'
                    if destination.get('runtime_mode') == 'vm'
                    else 'remote CORE host'
                ),
                'profile': profile,
                'profile_saved': bool(save_profile),
            })
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)}), 400

    @app.route('/load_xml', methods=['POST'])
    def load_xml():
        from webapp import app_backend as backend
        from webapp.reproduction_bundle import import_scenario_file

        progress_id = str(request.form.get('import_progress_id') or '').strip()
        profile_id = str(request.form.get('import_core_profile_id') or '').strip()
        # Materialization is the slow part of importing a bundle, so the
        # importer chooses. Absent field means yes, keeping the API-level
        # behaviour of existing callers (and tests) unchanged.
        raw_materialize = request.form.get('import_materialize')
        materialize_requested = (
            True if raw_materialize is None
            else str(raw_materialize).strip().lower() not in ('0', 'false', 'no', 'off', '')
        )
        connection_overrides = {
            'core_host': request.form.get('import_core_host'),
            'core_port': request.form.get('import_core_port'),
            'ssh_host': request.form.get('import_ssh_host'),
            'ssh_port': request.form.get('import_ssh_port'),
            'ssh_username': request.form.get('import_ssh_username'),
            'ssh_password': request.form.get('core_ssh_password'),
            'venv_bin': request.form.get('import_core_venv_bin'),
        }
        transient_ssh_password = str(connection_overrides.get('ssh_password') or '')
        if len(transient_ssh_password) > 4096:
            _update_import_progress(
                progress_id,
                'Import failed',
                100,
                'The supplied SSH password is too long.',
                status='failed',
            )
            flash('Failed to import scenario file: the supplied SSH password is too long.')
            return redirect(url_for('index'))

        def report_progress(step: str, percent: int, detail: str = '') -> None:
            _update_import_progress(progress_id, step, percent, detail)

        report_progress('Receiving scenario file', 8, 'Upload received by ScenarioForge')
        user = current_user_getter()
        file = request.files.get('scenarios_xml')
        if not file or file.filename == '':
            _update_import_progress(progress_id, 'Import failed', 100, 'No file selected.', status='failed')
            flash('No file selected.')
            return redirect(url_for('index'))
        filename = secure_filename(file.filename) or f'scenario-upload-{os.getpid()}'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        report_progress('Saving uploaded file', 11, filename)
        file.save(filepath)
        try:
            os.chmod(filepath, 0o600)
        except OSError:
            pass
        try:
            imported = import_scenario_file(
                filepath,
                app.config['UPLOAD_FOLDER'],
                progress=report_progress,
            )
            filepath = imported.xml_path
            report_progress('Parsing imported scenario', 55, os.path.basename(filepath))
            payload = parse_scenarios_xml(filepath)
            scenario_label = ''
            scenarios = payload.get('scenarios') if isinstance(payload, dict) else None
            scenario_labels: list[str] = []
            if isinstance(scenarios, list):
                scenario_labels = [
                    str(item.get('name') or '').strip()
                    for item in scenarios
                    if isinstance(item, dict) and str(item.get('name') or '').strip()
                ]
            if isinstance(scenarios, list) and scenarios and isinstance(scenarios[0], dict):
                scenario_label = str(scenarios[0].get('name') or '').strip()
            destination = _import_materialization_destination(
                connection_overrides=connection_overrides,
                profile_id=profile_id,
                include_password=False,
                scenario_norm=backend._normalize_scenario_label(scenario_label),
            )
            destination_core_cfg = dict(destination.get('public_core_cfg') or {})
            destination_core_cfg.pop('ssh_password', None)
            if destination_core_cfg:
                report_progress(
                    'Binding destination CORE connection',
                    57,
                    'Replacing source connection metadata with this installation’s destination settings',
                )
                for destination_scenario in (scenario_labels or [None]):
                    rebound, rebound_message = backend._update_core_config_in_xml(
                        filepath,
                        destination_scenario,
                        destination_core_cfg,
                    )
                    if not rebound:
                        raise ValueError(
                            f'Unable to bind destination CORE connection: {rebound_message}'
                        )
                payload = parse_scenarios_xml(filepath)
            auto_materialization = _auto_materialize_imported_bundle(
                imported,
                payload,
                progress=report_progress,
                connection_overrides=connection_overrides,
                profile_id=profile_id,
                requested=materialize_requested,
            )
            if auto_materialization.get('attempted') and not auto_materialization.get('ok'):
                materialization_detail = str(auto_materialization.get('error') or '').strip()
                if not materialization_detail:
                    restored_count = int(auto_materialization.get('restored_sources') or 0)
                    missing_count = len(auto_materialization.get('missing') or [])
                    materialization_detail = (
                        f'Restored {restored_count}/{imported.bundled_artifact_sources} artifact sources; '
                        f'{missing_count} expected paths missing. Import will continue.'
                    )
                report_progress(
                    'Artifact materialization needs attention',
                    92,
                    materialization_detail,
                )
            report_progress('Loading scenario into editor', 94, 'Preparing imported scenario state')
            if 'core' not in payload:
                payload['core'] = default_core_dict()
            payload['result_path'] = filepath
            attach_base_upload(payload)
            hydrate_base_upload_from_disk(payload)
            payload['host_interfaces'] = enumerate_host_interfaces()
            if payload.get('base_upload'):
                save_base_upload_state(payload['base_upload'])
            xml_text = ''
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    xml_text = f.read()
            except Exception:
                xml_text = ''
            payload = prepare_payload_for_index(payload, user=user)
            snapshot_source = dict(payload)
            snapshot_source['active_index'] = 0
            snapshot_source['project_key_hint'] = payload.get('result_path')
            persist_editor_state_snapshot(snapshot_source, user=user)
            snapshot = load_editor_state_snapshot(user)
            if snapshot:
                payload['editor_snapshot'] = snapshot
            if imported.kind == 'reproduction-bundle':
                payload['reproduction_import'] = {
                    'fidelity': imported.fidelity,
                    'manifest_path': imported.manifest_path,
                    'bundled_artifact_sources': imported.bundled_artifact_sources,
                    'total_artifact_sources': imported.total_artifact_sources,
                    'auto_materialization': auto_materialization,
                }
                if imported.bundled_artifact_sources and auto_materialization.get('declined'):
                    flash(
                        'Imported ScenarioForge reproduction bundle '
                        f'({imported.fidelity}; {imported.bundled_artifact_sources} artifact '
                        'source(s) bundled but not materialized). Re-import with '
                        'materialization enabled to copy them to the CORE host.'
                    )
                elif imported.bundled_artifact_sources and auto_materialization.get('ok'):
                    flash(
                        'Imported ScenarioForge reproduction bundle '
                        f'({imported.fidelity}; {imported.bundled_artifact_sources}/'
                        f'{imported.total_artifact_sources} artifact sources automatically materialized).'
                    )
                elif imported.bundled_artifact_sources:
                    restored = int(auto_materialization.get('restored_sources') or 0)
                    missing = len(auto_materialization.get('missing') or [])
                    error = str(auto_materialization.get('error') or '').strip()
                    detail = f' {missing} expected path(s) are still missing.' if missing else ''
                    if error:
                        detail += f' Automatic materialization error: {error}'
                    flash(
                        'Imported ScenarioForge reproduction bundle, but '
                        f'materialization restored {restored}/{imported.bundled_artifact_sources} '
                        f'artifact sources.{detail} Re-import the bundle to retry.'
                    )
                else:
                    flash(
                        'Imported ScenarioForge replay package. Artifacts will be '
                        'recreated from the saved flow when materialized.'
                    )
            _update_import_progress(
                progress_id,
                'Import complete',
                100,
                'Scenario is ready.',
                status='complete',
            )
            return render_template('index.html', payload=payload, logs='', xml_preview=xml_text, ui_build_id=ui_build_id)
        except Exception as e:
            _update_import_progress(
                progress_id,
                'Import failed',
                100,
                str(e),
                status='failed',
            )
            flash(f'Failed to import scenario file: {e}')
            return redirect(url_for('index'))

    @app.route('/save_xml', methods=['POST'])
    def save_xml():
        data_str = request.form.get('scenarios_json')
        if not data_str:
            flash('No data received.')
            return redirect(url_for('index'))
        user = current_user_getter()
        try:
            data = json.loads(data_str)
        except Exception as e:
            flash(f'Invalid JSON: {e}')
            return redirect(url_for('index'))
        try:
            active_index = None
            try:
                active_index = int(data.get('active_index')) if 'active_index' in data else None
            except Exception:
                active_index = None
            core_meta = None
            try:
                core_str = request.form.get('core_json')
                if core_str:
                    core_meta = json.loads(core_str)
            except Exception:
                core_meta = None
            client_project_hint = (request.form.get('project_key_hint') or '').strip()
            client_scenario_query = (request.form.get('scenario_query') or '').strip()
            normalized_core = normalize_core_config(core_meta, include_password=True) if core_meta else None
            try:
                scenarios_list = data.get('scenarios') or []
                if isinstance(scenarios_list, list):
                    normalize_scenario_names_strict(scenarios_list)
                    scenarios_list = _concretize_scenarios_for_save(scenarios_list, seed=data.get('seed'))
                    data['scenarios'] = scenarios_list
            except ValueError as exc:
                flash(f'Failed to save XML: {exc}')
                return redirect(url_for('index'))
            scenario_count = len(data.get('scenarios') or []) if isinstance(data.get('scenarios'), list) else 0
            scenario_names_desc = []
            try:
                scenario_names_desc = [str((sc or {}).get('name') or '').strip() for sc in (data.get('scenarios') or []) if isinstance(sc, dict)]
            except Exception:
                scenario_names_desc = []
            username = (user or {}).get('username') if isinstance(user, dict) else None
            try:
                if log is not None:
                    log.info(
                        '[save_xml] user=%s scen_count=%s active_index=%s project_hint=%s scenario_query=%s names=%s',
                        username or 'anonymous',
                        scenario_count,
                        active_index if active_index is not None else 'none',
                        client_project_hint or '<none>',
                        client_scenario_query or '<none>',
                        ', '.join(name for name in scenario_names_desc if name) or '<unnamed>'
                    )
            except Exception:
                pass
            scenarios_list = data.get('scenarios') if isinstance(data.get('scenarios'), list) else []
            ts = local_timestamp_safe()
            out_dir = os.path.join(outputs_dir(), f'scenarios-{ts}')
            os.makedirs(out_dir, exist_ok=True)
            try:
                legacy_bundle = os.path.join(out_dir, 'scenarios.xml')
                if os.path.exists(legacy_bundle):
                    os.remove(legacy_bundle)
            except Exception:
                pass
            scenario_paths_map: dict[str, str] = {}
            active_out_path = None
            if scenarios_list:
                for idx, scen in enumerate(scenarios_list):
                    if not isinstance(scen, dict):
                        continue
                    raw_name = (scen.get('name') or '').strip()
                    display_name = sanitize_scenario_name_strict(raw_name, f'NewScenario{idx + 1}')
                    stem = secure_filename(display_name).strip('_-.') or f'Scenario_{idx + 1}'
                    out_path = os.path.join(out_dir, f'{stem}.xml')
                    if os.path.exists(out_path):
                        suffix = 2
                        base = stem
                        while os.path.exists(out_path):
                            stem = f'{base}-{suffix}'
                            out_path = os.path.join(out_dir, f'{stem}.xml')
                            suffix += 1
                    scen_to_write = _scenario_for_output_path(scen, out_path, display_name)
                    scenarios_list[idx] = scen_to_write
                    try:
                        tree = build_scenarios_xml({'scenarios': [scen_to_write], 'core': normalized_core})
                        raw = ET.tostring(tree.getroot(), encoding='utf-8')
                        if LET is not None:
                            lroot = LET.fromstring(raw)
                            pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
                            with open(out_path, 'wb') as f:
                                f.write(pretty)
                        else:
                            with open(out_path, 'wb') as f:
                                f.write(raw)
                    except Exception:
                        try:
                            tree = build_scenarios_xml({'scenarios': [scen_to_write], 'core': normalized_core})
                            tree.write(out_path, encoding='utf-8', xml_declaration=True)
                        except Exception:
                            continue
                    scenario_paths_map[display_name] = out_path
                    if active_index is not None and active_index == idx:
                        active_out_path = out_path
                if active_out_path is None and scenario_paths_map:
                    active_out_path = next(iter(scenario_paths_map.values()))
            else:
                out_path = None

            out_path = active_out_path
            try:
                if log is not None:
                    if scenario_paths_map:
                        log.info('[save_xml] wrote %s scenario xml files under %s', len(scenario_paths_map), out_dir)
                    else:
                        log.info('[save_xml] persisted empty scenario state with no xml output')
            except Exception:
                pass

            xml_text = ''
            if out_path:
                try:
                    with open(out_path, 'r', encoding='utf-8', errors='ignore') as f:
                        xml_text = f.read()
                except Exception:
                    xml_text = ''
            try:
                names_for_catalog = [name for name in scenario_names_desc if isinstance(name, str) and name.strip()]
                if names_for_catalog:
                    persist_scenario_catalog(names_for_catalog, source_path=scenario_paths_map or out_path)
            except Exception:
                pass
            if out_path:
                flash(f'Scenarios saved (per-scenario). Active XML: {os.path.basename(out_path)}')
            else:
                flash('Empty scenario state saved.')
            payload = {
                'scenarios': data.get('scenarios', []),
                'result_path': out_path,
                'core': normalize_core_config(normalized_core or {}, include_password=False) if normalized_core else default_core_dict(),
            }
            payload['host_interfaces'] = enumerate_host_interfaces()
            attach_base_upload(payload)
            hydrate_base_upload_from_disk(payload)
            if payload.get('base_upload'):
                save_base_upload_state(payload['base_upload'])
            payload = prepare_payload_for_index(payload, user=user)
            if client_project_hint:
                payload['project_key_hint'] = client_project_hint
            if client_scenario_query:
                payload['scenario_query'] = client_scenario_query
            snapshot_source = dict(payload)
            try:
                snapshot_source['scenarios'] = copy.deepcopy(data.get('scenarios') or [])
            except Exception:
                snapshot_source['scenarios'] = data.get('scenarios') or []
            snapshot_source['active_index'] = active_index
            if client_project_hint:
                snapshot_source['project_key_hint'] = client_project_hint
            elif payload.get('project_key_hint'):
                snapshot_source['project_key_hint'] = payload.get('project_key_hint')
            else:
                snapshot_source['project_key_hint'] = payload.get('result_path')
            if client_scenario_query:
                snapshot_source['scenario_query'] = client_scenario_query
            elif payload.get('scenario_query'):
                snapshot_source['scenario_query'] = payload.get('scenario_query')
            persist_editor_state_snapshot(snapshot_source, user=user)
            snapshot = load_editor_state_snapshot(user)
            if snapshot:
                payload['editor_snapshot'] = snapshot
            try:
                if log is not None:
                    log.info('[save_xml] success user=%s xml=%s scen_count=%s', username or 'anonymous', out_path, scenario_count)
            except Exception:
                pass
            return render_template('index.html', payload=payload, logs='', xml_preview=xml_text, ui_build_id=ui_build_id)
        except Exception as e:
            flash(f'Failed to save XML: {e}')
            return redirect(url_for('index'))

    @app.route('/save_xml_api', methods=['POST'])
    def save_xml_api():
        try:
            user = current_user_getter()
            data = request.get_json(silent=True) or {}
            scenarios = data.get('scenarios')
            core_meta = data.get('core')
            normalized_core = normalize_core_config(core_meta, include_password=True) if isinstance(core_meta, (dict, list)) or core_meta else None
            raw_project_hint = data.get('project_key_hint') if isinstance(data, dict) else None
            project_key_hint = raw_project_hint.strip() if isinstance(raw_project_hint, str) else ''
            raw_scenario_query = data.get('scenario_query') if isinstance(data, dict) else None
            scenario_query_hint = raw_scenario_query.strip() if isinstance(raw_scenario_query, str) else ''
            active_index = None
            try:
                active_index = int(data.get('active_index')) if 'active_index' in data else None
            except Exception:
                active_index = None

            def _norm_name(value: Any) -> str:
                try:
                    return ' '.join(str(value or '').strip().lower().split())
                except Exception:
                    return ''

            def _candidate_source_xml_paths(project_hint_path: str, scenario_name: str) -> list[str]:
                out: list[str] = []
                try:
                    p = str(project_hint_path or '').strip()
                    if p and os.path.isfile(p):
                        out.append(os.path.abspath(p))
                except Exception:
                    pass
                try:
                    p = str(project_hint_path or '').strip()
                    if p and os.path.exists(p):
                        base_dir = os.path.dirname(os.path.abspath(p))
                        stem = secure_filename(str(scenario_name or '').strip()).strip('_-.')
                        if stem:
                            candidate = os.path.join(base_dir, f'{stem}.xml')
                            if os.path.isfile(candidate):
                                out.append(os.path.abspath(candidate))
                        if os.path.isdir(base_dir):
                            target = _norm_name(scenario_name)
                            if target:
                                for name in os.listdir(base_dir):
                                    if not name.lower().endswith('.xml'):
                                        continue
                                    try:
                                        if _norm_name(os.path.splitext(name)[0]) == target:
                                            out.append(os.path.abspath(os.path.join(base_dir, name)))
                                    except Exception:
                                        continue
                except Exception:
                    pass
                # stable + de-dup
                uniq: list[str] = []
                seen: set[str] = set()
                for p in out:
                    if p in seen:
                        continue
                    seen.add(p)
                    uniq.append(p)
                return uniq

            def _has_meaningful_value(value: Any) -> bool:
                if value is None:
                    return False
                if isinstance(value, str):
                    return bool(value.strip())
                if isinstance(value, bool):
                    return value is True
                if isinstance(value, (int, float)):
                    return True
                if isinstance(value, list):
                    return len(value) > 0
                if isinstance(value, dict):
                    return any(_has_meaningful_value(v) for v in value.values())
                return False

            def _preserve_hitl_if_missing(scen: Any, project_hint_path: str, source_scen: Any = None) -> Any:
                if not isinstance(scen, dict):
                    return scen
                existing_hitl = scen.get('hitl') if isinstance(scen.get('hitl'), dict) else None

                def _merge_verified_hitl_fields(source_hitl: Any, incoming_hitl: Any) -> Any:
                    if not isinstance(source_hitl, dict):
                        return incoming_hitl
                    if not isinstance(incoming_hitl, dict):
                        return copy.deepcopy(source_hitl)

                    merged_hitl = copy.deepcopy(incoming_hitl)
                    source = copy.deepcopy(source_hitl)

                    try:
                        if bool(source.get('bridge_validated')) and not bool(merged_hitl.get('bridge_validated')):
                            merged_hitl['bridge_validated'] = True
                            if (not merged_hitl.get('bridge_validated_at')) and source.get('bridge_validated_at'):
                                merged_hitl['bridge_validated_at'] = source.get('bridge_validated_at')
                    except Exception:
                        pass

                    source_prox = source.get('proxmox') if isinstance(source.get('proxmox'), dict) else {}
                    merged_prox = merged_hitl.get('proxmox') if isinstance(merged_hitl.get('proxmox'), dict) else {}
                    merged_prox = dict(merged_prox)
                    try:
                        source_secret = str(source_prox.get('secret_id') or '').strip()
                        source_validated = bool(source_prox.get('validated'))
                        merged_secret = str(merged_prox.get('secret_id') or '').strip()
                        merged_validated = bool(merged_prox.get('validated'))
                        if source_validated and source_secret and (not merged_validated or not merged_secret):
                            merged_prox['secret_id'] = source_secret
                            merged_prox['validated'] = True
                            if (not merged_prox.get('last_validated_at')) and source_prox.get('last_validated_at'):
                                merged_prox['last_validated_at'] = source_prox.get('last_validated_at')
                        for key in ('url', 'port', 'verify_ssl', 'stored_at', 'last_message'):
                            if key not in merged_prox or merged_prox.get(key) in (None, ''):
                                if source_prox.get(key) not in (None, ''):
                                    merged_prox[key] = source_prox.get(key)
                    except Exception:
                        pass
                    if merged_prox:
                        merged_hitl['proxmox'] = merged_prox

                    source_core = source.get('core') if isinstance(source.get('core'), dict) else {}
                    merged_core = merged_hitl.get('core') if isinstance(merged_hitl.get('core'), dict) else {}
                    merged_core = dict(merged_core)
                    try:
                        source_core_secret = str(source_core.get('core_secret_id') or '').strip()
                        source_vm_key = str(source_core.get('vm_key') or '').strip()
                        source_validated = bool(source_core.get('validated'))
                        merged_core_secret = str(merged_core.get('core_secret_id') or '').strip()
                        merged_vm_key = str(merged_core.get('vm_key') or '').strip()
                        merged_validated = bool(merged_core.get('validated'))
                        if source_validated and source_core_secret and source_vm_key and (
                            (not merged_validated) or (not merged_core_secret) or (not merged_vm_key)
                        ):
                            merged_core['core_secret_id'] = source_core_secret
                            merged_core['vm_key'] = source_vm_key
                            merged_core['validated'] = True
                            if (not merged_core.get('last_validated_at')) and source_core.get('last_validated_at'):
                                merged_core['last_validated_at'] = source_core.get('last_validated_at')
                        for key in ('vm_name', 'vm_node', 'grpc_host', 'grpc_port', 'ssh_host', 'ssh_port', 'stored_at'):
                            if key not in merged_core or merged_core.get(key) in (None, ''):
                                if source_core.get(key) not in (None, ''):
                                    merged_core[key] = source_core.get(key)
                    except Exception:
                        pass
                    if merged_core:
                        merged_hitl['core'] = merged_core

                    return merged_hitl

                scenario_name = str(scen.get('name') or '').strip()
                target = _norm_name(scenario_name)
                if not target:
                    return scen

                # Fast path: if the parsed source scenario is already available, merge from it.
                try:
                    source_hitl = source_scen.get('hitl') if isinstance(source_scen, dict) else None
                    if isinstance(source_hitl, dict) and _has_meaningful_value(source_hitl):
                        out = dict(scen)
                        if isinstance(existing_hitl, dict) and _has_meaningful_value(existing_hitl):
                            out['hitl'] = _merge_verified_hitl_fields(source_hitl, existing_hitl)
                        else:
                            out['hitl'] = copy.deepcopy(source_hitl)
                        return out
                except Exception:
                    pass

                explicit_path = ''
                try:
                    explicit_path = str(scen.get('saved_xml_path') or '').strip()
                except Exception:
                    explicit_path = ''

                candidate_paths = []
                if explicit_path and os.path.isfile(explicit_path):
                    candidate_paths.append(os.path.abspath(explicit_path))
                candidate_paths.extend(_candidate_source_xml_paths(project_hint_path, scenario_name))

                seen: set[str] = set()
                deduped: list[str] = []
                for p in candidate_paths:
                    if not p or p in seen:
                        continue
                    seen.add(p)
                    deduped.append(p)

                for src in deduped:
                    try:
                        parsed = parse_scenarios_xml(src)
                        rows = parsed.get('scenarios') if isinstance(parsed, dict) else None
                        if isinstance(rows, list):
                            for row in rows:
                                if not isinstance(row, dict):
                                    continue
                                if _norm_name(row.get('name')) != target:
                                    continue
                                hitl = row.get('hitl') if isinstance(row.get('hitl'), dict) else None
                                if isinstance(hitl, dict) and _has_meaningful_value(hitl):
                                    out = dict(scen)
                                    if isinstance(existing_hitl, dict) and _has_meaningful_value(existing_hitl):
                                        out['hitl'] = _merge_verified_hitl_fields(hitl, existing_hitl)
                                        try:
                                            if log is not None:
                                                log.info('[save_xml_api] merged verified hitl fields for scenario=%s from source=%s', scenario_name, src)
                                        except Exception:
                                            pass
                                    else:
                                        out['hitl'] = copy.deepcopy(hitl)
                                        try:
                                            if log is not None:
                                                log.info('[save_xml_api] preserved hitl for scenario=%s from source=%s', scenario_name, src)
                                        except Exception:
                                            pass
                                    return out
                    except Exception:
                        pass

                    # Fallback for legacy/lowercase HITL tags not mapped by parser.
                    try:
                        tree = ET.parse(src)
                        root = tree.getroot()

                        def _lname(tag: Any) -> str:
                            try:
                                raw = str(tag or '')
                            except Exception:
                                raw = ''
                            if '}' in raw:
                                raw = raw.rsplit('}', 1)[-1]
                            return raw.strip().lower()

                        def _to_bool_if_known(key: str, value: Any) -> Any:
                            k = str(key or '').strip().lower()
                            if k in {'enabled', 'validated', 'verify_ssl', 'remember_credentials', 'ssh_enabled'}:
                                sval = str(value or '').strip().lower()
                                if sval in {'1', 'true', 'yes', 'on'}:
                                    return True
                                if sval in {'0', 'false', 'no', 'off'}:
                                    return False
                            return value

                        for scenario_el in list(root):
                            if _lname(getattr(scenario_el, 'tag', '')) != 'scenario':
                                continue
                            if _norm_name(scenario_el.get('name')) != target:
                                continue
                            editor = None
                            for child in list(scenario_el):
                                if _lname(getattr(child, 'tag', '')) == 'scenarioeditor':
                                    editor = child
                                    break
                            if editor is None:
                                continue
                            hitl_el = None
                            for child in list(editor):
                                if _lname(getattr(child, 'tag', '')) == 'hardwareinloop':
                                    hitl_el = child
                                    break
                            if hitl_el is None:
                                continue

                            hitl_dict: dict[str, Any] = {}
                            try:
                                enabled_raw = hitl_el.get('enabled')
                                if enabled_raw is not None:
                                    hitl_dict['enabled'] = _to_bool_if_known('enabled', enabled_raw)
                            except Exception:
                                pass

                            core_dict: dict[str, Any] = {}
                            prox_dict: dict[str, Any] = {}
                            for node in list(hitl_el):
                                node_name = _lname(getattr(node, 'tag', ''))
                                if node_name == 'coreconnection':
                                    for ak, av in dict(node.attrib or {}).items():
                                        core_dict[str(ak)] = _to_bool_if_known(str(ak), av)
                                elif node_name == 'proxmoxconnection':
                                    for ak, av in dict(node.attrib or {}).items():
                                        prox_dict[str(ak)] = _to_bool_if_known(str(ak), av)
                            if core_dict:
                                hitl_dict['core'] = core_dict
                            if prox_dict:
                                hitl_dict['proxmox'] = prox_dict

                            if _has_meaningful_value(hitl_dict):
                                out = dict(scen)
                                out['hitl'] = hitl_dict
                                try:
                                    if log is not None:
                                        log.info('[save_xml_api] preserved hitl (xml fallback) for scenario=%s from source=%s', scenario_name, src)
                                except Exception:
                                    pass
                                return out
                    except Exception:
                        continue
                return scen

            def _load_scenario_from_sources(scenario_name: str, project_hint_path: str) -> dict[str, Any] | None:
                target = _norm_name(scenario_name)
                if not target:
                    return None
                for src in _candidate_source_xml_paths(project_hint_path, scenario_name):
                    try:
                        parsed = parse_scenarios_xml(src)
                        rows = parsed.get('scenarios') if isinstance(parsed, dict) else None
                        if not isinstance(rows, list):
                            continue
                        for row in rows:
                            if not isinstance(row, dict):
                                continue
                            if _norm_name(row.get('name')) != target:
                                continue
                            return row
                    except Exception:
                        continue
                return None

            def _deep_merge_preserve_missing(source: Any, incoming: Any) -> Any:
                """Merge incoming over source while preserving fields missing in incoming.

                - Dicts merge recursively.
                - Lists/scalars replace when provided by incoming.
                - Missing keys in incoming stay untouched from source.
                """
                if isinstance(source, dict) and isinstance(incoming, dict):
                    merged: dict[str, Any] = copy.deepcopy(source)
                    for key, value in incoming.items():
                        if key in merged:
                            merged[key] = _deep_merge_preserve_missing(merged.get(key), value)
                        else:
                            merged[key] = copy.deepcopy(value)
                    return merged
                return copy.deepcopy(incoming)

            def _is_reduced_snapshot_payload(scen: Any) -> bool:
                """Detect reduced UI snapshots that should not clear section items."""
                if not isinstance(scen, dict):
                    return False
                sections = scen.get('sections') if isinstance(scen.get('sections'), dict) else None
                if not isinstance(sections, dict) or not sections:
                    return False

                has_summary_signal = False
                for key in ('scenario_total_nodes', 'base_nodes', 'combined_nodes', 'additional_nodes'):
                    try:
                        raw = scen.get(key)
                        if raw is not None and str(raw).strip() != '':
                            has_summary_signal = True
                            break
                    except Exception:
                        continue
                if not has_summary_signal:
                    return False

                for sec in sections.values():
                    if not isinstance(sec, dict):
                        continue
                    items = sec.get('items') if isinstance(sec.get('items'), list) else None
                    if isinstance(items, list) and len(items) > 0:
                        return False
                return True

            def _topology_signature(scen: Any) -> str:
                if not isinstance(scen, dict):
                    return ''
                sections = scen.get('sections') if isinstance(scen.get('sections'), dict) else {}
                if not isinstance(sections, dict):
                    sections = {}
                keys = (
                    'Node Information',
                    'Routing',
                    'Services',
                    'Traffic',
                    'Vulnerabilities',
                    'Flag Node Generators',
                    'Segmentation',
                )
                picked: dict[str, Any] = {}
                for key in keys:
                    sec = sections.get(key)
                    if isinstance(sec, dict):
                        picked[key] = sec
                summary = {
                    'density_count': scen.get('density_count'),
                    'scenario_total_nodes': scen.get('scenario_total_nodes'),
                    'sections': picked,
                }
                try:
                    return json.dumps(summary, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
                except Exception:
                    return ''

            def _with_flow_state_dirty_if_topology_changed(scen: Any, src: Any) -> Any:
                if not isinstance(scen, dict):
                    return scen
                out = dict(scen)
                flow_state = out.get('flow_state') if isinstance(out.get('flow_state'), dict) else {}
                if not flow_state and isinstance(src, dict) and isinstance(src.get('flow_state'), dict):
                    flow_state = dict(src.get('flow_state') or {})
                if not isinstance(src, dict):
                    if flow_state:
                        out['flow_state'] = flow_state
                    return out
                try:
                    changed = _topology_signature(out) != _topology_signature(src)
                except Exception:
                    changed = False
                if changed:
                    flow_state = dict(flow_state or {})
                    # Topology/IP changes invalidate saved chain placement and resolved values.
                    # Keep the dirty marker but clear chain payload so Flag Sequencing starts clean.
                    flow_state['chain'] = []
                    flow_state['chain_ids'] = []
                    flow_state['length'] = 0
                    flow_state['flag_assignments'] = []
                    flow_state['flags_enabled'] = False
                    flow_state['topology_dirty'] = True
                    flow_state['topology_dirty_reason'] = 'topology_or_ip_changed'
                    flow_state['updated_at'] = local_timestamp_safe()
                    out['flow_state'] = flow_state
                elif flow_state:
                    out['flow_state'] = flow_state
                return out

            if not isinstance(scenarios, list):
                return jsonify({'ok': False, 'error': 'Invalid payload (scenarios list required)'}), 400

            source_by_norm: dict[str, dict[str, Any]] = {}
            if isinstance(scenarios, list):
                for scen in scenarios:
                    if not isinstance(scen, dict):
                        continue
                    name = str(scen.get('name') or '').strip()
                    norm = _norm_name(name)
                    if not norm or norm in source_by_norm:
                        continue
                    src = _load_scenario_from_sources(name, project_key_hint)
                    if isinstance(src, dict):
                        source_by_norm[norm] = src

            # Minimal patch semantics: merge incoming fields over source XML scenario.
            if isinstance(scenarios, list):
                merged_with_source: list[Any] = []
                for scen in scenarios:
                    if not isinstance(scen, dict):
                        merged_with_source.append(scen)
                        continue
                    norm = _norm_name(scen.get('name'))
                    src = source_by_norm.get(norm)
                    if isinstance(src, dict):
                        if _is_reduced_snapshot_payload(scen):
                            merged = dict(src)
                            for key, val in scen.items():
                                if key == 'sections':
                                    continue
                                merged[key] = val
                            merged_with_source.append(merged)
                        else:
                            merged_with_source.append(_deep_merge_preserve_missing(src, scen))
                    else:
                        merged_with_source.append(scen)
                scenarios = merged_with_source

            # If topology/IP-related fields changed compared to source XML, mark
            # FlowState as dirty so Flag Sequencing prompts a re-generate.
            if isinstance(scenarios, list):
                marked: list[Any] = []
                for scen in scenarios:
                    if not isinstance(scen, dict):
                        marked.append(scen)
                        continue
                    norm = _norm_name(scen.get('name'))
                    src = source_by_norm.get(norm)
                    marked.append(_with_flow_state_dirty_if_topology_changed(scen, src))
                scenarios = marked

            if isinstance(scenarios, list):
                preserved: list[Any] = []
                for scen in scenarios:
                    if not isinstance(scen, dict):
                        preserved.append(scen)
                        continue
                    norm = _norm_name(scen.get('name'))
                    preserved.append(_preserve_hitl_if_missing(scen, project_key_hint, source_scen=source_by_norm.get(norm)))
                scenarios = preserved

            # Do not let a client-side dirty indicator delete FlowState.  A page can
            # become generally dirty for reasons unrelated to topology (for example,
            # restoring UI state while navigating between Scenario pages).  The
            # comparison above is the authoritative check: it clears FlowState only
            # when the topology represented by the incoming XML actually differs
            # from the source XML.  Keeping this server-side also protects a saved
            # chain from stale browser state.
            try:
                normalize_scenario_names_strict(scenarios)
                scenarios = _concretize_scenarios_for_save(scenarios, seed=data.get('seed'))
            except ValueError as exc:
                # A topology request must never be downgraded into an empty
                # Specific generator row.  Return the actionable validation
                # error to the page and leave the existing XML untouched.
                return jsonify({'ok': False, 'error': str(exc)}), 422
            scenario_names: list[str] = []
            try:
                scenario_names = [str((s or {}).get('name') or '').strip() for s in scenarios if isinstance(s, dict)]
            except Exception:
                scenario_names = []
            username = (user or {}).get('username') if isinstance(user, dict) else None
            try:
                if log is not None:
                    log.info(
                        '[save_xml_api] user=%s scen_count=%s active_index=%s project_hint=%s scenario_query=%s names=%s',
                        username or 'anonymous',
                        len(scenarios),
                        active_index if active_index is not None else 'none',
                        project_key_hint or '<none>',
                        scenario_query_hint or '<none>',
                        ', '.join(name for name in scenario_names if name) or '<unnamed>'
                    )
            except Exception:
                pass
            ts = local_timestamp_safe()
            out_dir = os.path.join(outputs_dir(), f'scenarios-{ts}')
            os.makedirs(out_dir, exist_ok=True)
            try:
                legacy_bundle = os.path.join(out_dir, 'scenarios.xml')
                if os.path.exists(legacy_bundle):
                    os.remove(legacy_bundle)
            except Exception:
                pass
            scenario_paths_map: dict[str, str] = {}
            scenario_paths_by_index: list[str | None] = []
            active_out_path = None
            if scenarios:
                for idx, scen in enumerate(scenarios):
                    if not isinstance(scen, dict):
                        scenario_paths_by_index.append(None)
                        continue
                    raw_name = (scen.get('name') or '').strip()
                    display_name = sanitize_scenario_name_strict(raw_name, f'NewScenario{idx + 1}')
                    stem_raw = display_name
                    stem = secure_filename(stem_raw).strip('_-.') or f'NewScenario{idx + 1}'
                    out_path = os.path.join(out_dir, f'{stem}.xml')
                    if os.path.exists(out_path):
                        suffix = 2
                        base = stem
                        while os.path.exists(out_path):
                            stem = f'{base}-{suffix}'
                            out_path = os.path.join(out_dir, f'{stem}.xml')
                            suffix += 1
                    scen_to_write = _scenario_for_output_path(scen, out_path, display_name)
                    scenarios[idx] = scen_to_write
                    try:
                        tree = build_scenarios_xml({'scenarios': [scen_to_write], 'core': normalized_core})
                        raw = ET.tostring(tree.getroot(), encoding='utf-8')
                        if LET is not None:
                            lroot = LET.fromstring(raw)
                            pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
                            with open(out_path, 'wb') as f:
                                f.write(pretty)
                        else:
                            with open(out_path, 'wb') as f:
                                f.write(raw)
                    except Exception:
                        try:
                            tree = build_scenarios_xml({'scenarios': [scen_to_write], 'core': normalized_core})
                            tree.write(out_path, encoding='utf-8', xml_declaration=True)
                        except Exception:
                            continue
                    try:
                        parsed = ET.parse(out_path)
                        root = parsed.getroot()
                        scenario_count = len(root.findall('Scenario'))
                        if scenario_count != 1:
                            tree = build_scenarios_xml({'scenarios': [scen_to_write], 'core': normalized_core})
                            tree.write(out_path, encoding='utf-8', xml_declaration=True)
                    except Exception:
                        pass
                    scenario_paths_map[display_name] = out_path
                    scenario_paths_by_index.append(out_path)
                    if active_index is not None and active_index == idx:
                        active_out_path = out_path
                if active_out_path is None and scenario_paths_map:
                    active_out_path = next(iter(scenario_paths_map.values()))
            else:
                active_out_path = None
            out_path = active_out_path
            try:
                if log is not None:
                    if scenario_paths_map:
                        log.info('[save_xml_api] wrote %s scenario xml files under %s', len(scenario_paths_map), out_dir)
                    else:
                        log.info('[save_xml_api] persisted empty scenario state with no xml output')
            except Exception:
                pass
            resp_core = normalize_core_config(normalized_core or core_meta or {}, include_password=False) if (normalized_core or core_meta) else default_core_dict()
            snapshot_source = {
                'scenarios': scenarios,
                'core': resp_core,
                'result_path': out_path,
                'active_index': active_index,
                'project_key_hint': project_key_hint or out_path,
            }
            try:
                snapshot_source['saved_xml_paths_by_index'] = scenario_paths_by_index
            except Exception:
                pass
            if scenario_query_hint:
                snapshot_source['scenario_query'] = scenario_query_hint
            try:
                if active_index is not None and 0 <= active_index < len(scenarios):
                    active_name = str((scenarios[active_index] or {}).get('name') or '').strip()
                    if active_name:
                        snapshot_source['result_path_scenario'] = active_name
            except Exception:
                pass
            persist_editor_state_snapshot(snapshot_source, user=user)
            try:
                if log is not None:
                    log.info('[save_xml_api] success user=%s xml=%s scen_count=%s', username or 'anonymous', out_path, len(scenarios))
            except Exception:
                pass
            try:
                names_for_catalog = [name for name in scenario_names if isinstance(name, str) and name.strip()]
                if names_for_catalog:
                    persist_scenario_catalog(names_for_catalog, source_path=scenario_paths_map or out_path)
            except Exception:
                pass
            response_payload = {
                'ok': True,
                'result_path': out_path,
                'core': resp_core,
                # The browser normally resolves Random before save, but this
                # keeps API clients able to adopt the server's ground truth.
                'scenarios': scenarios,
            }
            if scenario_paths_map:
                response_payload['scenario_paths'] = scenario_paths_map
            response_payload['scenario_paths_by_index'] = scenario_paths_by_index
            if active_index is not None and 0 <= active_index < len(scenarios):
                try:
                    active_name = str((scenarios[active_index] or {}).get('name') or '').strip()
                except Exception:
                    active_name = ''
                if active_name:
                    response_payload['active_scenario'] = active_name
            return jsonify(response_payload)
        except Exception as e:
            try:
                if log is not None:
                    log.exception('[save_xml_api] failed: %s', e)
            except Exception:
                pass
            return jsonify({'ok': False, 'error': str(e)}), 500

    @app.route('/render_xml_api', methods=['POST'])
    def render_xml_api():
        """Render scenario XML for preview without persisting to disk."""
        try:
            data = request.get_json(silent=True) or {}
            scenarios = data.get('scenarios')
            core_meta = data.get('core')
            normalized_core = normalize_core_config(core_meta, include_password=True) if isinstance(core_meta, (dict, list)) or core_meta else None
            if not isinstance(scenarios, list):
                return jsonify({'ok': False, 'error': 'Invalid payload (scenarios list required)'}), 400
            tree = build_scenarios_xml({'scenarios': scenarios, 'core': normalized_core})
            try:
                raw = ET.tostring(tree.getroot(), encoding='utf-8')
                if LET is not None:
                    lroot = LET.fromstring(raw)
                    pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
                    return Response(pretty, mimetype='application/xml')
                out = ET.tostring(tree.getroot(), encoding='utf-8', xml_declaration=True)
                return Response(out, mimetype='application/xml')
            except Exception:
                out = ET.tostring(tree.getroot(), encoding='utf-8', xml_declaration=True)
                return Response(out, mimetype='application/xml')
        except Exception as e:
            try:
                if log is not None:
                    log.exception('[render_xml_api] failed: %s', e)
            except Exception:
                pass
            return jsonify({'ok': False, 'error': str(e)}), 500
