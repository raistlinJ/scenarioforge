from __future__ import annotations

import os
import re
import shutil
import json
import uuid
from typing import Any

from flask import Response, jsonify, request, send_file

from webapp.routes._registration import begin_route_registration, mark_routes_registered


_BATCH_LOG_LINE_LIMIT = 500
_ACTIVE_CHILD_TAIL_LIMIT = 18
_RESULT_CHILD_TAIL_LIMIT = 12
_FILE_INPUT_TYPES = {'file', 'path', 'artifact', 'binary'}
_ACTIVE_FLAG_RUN_KINDS = {'flag_generator_test', 'flag_node_generator_test', 'flag_test_batch'}
_FLAG_BATCH_SCOPES = {'unvalidated', 'failed', 'all_enabled'}


def _append_batch_log(meta: dict[str, Any], message: str) -> None:
    if not isinstance(meta, dict):
        return
    lines = meta.get('log_lines')
    if not isinstance(lines, list):
        lines = []
    text = str(message or '').strip()
    if not text:
        return
    lines.append(text)
    if len(lines) > _BATCH_LOG_LINE_LIMIT:
        lines = lines[-_BATCH_LOG_LINE_LIMIT:]
    meta['log_lines'] = lines


def _tail_log_lines(log_path: str, limit: int = 20) -> list[str]:
    path = str(log_path or '').strip()
    if not path:
        return []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
            lines = [str(line).rstrip('\n') for line in handle.readlines()]
    except Exception:
        return []
    trimmed = [line for line in lines if str(line).strip()]
    if limit > 0 and len(trimmed) > limit:
        trimmed = trimmed[-limit:]
    return trimmed


def _kind_label(kind: str) -> str:
    key = str(kind or '').strip().lower()
    if key == 'flag-node-generator':
        return 'Flag-Node-Generators'
    return 'Flag-Generators'


def _kind_run_kind(kind: str) -> str:
    return 'flag_node_generator_test' if str(kind or '').strip().lower() == 'flag-node-generator' else 'flag_generator_test'


def _kind_run_prefix(kind: str) -> str:
    return 'flagnodegen' if str(kind or '').strip().lower() == 'flag-node-generator' else 'flaggen'


def _active_flag_run(backend: Any) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    try:
        items = list(backend.RUNS.items())
    except Exception:
        return None, None
    for run_id, meta in items:
        if not isinstance(meta, dict):
            continue
        if meta.get('kind') in _ACTIVE_FLAG_RUN_KINDS and not meta.get('done'):
            return str(run_id or meta.get('run_id') or '').strip(), meta
    return None, None


def _active_run_payload(run_id: str | None, meta: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(meta, dict):
        return None
    run_id_value = str(meta.get('run_id') or run_id or '').strip()
    kind = str(meta.get('kind') or '').strip()
    payload = {
        'run_id': run_id_value,
        'kind': kind,
        'status': str(meta.get('status') or ''),
        'started_at': meta.get('started_at'),
        'generator_id': str(meta.get('generator_id') or '').strip(),
        'generator_name': str(meta.get('generator_name') or '').strip(),
    }
    if kind == 'flag_test_batch':
        payload.update(
            {
                'batch': True,
                'kind_name': str(meta.get('kind_name') or ''),
                'active_item_id': meta.get('active_item_id'),
                'active_item_name': meta.get('active_item_name'),
                'active_child_run_id': meta.get('active_child_run_id'),
                'progress': _summarize_batch(meta),
            }
        )
    else:
        payload['batch'] = False
    return payload


def _stop_active_flag_run(backend: Any, run_id: str, meta: dict[str, Any]) -> None:
    kind = str(meta.get('kind') or '').strip()
    if kind == 'flag_test_batch':
        _request_batch_stop(backend, meta)
        return
    if kind in ('flag_generator_test', 'flag_node_generator_test'):
        if run_id and not meta.get('run_id'):
            meta['run_id'] = run_id
        _cleanup_child_run(backend, meta)


def _selected_item_label(item: dict[str, Any]) -> str:
    name = str(item.get('name') or '').strip()
    generator_id = str(item.get('id') or '').strip()
    return name or generator_id or 'generator'


def _dependency_search_fields(item: dict[str, Any]) -> list[str]:
    fields: list[str] = []
    missing = item.get('missing_required_files') if isinstance(item.get('missing_required_files'), list) else []
    missing_values = [str(value or '').strip() for value in missing if str(value or '').strip()]
    if missing_values:
        fields.extend(['missing', 'missing-files', 'has:missing', 'needs-files', 'compose-support-missing'])
        fields.extend(missing_values)
    else:
        fields.extend(['complete', 'has:all-files', 'no-missing'])

    warning = str(item.get('compose_dependency_warning') or '').strip()
    if warning:
        fields.append(warning)

    required = item.get('required_files') if isinstance(item.get('required_files'), list) else []
    for entry in required:
        if isinstance(entry, dict):
            for key in ('path', 'rel_path', 'kind', 'service', 'source'):
                value = str(entry.get(key) or '').strip()
                if value:
                    fields.append(value)
            fields.append('optional' if entry.get('required') is False else 'required')
            if entry.get('exists') is False:
                fields.append('missing')
            elif entry.get('exists') is True:
                fields.append('present')
        else:
            value = str(entry or '').strip()
            if value:
                fields.append(value)
    return fields


def _item_matches_query(item: dict[str, Any], query: str) -> bool:
    needle = str(query or '').strip().lower()
    if not needle:
        return True
    fields = [
        str(item.get('id') or ''),
        str(item.get('name') or ''),
        str(item.get('from_source') or ''),
        str(item.get('_source_path') or ''),
    ]
    fields.extend(_dependency_search_fields(item))
    return any(needle in str(value).lower() for value in fields)


def _normalize_scope(scope: Any) -> str:
    value = str(scope or 'unvalidated').strip().lower()
    return value if value in _FLAG_BATCH_SCOPES else 'unvalidated'


def _scope_label(scope: Any) -> str:
    value = _normalize_scope(scope)
    if value == 'failed':
        return 'Previously Failed'
    if value == 'all_enabled':
        return 'All Enabled'
    return 'Unvalidated / Incomplete'


def _item_matches_scope(item: dict[str, Any], scope: str) -> bool:
    value = _normalize_scope(scope)
    if value == 'failed':
        return item.get('validated_ok') is False
    if value == 'unvalidated':
        return item.get('validated_ok') is None or item.get('validated_incomplete') is True
    return True


def _is_file_input_type(value: Any) -> bool:
    return str(value or '').strip().lower() in _FILE_INPUT_TYPES


def _safe_token(value: Any, *, fallback: str = 'item') -> str:
    text = re.sub(r'[^A-Za-z0-9_-]+', '_', str(value or '').strip()).strip('_')
    return text[:32] or fallback


def _choice_value(inp: dict[str, Any]) -> Any:
    for key in ('enum', 'choices', 'options'):
        raw = inp.get(key)
        if not isinstance(raw, list) or not raw:
            continue
        first = raw[0]
        if isinstance(first, dict):
            for value_key in ('value', 'id', 'name', 'label'):
                value = first.get(value_key)
                if value not in (None, ''):
                    return value
            continue
        if first not in (None, ''):
            return first
    return None


def _numeric_bounds(inp: dict[str, Any], *, default_min: int, default_max: int) -> tuple[int, int]:
    minimum = default_min
    maximum = default_max
    for key in ('min', 'minimum'):
        try:
            if inp.get(key) not in (None, ''):
                minimum = int(inp.get(key))
                break
        except Exception:
            pass
    for key in ('max', 'maximum'):
        try:
            if inp.get(key) not in (None, ''):
                maximum = int(inp.get(key))
                break
        except Exception:
            pass
    if maximum < minimum:
        maximum = minimum
    return minimum, maximum


def _generated_batch_input_value(inp: dict[str, Any], item: dict[str, Any]) -> Any:
    name = str(inp.get('name') or '').strip()
    name_l = name.lower()
    input_type = str(inp.get('type') or 'string').strip().lower()
    fmt = str(inp.get('format') or '').strip().lower()
    token = uuid.uuid4().hex
    generator_id = _safe_token(item.get('id') or item.get('name'))

    choice = _choice_value(inp)
    if choice not in (None, ''):
        return choice

    if input_type in {'number', 'integer', 'int'} or 'port' in name_l:
        default_min, default_max = (1024, 65535) if 'port' in name_l else (1, 9999)
        minimum, maximum = _numeric_bounds(inp, default_min=default_min, default_max=default_max)
        span = max(1, maximum - minimum + 1)
        return minimum + (int(token[:8], 16) % span)
    if input_type in {'bool', 'boolean'}:
        return True

    if name_l == 'seed' or name_l.endswith('_seed'):
        return f'batch_{generator_id}_{token[:12]}'
    if name_l == 'node_name' or name_l.endswith('_node_name'):
        return f'node_{generator_id}_{token[:8]}'[:63]
    if name_l in {'flag_prefix', 'prefix'} or 'flag_prefix' in name_l:
        return 'FLAG'
    if 'credential' in name_l and 'user' in name_l and 'password' in name_l:
        return f'user_{token[:6]}:pw_{token[6:16]}'
    if fmt == 'email' or 'email' in name_l:
        return f'user_{token[:10]}@example.test'
    if fmt in {'uri', 'url'} or 'url' in name_l or name_l.endswith('_uri'):
        return f'http://example.test/{token[:12]}'
    if fmt in {'ipv4', 'ip'} or name_l in {'ip', 'host_ip', 'target_ip', 'ip4', 'ipv4'} or name_l.endswith('_ip'):
        return f'10.{int(token[:2], 16) % 250 + 1}.{int(token[2:4], 16)}.{int(token[4:6], 16) or 1}'
    if fmt == 'hostname' or name_l in {'host', 'hostname'} or name_l.endswith('_host'):
        return f'host-{token[:10]}.local'
    if 'username' in name_l or name_l in {'user', 'login'} or name_l.endswith('_user'):
        return f'user_{token[:10]}'
    if 'password' in name_l or 'passwd' in name_l:
        return f'Pw_{token[:14]}'
    if 'secret' in name_l or 'token' in name_l or 'api_key' in name_l or 'apikey' in name_l:
        return f'secret_{token[:16]}'
    if 'path' in name_l or 'file' in name_l or 'filename' in name_l:
        return f'generated_{token[:10]}.txt'
    return f'value_{token[:12]}'


def _build_batch_input_config(item: dict[str, Any]) -> dict[str, Any]:
    cfg: dict[str, Any] = {}
    manual_inputs: list[str] = []
    generated_inputs: list[str] = []
    inputs = item.get('inputs') if isinstance(item.get('inputs'), list) else []
    for inp in inputs:
        if not isinstance(inp, dict):
            continue
        name = str(inp.get('name') or '').strip()
        if not name:
            continue
        has_default = 'default' in inp and inp.get('default') not in (None, '')
        input_type = str(inp.get('type') or '').strip().lower()
        required = bool(inp.get('required') is True)
        if has_default:
            cfg[name] = inp.get('default')
        if _is_file_input_type(input_type):
            if required and not has_default:
                manual_inputs.append(name)
            continue
        if required and not has_default:
            cfg[name] = _generated_batch_input_value(inp, item)
            generated_inputs.append(name)
    if manual_inputs:
        names = ', '.join(manual_inputs)
        return {
            'ok': False,
            'cfg': cfg,
            'manual_inputs': manual_inputs,
            'generated_inputs': generated_inputs,
            'reason': f'requires file/artifact input(s): {names}',
        }
    return {
        'ok': True,
        'cfg': cfg,
        'manual_inputs': [],
        'generated_inputs': generated_inputs,
        'reason': '',
    }


def _collect_catalog_items(backend: Any, kind: str) -> list[dict[str, Any]]:
    try:
        generators, _plugins_by_id, _errors = backend._flag_generators_from_manifests(kind=kind)
    except Exception:
        return []
    items = [dict(generator) for generator in (generators or []) if isinstance(generator, dict) and backend._is_installed_generator_view(generator)]
    try:
        items = backend._annotate_disabled_state(items, kind=kind)
    except Exception:
        pass
    for item in items:
        item['disabled'] = bool(item.get('_disabled'))
        if 'validated_ok' not in item:
            item['validated_ok'] = item.get('_validated_ok')
        if 'validated_incomplete' not in item:
            item['validated_incomplete'] = bool(item.get('_validated_incomplete') is True)
        if 'validated_at' not in item:
            item['validated_at'] = item.get('_validated_at')
    return items


def _selection_payload(selected_items: list[dict[str, Any]]) -> dict[str, int]:
    eligible_count = 0
    manual_count = 0
    generated_count = 0
    for item in selected_items:
        eligibility = _build_batch_input_config(item)
        if eligibility.get('ok'):
            eligible_count += 1
        else:
            manual_count += 1
        generated_count += len(eligibility.get('generated_inputs') if isinstance(eligibility.get('generated_inputs'), list) else [])
    return {
        'selected_count': len(selected_items),
        'eligible_count': eligible_count,
        'manual_input_count': manual_count,
        'generated_input_count': generated_count,
    }


def _count_child_outputs(run_dir: str) -> int:
    path = str(run_dir or '').strip()
    if not path or not os.path.isdir(path):
        return 0
    count = 0
    for root, _dirs, filenames in os.walk(path):
        rel_root = os.path.relpath(root, path).replace('\\', '/')
        for filename in filenames:
            rel = filename if rel_root == '.' else f'{rel_root}/{filename}'
            if rel == 'run.log':
                continue
            if rel_root == 'inputs' or rel_root.startswith('inputs/'):
                continue
            count += 1
    return count


def _read_outputs_manifest(run_dir: str) -> tuple[dict[str, Any] | None, str]:
    manifest_path = os.path.join(str(run_dir or '').strip(), 'outputs.json')
    if not manifest_path or not os.path.isfile(manifest_path):
        return None, manifest_path
    try:
        with open(manifest_path, 'r', encoding='utf-8') as handle:
            payload = json.load(handle)
    except Exception:
        return None, manifest_path
    return payload if isinstance(payload, dict) else None, manifest_path


def _declared_output_names(item: dict[str, Any]) -> list[str]:
    outputs = item.get('outputs') if isinstance(item.get('outputs'), list) else []
    names: list[str] = []
    for entry in outputs:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get('name') or entry.get('artifact') or '').strip()
        if name and name not in names:
            names.append(name)
    return names


def _split_inject_spec(raw: Any) -> tuple[str, str]:
    text = str(raw or '').strip()
    if not text:
        return '', ''
    for sep in ('->', '=>'):
        if sep in text:
            left, right = text.split(sep, 1)
            return left.strip(), right.strip()
    return text, ''


def _candidate_paths_for_generated_value(run_dir: str, raw_value: Any) -> list[str]:
    text = str(raw_value or '').strip().replace('\\', '/')
    if not text:
        return []
    values = [text]
    if text.startswith('artifacts/'):
        values.append(text[len('artifacts/'):])
    elif not text.startswith('/'):
        values.append(f'artifacts/{text}')

    out: list[str] = []
    for value in values:
        if not value:
            continue
        candidate = value if os.path.isabs(value) else os.path.abspath(os.path.join(run_dir, value.lstrip('/')))
        if candidate not in out:
            out.append(candidate)
    return out


def _first_existing_path(paths: list[str]) -> str:
    for path in paths:
        try:
            if path and os.path.exists(path):
                return path
        except Exception:
            continue
    return ''


def _generated_compose_candidates(run_dir: str, outputs: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for key in ('File(path)', 'Compose(path)', 'DockerCompose(path)'):
        value = outputs.get(key)
        if isinstance(value, str) and value.strip():
            candidates.extend(_candidate_paths_for_generated_value(run_dir, value))
    for name in ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'):
        candidates.append(os.path.abspath(os.path.join(run_dir, name)))
        candidates.append(os.path.abspath(os.path.join(run_dir, 'outputs', name)))
        candidates.append(os.path.abspath(os.path.join(run_dir, 'artifacts', name)))
    dedup: list[str] = []
    for path in candidates:
        if path and path not in dedup:
            dedup.append(path)
    return dedup


def _compose_has_services(path: str) -> bool | None:
    try:
        import yaml  # type: ignore
    except Exception:
        return None
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
            obj = yaml.safe_load(handle) or {}
    except Exception:
        return False
    services = obj.get('services') if isinstance(obj, dict) else None
    return bool(isinstance(services, dict) and services)


def _generator_contract_assurance(kind: str, item: dict[str, Any], run_dir: str) -> dict[str, Any]:
    summary: dict[str, Any] = {
        'ok': False,
        'run_dir': str(run_dir or ''),
        'outputs_manifest': '',
        'declared_outputs': [],
        'missing_outputs': [],
        'injects_checked': [],
        'injects_missing': [],
        'compose_path': '',
        'compose_checked': False,
        'compose_has_services': None,
        'issues': [],
    }
    run_dir = str(run_dir or '').strip()
    if not run_dir or not os.path.isdir(run_dir):
        summary['issues'].append('run_dir missing')
        return summary

    manifest, manifest_path = _read_outputs_manifest(run_dir)
    summary['outputs_manifest'] = manifest_path
    if not isinstance(manifest, dict):
        summary['issues'].append('outputs.json missing or invalid')
        return summary

    outputs = manifest.get('outputs') if isinstance(manifest.get('outputs'), dict) else {}
    declared_outputs = _declared_output_names(item)
    summary['declared_outputs'] = declared_outputs
    missing_outputs = [name for name in declared_outputs if name not in outputs]
    summary['missing_outputs'] = missing_outputs
    if missing_outputs:
        summary['issues'].append('missing declared outputs: ' + ', '.join(missing_outputs[:8]))

    inject_files = item.get('inject_files') if isinstance(item.get('inject_files'), list) else []
    for raw in inject_files:
        src_raw, _dest = _split_inject_spec(raw)
        if not src_raw:
            continue
        output_value = outputs.get(src_raw) if src_raw in outputs else src_raw
        candidates = _candidate_paths_for_generated_value(run_dir, output_value)
        existing = _first_existing_path(candidates)
        summary['injects_checked'].append({'spec': str(raw), 'source': str(output_value), 'path': existing or (candidates[0] if candidates else '')})
        if not existing:
            summary['injects_missing'].append(str(raw))
    if summary['injects_missing']:
        missing = summary['injects_missing']
        summary['issues'].append('missing inject source(s): ' + ', '.join(str(x) for x in missing[:8]))

    if str(kind or '').strip().lower() == 'flag-node-generator':
        compose_path = _first_existing_path(_generated_compose_candidates(run_dir, outputs))
        summary['compose_path'] = compose_path
        summary['compose_checked'] = True
        if not compose_path:
            summary['issues'].append('generated docker-compose.yml missing')
        else:
            has_services = _compose_has_services(compose_path)
            summary['compose_has_services'] = has_services
            if has_services is False:
                summary['issues'].append('generated compose has no services or is invalid YAML')

    summary['ok'] = not bool(summary['issues'])
    return summary


def _classify_validation_summary(summary: dict[str, Any] | None) -> list[str]:
    if not isinstance(summary, dict):
        return []
    if summary.get('validation_unavailable') is True:
        return ['validation unavailable']
    issues: list[str] = []
    for key, label in (
        ('missing_nodes', 'missing nodes'),
        ('docker_not_running', 'docker not running'),
        ('port_unreachable', 'port not open/accessible'),
        ('injects_missing', 'missing inject files'),
        ('injects_unreadable', 'inject files empty/unreadable'),
        ('generator_outputs_missing', 'missing generator outputs'),
        ('generator_injects_missing', 'missing generator inject sources'),
    ):
        values = summary.get(key)
        count = len(values) if isinstance(values, list) else 0
        if count > 0:
            issues.append(f'{label}: {count}')
    if summary.get('ok') is False and not issues:
        issues.append('scenario validation failed')
    return issues


def _validation_categories(summary: dict[str, Any] | None) -> list[str]:
    if not isinstance(summary, dict):
        return []
    if summary.get('validation_unavailable') is True:
        return ['validation_unavailable']
    categories: list[str] = []
    for key, category in (
        ('missing_nodes', 'core_runtime'),
        ('docker_not_running', 'docker_runtime'),
        ('port_unreachable', 'port_unreachable'),
        ('injects_missing', 'artifact_injection'),
        ('injects_unreadable', 'artifact_injection_content'),
        ('generator_outputs_missing', 'generator_outputs'),
        ('generator_injects_missing', 'generator_injects'),
    ):
        values = summary.get(key)
        if isinstance(values, list) and values:
            categories.append(category)
    if not categories and summary.get('ok') is True:
        categories.append('scenario_validation_passed')
    return categories


def _ensure_child_validation_summary(backend: Any, child_meta: dict[str, Any]) -> dict[str, Any] | None:
    existing = child_meta.get('execute_validation_summary') if isinstance(child_meta.get('execute_validation_summary'), dict) else None
    if existing is None and isinstance(child_meta.get('validation_summary'), dict):
        existing = child_meta.get('validation_summary')
    if isinstance(existing, dict):
        return existing
    if not child_meta.get('done'):
        return None

    log_path = str(child_meta.get('log_path') or '').strip()
    log_text = ''
    if log_path:
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as handle:
                log_text = handle.read()
        except Exception:
            log_text = ''

    if log_text:
        try:
            parsed = backend._extract_validation_summary_from_text(log_text)
            if isinstance(parsed, dict):
                child_meta['execute_validation_summary'] = parsed
                child_meta['validation_summary'] = parsed
                return parsed
        except Exception:
            pass

    xml_path = str(child_meta.get('xml_path') or '').strip()
    if not xml_path:
        return None
    core_cfg = child_meta.get('core_cfg') if isinstance(child_meta.get('core_cfg'), dict) else None
    if not isinstance(core_cfg, dict):
        return None

    try:
        backend._sync_remote_artifacts(child_meta)
    except Exception:
        pass

    report_md = None
    summary_json = None
    try:
        report_md = backend._extract_report_path_from_text(log_text) if log_text else None
    except Exception:
        report_md = None
    if not report_md:
        try:
            report_md = backend._find_latest_report_path()
        except Exception:
            report_md = None
    try:
        summary_json = backend._extract_summary_path_from_text(log_text) if log_text else None
    except Exception:
        summary_json = None
    if not summary_json:
        try:
            summary_json = backend._derive_summary_from_report(report_md)
        except Exception:
            summary_json = None

    post_saved = str(child_meta.get('post_xml_path') or child_meta.get('session_xml_path') or '').strip() or None
    if not post_saved and log_text:
        try:
            session_id = backend._extract_session_id_from_text(log_text)
        except Exception:
            session_id = None
        if session_id:
            try:
                post_dir = backend.os.path.join(backend.os.path.dirname(xml_path), 'core-post')
                post_saved = backend._grpc_save_current_session_xml_with_config(core_cfg, post_dir, session_id=session_id)
                if post_saved:
                    child_meta['post_xml_path'] = post_saved
                    child_meta['session_xml_path'] = post_saved
            except Exception:
                post_saved = None

    if not post_saved:
        return None
    try:
        validation = backend._validate_session_nodes_and_injects(
            scenario_xml_path=xml_path,
            session_xml_path=post_saved,
            core_cfg=core_cfg,
            preview_plan_path=str(child_meta.get('preview_plan_path') or '').strip() or None,
            scenario_label=str(child_meta.get('scenario_name') or child_meta.get('test_scenario_tag') or '').strip() or None,
            flow_enabled=backend._coerce_bool(child_meta.get('flow_enabled')),
        )
    except Exception:
        return None
    if isinstance(validation, dict):
        child_meta['validation_summary'] = validation
        child_meta['execute_validation_summary'] = validation
        try:
            backend._persist_execute_validation_artifacts(report_md, summary_json, validation)
        except Exception:
            pass
        try:
            if log_path:
                backend._append_async_run_log_line(child_meta, '[validate] VALIDATION_SUMMARY_JSON: ' + backend.json.dumps(validation))
        except Exception:
            pass
        return validation
    return None


def _categorize_result(*, async_error: str | None, return_code: int | None, outputs_count: int | None, skipped: bool = False, manual_input: bool = False) -> list[str]:
    categories: list[str] = []
    if skipped:
        categories.append('batch_stopped')
    if manual_input:
        categories.append('requires_manual_input')
    if async_error:
        lower = async_error.lower()
        if 'active session' in lower:
            categories.append('core_session_busy')
        elif 'unable to verify core sessions' in lower or 'ssh' in lower:
            categories.append('core_connectivity')
        else:
            categories.append('execution_error')
    if return_code not in (None, 0):
        categories.append('execute_returncode')
    if outputs_count == 0 and not async_error and return_code in (None, 0) and not manual_input and not skipped:
        categories.append('outputs_missing')
    if not categories and outputs_count and outputs_count > 0:
        categories.append('outputs_present')
    if not categories:
        categories.append('uncategorized')
    return categories


def _snapshot_child_log(
    backend: Any,
    batch_meta: dict[str, Any],
    *,
    item_id: str,
    item_name: str,
    child_meta: dict[str, Any] | None,
) -> dict[str, Any]:
    meta = child_meta if isinstance(child_meta, dict) else {}
    log_path = str(meta.get('log_path') or '').strip()
    if not log_path or not os.path.isfile(log_path):
        return {}
    batch_run_id = str(batch_meta.get('run_id') or '').strip() or 'batch'
    safe_name = re.sub(r'[^a-z0-9_.-]+', '-', str(item_name or '').strip().lower()).strip('-') or 'item'
    safe_id = re.sub(r'[^a-z0-9_.-]+', '-', str(item_id or '').strip().lower()).strip('-') or 'item'
    batch_log_dir = os.path.join(backend._outputs_dir(), 'flag-batch-logs', batch_run_id)
    os.makedirs(batch_log_dir, exist_ok=True)
    file_name = f'{safe_id}-{safe_name}.log'
    dest_path = os.path.join(batch_log_dir, file_name)
    try:
        shutil.copy2(log_path, dest_path)
    except Exception:
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as src, open(dest_path, 'w', encoding='utf-8') as dst:
                dst.write(src.read())
        except Exception:
            return {}
    return {
        'log_path': dest_path,
        'log_filename': file_name,
        'log_download_url': f'/flag_catalog_items/batch/item_log?run_id={batch_run_id}&item_id={item_id}',
    }


def _append_child_result_tail(batch_meta: dict[str, Any], item_id: str, child_meta: dict[str, Any] | None) -> None:
    meta = child_meta if isinstance(child_meta, dict) else {}
    log_path = str(meta.get('log_path') or '').strip()
    if not log_path:
        return
    tail = _tail_log_lines(log_path, limit=_RESULT_CHILD_TAIL_LIMIT)
    for line in tail:
        _append_batch_log(batch_meta, f'[item {item_id}] {line}')


def _active_child_snapshot(backend: Any, meta: dict[str, Any]) -> dict[str, Any] | None:
    child_run_id = str(meta.get('active_child_run_id') or '').strip()
    if not child_run_id:
        return None
    child_meta = backend.RUNS.get(child_run_id)
    if not isinstance(child_meta, dict):
        return {
            'run_id': child_run_id,
            'status': 'missing',
            'done': True,
            'cleanup_started': False,
            'cleanup_done': False,
            'returncode': None,
            'log_tail': [],
        }
    return {
        'run_id': child_run_id,
        'status': str(child_meta.get('status') or ''),
        'done': bool(child_meta.get('done')),
        'cleanup_started': bool(child_meta.get('cleanup_started')),
        'cleanup_done': bool(child_meta.get('cleanup_done')),
        'returncode': child_meta.get('returncode'),
        'log_tail': _tail_log_lines(str(child_meta.get('log_path') or ''), limit=_ACTIVE_CHILD_TAIL_LIMIT),
    }


def _status_log_lines(meta: dict[str, Any], active_child: dict[str, Any] | None) -> list[str]:
    lines = list(meta.get('log_lines') if isinstance(meta.get('log_lines'), list) else [])
    if not isinstance(active_child, dict):
        return lines
    child_status = str(active_child.get('status') or '').strip() or 'unknown'
    child_run_id = str(active_child.get('run_id') or '').strip() or 'unknown'
    child_tail = active_child.get('log_tail') if isinstance(active_child.get('log_tail'), list) else []
    lines.append(f'[child] run {child_run_id} status={child_status}')
    for line in child_tail:
        lines.append(f'[child] {line}')
    if len(lines) > _BATCH_LOG_LINE_LIMIT:
        lines = lines[-_BATCH_LOG_LINE_LIMIT:]
    return lines


def _summarize_batch(meta: dict[str, Any]) -> dict[str, int]:
    items = meta.get('selected_items') if isinstance(meta.get('selected_items'), list) else []
    total = len(items)
    results = meta.get('results') if isinstance(meta.get('results'), list) else []
    counts = {
        'total': total,
        'completed': len(results),
        'passed': 0,
        'failed': 0,
        'incomplete': 0,
        'skipped': 0,
    }
    for result in results:
        if not isinstance(result, dict):
            continue
        status = str(result.get('status') or '').strip().lower()
        if status in counts:
            counts[status] += 1
    counts['pending'] = max(0, total - counts['completed'])
    return counts


def _collect_category_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in results:
        if not isinstance(result, dict):
            continue
        categories = result.get('categories') if isinstance(result.get('categories'), list) else []
        for raw in categories:
            key = str(raw or '').strip()
            if not key:
                continue
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _classify_single_run(backend: Any, child_meta: dict[str, Any] | None) -> dict[str, Any]:
    meta = child_meta if isinstance(child_meta, dict) else {}
    run_id = str(meta.get('run_id') or '')
    log_path = str(meta.get('log_path') or '').strip()
    log_text = ''
    if log_path:
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                log_text = file_handle.read()
        except Exception:
            log_text = ''
    async_error = None
    if log_text:
        try:
            async_error = backend._extract_async_error_from_text(log_text)
        except Exception:
            async_error = None
    if not async_error:
        async_error = str(meta.get('error') or '').strip() or None

    return_code = meta.get('returncode')
    try:
        numeric_return_code = int(return_code)
    except Exception:
        numeric_return_code = None

    outputs_count = _count_child_outputs(str(meta.get('run_dir') or ''))
    kind = 'flag-node-generator' if str(meta.get('kind') or '') == 'flag_node_generator_test' else 'flag-generator'
    generator_item = meta.get('generator_item') if isinstance(meta.get('generator_item'), dict) else {}
    assurance = _generator_contract_assurance(kind, generator_item, str(meta.get('run_dir') or ''))
    try:
        meta['assurance_summary'] = assurance
    except Exception:
        pass

    if async_error:
        return {
            'status': 'failed',
            'reason': async_error,
            'categories': _categorize_result(async_error=async_error, return_code=numeric_return_code, outputs_count=outputs_count),
            'run_id': run_id,
            'returncode': numeric_return_code,
            'outputs_count': outputs_count,
            'assurance_summary': assurance,
        }

    if numeric_return_code not in (None, 0):
        reason = f'execute returncode={numeric_return_code}'
        if outputs_count == 0:
            reason = f'{reason}; no outputs detected'
        return {
            'status': 'failed',
            'reason': reason,
            'categories': _categorize_result(async_error=None, return_code=numeric_return_code, outputs_count=outputs_count),
            'run_id': run_id,
            'returncode': numeric_return_code,
            'outputs_count': outputs_count,
            'assurance_summary': assurance,
        }

    if not assurance.get('ok'):
        issues = assurance.get('issues') if isinstance(assurance.get('issues'), list) else []
        reason = '; '.join(str(issue) for issue in issues if str(issue).strip()) or 'generator contract assurance failed'
        categories = ['generator_contract']
        if assurance.get('missing_outputs'):
            categories.append('generator_outputs')
        if assurance.get('injects_missing'):
            categories.append('generator_injects')
        if assurance.get('compose_checked') and not assurance.get('compose_path'):
            categories.append('compose_missing')
        if assurance.get('compose_has_services') is False:
            categories.append('compose_invalid')
        return {
            'status': 'failed',
            'reason': reason,
            'categories': categories,
            'run_id': run_id,
            'returncode': numeric_return_code,
            'outputs_count': outputs_count,
            'assurance_summary': assurance,
        }

    validation_summary = _ensure_child_validation_summary(backend, meta)
    try:
        meta['execute_validation_summary'] = validation_summary
    except Exception:
        pass
    if not isinstance(validation_summary, dict):
        return {
            'status': 'incomplete',
            'reason': 'run finished without scenario validation summary',
            'categories': ['scenario_validation_missing'],
            'run_id': run_id,
            'returncode': numeric_return_code,
            'outputs_count': outputs_count,
            'assurance_summary': assurance,
            'validation_summary': None,
        }

    validation_issues = _classify_validation_summary(validation_summary)
    if validation_issues:
        return {
            'status': 'failed',
            'reason': '; '.join(validation_issues),
            'categories': _validation_categories(validation_summary) or ['scenario_validation_failed'],
            'run_id': run_id,
            'returncode': numeric_return_code,
            'outputs_count': outputs_count,
            'assurance_summary': assurance,
            'validation_summary': validation_summary,
        }

    return {
        'status': 'passed',
        'reason': 'contract and scenario validation passed',
        'categories': ['generator_contract_passed'] + _validation_categories(validation_summary),
        'run_id': run_id,
        'returncode': numeric_return_code,
        'outputs_count': outputs_count,
        'assurance_summary': assurance,
        'validation_summary': validation_summary,
    }


def _cleanup_child_run(backend: Any, child_meta: dict[str, Any] | None) -> None:
    meta = child_meta if isinstance(child_meta, dict) else None
    if not isinstance(meta, dict):
        return
    if meta.get('cleanup_started'):
        return
    meta['cleanup_started'] = True
    meta['cleanup_requested'] = True

    try:
        backend._cleanup_remote_test_runtime(meta)
    except Exception:
        pass

    try:
        if meta.get('remote'):
            try:
                channel = meta.get('ssh_channel')
                if channel is not None and hasattr(channel, 'close'):
                    channel.close()
            except Exception:
                pass
            try:
                client_obj = meta.get('ssh_client')
                if client_obj is not None:
                    client_obj.close()
            except Exception:
                pass
            try:
                core_cfg = meta.get('core_cfg') if isinstance(meta.get('core_cfg'), dict) else None
                remote_run_dir = str(meta.get('remote_run_dir') or '').strip()
                if core_cfg and remote_run_dir:
                    client = backend._open_ssh_client(core_cfg)
                    try:
                        backend._remote_remove_path(client, remote_run_dir)
                    finally:
                        client.close()
            except Exception:
                pass
    except Exception:
        pass

    try:
        proc = meta.get('proc')
        if proc and hasattr(proc, 'poll') and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    except Exception:
        pass

    try:
        handle = meta.get('ssh_log_handle')
        if handle:
            handle.flush()
            handle.close()
    except Exception:
        pass

    run_dir = str(meta.get('run_dir') or '').strip()
    abs_run_dir = os.path.abspath(run_dir) if run_dir else ''
    try:
        outputs_root = os.path.abspath(backend._outputs_dir())
    except Exception:
        outputs_root = ''
    if abs_run_dir and outputs_root and (abs_run_dir == outputs_root or abs_run_dir.startswith(outputs_root + os.sep)):
        try:
            if os.path.isdir(abs_run_dir):
                shutil.rmtree(abs_run_dir, ignore_errors=True)
        except Exception:
            pass

    meta['done'] = True
    meta['cleanup_done'] = True
    run_id = str(meta.get('run_id') or '').strip()
    if run_id:
        try:
            backend.RUNS.pop(run_id, None)
        except Exception:
            pass


def _start_child_run(backend: Any, *, kind: str, item: dict[str, Any], core_cfg: dict[str, Any]) -> tuple[dict[str, Any], int]:
    generator_id = str(item.get('id') or '').strip()
    if not generator_id:
        return {'ok': False, 'error': 'Invalid generator id'}, 400

    try:
        backend._ensure_core_vm_idle_for_test(core_cfg)
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}, 409

    cfg_payload = _build_batch_input_config(item)
    if not cfg_payload.get('ok'):
        return {
            'ok': False,
            'error': str(cfg_payload.get('reason') or 'requires manual input'),
            'manual_input': True,
        }, 400
    generated_inputs = cfg_payload.get('generated_inputs') if isinstance(cfg_payload.get('generated_inputs'), list) else []

    run_id = backend._local_timestamp_safe() + '-' + backend.uuid.uuid4().hex[:10]
    run_root = backend._flag_node_generators_runs_dir() if str(kind or '').strip().lower() == 'flag-node-generator' else backend._flag_generators_runs_dir()
    run_dir = os.path.join(run_root, run_id)
    os.makedirs(run_dir, exist_ok=True)
    log_path = os.path.join(run_dir, 'run.log')

    prefix = _kind_run_prefix(kind)
    try:
        with open(log_path, 'a', encoding='utf-8') as log_f:
            log_f.write(f'[{prefix}] starting {generator_id} (remote CORE VM)\n')
            if generated_inputs:
                log_f.write(f'[{prefix}] autogenerated batch input(s): {", ".join(str(x) for x in generated_inputs)}\n')
            try:
                backend._write_sse_marker(log_f, 'phase', {
                    'phase': 'starting',
                    'generator_id': generator_id,
                    'run_id': run_id,
                    'remote': True,
                })
            except Exception:
                pass
    except Exception:
        pass

    log_handle = None
    try:
        log_handle = open(log_path, 'a', encoding='utf-8')
        remote_meta = backend._start_remote_flag_test_process(
            run_id=run_id,
            run_dir=run_dir,
            log_handle=log_handle,
            kind=kind,
            generator_id=generator_id,
            cfg=dict(cfg_payload.get('cfg') or {}),
            core_cfg=core_cfg,
        )
    except Exception as exc:
        try:
            with open(log_path, 'a', encoding='utf-8') as log_f:
                log_f.write(f'[{prefix}] failed to start remote run: {exc}\n')
        except Exception:
            pass
        try:
            if log_handle:
                log_handle.close()
        except Exception:
            pass
        return {'ok': False, 'error': f'Failed launching remote generator: {exc}'}, 500

    child_meta = {
        'run_id': run_id,
        'proc': None,
        'log_path': log_path,
        'done': False,
        'returncode': None,
        'status': 'generator_running',
        'run_dir': run_dir,
        'kind': _kind_run_kind(kind),
        'generator_id': generator_id,
        'generator_name': _selected_item_label(item),
        'execute_like_real': True,
        'remote': True,
        'core_cfg': core_cfg,
        'generator_item': dict(item),
        'generated_inputs': list(generated_inputs),
        'remote_run_dir': remote_meta.get('remote_run_dir'),
        'remote_repo_dir': remote_meta.get('remote_repo_dir'),
        'ssh_client': remote_meta.get('ssh_client'),
        'ssh_channel': remote_meta.get('ssh_channel'),
        'ssh_log_thread': remote_meta.get('ssh_log_thread'),
        'ssh_log_handle': log_handle,
        'cleanup_requested': False,
        'cleanup_started': False,
        'cleanup_done': False,
    }
    backend.RUNS[run_id] = child_meta

    ephemeral_runner = backend._flagnodegen_run_ephemeral_execute if str(kind or '').strip().lower() == 'flag-node-generator' else backend._flaggen_run_ephemeral_execute

    def _finalize_remote_child(run_id_local: str) -> None:
        meta = backend.RUNS.get(run_id_local)
        if not isinstance(meta, dict):
            return
        rc = -1
        try:
            channel = meta.get('ssh_channel')
            if channel is not None:
                while True:
                    try:
                        if channel.exit_status_ready():
                            rc = int(channel.recv_exit_status())
                            break
                    except Exception:
                        break
                    backend.time.sleep(0.5)
        finally:
            try:
                with open(str(meta.get('log_path') or ''), 'a', encoding='utf-8') as log_f:
                    try:
                        backend._write_sse_marker(log_f, 'phase', {'phase': 'generator_done', 'returncode': rc})
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                if not meta.get('cleanup_requested'):
                    backend._sync_remote_flag_test_outputs(meta)
            except Exception:
                pass
            try:
                backend._purge_remote_flag_test_dir(meta)
            except Exception:
                pass
            try:
                thread_obj = meta.get('ssh_log_thread')
                if thread_obj and hasattr(thread_obj, 'join'):
                    thread_obj.join(timeout=3)
            except Exception:
                pass
            try:
                client_obj = meta.get('ssh_client')
                if client_obj:
                    client_obj.close()
            except Exception:
                pass
            try:
                handle = meta.get('ssh_log_handle')
                if handle:
                    handle.flush()
                    handle.close()
            except Exception:
                pass
            if rc == 0 and not meta.get('cleanup_requested'):
                try:
                    ephemeral_runner(run_id_local)
                    return
                except Exception as exc:
                    meta['done'] = True
                    meta['returncode'] = 1
                    meta['status'] = 'failed'
                    meta['error'] = f'ephemeral execute failed: {exc}'
            meta['done'] = True
            meta['returncode'] = rc
            meta['status'] = 'completed' if rc == 0 else 'failed'
            try:
                with open(str(meta.get('log_path') or ''), 'a', encoding='utf-8') as log_f:
                    try:
                        backend._write_sse_marker(log_f, 'phase', {'phase': 'done', 'returncode': rc})
                    except Exception:
                        pass
            except Exception:
                pass

    backend.threading.Thread(
        target=_finalize_remote_child,
        args=(run_id,),
        name=f'flag-batch-child-{run_id[:8]}',
        daemon=True,
    ).start()

    return {'ok': True, 'run_id': run_id}, 200


def _request_batch_stop(backend: Any, meta: dict[str, Any]) -> None:
    meta['stop_requested'] = True
    if not meta.get('done'):
        meta['status'] = 'stopping'
    _append_batch_log(meta, '[batch] stop requested')
    active_child_run_id = str(meta.get('active_child_run_id') or '').strip()
    if not active_child_run_id:
        return
    child_meta = backend.RUNS.get(active_child_run_id)
    if not isinstance(child_meta, dict) or child_meta.get('cleanup_started'):
        if not isinstance(child_meta, dict):
            meta['active_child_stop_requested'] = True
            _append_batch_log(meta, f'[batch] active test {active_child_run_id} metadata already missing')
        elif child_meta.get('cleanup_started'):
            meta['active_child_stop_requested'] = True
            _append_batch_log(meta, f'[batch] active test {active_child_run_id} cleanup already in progress')
        return
    try:
        _cleanup_child_run(backend, child_meta)
        meta['active_child_stop_requested'] = True
        _append_batch_log(meta, f'[batch] stopping active test {active_child_run_id}')
    except Exception as exc:
        _append_batch_log(meta, f'[batch] failed to stop active test {active_child_run_id}: {exc}')


def _run_batch(backend: Any, batch_meta: dict[str, Any], core_cfg: dict[str, Any]) -> None:
    items = batch_meta.get('selected_items') if isinstance(batch_meta.get('selected_items'), list) else []
    total = len(items)
    kind = str(batch_meta.get('kind_name') or 'flag-generator').strip().lower()
    batch_meta['status'] = 'running'
    _append_batch_log(batch_meta, f'[batch] queued {total} item(s)')

    for index, item in enumerate(items):
        if batch_meta.get('stop_requested'):
            break
        item_id = str(item.get('id') or '').strip()
        item_name = _selected_item_label(item)
        batch_meta['active_item_id'] = item_id
        batch_meta['active_item_name'] = item_name
        batch_meta['active_index'] = index + 1
        batch_meta['active_child_run_id'] = None
        batch_meta['active_child_stop_requested'] = False
        _append_batch_log(batch_meta, f'[batch] starting {index + 1}/{total}: {item_id} {item_name}')

        eligibility = _build_batch_input_config(item)
        if not eligibility.get('ok'):
            reason = str(eligibility.get('reason') or 'requires manual input')
            batch_meta.setdefault('results', []).append(
                {
                    'item_id': item_id,
                    'item_name': item_name,
                    'status': 'skipped',
                    'reason': reason,
                    'categories': _categorize_result(async_error=None, return_code=None, outputs_count=None, manual_input=True),
                    'outputs_count': 0,
                    'finished_at': backend._local_timestamp_display(),
                }
            )
            _append_batch_log(batch_meta, f'[batch] skipped {item_id}: {reason}')
            batch_meta['active_item_id'] = None
            batch_meta['active_item_name'] = None
            continue

        start_payload, status_code = _start_child_run(backend, kind=kind, item=item, core_cfg=core_cfg)
        if status_code != 200 or start_payload.get('ok') is not True:
            reason = str(start_payload.get('error') or f'failed to start (http {status_code})')
            batch_meta.setdefault('results', []).append(
                {
                    'item_id': item_id,
                    'item_name': item_name,
                    'status': 'failed',
                    'reason': reason,
                    'categories': _categorize_result(async_error=reason, return_code=None, outputs_count=None),
                    'outputs_count': 0,
                    'finished_at': backend._local_timestamp_display(),
                }
            )
            _append_batch_log(batch_meta, f'[batch] start failed for {item_id}: {reason}')
            batch_meta['active_item_id'] = None
            batch_meta['active_item_name'] = None
            continue

        child_run_id = str(start_payload.get('run_id') or '').strip()
        batch_meta['active_child_run_id'] = child_run_id
        _append_batch_log(batch_meta, f'[batch] child run {child_run_id} created for {item_id} {item_name}')
        classification: dict[str, Any] | None = None

        while True:
            child_meta = backend.RUNS.get(child_run_id)

            if not isinstance(child_meta, dict):
                reason = 'batch stop requested; child metadata missing' if batch_meta.get('stop_requested') else 'test metadata unavailable'
                categories = _categorize_result(async_error=None, return_code=None, outputs_count=None, skipped=bool(batch_meta.get('stop_requested')))
                if 'metadata_missing' not in categories:
                    categories.append('metadata_missing')
                classification = {
                    'status': 'incomplete',
                    'reason': reason,
                    'categories': categories,
                    'run_id': child_run_id,
                    'returncode': None,
                    'outputs_count': 0,
                }
                if batch_meta.get('stop_requested'):
                    batch_meta['active_child_stop_requested'] = True
                _append_batch_log(batch_meta, f'[batch] child run {child_run_id} metadata missing for {item_id} {item_name}')
                break

            if batch_meta.get('stop_requested') and isinstance(child_meta, dict) and not child_meta.get('cleanup_started'):
                classification = {
                    'status': 'incomplete',
                    'reason': 'batch stop requested',
                    'categories': _categorize_result(async_error=None, return_code=child_meta.get('returncode'), outputs_count=None, skipped=True),
                    'run_id': child_run_id,
                    'returncode': child_meta.get('returncode'),
                    'outputs_count': 0,
                }
                classification.update(_snapshot_child_log(backend, batch_meta, item_id=item_id, item_name=item_name, child_meta=child_meta))
                try:
                    _cleanup_child_run(backend, child_meta)
                except Exception as exc:
                    classification['reason'] = f'batch stop requested; cleanup error: {exc}'
                    categories = classification.get('categories') if isinstance(classification.get('categories'), list) else []
                    if 'cleanup_error' not in categories:
                        categories.append('cleanup_error')
                    classification['categories'] = categories
                _append_batch_log(batch_meta, f'[batch] stopping {item_id} {item_name}')

            if batch_meta.get('stop_requested') and isinstance(child_meta, dict) and child_meta.get('cleanup_started') and classification is None:
                classification = {
                    'status': 'incomplete',
                    'reason': 'batch stop requested',
                    'categories': _categorize_result(async_error=None, return_code=child_meta.get('returncode'), outputs_count=None, skipped=True),
                    'run_id': child_run_id,
                    'returncode': child_meta.get('returncode'),
                    'outputs_count': 0,
                }
                classification.update(_snapshot_child_log(backend, batch_meta, item_id=item_id, item_name=item_name, child_meta=child_meta))
                batch_meta['active_child_stop_requested'] = True
                _append_batch_log(batch_meta, f'[batch] waiting for cleanup of {item_id} {item_name}')

            if isinstance(child_meta, dict) and child_meta.get('done') and not child_meta.get('cleanup_started'):
                classification = _classify_single_run(backend, child_meta)
                classification.update(_snapshot_child_log(backend, batch_meta, item_id=item_id, item_name=item_name, child_meta=child_meta))
                _append_child_result_tail(batch_meta, item_id, child_meta)
                try:
                    _cleanup_child_run(backend, child_meta)
                except Exception as exc:
                    classification['status'] = 'incomplete'
                    classification['reason'] = f"{classification.get('reason') or 'cleanup error'}; cleanup error: {exc}"
                _append_batch_log(batch_meta, f"[batch] finished {item_id} with {classification.get('status')}: {classification.get('reason')}")

            child_meta = backend.RUNS.get(child_run_id)
            if classification is not None and (not isinstance(child_meta, dict) or child_meta.get('cleanup_done')):
                break

            backend.time.sleep(1.0)

        if classification is None:
            classification = {
                'status': 'incomplete',
                'reason': 'test metadata unavailable',
                'categories': ['metadata_missing'],
                'run_id': child_run_id,
                'returncode': None,
                'outputs_count': 0,
            }

        batch_meta.setdefault('results', []).append(
            {
                'item_id': item_id,
                'item_name': item_name,
                'status': classification.get('status'),
                'reason': classification.get('reason'),
                'categories': classification.get('categories') if isinstance(classification.get('categories'), list) else [],
                'run_id': classification.get('run_id'),
                'returncode': classification.get('returncode'),
                'outputs_count': classification.get('outputs_count'),
                'assurance_summary': classification.get('assurance_summary'),
                'validation_summary': classification.get('validation_summary'),
                'log_path': classification.get('log_path'),
                'log_filename': classification.get('log_filename'),
                'log_download_url': classification.get('log_download_url'),
                'finished_at': backend._local_timestamp_display(),
            }
        )
        try:
            status_value = str(classification.get('status') or '').strip().lower()
            validated_ok = True if status_value == 'passed' else (False if status_value == 'failed' else None)
            backend._persist_generator_test_result(
                kind=kind,
                generator_id=item_id,
                generator_name=item_name,
                validated_ok=validated_ok,
                validated_incomplete=(validated_ok is None),
                source_log_path=str(classification.get('log_path') or ''),
            )
        except Exception:
            pass
        batch_meta['active_item_id'] = None
        batch_meta['active_item_name'] = None
        batch_meta['active_child_run_id'] = None
        batch_meta['active_child_stop_requested'] = False

    if batch_meta.get('stop_requested'):
        seen_ids = {str(result.get('item_id') or '').strip() for result in batch_meta.get('results') or [] if isinstance(result, dict)}
        for item in items:
            item_id = str(item.get('id') or '').strip()
            if item_id in seen_ids:
                continue
            batch_meta.setdefault('results', []).append(
                {
                    'item_id': item_id,
                    'item_name': _selected_item_label(item),
                    'status': 'skipped',
                    'reason': 'batch stop requested',
                    'categories': _categorize_result(async_error=None, return_code=None, outputs_count=None, skipped=True),
                    'outputs_count': 0,
                    'finished_at': backend._local_timestamp_display(),
                }
            )
        batch_meta['status'] = 'stopped'
        _append_batch_log(batch_meta, '[batch] stopped')
    else:
        batch_meta['status'] = 'completed'
        _append_batch_log(batch_meta, '[batch] completed')

    batch_meta['done'] = True
    batch_meta['finished_at'] = backend._local_timestamp_display()


def _result_payload(run_id: str, result: dict[str, Any]) -> dict[str, Any]:
    payload = dict(result or {})
    log_path = str(payload.get('log_path') or '').strip()
    log_filename = str(payload.get('log_filename') or '').strip()
    if log_path and os.path.isfile(log_path):
        if not log_filename:
            log_filename = os.path.basename(log_path)
            payload['log_filename'] = log_filename
        payload['log_available'] = True
        payload['log_download_url'] = str(payload.get('log_download_url') or f'/flag_catalog_items/batch/item_log?run_id={run_id}&item_id={payload.get("item_id") or ""}')
    else:
        payload.pop('log_download_url', None)
        payload['log_available'] = False
    return payload


def _result_payloads(meta: dict[str, Any]) -> list[dict[str, Any]]:
    run_id = str(meta.get('run_id') or '').strip()
    results = meta.get('results') if isinstance(meta.get('results'), list) else []
    return [_result_payload(run_id, result) for result in results if isinstance(result, dict)]


def _export_payload(meta: dict[str, Any]) -> dict[str, Any]:
    results = _result_payloads(meta)
    return {
        'ok': True,
        'run_id': str(meta.get('run_id') or ''),
        'status': str(meta.get('status') or ''),
        'done': bool(meta.get('done')),
        'selection': {
            'kind': str(meta.get('kind_name') or ''),
            'scope': str(meta.get('scope') or 'unvalidated'),
            'scope_label': _scope_label(meta.get('scope') or 'unvalidated'),
            'query': str(meta.get('query') or ''),
            'include_disabled': bool(meta.get('include_disabled')),
            'limit': meta.get('limit'),
        },
        'started_at': meta.get('started_at'),
        'finished_at': meta.get('finished_at'),
        'progress': _summarize_batch(meta),
        'category_counts': _collect_category_counts(results),
        'results': results,
        'log_lines': _status_log_lines(meta, None),
    }


def _markdown_report(meta: dict[str, Any]) -> str:
    results = meta.get('results') if isinstance(meta.get('results'), list) else []
    progress = _summarize_batch(meta)
    category_counts = _collect_category_counts(results)
    lines = [
        '# Flag Catalog Batch Test Report',
        '',
        f"- Run ID: {str(meta.get('run_id') or '')}",
        f"- Kind: {_kind_label(str(meta.get('kind_name') or ''))}",
        f"- Status: {str(meta.get('status') or '')}",
        f"- Started: {str(meta.get('started_at') or '')}",
        f"- Finished: {str(meta.get('finished_at') or '')}",
        f"- Scope: {_scope_label(meta.get('scope') or 'unvalidated')}",
        f"- Query: {str(meta.get('query') or '')}",
        '',
        '## Progress',
        '',
        f"- Total: {progress.get('total', 0)}",
        f"- Completed: {progress.get('completed', 0)}",
        f"- Passed: {progress.get('passed', 0)}",
        f"- Failed: {progress.get('failed', 0)}",
        f"- Incomplete: {progress.get('incomplete', 0)}",
        f"- Skipped: {progress.get('skipped', 0)}",
        f"- Pending: {progress.get('pending', 0)}",
        '',
        '## Failure Categories',
        '',
    ]
    if category_counts:
        for key, value in category_counts.items():
            lines.append(f'- {key}: {value}')
    else:
        lines.append('- none')
    lines.extend([
        '',
        '## Results',
        '',
        '| Item ID | Item | Status | Categories | Reason |',
        '| --- | --- | --- | --- | --- |',
    ])
    for result in results:
        if not isinstance(result, dict):
            continue
        categories = result.get('categories') if isinstance(result.get('categories'), list) else []
        lines.append(
            '| {item_id} | {item_name} | {status} | {categories} | {reason} |'.format(
                item_id=str(result.get('item_id') or '').replace('|', '/'),
                item_name=str(result.get('item_name') or '').replace('|', '/'),
                status=str(result.get('status') or ''),
                categories=', '.join(str(cat) for cat in categories) or '-',
                reason=str(result.get('reason') or '').replace('|', '/'),
            )
        )
    return '\n'.join(lines) + '\n'


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_catalog_batch_routes'):
        return

    backend = backend_module

    def _find_batch_meta(run_id: str) -> dict[str, Any] | None:
        target = str(run_id or '').strip()
        if target:
            meta = backend.RUNS.get(target)
            if isinstance(meta, dict) and meta.get('kind') == 'flag_test_batch':
                return meta
            return None
        active = None
        for candidate in backend.RUNS.values():
            if not isinstance(candidate, dict) or candidate.get('kind') != 'flag_test_batch':
                continue
            if not candidate.get('done'):
                return candidate
            active = candidate
        return active

    @app.route('/flag_catalog_items/batch/start', methods=['POST'])
    def flag_catalog_items_batch_start():
        backend._require_builder_or_admin()
        payload = request.get_json(silent=True) or {}

        try:
            active_run_id, active_meta = _active_flag_run(backend)
            if isinstance(active_meta, dict):
                return jsonify(
                    {
                        'ok': False,
                        'error': 'Another flag test or batch run is already active',
                        'active_run': _active_run_payload(active_run_id, active_meta),
                        'can_stop_active': True,
                    }
                ), 409
        except Exception:
            pass

        kind = str(payload.get('kind') or 'flag-generator').strip().lower()
        if kind not in ('flag-generator', 'flag-node-generator'):
            kind = 'flag-generator'
        query = str(payload.get('query') or '').strip()
        scope = _normalize_scope(payload.get('scope'))
        include_disabled = backend._coerce_bool(payload.get('include_disabled')) if 'include_disabled' in payload else False
        limit = None
        try:
            limit_raw = payload.get('limit')
            if limit_raw not in (None, '', False):
                limit = max(1, min(int(limit_raw), 500))
        except Exception:
            limit = None

        items = _collect_catalog_items(backend, kind)
        selected_items: list[dict[str, Any]] = []
        for item in items:
            if not include_disabled and bool(item.get('_disabled') or item.get('disabled')):
                continue
            if not _item_matches_scope(item, scope):
                continue
            if not _item_matches_query(item, query):
                continue
            selected_items.append(item)
        if limit is not None:
            selected_items = selected_items[:limit]
        if not selected_items:
            return jsonify({'ok': False, 'error': 'No generators matched the selected batch filters'}), 400

        try:
            core_cfg = backend._merge_core_configs(payload.get('core'), include_password=True)
            runtime_mode = str(getattr(backend, '_webui_runtime_mode', lambda: 'native')() or 'native').strip().lower()
            core_cfg = backend._prefer_explicit_or_ssh_core_host(core_cfg, payload.get('core'))
            if not core_cfg.get('host'):
                if runtime_mode == 'vm':
                    core_cfg['host'] = core_cfg.get('ssh_host') or '127.0.0.1'
                else:
                    core_cfg['host'] = '127.0.0.1'
            if not core_cfg.get('port'):
                core_cfg['port'] = backend.CORE_PORT
            core_cfg = backend._require_core_ssh_credentials(core_cfg)
            backend._ensure_core_vm_idle_for_test(core_cfg)
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'CORE VM SSH config required: {exc}'}), 400

        batch_run_id = str(backend.uuid.uuid4())[:12]
        selection_stats = _selection_payload(selected_items)
        batch_meta = {
            'kind': 'flag_test_batch',
            'kind_name': kind,
            'run_id': batch_run_id,
            'done': False,
            'status': 'queued',
            'scope': scope,
            'query': query,
            'include_disabled': include_disabled,
            'limit': limit,
            'selected_items': [dict(item) for item in selected_items],
            'results': [],
            'log_lines': [],
            'active_item_id': None,
            'active_item_name': None,
            'active_child_run_id': None,
            'active_child_stop_requested': False,
            'stop_requested': False,
            'started_at': backend._local_timestamp_display(),
            'finished_at': None,
        }
        backend.RUNS[batch_run_id] = batch_meta

        try:
            backend.threading.Thread(
                target=_run_batch,
                args=(backend, batch_meta, core_cfg),
                name=f'flag-batch-{batch_run_id[:8]}',
                daemon=True,
            ).start()
        except Exception as exc:
            backend.RUNS.pop(batch_run_id, None)
            return jsonify({'ok': False, 'error': f'failed to start batch run: {exc}'}), 500

        return jsonify(
            {
                'ok': True,
                'run_id': batch_run_id,
                'kind': kind,
                'selected_count': selection_stats['selected_count'],
                'eligible_count': selection_stats['eligible_count'],
                'manual_input_count': selection_stats['manual_input_count'],
                'generated_input_count': selection_stats['generated_input_count'],
                'scope': scope,
                'scope_label': _scope_label(scope),
                'include_disabled': include_disabled,
                'limit': limit,
            }
        )

    @app.route('/flag_catalog_items/batch/active')
    def flag_catalog_items_batch_active():
        backend._require_builder_or_admin()
        active_run_id, active_meta = _active_flag_run(backend)
        return jsonify({'ok': True, 'active_run': _active_run_payload(active_run_id, active_meta)})

    @app.route('/flag_catalog_items/batch/status')
    def flag_catalog_items_batch_status():
        backend._require_builder_or_admin()
        run_id = str(request.args.get('run_id') or '').strip()
        meta = _find_batch_meta(run_id)
        if not isinstance(meta, dict):
            status_code = 404 if run_id else 200
            return jsonify({'ok': False, 'error': 'not found'}), status_code
        active_child = _active_child_snapshot(backend, meta)
        return jsonify(
            {
                'ok': True,
                'run_id': str(meta.get('run_id') or ''),
                'done': bool(meta.get('done')),
                'status': str(meta.get('status') or ''),
                'stop_requested': bool(meta.get('stop_requested')),
                'started_at': meta.get('started_at'),
                'finished_at': meta.get('finished_at'),
                'selection': {
                    'kind': str(meta.get('kind_name') or ''),
                    'kind_label': _kind_label(str(meta.get('kind_name') or '')),
                    'scope': str(meta.get('scope') or 'unvalidated'),
                    'scope_label': _scope_label(meta.get('scope') or 'unvalidated'),
                    'query': str(meta.get('query') or ''),
                    'include_disabled': bool(meta.get('include_disabled')),
                    'limit': meta.get('limit'),
                },
                'progress': _summarize_batch(meta),
                'category_counts': _collect_category_counts(meta.get('results') if isinstance(meta.get('results'), list) else []),
                'active_item': (
                    {
                        'id': meta.get('active_item_id'),
                        'name': meta.get('active_item_name'),
                        'child_run_id': meta.get('active_child_run_id'),
                        'stop_requested': bool(meta.get('active_child_stop_requested')),
                        'child_status': active_child,
                    }
                    if meta.get('active_item_id')
                    else None
                ),
                'active_child': active_child,
                'results': _result_payloads(meta),
                'log_lines': _status_log_lines(meta, active_child),
            }
        )

    @app.route('/flag_catalog_items/batch/stop', methods=['POST'])
    def flag_catalog_items_batch_stop():
        backend._require_builder_or_admin()
        payload = request.get_json(silent=True) or {}
        run_id = str(payload.get('run_id') or '').strip()
        meta = _find_batch_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        _request_batch_stop(backend, meta)
        return jsonify({'ok': True, 'run_id': str(meta.get('run_id') or ''), 'stop_requested': True})

    @app.route('/flag_catalog_items/batch/stop_active', methods=['POST'])
    def flag_catalog_items_batch_stop_active():
        backend._require_builder_or_admin()
        active_run_id, active_meta = _active_flag_run(backend)
        if not isinstance(active_meta, dict):
            return jsonify({'ok': False, 'error': 'no active flag test or batch run'}), 404
        active_payload = _active_run_payload(active_run_id, active_meta)
        _stop_active_flag_run(backend, str(active_run_id or ''), active_meta)
        return jsonify(
            {
                'ok': True,
                'run_id': str((active_payload or {}).get('run_id') or active_run_id or ''),
                'stop_requested': True,
                'active_run': active_payload,
            }
        )

    @app.route('/flag_catalog_items/batch/export.json')
    def flag_catalog_items_batch_export_json():
        backend._require_builder_or_admin()
        run_id = str(request.args.get('run_id') or '').strip()
        meta = _find_batch_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        return jsonify(_export_payload(meta))

    @app.route('/flag_catalog_items/batch/export.md')
    def flag_catalog_items_batch_export_markdown():
        backend._require_builder_or_admin()
        run_id = str(request.args.get('run_id') or '').strip()
        meta = _find_batch_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        report = _markdown_report(meta)
        filename = f"flag-batch-{str(meta.get('run_id') or 'report')}.md"
        headers = {'Content-Disposition': f'attachment; filename={filename}'}
        return Response(report, mimetype='text/markdown; charset=utf-8', headers=headers)

    @app.route('/flag_catalog_items/batch/item_log')
    def flag_catalog_items_batch_item_log():
        backend._require_builder_or_admin()
        run_id = str(request.args.get('run_id') or '').strip()
        item_id = str(request.args.get('item_id') or '').strip()
        meta = _find_batch_meta(run_id)
        if not isinstance(meta, dict):
            return jsonify({'ok': False, 'error': 'not found'}), 404
        results = meta.get('results') if isinstance(meta.get('results'), list) else []
        for result in results:
            if not isinstance(result, dict):
                continue
            if str(result.get('item_id') or '').strip() != item_id:
                continue
            log_path = str(result.get('log_path') or '').strip()
            if not log_path or not os.path.isfile(log_path):
                return jsonify({'ok': False, 'error': 'log not available'}), 404
            download_name = str(result.get('log_filename') or os.path.basename(log_path) or f'batch-item-{item_id}.log').strip()
            return send_file(log_path, as_attachment=True, download_name=download_name, mimetype='text/plain; charset=utf-8')
        return jsonify({'ok': False, 'error': 'not found'}), 404

    mark_routes_registered(app, 'flag_catalog_batch_routes')
