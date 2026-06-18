from __future__ import annotations

import hashlib
import json
import os
import xml.etree.ElementTree as ET
from typing import Any, Callable

from flask import jsonify, render_template, request, send_file

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    get_repo_root: Callable[[], str],
    outputs_dir: Callable[[], str],
    load_run_history: Callable[[], list[dict[str, Any]]],
    derive_summary_from_report: Callable[[str | None], str | None],
    load_summary_counts: Callable[[str | None], dict[str, Any]],
    summary_text_from_counts: Callable[[dict[str, Any]], str],
    current_user_getter: Callable[[], dict[str, Any] | None],
    scenario_catalog_for_user: Callable[..., Any],
    collect_scenario_participant_urls: Callable[..., dict[str, str]],
    normalize_scenario_label: Callable[[Any], str],
    builder_filter_report_scenarios: Callable[..., tuple[list[str], str, Any]],
    filter_history_by_scenario: Callable[[list[dict[str, Any]], str], list[dict[str, Any]]],
    resolve_scenario_display: Callable[[str, list[str], str], str],
    scenario_names_from_xml: Callable[[str | None], list[str]],
    run_history_path: str,
    logger=None,
) -> None:
    """Register report + download routes extracted from app_backend."""

    if not begin_route_registration(app, "reports_downloads_routes"):
        return

    log = logger or getattr(app, "logger", None)

    def _stable_cache_hash(value: Any) -> str:
        try:
            raw = json.dumps(value, sort_keys=True, separators=(',', ':'), default=str)
        except Exception:
            raw = repr(value)
        return hashlib.sha256(raw.encode('utf-8', errors='ignore')).hexdigest()[:24]

    def _path_fingerprint(value: Any) -> str:
        path = _existing_path(value)
        if not path:
            return ''
        try:
            st = os.stat(path)
            mtime_ns = int(getattr(st, 'st_mtime_ns', 0) or 0)
            return f"{path}|{int(getattr(st, 'st_size', 0) or 0)}|{mtime_ns}"
        except Exception:
            return path

    def _clean_str(value: Any) -> str:
        try:
            text = str(value or '').strip()
        except Exception:
            return ''
        return '' if text.lower() in {'', 'n/a', 'none', 'null', '-'} else text

    def _existing_path(value: Any) -> str:
        raw = _clean_str(value)
        if not raw:
            return ''
        candidates = [raw]
        try:
            repo_root = get_repo_root()
            if not os.path.isabs(raw):
                candidates.append(os.path.abspath(os.path.join(repo_root, raw)))
            norm = os.path.normpath(raw)
            parts = norm.strip(os.sep).split(os.sep)
            if raw.startswith('outputs' + os.sep):
                tail = raw.split(os.sep, 1)[-1]
                candidates.append(os.path.abspath(os.path.join(outputs_dir(), tail)))
            if os.path.isabs(raw) and 'outputs' in parts:
                try:
                    idx = parts.index('outputs')
                    tail = os.path.join(*parts[idx + 1:]) if idx + 1 < len(parts) else ''
                    candidates.append(os.path.abspath(os.path.join(outputs_dir(), tail)))
                except Exception:
                    pass
        except Exception:
            pass
        seen: set[str] = set()
        for candidate in candidates:
            candidate = _clean_str(candidate)
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            try:
                if os.path.exists(candidate):
                    return os.path.abspath(candidate)
            except Exception:
                continue
        return ''

    def _load_summary_metadata(summary_path: Any) -> dict[str, Any]:
        path = _existing_path(summary_path)
        if not path:
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as handle:
                payload = json.load(handle)
            metadata = payload.get('metadata') if isinstance(payload, dict) else None
            return metadata if isinstance(metadata, dict) else {}
        except Exception:
            return {}

    def _metadata_has_preview_signal(metadata: dict[str, Any]) -> bool:
        if not isinstance(metadata, dict):
            return False
        signal_keys = {
            'preview_host_total',
            'preview_attached',
            'preview_realized',
            'preview_drift',
            'plan_drift',
            'plan_summary',
            'planSummary',
            'segmentation_preview_rules',
            'router_edges_policy',
            'topo_router_edges_policy',
            'r2s_policy',
            'topo_r2s_policy',
        }
        if any(key in metadata for key in signal_keys):
            return True
        flow = metadata.get('flow')
        return isinstance(flow, dict) and bool(flow)

    def _preview_ref_from_metadata(metadata: dict[str, Any], entry: dict[str, Any]) -> str:
        if not isinstance(metadata, dict):
            return ''
        candidates: list[Any] = [
            metadata.get('preview_plan_path'),
            metadata.get('flow_preview_plan_path'),
            metadata.get('source_preview_plan_path'),
            metadata.get('base_preview_plan_path'),
        ]
        for nested_key in ('flow', 'flow_meta', 'metadata'):
            nested = metadata.get(nested_key)
            if isinstance(nested, dict):
                candidates.extend([
                    nested.get('preview_plan_path'),
                    nested.get('source_preview_plan_path'),
                    nested.get('base_preview_plan_path'),
                ])
        for candidate in candidates:
            resolved = _existing_path(candidate)
            if resolved:
                return resolved
        if _metadata_has_preview_signal(metadata):
            for candidate in (
                metadata.get('xml_path'),
                entry.get('single_scenario_xml_path'),
                entry.get('scenario_xml_path'),
                entry.get('xml_path'),
            ):
                resolved = _existing_path(candidate)
                if resolved:
                    return resolved
        return ''

    def _xml_has_embedded_preview_or_flow(path_value: Any, scenario_names: Any) -> bool:
        path = _existing_path(path_value)
        if not path:
            return False
        try:
            target_norms: set[str] = set()
            if isinstance(scenario_names, list):
                target_norms = {normalize_scenario_label(name) for name in scenario_names if _clean_str(name)}
            elif _clean_str(scenario_names):
                target_norms = {normalize_scenario_label(scenario_names)}
            root = ET.parse(path).getroot()
            editors: list[ET.Element] = []
            if root.tag == 'ScenarioEditor':
                editors = [root]
            elif root.tag == 'Scenarios':
                for scen_el in root.findall('Scenario'):
                    name = _clean_str(scen_el.get('name'))
                    if target_norms and normalize_scenario_label(name) not in target_norms:
                        continue
                    editor = scen_el.find('ScenarioEditor')
                    if editor is not None:
                        editors.append(editor)
            for editor in editors:
                plan_el = editor.find('PlanPreview')
                if plan_el is not None and _clean_str(plan_el.text):
                    return True
                flow_el = editor.find('FlagSequencing/FlowState')
                if flow_el is not None and (flow_el.attrib or list(flow_el) or _clean_str(flow_el.text)):
                    return True
        except Exception:
            return False
        return False

    def _entry_has_flow_artifact_signal(entry: dict[str, Any]) -> bool:
        if not isinstance(entry, dict):
            return False
        if str(entry.get('flow_enabled') or '').strip().lower() in {'1', 'true', 'yes', 'on'}:
            return True
        validation = entry.get('validation_summary')
        if not isinstance(validation, dict):
            return False
        flow_keys = (
            'generator_validation_detail',
            'generator_outputs_missing',
            'generator_injects_missing',
            'inject_files_expected_by_node',
            'inject_dirs_expected',
            'inject_nodes_expected',
            'injects_detail',
        )
        for key in flow_keys:
            value = validation.get(key)
            if isinstance(value, (list, dict)) and bool(value):
                return True
        return False

    def _enrich_report_entry_paths(entry: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(entry, dict):
            return entry
        if not _clean_str(entry.get('scenario_xml_path')):
            for key in ('single_scenario_xml_path', 'xml_path'):
                resolved_xml = _existing_path(entry.get(key))
                if resolved_xml:
                    entry['scenario_xml_path'] = resolved_xml
                    break
        preview_path = _existing_path(entry.get('preview_plan_path'))
        if not preview_path:
            metadata = _load_summary_metadata(entry.get('summary_path'))
            preview_path = _preview_ref_from_metadata(metadata, entry)
        if not preview_path:
            for key in ('single_scenario_xml_path', 'scenario_xml_path', 'xml_path'):
                candidate = entry.get(key)
                if _xml_has_embedded_preview_or_flow(candidate, entry.get('scenario_names')):
                    preview_path = _existing_path(candidate)
                    break
        if not preview_path and _entry_has_flow_artifact_signal(entry):
            for key in ('single_scenario_xml_path', 'scenario_xml_path', 'xml_path'):
                preview_path = _existing_path(entry.get(key))
                if preview_path:
                    break
        entry['preview_plan_path'] = preview_path or ''
        return entry

    @app.route('/download_report')
    def download_report():
        result_path = request.args.get('path')
        try:
            if result_path:
                if (result_path.startswith('"') and result_path.endswith('"')) or (result_path.startswith("'") and result_path.endswith("'")):
                    result_path = result_path[1:-1]
                if result_path.startswith('file://'):
                    result_path = result_path[len('file://'):]
                try:
                    from urllib.parse import unquote
                    result_path = unquote(result_path)
                except Exception:
                    pass
                result_path = os.path.expanduser(result_path)
                result_path = os.path.normpath(result_path)
        except Exception:
            pass

        candidates = []
        if result_path:
            candidates.append(result_path)
            try:
                repo_root = get_repo_root()
                if not os.path.isabs(result_path):
                    candidates.append(os.path.abspath(os.path.join(repo_root, result_path)))
                if result_path.startswith('webapp' + os.sep):
                    candidates.append(os.path.abspath(os.path.join(repo_root, result_path)))
                    candidates.append(os.path.abspath(os.path.join(repo_root, result_path.split(os.sep, 1)[-1])))
                if result_path.startswith('outputs' + os.sep):
                    candidates.append(os.path.abspath(os.path.join(outputs_dir(), result_path.split(os.sep, 1)[-1])))
                rp_norm = os.path.normpath(result_path)
                parts = rp_norm.strip(os.sep).split(os.sep)
                if os.path.isabs(result_path) and 'outputs' in parts:
                    try:
                        idx = parts.index('outputs')
                        tail = os.path.join(*parts[idx+1:]) if idx+1 < len(parts) else ''
                        candidates.append(os.path.join(outputs_dir(), tail))
                    except Exception:
                        pass
                if os.path.isabs(result_path) and 'webapp' in parts:
                    parts_wo = [p for p in parts if p != 'webapp']
                    candidates.append(os.path.sep + os.path.join(*parts_wo))
                try:
                    out_abs = os.path.abspath(outputs_dir())
                    if os.path.isabs(result_path) and 'core-sessions' in parts and not result_path.startswith(out_abs):
                        idx = parts.index('core-sessions')
                        tail = os.path.join(*parts[idx+1:]) if idx+1 < len(parts) else ''
                        candidates.append(os.path.join(out_abs, 'core-sessions', tail))
                except Exception:
                    pass
            except Exception:
                pass

        chosen = None
        for p in candidates:
            if p and os.path.exists(p):
                chosen = p
                break
        if chosen:
            try:
                if log is not None:
                    log.info("[download] serving file: %s", os.path.abspath(chosen))
            except Exception:
                pass
            return send_file(chosen, as_attachment=True)

        try:
            if log is not None:
                log.warning("[download] file not found via direct candidates; requested=%s; candidates=%s", result_path, candidates)
        except Exception:
            pass

        try:
            base_name = os.path.basename(result_path) if result_path else None
            if base_name and base_name.lower().endswith('.xml'):
                candidates_found = []
                root_dir = os.path.join(outputs_dir(), 'core-sessions')
                if os.path.exists(root_dir):
                    for dp, _dn, files in os.walk(root_dir):
                        for fn in files:
                            if fn == base_name:
                                alt = os.path.join(dp, fn)
                                if os.path.exists(alt):
                                    candidates_found.append(alt)
                out_dir = outputs_dir()
                if os.path.exists(out_dir):
                    try:
                        for name in os.listdir(out_dir):
                            if not name.startswith('scenarios-'):
                                continue
                            p = os.path.join(out_dir, name)
                            if not os.path.isdir(p):
                                continue
                            for dp, _dn, files in os.walk(p):
                                for fn in files:
                                    if fn == base_name:
                                        alt = os.path.join(dp, fn)
                                        if os.path.exists(alt):
                                            candidates_found.append(alt)
                    except Exception:
                        pass
                if candidates_found:
                    try:
                        candidates_found.sort(key=lambda p: os.stat(p).st_mtime, reverse=True)
                    except Exception:
                        pass
                    chosen_alt = candidates_found[0]
                    try:
                        if log is not None:
                            log.info("[download] basename match: %s -> %s", base_name, chosen_alt)
                    except Exception:
                        pass
                    return send_file(chosen_alt, as_attachment=True)
        except Exception:
            pass

        try:
            if log is not None:
                log.warning("[download] file not found: %s (candidates=%s)", result_path, candidates)
        except Exception:
            pass
        return "File not found", 404

    @app.route('/reports')
    def reports_page():
        raw = load_run_history()
        enriched = []
        for entry in raw:
            e = dict(entry)
            if not (isinstance(e.get('scenario_names'), list) and e.get('scenario_names')):
                scen = (e.get('scenario_name') or '').strip() if isinstance(e.get('scenario_name'), str) else ''
                if scen:
                    e['scenario_names'] = [scen]
                else:
                    src_xml = e.get('single_scenario_xml_path') or e.get('scenario_xml_path') or e.get('xml_path')
                    names = scenario_names_from_xml(src_xml) if src_xml else []
                    e['scenario_names'] = [names[0]] if isinstance(names, list) and names else []
            session_xml = e.get('session_xml_path') or e.get('post_xml_path')
            if session_xml:
                e['session_xml_path'] = session_xml
            if not e.get('summary_path'):
                derived_summary = derive_summary_from_report(e.get('report_path'))
                if derived_summary:
                    e['summary_path'] = derived_summary
            sn = e.get('scenario_names')
            if not isinstance(sn, list):
                if sn is None:
                    e['scenario_names'] = []
                elif isinstance(sn, str):
                    if '||' in sn:
                        e['scenario_names'] = [s for s in sn.split('||') if s]
                    else:
                        e['scenario_names'] = [s.strip() for s in sn.split(',') if s.strip()]
                else:
                    e['scenario_names'] = []
            if isinstance(e.get('scenario_names'), list) and len(e['scenario_names']) > 1:
                e['scenario_names'] = [e['scenario_names'][0]]
            _enrich_report_entry_paths(e)
            enriched.append(e)
        enriched = sorted(enriched, key=lambda x: x.get('timestamp', ''), reverse=True)
        user = current_user_getter()
        scenario_names, scenario_paths, scenario_url_hints = scenario_catalog_for_user(enriched, user=user)
        scenario_participant_urls = collect_scenario_participant_urls(scenario_paths, scenario_url_hints)
        participant_url_flags = {
            norm: bool(url)
            for norm, url in scenario_participant_urls.items()
            if isinstance(norm, str) and norm
        }
        scenario_query = request.args.get('scenario', '').strip()
        scenario_norm = normalize_scenario_label(scenario_query)
        scenario_names, scenario_norm, _allowed_norms = builder_filter_report_scenarios(
            scenario_names,
            scenario_norm,
            user=user,
        )
        if scenario_names and not scenario_norm:
            scenario_norm = normalize_scenario_label(scenario_names[0])
        if scenario_norm:
            enriched = filter_history_by_scenario(enriched, scenario_norm)
        for entry in enriched:
            try:
                counts = load_summary_counts(entry.get('summary_path'))
                entry['summary_output'] = summary_text_from_counts(counts)
            except Exception:
                entry['summary_output'] = ''
        scenario_display = resolve_scenario_display(scenario_norm, scenario_names, scenario_query)
        return render_template(
            'reports.html',
            history=enriched,
            scenarios=scenario_names,
            active_scenario=scenario_display,
            participant_url_flags=participant_url_flags,
        )

    @app.route('/reports_data')
    def reports_data():
        raw = load_run_history()
        enriched = []
        for entry in raw:
            e = dict(entry)
            if not (isinstance(e.get('scenario_names'), list) and e.get('scenario_names')):
                scen = (e.get('scenario_name') or '').strip() if isinstance(e.get('scenario_name'), str) else ''
                if scen:
                    e['scenario_names'] = [scen]
                else:
                    src_xml = e.get('single_scenario_xml_path') or e.get('scenario_xml_path') or e.get('xml_path')
                    names = scenario_names_from_xml(src_xml) if src_xml else []
                    e['scenario_names'] = [names[0]] if isinstance(names, list) and names else []
            session_xml = e.get('session_xml_path') or e.get('post_xml_path')
            if session_xml:
                e['session_xml_path'] = session_xml
            if not e.get('summary_path'):
                derived_summary = derive_summary_from_report(e.get('report_path'))
                if derived_summary:
                    e['summary_path'] = derived_summary
            sn = e.get('scenario_names')
            if not isinstance(sn, list):
                if sn is None:
                    e['scenario_names'] = []
                elif isinstance(sn, str):
                    if '||' in sn:
                        e['scenario_names'] = [s for s in sn.split('||') if s]
                    else:
                        e['scenario_names'] = [s.strip() for s in sn.split(',') if s.strip()]
                else:
                    e['scenario_names'] = []
            if isinstance(e.get('scenario_names'), list) and len(e['scenario_names']) > 1:
                e['scenario_names'] = [e['scenario_names'][0]]
            _enrich_report_entry_paths(e)
            enriched.append(e)
        enriched = sorted(enriched, key=lambda x: x.get('timestamp', ''), reverse=True)
        user = current_user_getter()
        scenario_names, scenario_paths, scenario_url_hints = scenario_catalog_for_user(enriched, user=user)
        scenario_participant_urls = collect_scenario_participant_urls(scenario_paths, scenario_url_hints)
        participant_url_flags = {
            norm: bool(url)
            for norm, url in scenario_participant_urls.items()
            if isinstance(norm, str) and norm
        }
        scenario_query = request.args.get('scenario', '').strip()
        scenario_norm = normalize_scenario_label(scenario_query)
        scenario_names, scenario_norm, _allowed_norms = builder_filter_report_scenarios(
            scenario_names,
            scenario_norm,
            user=user,
        )
        if scenario_names and not scenario_norm:
            scenario_norm = normalize_scenario_label(scenario_names[0])
        if scenario_norm:
            enriched = filter_history_by_scenario(enriched, scenario_norm)
        scenario_display = resolve_scenario_display(scenario_norm, scenario_names, scenario_query)
        reports_data_cache_key = _stable_cache_hash(
            {
                'user': {
                    'username': str((user or {}).get('username') or '') if isinstance(user, dict) else str(getattr(user, 'username', '') or ''),
                    'role': str((user or {}).get('role') or '') if isinstance(user, dict) else str(getattr(user, 'role', '') or ''),
                },
                'history': enriched,
                'scenarios': scenario_names,
                'active_scenario': scenario_display,
                'participant_url_flags': participant_url_flags,
                'summary_refs': [
                    {
                        'summary_path': _path_fingerprint(entry.get('summary_path')),
                        'report_path': _path_fingerprint(entry.get('report_path')),
                        'scenario_xml_path': _path_fingerprint(entry.get('scenario_xml_path')),
                        'xml_path': _path_fingerprint(entry.get('xml_path')),
                        'single_scenario_xml_path': _path_fingerprint(entry.get('single_scenario_xml_path')),
                        'preview_plan_path': _path_fingerprint(entry.get('preview_plan_path')),
                    }
                    for entry in enriched
                ],
            }
        )
        incoming_cache_key = (request.args.get('if_data_cache_key') or request.headers.get('X-Data-Cache-Key') or '').strip()
        if incoming_cache_key and incoming_cache_key == reports_data_cache_key:
            return jsonify({'ok': True, 'data_cache_key': reports_data_cache_key, 'not_modified': True})
        for entry in enriched:
            try:
                counts = load_summary_counts(entry.get('summary_path'))
                entry['summary_output'] = summary_text_from_counts(counts)
            except Exception:
                entry['summary_output'] = ''
        return jsonify({
            'ok': True,
            'history': enriched,
            'scenarios': scenario_names,
            'active_scenario': scenario_display,
            'participant_url_flags': participant_url_flags,
            'data_cache_key': reports_data_cache_key,
        })

    @app.route('/reports/delete', methods=['POST'])
    def reports_delete():
        try:
            payload = request.get_json(force=True, silent=True) or {}
            run_ids = payload.get('run_ids') or []
            if not isinstance(run_ids, list):
                return jsonify({'error': 'run_ids must be a list'}), 400
            run_ids_set = set([str(x) for x in run_ids if x])
            if not run_ids_set:
                return jsonify({'deleted': 0})
            history = load_run_history()
            kept = []
            deleted_count = 0
            out_dir = outputs_dir()
            for entry in history:
                rid = str(entry.get('run_id') or '')
                rid_fallback = "|".join([
                    str(entry.get('timestamp') or ''),
                    str(entry.get('scenario_xml_path') or entry.get('xml_path') or ''),
                    str(entry.get('report_path') or ''),
                    str(entry.get('full_scenario_path') or ''),
                ])
                if (rid and rid in run_ids_set) or (rid_fallback and rid_fallback in run_ids_set):
                    for key in ('full_scenario_path', 'scenario_xml_path', 'pre_xml_path', 'post_xml_path', 'xml_path', 'single_scenario_xml_path'):
                        p = entry.get(key)
                        if not p:
                            continue
                        try:
                            ap = os.path.abspath(p)
                            if ap.startswith(os.path.abspath(out_dir)) and os.path.exists(ap):
                                try:
                                    os.remove(ap)
                                    if log is not None:
                                        log.info("[reports.delete] removed %s", ap)
                                except IsADirectoryError:
                                    if log is not None:
                                        log.warning("[reports.delete] skipping directory %s", ap)
                        except Exception as e:
                            if log is not None:
                                log.warning("[reports.delete] error removing %s: %s", p, e)
                    deleted_count += 1
                else:
                    kept.append(entry)

            os.makedirs(os.path.dirname(run_history_path), exist_ok=True)
            tmp = run_history_path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(kept, f, indent=2)
            os.replace(tmp, run_history_path)
            return jsonify({'deleted': deleted_count})
        except Exception as e:
            try:
                if log is not None:
                    log.exception("[reports.delete] failed: %s", e)
            except Exception:
                pass
            return jsonify({'error': 'internal error'}), 500

    mark_routes_registered(app, "reports_downloads_routes")
