from __future__ import annotations

import os
from typing import Any

from flask import render_template, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'scenarios_pages_routes'):
        return

    backend = backend_module

    def _sort_route_scenario_names(names):
        try:
            return backend._sort_scenario_display_names(names)
        except Exception:
            try:
                return sorted(list(names or []), key=backend._scenario_display_sort_key)
            except Exception:
                return list(names or [])

    def _merge_route_scenario_names(existing_names, xml_names):
        merged = []
        seen = set()
        for raw in list(existing_names or []) + list(xml_names or []):
            try:
                display = str(raw or '').strip()
            except Exception:
                display = ''
            if not display:
                continue
            norm = backend._normalize_scenario_label(display)
            if not norm or norm in seen:
                continue
            seen.add(norm)
            merged.append(display)
        return _sort_route_scenario_names(merged)

    def _select_route_scenario_xml_path(candidates, scenario_norm: str) -> str | None:
        scen_norm = backend._normalize_scenario_label(scenario_norm)
        if not scen_norm:
            return backend._select_existing_path(candidates)
        if candidates in (None, ''):
            return None
        if isinstance(candidates, (str, os.PathLike)):
            raw_candidates = [candidates]
        else:
            try:
                raw_candidates = list(candidates)
            except Exception:
                raw_candidates = [candidates]

        best_path = None
        best_mtime = float('-inf')
        for candidate in raw_candidates:
            candidate_path = backend._existing_xml_path_or_none(candidate)
            if not candidate_path:
                continue
            try:
                names = backend._scenario_names_from_xml(candidate_path)
            except Exception:
                names = []
            if not any(backend._normalize_scenario_label(name) == scen_norm for name in names or []):
                continue
            try:
                mtime = os.path.getmtime(candidate_path)
            except Exception:
                mtime = 0.0
            if best_path is None or mtime >= best_mtime:
                best_path = candidate_path
                best_mtime = mtime
        return best_path

    def _build_route_scenario_xml_map(
        scenario_names,
        scenario_paths,
        current_xml_path: str,
        current_xml_scenario_names,
        fallback_scenario_norm: str,
    ) -> dict[str, str]:
        scenario_xml_by_name: dict[str, str] = {}
        try:
            if current_xml_path and isinstance(scenario_names, list):
                xml_name_norms = {
                    backend._normalize_scenario_label(name)
                    for name in (current_xml_scenario_names or [])
                    if backend._normalize_scenario_label(name)
                }
                for name in scenario_names:
                    display_name = str(name)
                    name_norm = backend._normalize_scenario_label(display_name)
                    if not name_norm:
                        continue
                    if xml_name_norms:
                        if name_norm in xml_name_norms:
                            scenario_xml_by_name[display_name] = current_xml_path
                    elif fallback_scenario_norm and name_norm == fallback_scenario_norm:
                        scenario_xml_by_name[display_name] = current_xml_path
            if isinstance(scenario_names, list) and isinstance(scenario_paths, dict):
                for name in scenario_names:
                    display_name = str(name)
                    if display_name in scenario_xml_by_name:
                        continue
                    try:
                        name_norm = backend._normalize_scenario_label(display_name)
                        raw_path = scenario_paths.get(name_norm) or scenario_paths.get(display_name) or ''
                        chosen = _select_route_scenario_xml_path(raw_path, name_norm) or ''
                        if chosen:
                            scenario_xml_by_name[display_name] = os.path.abspath(chosen)
                    except Exception:
                        scenario_xml_by_name.setdefault(display_name, '')
        except Exception:
            return {}
        return scenario_xml_by_name

    def _flow_page_view():
        current_user = backend._current_user()
        scenario_names, scenario_paths, scenario_url_hints = backend._scenario_catalog_for_user(None, user=current_user)
        scenario_names = _sort_route_scenario_names(scenario_names)
        scenario_participant_urls = backend._collect_scenario_participant_urls(scenario_paths, scenario_url_hints)
        participant_url_flags = {
            norm: bool(url)
            for norm, url in scenario_participant_urls.items()
            if isinstance(norm, str) and norm
        }

        scenario_query = request.args.get('scenario', '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_query)
        if scenario_names:
            if not scenario_norm:
                scenario_norm = backend._normalize_scenario_label(scenario_names[0])
        active_scenario = backend._resolve_scenario_display(scenario_norm, scenario_names, scenario_query)

        active_scenario_xml_path = ''
        xml_path = (request.args.get('xml_path') or '').strip()
        if not active_scenario_xml_path:
            try:
                if scenario_norm:
                    latest_xml = backend._latest_xml_path_for_scenario(scenario_norm) or ''
                    if latest_xml:
                        latest_abs = os.path.abspath(latest_xml)
                        if os.path.exists(latest_abs):
                            active_scenario_xml_path = latest_abs
            except Exception:
                active_scenario_xml_path = ''
        try:
            if (not active_scenario_xml_path) and xml_path:
                xml_path_abs = os.path.abspath(xml_path)
                if os.path.exists(xml_path_abs):
                    active_scenario_xml_path = xml_path_abs
        except Exception:
            active_scenario_xml_path = ''
        if not active_scenario_xml_path:
            try:
                if scenario_norm and isinstance(scenario_paths, dict):
                    raw_path = scenario_paths.get(scenario_norm) or scenario_paths.get(active_scenario) or ''
                    chosen = _select_route_scenario_xml_path(raw_path, scenario_norm)
                    if chosen:
                        active_scenario_xml_path = os.path.abspath(chosen)
            except Exception:
                active_scenario_xml_path = ''

        parsed_active_xml: dict[str, Any] | None = None
        xml_scenario_names: list[str] = []
        try:
            if active_scenario_xml_path and os.path.isfile(active_scenario_xml_path):
                parsed_for_names = backend._parse_scenarios_xml(active_scenario_xml_path)
                if isinstance(parsed_for_names, dict):
                    parsed_active_xml = parsed_for_names
                scen_list_for_names = parsed_for_names.get('scenarios') if isinstance(parsed_for_names, dict) else None
                if isinstance(scen_list_for_names, list):
                    for scenario in scen_list_for_names:
                        if not isinstance(scenario, dict):
                            continue
                        name = str(scenario.get('name') or '').strip()
                        if name:
                            xml_scenario_names.append(name)
                        hitl = scenario.get('hitl') if isinstance(scenario.get('hitl'), dict) else None
                        participant_url = str((hitl or {}).get('participant_proxmox_url') or '').strip()
                        if name and participant_url:
                            scenario_participant_urls[backend._normalize_scenario_label(name)] = participant_url
        except Exception:
            xml_scenario_names = []

        if xml_scenario_names:
            scenario_names = _merge_route_scenario_names(scenario_names, xml_scenario_names)
        if scenario_names:
            if not scenario_norm or not any(backend._normalize_scenario_label(name) == scenario_norm for name in scenario_names):
                scenario_norm = backend._normalize_scenario_label(scenario_names[0])
            active_scenario = backend._resolve_scenario_display(scenario_norm, scenario_names, scenario_query)

        scenario_xml_by_name = _build_route_scenario_xml_map(
            scenario_names,
            scenario_paths,
            active_scenario_xml_path,
            xml_scenario_names,
            scenario_norm,
        )

        xml_preview = ''
        flow_state_by_scenario: dict[str, Any] = {}
        try:
            if active_scenario_xml_path and os.path.isfile(active_scenario_xml_path):
                try:
                    parsed = parsed_active_xml if isinstance(parsed_active_xml, dict) else backend._parse_scenarios_xml(active_scenario_xml_path)
                    scen_list = parsed.get('scenarios') if isinstance(parsed, dict) else None
                    if isinstance(scen_list, list):
                        for scenario in scen_list:
                            if not isinstance(scenario, dict):
                                continue
                            name = str(scenario.get('name') or '').strip()
                            flow_state = scenario.get('flow_state')
                            if name and isinstance(flow_state, dict) and flow_state:
                                flow_state_by_scenario[backend._normalize_scenario_label(name)] = flow_state
                except Exception:
                    flow_state_by_scenario = {}
        except Exception:
            xml_preview = ''

        try:
            active_flow_state = flow_state_by_scenario.get(backend._normalize_scenario_label(active_scenario)) if isinstance(flow_state_by_scenario, dict) else None
            chain_ids = active_flow_state.get('chain_ids') if isinstance(active_flow_state, dict) and isinstance(active_flow_state.get('chain_ids'), list) else []
            try:
                xml_mtime = float(os.path.getmtime(active_scenario_xml_path)) if active_scenario_xml_path and os.path.exists(active_scenario_xml_path) else 0.0
            except Exception:
                xml_mtime = 0.0
            app.logger.info(
                '[flow.page] scenario=%s xml=%s exists=%s mtime=%s sha12=%s flow_chain_len=%s flow_enabled=%s flow_state_entries=%s',
                backend._normalize_scenario_label(active_scenario),
                active_scenario_xml_path,
                bool(active_scenario_xml_path and os.path.exists(active_scenario_xml_path)),
                xml_mtime,
                '',
                len(chain_ids) if isinstance(chain_ids, list) else None,
                active_flow_state.get('flow_enabled') if isinstance(active_flow_state, dict) and 'flow_enabled' in active_flow_state else None,
                len(flow_state_by_scenario or {}),
            )
        except Exception:
            pass

        return render_template(
            'flow.html',
            scenarios=scenario_names,
            active_scenario=active_scenario,
            participant_url_flags=participant_url_flags,
            scenario_xml_by_name=scenario_xml_by_name,
            preview_xml_path=active_scenario_xml_path,
            xml_preview=xml_preview,
            flow_state_by_scenario=flow_state_by_scenario,
            active_page='scenarios',
        )

    def _scenarios_preview_page_view():
        current_user = backend._current_user()
        scenario_names, scenario_paths, _scenario_url_hints = backend._scenario_catalog_for_user(None, user=current_user)
        scenario_names = _sort_route_scenario_names(scenario_names)

        scenario_query = (request.args.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_query)
        if scenario_names:
            if not scenario_norm:
                scenario_norm = backend._normalize_scenario_label(scenario_names[0])
        active_scenario = backend._resolve_scenario_display(scenario_norm, scenario_names, scenario_query)

        xml_path = (request.args.get('xml_path') or '').strip()
        xml_path_abs = ''
        if not xml_path_abs:
            try:
                if scenario_norm:
                    latest_xml = backend._latest_xml_path_for_scenario(scenario_norm) or ''
                    if latest_xml:
                        latest_abs = os.path.abspath(latest_xml)
                        if os.path.exists(latest_abs):
                            xml_path_abs = latest_abs
            except Exception:
                xml_path_abs = ''
        try:
            if (not xml_path_abs) and xml_path:
                xml_path_abs = os.path.abspath(xml_path)
                if not os.path.exists(xml_path_abs):
                    xml_path_abs = ''
        except Exception:
            xml_path_abs = ''
        if not xml_path_abs:
            try:
                raw_path = ''
                if scenario_norm and isinstance(scenario_paths, dict):
                    raw_path = scenario_paths.get(scenario_norm) or scenario_paths.get(active_scenario) or ''
                chosen = _select_route_scenario_xml_path(raw_path, scenario_norm)
                if chosen:
                    xml_path_abs = os.path.abspath(chosen)
            except Exception:
                xml_path_abs = ''

        xml_scenario_names: list[str] = []
        try:
            if xml_path_abs and os.path.isfile(xml_path_abs):
                parsed_for_names = backend._parse_scenarios_xml(xml_path_abs)
                scen_list_for_names = parsed_for_names.get('scenarios') if isinstance(parsed_for_names, dict) else None
                if isinstance(scen_list_for_names, list):
                    for scenario in scen_list_for_names:
                        if not isinstance(scenario, dict):
                            continue
                        name = str(scenario.get('name') or '').strip()
                        if name:
                            xml_scenario_names.append(name)
        except Exception:
            xml_scenario_names = []

        if xml_scenario_names:
            scenario_names = _merge_route_scenario_names(scenario_names, xml_scenario_names)
        if scenario_names:
            if not scenario_norm or not any(backend._normalize_scenario_label(name) == scenario_norm for name in scenario_names):
                scenario_norm = backend._normalize_scenario_label(scenario_names[0])
            active_scenario = backend._resolve_scenario_display(scenario_norm, scenario_names, scenario_query)

        scenario_xml_by_name = _build_route_scenario_xml_map(
            scenario_names,
            scenario_paths,
            xml_path_abs,
            xml_scenario_names,
            scenario_norm,
        )

        xml_preview = ''
        try:
            if xml_path_abs and os.path.exists(xml_path_abs):
                with open(xml_path_abs, 'r', encoding='utf-8', errors='ignore') as handle:
                    xml_preview = handle.read()
        except Exception:
            xml_preview = ''

        try:
            snap = backend._xml_trace_snapshot(xml_path_abs, active_scenario)
            app.logger.info(
                '[flow.preview_page] scenario=%s xml=%s exists=%s mtime=%s sha12=%s flow_chain_len=%s flow_enabled=%s',
                backend._normalize_scenario_label(active_scenario),
                snap.get('xml_path'),
                snap.get('exists'),
                snap.get('mtime'),
                snap.get('sha12'),
                snap.get('flow_chain_len'),
                snap.get('flow_enabled'),
            )
        except Exception:
            pass

        return render_template(
            'scenarios_preview.html',
            scenarios=scenario_names,
            active_scenario=active_scenario,
            scenario_xml_by_name=scenario_xml_by_name,
            scenario_tab=active_scenario,
            preview_xml_path=xml_path_abs,
            xml_preview=xml_preview,
            active_page='scenarios',
        )

    app.add_url_rule('/scenarios/flag-sequencing', endpoint='flow_page', view_func=_flow_page_view, methods=['GET'])
    app.add_url_rule('/scenarios/preview', endpoint='scenarios_preview_page', view_func=_scenarios_preview_page_view, methods=['GET'])
    app.add_url_rule('/scenarios/preview', endpoint='scenarios_preview', view_func=_scenarios_preview_page_view, methods=['GET'])

    mark_routes_registered(app, 'scenarios_pages_routes')