from __future__ import annotations

import os
from typing import Any
from typing import Optional

from flask import jsonify
from flask import request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_attackflow_preview_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/attackflow_preview')
    def api_flow_attackflow_preview():
        scenario_label = (request.args.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        preset = str(request.args.get('preset') or '').strip()
        mode = str(request.args.get('mode') or '').strip().lower()
        xml_hint = (request.args.get('xml_path') or '').strip()
        length_raw = request.args.get('length')
        try:
            length = int(length_raw) if length_raw is not None else 5
        except Exception:
            length = 5
        preset_steps = backend._flow_preset_steps(preset)
        if preset_steps:
            length = len(preset_steps)
        length = max(1, min(length, 50))
        requested_length = length

        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400

        prefer_preview = str(request.args.get('prefer_preview') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        force_preview = str(request.args.get('force_preview') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        prefer_flow = str(request.args.get('prefer_flow') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        best_effort_query = str(request.args.get('best_effort') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        allow_node_duplicates = str(request.args.get('allow_node_duplicates') or request.args.get('allow_duplicates') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        include_all_topology_vulns_arg = request.args.get('include_all_topology_vulns')
        include_all_topology_pivots_arg = request.args.get('include_all_topology_pivots')
        include_all_topology_vulns = str(include_all_topology_vulns_arg or '').strip().lower() in ('1', 'true', 'yes', 'y')
        include_all_topology_pivots = str(include_all_topology_pivots_arg or '').strip().lower() in ('1', 'true', 'yes', 'y')
        debug_mode = str(request.args.get('debug') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        dependency_level = backend._flow_normalize_dependency_level(request.args.get('dependency_level'))
        ignore_saved_flow = bool(force_preview)
        selected_by = 'xml'

        preview_plan_path = (request.args.get('preview_plan') or '').strip() or None
        if preview_plan_path:
            try:
                preview_plan_path = os.path.abspath(preview_plan_path)
                if (not preview_plan_path.lower().endswith('.xml')) or (not os.path.exists(preview_plan_path)):
                    preview_plan_path = None
            except Exception:
                preview_plan_path = None

        if not preview_plan_path and xml_hint:
            try:
                xml_abs = os.path.abspath(xml_hint)
                if os.path.exists(xml_abs) and xml_abs.lower().endswith('.xml'):
                    payload_hint = backend._load_plan_preview_from_xml(xml_abs, scenario_norm)
                    if isinstance(payload_hint, dict):
                        meta_hint = payload_hint.get('metadata') if isinstance(payload_hint.get('metadata'), dict) else {}
                        scen_hint = str(meta_hint.get('scenario') or '').strip()
                        if (not scen_hint) or backend._normalize_scenario_label(scen_hint) == scenario_norm:
                            preview_plan_path = xml_abs
                            selected_by = 'xml_hint'
            except Exception:
                pass

        if not preview_plan_path:
            preview_plan_path = backend._latest_xml_path_for_scenario(scenario_norm)
            if preview_plan_path:
                selected_by = 'latest_xml'

        if not preview_plan_path:
            return jsonify({'ok': False, 'error': 'No XML found for this scenario. Save XML with a PlanPreview first.'}), 404

        payload = {}
        preview = None
        try:
            attempts = 0
            while attempts < 2:
                attempts += 1
                payload = backend._load_preview_payload_from_path(preview_plan_path, scenario_norm)
                if not isinstance(payload, dict):
                    return jsonify({'ok': False, 'error': 'Preview plan not embedded in XML.'}), 404
                meta_chk = payload.get('metadata') if isinstance(payload, dict) else None
                scen_chk = ''
                if isinstance(meta_chk, dict):
                    scen_chk = str(meta_chk.get('scenario') or '').strip()
                    flow_chk = meta_chk.get('flow') if isinstance(meta_chk.get('flow'), dict) else None
                    if not scen_chk and isinstance(flow_chk, dict):
                        scen_chk = str(flow_chk.get('scenario') or '').strip()
                scen_chk_norm = backend._normalize_scenario_label(scen_chk) if scen_chk else ''
                if scen_chk_norm and scen_chk_norm != scenario_norm:
                    preview_plan_path = backend._latest_preview_plan_for_scenario_norm_origin(scenario_norm, origin='planner')
                    if not preview_plan_path:
                        return jsonify({'ok': False, 'error': 'No preview plan found for this scenario. Generate a Full Preview first.'}), 404
                    continue
                break
            preview = payload.get('full_preview') if isinstance(payload, dict) else None
            if not isinstance(preview, dict):
                return jsonify({'ok': False, 'error': 'Preview plan is missing full_preview.'}), 422
        except Exception as exc:
            return jsonify({'ok': False, 'error': f'Failed to load preview plan: {exc}'}), 500

        def _docker_count_from_preview(full_preview: dict) -> int:
            try:
                hosts = full_preview.get('hosts') or []
            except Exception:
                hosts = []
            if not isinstance(hosts, list):
                return 0
            total = 0
            for host in hosts:
                if not isinstance(host, dict):
                    continue
                role = str(host.get('role') or '').strip().lower()
                if role == 'docker':
                    total += 1
            return total

        def _docker_count_from_editor_snapshot(snapshot: dict, scen_norm: str) -> int:
            try:
                scenarios = snapshot.get('scenarios') or []
            except Exception:
                scenarios = []
            if not isinstance(scenarios, list):
                return 0
            match = None
            for scen in scenarios:
                if not isinstance(scen, dict):
                    continue
                nm = backend._normalize_scenario_label(scen.get('name') or '')
                if nm and nm == scen_norm:
                    match = scen
                    break
            if not isinstance(match, dict):
                return 0
            section = (match.get('sections') or {}).get('Node Information')
            if not isinstance(section, dict):
                return 0
            items = section.get('items') or []
            if not isinstance(items, list):
                return 0
            total = 0
            for item in items:
                if not isinstance(item, dict):
                    continue
                metric = str(item.get('v_metric') or 'Weight').strip()
                if metric != 'Count':
                    continue
                sel = str(item.get('selected') or '').strip().lower()
                if sel != 'docker':
                    continue
                try:
                    total += max(0, int(item.get('v_count') or 0))
                except Exception:
                    continue
            return total

        def _plan_epoch_seconds(plan_path: str, plan_payload: dict) -> float:
            try:
                meta = plan_payload.get('metadata') if isinstance(plan_payload, dict) else None
                if isinstance(meta, dict):
                    ts = backend._parse_iso_ts(meta.get('created_at'))
                    if ts > 0:
                        return ts
            except Exception:
                pass
            try:
                return float(os.path.getmtime(plan_path))
            except Exception:
                return 0.0

        def _editor_snapshot_epoch_seconds(owner: Optional[dict]) -> float:
            try:
                snap_path = backend._editor_state_snapshot_path(owner)
                if os.path.exists(snap_path):
                    return float(os.path.getmtime(snap_path))
            except Exception:
                pass
            return 0.0

        try:
            backend._canonicalize_payload_flow_from_xml(
                payload,
                xml_path=preview_plan_path,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            pass
        try:
            backend._flow_attach_pivoting_plan_from_xml(
                payload,
                xml_path=preview_plan_path,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            pass

        nodes, _links, adj = backend._build_topology_graph_from_preview_plan(preview)
        stats = backend._flow_compose_docker_stats(nodes)

        try:
            metadata_for_options = payload.get('metadata') if isinstance(payload, dict) else None
            flow_for_options = metadata_for_options.get('flow') if isinstance(metadata_for_options, dict) and isinstance(metadata_for_options.get('flow'), dict) else None
            if isinstance(flow_for_options, dict):
                if include_all_topology_vulns_arg is None:
                    include_all_topology_vulns = bool(flow_for_options.get('include_all_topology_vulns'))
                if include_all_topology_pivots_arg is None:
                    include_all_topology_pivots = bool(flow_for_options.get('include_all_topology_pivots'))
        except Exception:
            pass
        if include_all_topology_vulns or include_all_topology_pivots:
            ignore_saved_flow = True

        runtime_ip_by_id: dict[str, str] = {}
        try:
            session_xml_path = backend._latest_session_xml_for_scenario_norm(scenario_norm)
        except Exception:
            session_xml_path = None
        try:
            if session_xml_path and os.path.exists(str(session_xml_path)):
                runtime_nodes, _runtime_links, _runtime_adj = backend._build_topology_graph_from_session_xml(str(session_xml_path))
                for runtime_node in (runtime_nodes or []):
                    if not isinstance(runtime_node, dict):
                        continue
                    rid = str(runtime_node.get('id') or runtime_node.get('node_id') or '').strip()
                    if not rid:
                        continue
                    rip = backend._first_valid_ipv4(
                        runtime_node.get('ip4') or runtime_node.get('ipv4') or runtime_node.get('ip') or runtime_node.get('ips') or runtime_node.get('ipv4s') or ''
                    )
                    if rip:
                        runtime_ip_by_id[rid] = rip
        except Exception:
            runtime_ip_by_id = {}

        def _is_docker_like_host(host: dict[str, Any] | None) -> bool:
            if not isinstance(host, dict):
                return False
            try:
                role = str(host.get('role') or host.get('type') or '').strip().lower()
            except Exception:
                role = ''
            if role == 'docker':
                return True
            if host.get('compose') or host.get('compose_name'):
                return True
            return False

        def _effective_host_ip(nid: str, host: dict[str, Any] | None) -> str:
            preview_ip = ''
            try:
                preview_ip = backend._preview_host_ip4_any(host) if isinstance(host, dict) else ''
            except Exception:
                preview_ip = ''
            if _is_docker_like_host(host):
                return preview_ip
            return runtime_ip_by_id.get(nid) or preview_ip

        id_map_for_saved_flow = {
            str(n.get('id') or '').strip(): n
            for n in (nodes or [])
            if isinstance(n, dict) and str(n.get('id') or '').strip()
        }

        def _saved_flow_candidate_ids(flow_meta: dict[str, Any] | None) -> list[tuple[str, list[str]]]:
            candidates: list[tuple[str, list[str]]] = []
            seen: set[tuple[str, ...]] = set()

            def add(label: str, raw_ids: list[Any]) -> None:
                ids = [str(item or '').strip() for item in (raw_ids or []) if str(item or '').strip()]
                if not ids:
                    return
                key = tuple(ids)
                if key in seen:
                    return
                seen.add(key)
                candidates.append((label, ids))

            if not isinstance(flow_meta, dict):
                return candidates

            chain = flow_meta.get('chain') if isinstance(flow_meta.get('chain'), list) else []
            chain_ids_from_chain: list[str] = []
            for entry in (chain or []):
                if isinstance(entry, dict):
                    cid = str(entry.get('id') or entry.get('node_id') or '').strip()
                else:
                    cid = str(entry or '').strip()
                if cid:
                    chain_ids_from_chain.append(cid)
            add('chain', chain_ids_from_chain)

            raw_chain_ids = flow_meta.get('chain_ids') if isinstance(flow_meta.get('chain_ids'), list) else []
            add('chain_ids', raw_chain_ids)

            assignments = flow_meta.get('flag_assignments') if isinstance(flow_meta.get('flag_assignments'), list) else []
            assignment_ids = [
                str(a.get('node_id') or '').strip()
                for a in (assignments or [])
                if isinstance(a, dict) and str(a.get('node_id') or '').strip()
            ]
            add('assignment_node_ids', assignment_ids)
            return candidates

        def _assignment_kind(assignment: dict[str, Any] | None) -> str:
            if not isinstance(assignment, dict):
                return 'flag-generator'
            kind = str(assignment.get('type') or '').strip()
            if kind:
                return kind
            catalog = str(assignment.get('generator_catalog') or '').strip().lower()
            if catalog == 'flag_node_generators':
                return 'flag-node-generator'
            return 'flag-generator'

        def _assignments_fit_saved_nodes(chain_candidate: list[dict[str, Any]], assignments: list[Any]) -> bool:
            if not isinstance(assignments, list) or not assignments:
                return True
            if len(assignments) < len(chain_candidate):
                return False
            for idx, node in enumerate(chain_candidate):
                assignment = assignments[idx] if idx < len(assignments) else None
                if not isinstance(assignment, dict):
                    return False
                kind = _assignment_kind(assignment)
                is_vuln = bool(backend._flow_node_is_vuln(node))
                is_docker = bool(backend._flow_node_is_docker_role(node))
                if kind == 'flag-node-generator':
                    if not (is_docker and (not is_vuln)):
                        return False
                elif not is_vuln:
                    return False
            return True

        def _saved_chain_nodes_from_flow_state(
            flow_meta: dict[str, Any] | None,
            *,
            max_length: int | None = None,
        ) -> tuple[list[dict[str, Any]], str]:
            if not isinstance(flow_meta, dict):
                return [], ''
            assignments = flow_meta.get('flag_assignments') if isinstance(flow_meta.get('flag_assignments'), list) else []
            structurally_valid: list[tuple[list[dict[str, Any]], str]] = []
            for source, ids_in in _saved_flow_candidate_ids(flow_meta):
                ids = list(ids_in or [])
                if max_length is not None:
                    ids = ids[:max(0, int(max_length or 0))]
                if not ids:
                    continue
                if (not allow_node_duplicates) and (len(set(ids)) != len(ids)):
                    continue
                candidate_nodes = [id_map_for_saved_flow[cid] for cid in ids if cid in id_map_for_saved_flow]
                if len(candidate_nodes) != len(ids):
                    continue
                try:
                    invalid = any(
                        (not backend._flow_node_is_docker_role(node)) and (not backend._flow_node_is_vuln(node))
                        for node in candidate_nodes
                        if isinstance(node, dict)
                    )
                except Exception:
                    invalid = True
                if invalid:
                    continue
                structurally_valid.append((candidate_nodes, source))
                if _assignments_fit_saved_nodes(candidate_nodes, assignments):
                    return candidate_nodes, source
            if structurally_valid:
                return structurally_valid[0]
            return [], ''

        chain_nodes: list[dict[str, Any]] = []
        used_saved_chain = False
        if (not ignore_saved_flow) and (not preset_steps):
            try:
                meta = payload.get('metadata') if isinstance(payload, dict) else None
                flow_meta = meta.get('flow') if isinstance(meta, dict) else None
                chain_nodes, _saved_chain_source = _saved_chain_nodes_from_flow_state(flow_meta, max_length=length)
                if chain_nodes:
                    used_saved_chain = True
            except Exception:
                chain_nodes = []

        if not chain_nodes:
            if preset_steps:
                chain_nodes = backend._pick_flag_chain_nodes_for_preset(nodes, adj, steps=preset_steps)
            else:
                if allow_node_duplicates:
                    try:
                        seed_val = int((preview.get('seed') if isinstance(preview, dict) else None) or 0)
                    except Exception:
                        seed_val = 0
                    chain_nodes = backend._pick_flag_chain_nodes_allow_duplicates(nodes, adj, length=length, seed=seed_val)
                else:
                    chain_nodes = backend._pick_flag_chain_nodes(nodes, adj, length=length)

        warning: str | None = None
        if used_saved_chain:
            try:
                eff = len(chain_nodes)
                if eff > 0:
                    length = eff
            except Exception:
                pass
        if (not used_saved_chain) and (not preset_steps) and best_effort_query:
            try:
                available = len(chain_nodes)
            except Exception:
                available = 0
            if available > 0 and available < length:
                warning = f'Only {available} eligible nodes found; using chain length {available} instead of requested {length}.'
                length = available

        topology_inclusion_info: dict[str, Any] = {
            'requested': {
                'include_all_topology_vulns': bool(include_all_topology_vulns),
                'include_all_topology_pivots': bool(include_all_topology_pivots),
            },
            'added_node_ids': [],
            'added_vuln_node_ids': [],
            'added_pivot_node_ids': [],
            'effective_length': len(chain_nodes or []),
        }
        if (not preset_steps) and (include_all_topology_vulns or include_all_topology_pivots):
            chain_nodes, topology_inclusion_info = backend._flow_expand_chain_for_topology_requirements(
                nodes,
                chain_nodes,
                preview,
                include_all_topology_vulns=include_all_topology_vulns,
                include_all_topology_pivots=include_all_topology_pivots,
                pivot_context=payload,
            )
            length = max(length, len(chain_nodes or []))
        elif preset_steps and (include_all_topology_vulns or include_all_topology_pivots):
            topology_inclusion_info['ignored'] = 'preset'

        try:
            host_by_id: dict[str, dict[str, Any]] = {}
            hosts = preview.get('hosts') if isinstance(preview, dict) else None
            if isinstance(hosts, list):
                for host in hosts:
                    if not isinstance(host, dict):
                        continue
                    hid = str(host.get('node_id') or host.get('id') or '').strip()
                    if hid:
                        host_by_id[hid] = host
            if host_by_id:
                for node in (chain_nodes or []):
                    if not isinstance(node, dict):
                        continue
                    nid = str(node.get('id') or '').strip()
                    if not nid:
                        continue
                    host = host_by_id.get(nid)
                    if not isinstance(host, dict):
                        continue
                    try:
                        ip_val = _effective_host_ip(nid, host)
                    except Exception:
                        ip_val = ''
                    if ip_val:
                        node['ip4'] = ip_val
                        node['ipv4'] = ip_val
                    try:
                        ifaces = host.get('interfaces') if isinstance(host.get('interfaces'), list) else None
                    except Exception:
                        ifaces = None
                    if ifaces and not node.get('interfaces'):
                        node['interfaces'] = ifaces
        except Exception:
            host_by_id = {}

        host_ip_map: dict[str, str] = {}
        try:
            for hid, host in (host_by_id or {}).items():
                ip_val = _effective_host_ip(str(hid), host)
                if ip_val:
                    host_ip_map[str(hid)] = ip_val
        except Exception:
            host_ip_map = {}

        flag_assignments: list[dict[str, Any]] = []
        flow_state_from_xml: dict[str, Any] | None = None
        try:
            if not ignore_saved_flow:
                flow_state_from_xml = backend._flow_state_from_xml_path(preview_plan_path, scenario_label or scenario_norm)
            if flow_state_from_xml:
                candidate_nodes, _saved_flow_source = _saved_chain_nodes_from_flow_state(flow_state_from_xml)
                if candidate_nodes:
                    chain_nodes = candidate_nodes
                    fas = flow_state_from_xml.get('flag_assignments') if isinstance(flow_state_from_xml, dict) else None
                    if isinstance(fas, list) and fas:
                        ordered: list[dict[str, Any]] = []
                        for idx in range(len(chain_nodes)):
                            assignment = fas[idx] if idx < len(fas) else {}
                            if not isinstance(assignment, dict):
                                ordered.append({})
                                continue
                            assignment_copy = dict(assignment)
                            try:
                                assignment_copy['node_id'] = str((chain_nodes[idx] or {}).get('id') or '').strip()
                            except Exception:
                                pass
                            ordered.append(assignment_copy)
                        flag_assignments = ordered
                        try:
                            flag_assignments = backend._flow_enrich_saved_flag_assignments(
                                flag_assignments,
                                chain_nodes,
                                scenario_label=(scenario_label or scenario_norm),
                            )
                        except Exception:
                            pass
        except Exception:
            flow_state_from_xml = None
        try:
            pass
        except Exception:
            flag_assignments = []

        initial_facts_override: dict[str, list[str]] | None = None
        goal_facts_override: dict[str, list[str]] | None = None
        try:
            flow_for_facts = flow_state_from_xml if isinstance(flow_state_from_xml, dict) else None
            if isinstance(flow_for_facts, dict):
                initial_facts_override = backend._flow_normalize_fact_override(flow_for_facts.get('initial_facts'))
                goal_facts_override = backend._flow_normalize_fact_override(flow_for_facts.get('goal_facts'))
        except Exception:
            initial_facts_override = None
            goal_facts_override = None

        if not flag_assignments:
            if preset_steps and not used_saved_chain:
                preset_assignments, preset_err = backend._flow_compute_flag_assignments_for_preset(
                    preview,
                    chain_nodes,
                    scenario_label or scenario_norm,
                    preset,
                    pivot_context=payload,
                )
                if preset_err:
                    return jsonify({'ok': False, 'error': f'Error: {preset_err}', 'stats': stats, 'preview_plan_path': preview_plan_path}), 422
                flag_assignments = preset_assignments
            else:
                flag_assignments = backend._flow_compute_flag_assignments(
                    preview,
                    chain_nodes,
                    scenario_label or scenario_norm,
                    initial_facts_override=initial_facts_override,
                    goal_facts_override=goal_facts_override,
                    disallow_generator_reuse=(not allow_node_duplicates),
                    dependency_level=dependency_level,
                    pivot_context=payload,
                )
                if (not flag_assignments) and (not allow_node_duplicates):
                    flag_assignments = backend._flow_compute_flag_assignments(
                        preview,
                        chain_nodes,
                        scenario_label or scenario_norm,
                        initial_facts_override=initial_facts_override,
                        goal_facts_override=goal_facts_override,
                        disallow_generator_reuse=False,
                        dependency_level=dependency_level,
                        pivot_context=payload,
                    )
                    if flag_assignments:
                        try:
                            warning = warning or 'Not enough unique generators for this chain length; generator reuse was enabled.'
                        except Exception:
                            pass

        if not flag_assignments and chain_nodes:
            try:
                gens_enabled, _ = backend._flag_generators_from_enabled_sources()
            except Exception:
                gens_enabled = []
            try:
                node_gens_enabled, _ = backend._flag_node_generators_from_enabled_sources()
            except Exception:
                node_gens_enabled = []
            try:
                gens_enabled = [g for g in (gens_enabled or []) if isinstance(g, dict) and str(g.get('id') or '').strip()]
                node_gens_enabled = [g for g in (node_gens_enabled or []) if isinstance(g, dict) and str(g.get('id') or '').strip()]
            except Exception:
                gens_enabled = []
                node_gens_enabled = []

            fallback: list[dict[str, Any]] = []
            if gens_enabled or node_gens_enabled:
                for node in (chain_nodes or []):
                    if not isinstance(node, dict):
                        continue
                    nid = str(node.get('id') or '').strip()
                    if not nid:
                        continue
                    is_vuln = backend._flow_node_is_vuln(node)
                    is_docker = backend._flow_node_is_docker_role(node)
                    if is_vuln and gens_enabled:
                        gen = gens_enabled[0]
                        fallback.append({
                            'node_id': nid,
                            'id': str(gen.get('id') or ''),
                            'name': str(gen.get('name') or ''),
                            'type': 'flag-generator',
                            'flag_generator': str(gen.get('_source_name') or gen.get('source') or '').strip() or 'unknown',
                            'generator_catalog': 'flag_generators',
                        })
                    elif (not is_vuln) and is_docker and node_gens_enabled:
                        gen = node_gens_enabled[0]
                        fallback.append({
                            'node_id': nid,
                            'id': str(gen.get('id') or ''),
                            'name': str(gen.get('name') or ''),
                            'type': 'flag-node-generator',
                            'flag_generator': str(gen.get('_source_name') or gen.get('source') or '').strip() or 'unknown',
                            'generator_catalog': 'flag_node_generators',
                        })
            if fallback and len(fallback) == len(chain_nodes):
                flag_assignments = fallback

        try:
            flag_assignments = backend._flow_apply_pivot_context_to_assignments(
                flag_assignments,
                chain_nodes,
                preview=preview,
                pivot_context=payload,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            pass

        try:
            node_ids = [str(n.get('id') or '').strip() for n in (chain_nodes or []) if isinstance(n, dict) and str(n.get('id') or '').strip()]
            has_dupes = len(set(node_ids)) != len(node_ids)
        except Exception:
            has_dupes = False

        if (not used_saved_chain) and (not preset_steps) and (not has_dupes):
            debug_dag = str(request.args.get('debug_dag') or '').strip().lower() in ('1', 'true', 'yes', 'y')
            chain_nodes, flag_assignments, dag_debug = backend._flow_reorder_chain_by_generator_dag(
                chain_nodes,
                flag_assignments,
                scenario_label=(scenario_label or scenario_norm),
                dependency_level=dependency_level,
                return_debug=bool(debug_dag),
            )
        else:
            debug_dag = str(request.args.get('debug_dag') or '').strip().lower() in ('1', 'true', 'yes', 'y')
            dag_debug = None

        try:
            flag_assignments = backend._flow_apply_pivot_context_to_assignments(
                flag_assignments,
                chain_nodes,
                preview=preview,
                pivot_context=payload,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            pass

        try:
            if isinstance(flag_assignments, list) and isinstance(chain_nodes, list):
                desired_len = len(chain_nodes)
                if desired_len:
                    if len(flag_assignments) != desired_len:
                        flag_assignments = list(flag_assignments[:desired_len])
                        while len(flag_assignments) < desired_len:
                            flag_assignments.append({})
                    for idx in range(desired_len):
                        assignment = flag_assignments[idx]
                        if not isinstance(assignment, dict):
                            assignment = {}
                            flag_assignments[idx] = assignment
                        try:
                            nid = str((chain_nodes[idx] or {}).get('id') or '').strip()
                        except Exception:
                            nid = ''
                        if nid:
                            assignment.setdefault('node_id', nid)
        except Exception:
            pass

        try:
            for assignment in (flag_assignments or []):
                if not isinstance(assignment, dict):
                    continue
                existing = assignment.get('inject_files') if isinstance(assignment.get('inject_files'), list) else []
                if any(str(x or '').strip() for x in (existing or [])):
                    continue
                gid = str(assignment.get('id') or assignment.get('generator_id') or '').strip()
                if not gid:
                    continue
                gen_def = backend._gen_by_id.get(gid) if isinstance(backend._gen_by_id, dict) else None
                if not isinstance(gen_def, dict):
                    continue
                inject_files = gen_def.get('inject_files')
                if isinstance(inject_files, list) and inject_files:
                    assignment['inject_files'] = [str(x or '').strip() for x in inject_files if str(x or '').strip()]
                if not assignment.get('inject_candidate_paths'):
                    candidate_paths = gen_def.get('inject_candidate_paths')
                    if isinstance(candidate_paths, list) and candidate_paths:
                        assignment['inject_candidate_paths'] = [
                            str(x or '').strip().rstrip('/') or '/'
                            for x in candidate_paths
                            if str(x or '').strip().startswith('/')
                        ]
        except Exception:
            pass

        if not flag_assignments:
            flow_valid = False
            flow_errors = ['missing flag assignments']
            try:
                gens_enabled, _ = backend._flag_generators_from_enabled_sources()
            except Exception:
                gens_enabled = []
            try:
                node_gens_enabled, _ = backend._flag_node_generators_from_enabled_sources()
            except Exception:
                node_gens_enabled = []
            try:
                eligible_flag_gens = len([g for g in (gens_enabled or []) if isinstance(g, dict)])
            except Exception:
                eligible_flag_gens = 0
            try:
                eligible_node_gens = len([g for g in (node_gens_enabled or []) if isinstance(g, dict)])
            except Exception:
                eligible_node_gens = 0
            try:
                vuln_nodes = len([n for n in (chain_nodes or []) if isinstance(n, dict) and backend._flow_node_is_vuln(n)])
            except Exception:
                vuln_nodes = 0
            try:
                docker_nodes = len([n for n in (chain_nodes or []) if isinstance(n, dict) and backend._flow_node_is_docker_role(n)])
            except Exception:
                docker_nodes = 0
            flow_errors.extend([
                f'eligible_flag_generators={eligible_flag_gens}',
                f'eligible_flag_node_generators={eligible_node_gens}',
                f'chain_nodes={len(chain_nodes or [])}',
                f'chain_vuln_nodes={vuln_nodes}',
                f'chain_docker_nodes={docker_nodes}',
            ])
        else:
            flow_valid, flow_errors = backend._flow_validate_chain_order_by_requires_produces(
                chain_nodes,
                flag_assignments,
                scenario_label=(scenario_label or scenario_norm),
            )
            if flag_assignments:
                try:
                    id_map_nodes = {
                        str(n.get('id') or '').strip(): n
                        for n in (chain_nodes or [])
                        if isinstance(n, dict) and str(n.get('id') or '').strip()
                    }
                    for idx, assignment in enumerate(flag_assignments):
                        if not isinstance(assignment, dict):
                            continue
                        kind = str(assignment.get('type') or 'flag-generator').strip() or 'flag-generator'
                        nid = str(assignment.get('node_id') or '').strip()
                        if not nid and idx < len(chain_nodes) and isinstance(chain_nodes[idx], dict):
                            nid = str(chain_nodes[idx].get('id') or '').strip()
                        node = id_map_nodes.get(nid) if nid else None
                        if not isinstance(node, dict):
                            continue
                        is_vuln_node = bool(backend._flow_node_is_vuln(node))
                        is_docker_node = bool(backend._flow_node_is_docker_role(node))
                        if kind == 'flag-generator' and not is_vuln_node:
                            return jsonify({
                                'ok': False,
                                'error': f'Generator assignment for node {nid} is incompatible: flag-generator requires vulnerability node.',
                            }), 422
                        if kind == 'flag-node-generator' and is_vuln_node:
                            return jsonify({
                                'ok': False,
                                'error': f'Generator assignment for node {nid} is incompatible: flag-node-generator cannot be placed on a vulnerability node (must be flag-generator).',
                            }), 422
                except Exception:
                    pass
            try:
                assign_ids = [str(a.get('id') or a.get('generator_id') or '').strip() for a in (flag_assignments or []) if isinstance(a, dict)]
                chain_ids_dbg = [str(n.get('id') or '').strip() for n in (chain_nodes or []) if isinstance(n, dict) and str(n.get('id') or '').strip()]
                flow_errors_detail = (
                    f'assignments={len(flag_assignments or [])} '
                    f'assignments_with_id={len([x for x in assign_ids if x])} '
                    f'chain_nodes={len(chain_nodes or [])} '
                    f'chain_ids={",".join(chain_ids_dbg)}'
                )
            except Exception:
                flow_errors_detail = None

        try:
            gens_enabled, _ = backend._flag_generators_from_enabled_sources()
        except Exception:
            gens_enabled = []
        try:
            node_gens_enabled, _ = backend._flag_node_generators_from_enabled_sources()
        except Exception:
            node_gens_enabled = []
        enabled_ids: set[str] = set()
        for gen in (gens_enabled or []):
            if isinstance(gen, dict):
                gid = str(gen.get('id') or '').strip()
                if gid:
                    enabled_ids.add(gid)
        for gen in (node_gens_enabled or []):
            if isinstance(gen, dict):
                gid = str(gen.get('id') or '').strip()
                if gid:
                    enabled_ids.add(gid)

        missing_refs: list[str] = []
        try:
            for assignment in (flag_assignments or []):
                if not isinstance(assignment, dict):
                    continue
                gid = str(assignment.get('id') or assignment.get('generator_id') or '').strip()
                if not gid:
                    continue
                if gid not in enabled_ids:
                    missing_refs.append(gid)
        except Exception:
            missing_refs = []

        missing_refs = sorted(list(dict.fromkeys(missing_refs)))
        if missing_refs:
            try:
                if not preset_steps:
                    flag_assignments = backend._flow_compute_flag_assignments(
                        preview,
                        chain_nodes,
                        scenario_label or scenario_norm,
                        initial_facts_override=initial_facts_override,
                        goal_facts_override=goal_facts_override,
                        dependency_level=dependency_level,
                        pivot_context=payload,
                    )
                    missing_refs = []
                    try:
                        for assignment in (flag_assignments or []):
                            if not isinstance(assignment, dict):
                                continue
                            gid = str(assignment.get('id') or assignment.get('generator_id') or '').strip()
                            if gid and gid not in enabled_ids:
                                missing_refs.append(gid)
                    except Exception:
                        missing_refs = []
                    missing_refs = sorted(list(dict.fromkeys(missing_refs)))
            except Exception:
                pass
        if missing_refs:
            flow_errors = list(flow_errors or []) + [f'generator not found/enabled: {gid}' for gid in missing_refs]
            flow_valid = False

        flags_enabled = bool(flow_valid)
        run_generators = bool(flags_enabled or (mode in {'resolve', 'resolve_hints', 'hint', 'hint_only'}))

        try:
            host_by_id = {}
            hosts = preview.get('hosts') if isinstance(preview, dict) else None
            if isinstance(hosts, list):
                for host in hosts:
                    if not isinstance(host, dict):
                        continue
                    hid = str(host.get('node_id') or '').strip()
                    if hid:
                        host_by_id[hid] = host
        except Exception:
            host_by_id = {}
        try:
            vuln_by_node = preview.get('vulnerabilities_by_node') if isinstance(preview, dict) else None
            if not isinstance(vuln_by_node, dict):
                vuln_by_node = {}
        except Exception:
            vuln_by_node = {}

        def _preview_host_ip4(host: dict) -> str:
            try:
                ip4 = host.get('ip4')
                if isinstance(ip4, str) and backend._first_valid_ipv4(ip4):
                    return backend._first_valid_ipv4(ip4)
            except Exception:
                pass
            for key in ('ipv4', 'ip', 'ip_addr', 'address'):
                try:
                    value = host.get(key)
                except Exception:
                    value = None
                ip_str = backend._first_valid_ipv4(value)
                if ip_str:
                    return ip_str
            try:
                for key in ('ips', 'addresses', 'ip4s', 'ipv4s'):
                    value = host.get(key)
                    ip_str = backend._first_valid_ipv4(value)
                    if ip_str:
                        return ip_str
            except Exception:
                pass
            try:
                ifaces = host.get('interfaces')
                if isinstance(ifaces, list):
                    for iface in ifaces:
                        if not isinstance(iface, dict):
                            continue
                        for key in ('ip4', 'ipv4', 'ip', 'ip_addr', 'address'):
                            ip_str = backend._first_valid_ipv4(iface.get(key))
                            if ip_str:
                                return ip_str
            except Exception:
                pass
            return ''

        try:
            for assignment in (flag_assignments or []):
                if not isinstance(assignment, dict):
                    continue
                nid = str(assignment.get('node_id') or '').strip()
                if not nid:
                    continue
                host = host_by_id.get(nid)
                preview_ip4 = _effective_host_ip(nid, host) or (_preview_host_ip4(host) if isinstance(host, dict) else '')
                if not preview_ip4:
                    try:
                        node = next((n for n in (chain_nodes or []) if isinstance(n, dict) and str(n.get('id') or '').strip() == nid), None)
                    except Exception:
                        node = None
                    if isinstance(node, dict):
                        preview_ip4 = backend._first_valid_ipv4(node.get('ip4') or node.get('ipv4') or node.get('ip') or '')
                if not preview_ip4:
                    continue
                resolved_inputs = assignment.get('resolved_inputs') if isinstance(assignment.get('resolved_inputs'), dict) else None
                if resolved_inputs is None:
                    resolved_inputs = {}
                    assignment['resolved_inputs'] = resolved_inputs
                resolved_inputs['Knowledge(ip)'] = preview_ip4
                resolved_inputs['target_ip'] = preview_ip4
                resolved_inputs['host_ip'] = preview_ip4
                resolved_inputs['ip4'] = preview_ip4
                resolved_inputs['ipv4'] = preview_ip4
        except Exception:
            pass

        if len(chain_nodes) < 1:
            return jsonify({'ok': False, 'error': 'No eligible nodes found in preview plan (vulnerability nodes only for flag-generators).', 'stats': stats, 'preview_plan_path': preview_plan_path}), 422
        if (not used_saved_chain) and (not allow_node_duplicates) and len(chain_nodes) < length:
            return jsonify({
                'ok': False,
                'error': f'Only {len(chain_nodes)} eligible nodes found for chain length {length}.',
                'available': len(chain_nodes),
                'stats': stats,
                'preview_plan_path': preview_plan_path,
            }), 422

        host_ip_map = {}
        try:
            for hid, host in (host_by_id or {}).items():
                ip_val = _effective_host_ip(str(hid), host) or (_preview_host_ip4(host) if isinstance(host, dict) else '')
                if ip_val:
                    host_ip_map[str(hid)] = ip_val
        except Exception:
            host_ip_map = {}

        chain_out: list[dict[str, Any]] = []
        try:
            for node in (chain_nodes or []):
                if not isinstance(node, dict):
                    continue
                nid = str(node.get('id') or '').strip()
                host = host_by_id.get(nid) if nid else None
                ip_val = _effective_host_ip(nid, host) or (_preview_host_ip4(host) if isinstance(host, dict) else '')
                if not ip_val:
                    ip_val = backend._first_valid_ipv4(node.get('ip4') or node.get('ipv4') or node.get('ip') or '')
                ifaces = None
                try:
                    ifaces = host.get('interfaces') if isinstance(host, dict) and isinstance(host.get('interfaces'), list) else None
                except Exception:
                    ifaces = None
                vulns: list[str] = []
                try:
                    if isinstance(host, dict) and isinstance(host.get('vulnerabilities'), list):
                        vulns = [str(v).strip() for v in (host.get('vulnerabilities') or []) if str(v).strip()]
                except Exception:
                    vulns = []
                if not vulns:
                    try:
                        if isinstance(node.get('vulnerabilities'), list):
                            vulns = [str(v).strip() for v in (node.get('vulnerabilities') or []) if str(v).strip()]
                    except Exception:
                        vulns = []
                if (not vulns) and nid:
                    try:
                        raw_v = vuln_by_node.get(nid)
                        if isinstance(raw_v, list):
                            vulns = [str(v).strip() for v in raw_v if str(v).strip()]
                    except Exception:
                        vulns = []
                is_vuln = bool(vulns) or bool(node.get('is_vuln')) or bool(node.get('is_vulnerability')) or bool(node.get('is_vulnerable'))
                chain_out.append({
                    'id': str(node.get('id') or ''),
                    'name': str(node.get('name') or ''),
                    'type': str(node.get('type') or ''),
                    'is_vuln': bool(is_vuln),
                    'vulnerabilities': list(vulns or []),
                    'ip4': str(ip_val or ''),
                    'ipv4': str(ip_val or ''),
                    'interfaces': list(ifaces or []) if isinstance(ifaces, list) else [],
                })
        except Exception:
            chain_out = [{'id': str(n.get('id') or ''), 'name': str(n.get('name') or ''), 'type': str(n.get('type') or ''), 'is_vuln': bool(n.get('is_vuln'))} for n in (chain_nodes or []) if isinstance(n, dict)]

        def _participant_network_setup_from_preview(full_preview: Any) -> dict[str, Any]:
            if not isinstance(full_preview, dict):
                return {'items': []}

            def _clean(value: Any) -> str:
                try:
                    text = str(value or '').strip()
                except Exception:
                    return ''
                return '' if text.lower() in {'', 'none', 'null', 'n/a', '-'} else text

            def _first(*values: Any) -> str:
                for value in values:
                    text = _clean(value)
                    if text:
                        return text
                return ''

            def _strip_cidr(value: Any) -> str:
                text = _clean(value)
                return text.split('/', 1)[0].strip() if '/' in text else text

            def _prefix(value: Any) -> str:
                try:
                    if value is None:
                        return ''
                    parsed = int(str(value).strip())
                    if 0 <= parsed <= 32:
                        return str(parsed)
                except Exception:
                    return ''
                return ''

            def _address_cidr(ip_value: Any, prefix_value: Any, cidr_value: Any = None) -> str:
                cidr_text = _clean(cidr_value)
                if cidr_text and '/' in cidr_text:
                    return cidr_text
                ip_text = _strip_cidr(ip_value or cidr_text)
                prefix_text = _prefix(prefix_value)
                if ip_text and prefix_text:
                    return f'{ip_text}/{prefix_text}'
                return cidr_text or ip_text

            interfaces = full_preview.get('hitl_interfaces')
            if not isinstance(interfaces, list):
                hitl_cfg = full_preview.get('hitl_config') or full_preview.get('hitl')
                interfaces = hitl_cfg.get('interfaces') if isinstance(hitl_cfg, dict) else []
            items: list[dict[str, Any]] = []
            for idx, iface in enumerate(interfaces or []):
                if not isinstance(iface, dict):
                    continue
                external = iface.get('external_vm') if isinstance(iface.get('external_vm'), dict) else {}
                attachment = _clean(iface.get('attachment')).lower()
                iface_name = _first(
                    external.get('interface_name'),
                    external.get('ifname'),
                    external.get('guest_ifname'),
                    iface.get('participant_interface'),
                    iface.get('participant_ifname'),
                    iface.get('name'),
                    iface.get('slug'),
                    f'iface-{idx + 1}',
                )
                prefix_len = _prefix(iface.get('prefix_len')) or _prefix(iface.get('prefix'))
                participant_ip = _first(
                    iface.get('participant_ip4'),
                    iface.get('rj45_ip4'),
                    iface.get('ip4'),
                    iface.get('ipv4'),
                )
                if not participant_ip:
                    ip_list = iface.get('ipv4')
                    if isinstance(ip_list, list) and ip_list:
                        participant_ip = _first(ip_list[0])
                address_cidr = _address_cidr(
                    participant_ip,
                    prefix_len,
                    _first(iface.get('participant_ip4_cidr'), iface.get('rj45_ip4_cidr')),
                )
                if not prefix_len and '/' in address_cidr:
                    prefix_len = address_cidr.split('/', 1)[1].strip()
                gateway = _first(iface.get('default_gateway_ip4'), iface.get('gateway_ip4'))
                if not gateway:
                    if attachment == 'existing_router':
                        gateway = _first(iface.get('existing_router_ip4'))
                    elif attachment == 'new_router':
                        gateway = _first(iface.get('new_router_ip4'))
                if not gateway:
                    gateway = _first(iface.get('existing_router_ip4'), iface.get('new_router_ip4'))
                gateway = _strip_cidr(gateway)
                if not any((iface_name, address_cidr, gateway)):
                    continue
                items.append({
                    'interface': iface_name,
                    'address_cidr': address_cidr,
                    'ip4': _strip_cidr(participant_ip or address_cidr),
                    'prefix_len': prefix_len,
                    'default_gateway': gateway,
                    'attachment': attachment,
                    'network_cidr': _first(iface.get('link_network_cidr'), iface.get('link_network')),
                })
            return {'items': items, 'source': 'preview.hitl_interfaces' if items else ''}

        participant_network_setup = _participant_network_setup_from_preview(preview)

        def _preview_summary_from_preview(full_preview: Any) -> dict[str, Any]:
            if not isinstance(full_preview, dict):
                return {}

            def _as_list(value: Any) -> list[Any]:
                return value if isinstance(value, list) else []

            hosts = [item for item in _as_list(full_preview.get('hosts')) if isinstance(item, dict)]
            routers = [item for item in _as_list(full_preview.get('routers')) if isinstance(item, dict)]
            switches = [item for item in _as_list(full_preview.get('switches')) if isinstance(item, dict)]
            docker_hosts = [
                item for item in hosts
                if str(item.get('role') or '').strip().lower() == 'docker'
            ]
            vuln_hosts = [
                item for item in hosts
                if isinstance(item.get('vulnerabilities'), list) and item.get('vulnerabilities')
            ]
            hitl_interfaces = []
            for iface in _as_list(full_preview.get('hitl_interfaces')):
                if not isinstance(iface, dict):
                    continue
                hitl_interfaces.append({
                    'name': iface.get('name'),
                    'attachment': iface.get('attachment'),
                    'rj45_ip4': iface.get('rj45_ip4'),
                    'rj45_ip4_cidr': iface.get('rj45_ip4_cidr'),
                    'existing_router_ip4': iface.get('existing_router_ip4'),
                    'new_router_ip4': iface.get('new_router_ip4'),
                    'link_network_cidr': iface.get('link_network_cidr') or iface.get('link_network'),
                    'prefix_len': iface.get('prefix_len'),
                })
            segmentation_preview = full_preview.get('segmentation_preview')
            seg_rules = None
            if isinstance(segmentation_preview, dict):
                rules_val = segmentation_preview.get('rules')
                if isinstance(rules_val, list):
                    seg_rules = len(rules_val)
                elif segmentation_preview.get('rules_count') is not None:
                    seg_rules = segmentation_preview.get('rules_count')
            return {
                'counts': {
                    'hosts': len(hosts),
                    'routers': len(routers),
                    'switches': len(switches),
                    'docker_hosts': len(docker_hosts),
                    'vulnerability_hosts': len(vuln_hosts),
                    'total_nodes': len(hosts) + len(routers) + len(switches),
                },
                'lan_subnets': _as_list(full_preview.get('lan_subnets') or full_preview.get('router_switch_subnets')),
                'ip_allocation_mode': full_preview.get('ip_allocation_mode'),
                'hitl_enabled': bool(full_preview.get('hitl_enabled') or hitl_interfaces),
                'hitl_interfaces': hitl_interfaces,
                'segmentation_rules': seg_rules,
                'seed': full_preview.get('seed'),
                'routing_plan': full_preview.get('routing_plan') if isinstance(full_preview.get('routing_plan'), dict) else {},
            }

        preview_summary = _preview_summary_from_preview(preview)

        out = {
            'ok': True,
            'scenario': scenario_label or scenario_norm,
            'length': length,
            'requested_length': requested_length,
            'preview_plan_path': preview_plan_path,
            'chain': chain_out,
            'flag_assignments': flag_assignments,
            'stats': stats,
            'flow_valid': bool(flow_valid),
            'flow_errors': list(flow_errors or []),
            **({'flow_errors_detail': flow_errors_detail} if flow_errors_detail else {}),
            'flags_enabled': bool(flags_enabled),
            'allow_node_duplicates': bool(allow_node_duplicates),
            'include_all_topology_vulns': bool(include_all_topology_vulns),
            'include_all_topology_pivots': bool(include_all_topology_pivots),
            'topology_inclusion': dict(topology_inclusion_info or {}),
            'dependency_level': dependency_level,
            'participant_network_setup': participant_network_setup,
            'preview_summary': preview_summary,
            **({'host_ip_map': host_ip_map} if host_ip_map else {}),
        }
        if flow_errors_detail:
            out['flow_errors_detail'] = flow_errors_detail
        try:
            if not flow_valid:
                app.logger.warning('[flow.attackflow_preview] invalid flow: %s', (flow_errors_detail or (flow_errors or [])))
        except Exception:
            pass
        if initial_facts_override:
            out['initial_facts'] = initial_facts_override
        if goal_facts_override:
            out['goal_facts'] = goal_facts_override
        if warning:
            out['warning'] = warning
        if debug_mode:
            try:
                meta_dbg = payload.get('metadata') if isinstance(payload, dict) else None
            except Exception:
                meta_dbg = None
            out['debug'] = {
                'selected_by': selected_by,
                'prefer_preview': bool(prefer_preview),
                'force_preview': bool(force_preview),
                'ignore_saved_flow': bool(ignore_saved_flow),
                'used_saved_chain': bool(used_saved_chain),
                'preview_plan_path': preview_plan_path,
                'metadata': (meta_dbg if isinstance(meta_dbg, dict) else {}),
            }
        if debug_dag:
            out['sequencer_dag'] = dag_debug or {'ok': False, 'errors': ['not computed (saved chain)']}

        try:
            try:
                plan_basename = os.path.basename(str(preview_plan_path or ''))
            except Exception:
                plan_basename = str(preview_plan_path or '')
            try:
                preview_seed = (payload.get('metadata') or {}).get('seed') if isinstance(payload, dict) else None
            except Exception:
                preview_seed = None
            if preview_seed is None:
                try:
                    preview_seed = preview.get('seed') if isinstance(preview, dict) else None
                except Exception:
                    preview_seed = None
            app.logger.info(
                '[flow.attackflow_preview] scenario=%s chain_len=%s flow_valid=%s flow_errors=%s selected_by=%s plan=%s seed=%s',
                scenario_norm,
                len(chain_nodes or []),
                bool(flow_valid),
                (flow_errors or []),
                selected_by,
                plan_basename,
                preview_seed,
            )
        except Exception:
            pass

        return jsonify(out)

    mark_routes_registered(app, 'flag_sequencing_attackflow_preview_routes')