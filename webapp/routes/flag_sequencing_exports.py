from __future__ import annotations

from typing import Any

from flask import jsonify, request

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_exports_routes'):
        return

    backend = backend_module

    @app.route('/api/flag-sequencing/afb_from_chain', methods=['POST'])
    def api_flow_afb_from_chain():
        payload = request.get_json(silent=True) or {}
        scenario_label = str(payload.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        if not scenario_norm:
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400

        chain = payload.get('chain')
        if not isinstance(chain, list) or not chain:
            return jsonify({'ok': False, 'error': 'Missing chain.'}), 400

        chain_nodes: list[dict[str, Any]] = []
        for node in chain:
            if not isinstance(node, dict):
                continue
            node_id = str(node.get('id') or '').strip()
            if not node_id:
                continue
            is_vuln = False
            try:
                is_vuln = bool(node.get('is_vuln')) or bool(node.get('is_vulnerability')) or bool(node.get('is_vulnerable'))
            except Exception:
                is_vuln = False
            try:
                vulnerabilities = node.get('vulnerabilities') if isinstance(node.get('vulnerabilities'), list) else None
            except Exception:
                vulnerabilities = None
            chain_node = {
                'id': node_id,
                'name': str(node.get('name') or node_id),
                'type': str(node.get('type') or ''),
                'compose': str(node.get('compose') or ''),
                'compose_name': str(node.get('compose_name') or ''),
                'is_vuln': bool(is_vuln),
                **({'vulnerabilities': list(vulnerabilities or [])} if vulnerabilities else {}),
            }
            for extra_key in (
                'label',
                'hostname',
                'host_name',
                'docker_name',
                'container_name',
                'service_name',
                'ipv4',
                'ip4',
                'ip',
                'PivotProduces',
                'PivotRequires',
                'pivot',
                'pivot_rules',
                'pivot_source',
                'pivot_target',
                'pivot_sources',
                'pivot_targets',
            ):
                try:
                    if extra_key in node:
                        chain_node[extra_key] = node.get(extra_key)
                except Exception:
                    continue
            chain_nodes.append(chain_node)
        if not chain_nodes:
            return jsonify({'ok': False, 'error': 'Chain contained no valid nodes.'}), 400

        def _assignment_has_generator(assignment: dict[str, Any]) -> bool:
            if not isinstance(assignment, dict):
                return False
            try:
                return bool(str(assignment.get('id') or assignment.get('generator_id') or '').strip())
            except Exception:
                return False

        def _align_assignments_to_chain(assignments: Any) -> list[dict[str, Any]]:
            if not isinstance(assignments, list) or not assignments:
                return []
            assignment_by_node: dict[str, dict[str, Any]] = {}
            for assignment in assignments:
                if not isinstance(assignment, dict):
                    continue
                node_id = str(assignment.get('node_id') or '').strip()
                if node_id and node_id not in assignment_by_node:
                    assignment_by_node[node_id] = assignment

            aligned: list[dict[str, Any]] = []
            for index, node in enumerate(chain_nodes):
                node_id = str((node or {}).get('id') or '').strip()
                source = assignment_by_node.get(node_id) if node_id else None
                if source is None and index < len(assignments) and isinstance(assignments[index], dict):
                    source = assignments[index]
                if not isinstance(source, dict):
                    aligned.append({})
                    continue
                assignment_copy = dict(source)
                if node_id:
                    assignment_copy['node_id'] = node_id
                aligned.append(assignment_copy)
            return aligned

        def _complete_assignment_set(assignments: list[dict[str, Any]]) -> bool:
            return bool(assignments) and len(assignments) == len(chain_nodes) and all(_assignment_has_generator(a) for a in assignments)

        request_assignments = _align_assignments_to_chain(payload.get('flag_assignments'))

        flow_assignments_from_plan: list[dict[str, Any]] = []
        try:
            flow_meta = None
            xml_hint = str(payload.get('xml_path') or payload.get('preview_plan_path') or payload.get('preview_plan') or '').strip()
            if xml_hint:
                try:
                    xml_abs = backend.os.path.abspath(xml_hint)
                    if backend.os.path.exists(xml_abs):
                        reader = getattr(backend, '_flow_state_from_xml_path', None)
                        if callable(reader):
                            flow_meta = reader(xml_abs, scenario_label or scenario_norm)
                except Exception:
                    flow_meta = None
            if flow_meta is None:
                flow_meta = backend._flow_state_from_latest_xml(scenario_norm)
            saved_assignments = (flow_meta or {}).get('flag_assignments') if isinstance(flow_meta, dict) else None
            if isinstance(saved_assignments, list) and saved_assignments:
                ordered = _align_assignments_to_chain(saved_assignments)
                if _complete_assignment_set(ordered):
                    flow_assignments_from_plan = ordered
        except Exception:
            flow_assignments_from_plan = []

        flag_assignments: list[dict[str, Any]] = list(request_assignments) if _complete_assignment_set(request_assignments) else []
        preview: dict[str, Any] | None = None
        preview_payload: dict[str, Any] | None = None
        try:
            plan_path = str(payload.get('preview_plan_path') or payload.get('preview_plan') or payload.get('xml_path') or '').strip() or None
            if plan_path:
                try:
                    plan_path = backend.os.path.abspath(plan_path)
                except Exception:
                    pass
                try:
                    if not backend.os.path.exists(plan_path):
                        plan_path = None
                except Exception:
                    plan_path = None
            try:
                entry = backend._planner_get_plan(scenario_norm)
                if (not plan_path) and entry:
                    plan_path = entry.get('plan_path') or plan_path
            except Exception:
                plan_path = plan_path
            if not plan_path:
                plan_path = backend._latest_preview_plan_for_scenario_norm_origin(scenario_norm, origin='planner')
            if not plan_path:
                plan_path = backend._latest_preview_plan_for_scenario_norm(scenario_norm)
            if plan_path and backend.os.path.exists(plan_path):
                preview_payload = backend._load_preview_payload_from_path(plan_path, scenario_label or scenario_norm)
                if not isinstance(preview_payload, dict):
                    preview_payload = {}

                flow_meta_from_plan = None
                try:
                    if isinstance(preview_payload, dict):
                        backend._attach_latest_flow_into_plan_payload(preview_payload, scenario=(scenario_label or scenario_norm))
                        metadata = preview_payload.get('metadata') if isinstance(preview_payload.get('metadata'), dict) else {}
                        flow_meta_from_plan = metadata.get('flow') if isinstance(metadata, dict) else None
                except Exception:
                    flow_meta_from_plan = None

                try:
                    metadata = preview_payload.get('metadata') if isinstance(preview_payload, dict) else None
                    flow_meta = (metadata or {}).get('flow') if isinstance(metadata, dict) else None
                    flow_assignments = flow_meta.get('flag_assignments') if isinstance(flow_meta, dict) else None
                    if (not flag_assignments) and isinstance(flow_assignments, list) and flow_assignments:
                        aligned = _align_assignments_to_chain(flow_assignments)
                        if _complete_assignment_set(aligned):
                            flag_assignments = aligned
                except Exception:
                    pass

                if flow_meta_from_plan and isinstance(preview_payload, dict):
                    metadata_out = preview_payload.get('metadata') if isinstance(preview_payload.get('metadata'), dict) else {}
                    metadata_out = dict(metadata_out or {})
                    metadata_out['flow'] = flow_meta_from_plan
                    preview_payload['metadata'] = metadata_out
                preview = preview_payload.get('full_preview') if isinstance(preview_payload, dict) else None
                if isinstance(preview, dict):
                    try:
                        id_to_ipv4: dict[str, str] = {}
                        id_to_vuln: dict[str, dict[str, Any]] = {}
                        hosts = preview.get('hosts') if isinstance(preview.get('hosts'), list) else []
                        for host in hosts:
                            if not isinstance(host, dict):
                                continue
                            host_id = str(host.get('node_id') or host.get('id') or '').strip()
                            if not host_id:
                                continue
                            ip_value = host.get('ipv4')
                            if ip_value is None:
                                ip_value = host.get('ip4')
                            if ip_value is None:
                                ip_value = host.get('ip')
                            ip_str = backend._first_valid_ipv4(ip_value)
                            if ip_str:
                                id_to_ipv4[host_id] = ip_str
                            try:
                                vulnerabilities = host.get('vulnerabilities') if isinstance(host.get('vulnerabilities'), list) else None
                            except Exception:
                                vulnerabilities = None
                            try:
                                is_vuln = bool(host.get('is_vuln')) or bool(host.get('is_vulnerability')) or bool(host.get('is_vulnerable')) or bool(vulnerabilities)
                            except Exception:
                                is_vuln = bool(vulnerabilities)
                            if is_vuln or vulnerabilities:
                                id_to_vuln[host_id] = {
                                    'is_vuln': bool(is_vuln),
                                    'vulnerabilities': list(vulnerabilities or []),
                                }
                        if id_to_ipv4 or id_to_vuln:
                            for node in chain_nodes:
                                if not isinstance(node, dict):
                                    continue
                                node_id = str(node.get('id') or '').strip()
                                if not node_id:
                                    continue
                                if not str(node.get('ipv4') or '').strip() and node_id in id_to_ipv4:
                                    node['ipv4'] = id_to_ipv4[node_id]
                                if node_id in id_to_vuln:
                                    node_meta = id_to_vuln.get(node_id) or {}
                                    if 'is_vuln' not in node:
                                        node['is_vuln'] = bool(node_meta.get('is_vuln'))
                                    if 'vulnerabilities' not in node and node_meta.get('vulnerabilities'):
                                        node['vulnerabilities'] = list(node_meta.get('vulnerabilities') or [])
                    except Exception:
                        pass
                    if not flag_assignments:
                        try:
                            metadata = preview_payload.get('metadata') if isinstance(preview_payload, dict) else None
                            flow_meta = metadata.get('flow') if isinstance(metadata, dict) else None
                            initial_facts = backend._flow_normalize_fact_override(flow_meta.get('initial_facts')) if isinstance(flow_meta, dict) else None
                            goal_facts = backend._flow_normalize_fact_override(flow_meta.get('goal_facts')) if isinstance(flow_meta, dict) else None
                        except Exception:
                            initial_facts = None
                            goal_facts = None
                        flag_assignments = backend._flow_compute_flag_assignments(
                            preview,
                            chain_nodes,
                            scenario_label or scenario_norm,
                            initial_facts_override=initial_facts,
                            goal_facts_override=goal_facts,
                            pivot_context=preview_payload,
                        )
        except Exception:
            if not flag_assignments:
                flag_assignments = []

        if (not flag_assignments) and _complete_assignment_set(request_assignments):
            flag_assignments = request_assignments
        if (not flag_assignments) and flow_assignments_from_plan:
            flag_assignments = flow_assignments_from_plan

        try:
            flag_assignments = backend._flow_apply_pivot_context_to_assignments(
                flag_assignments,
                chain_nodes,
                preview=(preview if isinstance(preview, dict) else None),
                pivot_context=(preview_payload if isinstance(preview_payload, dict) else None),
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            pass

        try:
            initial_valid, initial_errors = backend._flow_validate_chain_order_by_requires_produces(
                chain_nodes,
                flag_assignments,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            initial_valid, initial_errors = True, []

        if (not initial_valid) and flag_assignments and any('before they are produced' in str(error or '') for error in (initial_errors or [])):
            try:
                dependency_level = None
                normalizer = getattr(backend, '_flow_normalize_dependency_level', None)
                if callable(normalizer):
                    dependency_level = normalizer(payload.get('dependency_level'))
                chain_nodes, flag_assignments, _dag_debug = backend._flow_reorder_chain_by_generator_dag(
                    chain_nodes,
                    flag_assignments,
                    scenario_label=(scenario_label or scenario_norm),
                    dependency_level=dependency_level,
                )
                flag_assignments = _align_assignments_to_chain(flag_assignments)
                flag_assignments = backend._flow_apply_pivot_context_to_assignments(
                    flag_assignments,
                    chain_nodes,
                    preview=(preview if isinstance(preview, dict) else None),
                    pivot_context=(preview_payload if isinstance(preview_payload, dict) else None),
                    scenario_label=(scenario_label or scenario_norm),
                )
            except Exception:
                pass

        try:
            flow_valid, flow_errors = backend._flow_validate_chain_order_by_requires_produces(
                chain_nodes,
                flag_assignments,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            flow_valid, flow_errors = True, []
        try:
            assignment_ids = [
                str(assignment.get('id') or assignment.get('generator_id') or '').strip()
                for assignment in (flag_assignments or [])
                if isinstance(assignment, dict)
            ]
            chain_ids_dbg = [
                str(node.get('id') or '').strip()
                for node in (chain_nodes or [])
                if isinstance(node, dict) and str(node.get('id') or '').strip()
            ]
            flow_errors_detail = (
                f"assignments={len(flag_assignments or [])} "
                f"assignments_with_id={len([value for value in assignment_ids if value])} "
                f"chain_nodes={len(chain_nodes or [])} "
                f"chain_ids={','.join(chain_ids_dbg)}"
            )
        except Exception:
            flow_errors_detail = None
        flags_enabled = bool(flow_valid)

        try:
            app.logger.info(
                '[flow.afb_from_chain] scenario=%s chain_len=%s flow_valid=%s flow_errors=%s detail=%s',
                scenario_norm,
                len(chain_nodes or []),
                bool(flow_valid),
                (flow_errors or []),
                (flow_errors_detail or ''),
            )
        except Exception:
            pass

        afb = backend._attack_flow_builder_afb_for_chain(
            chain_nodes=chain_nodes,
            scenario_label=scenario_label or scenario_norm,
            flag_assignments=flag_assignments,
        )
        attack_graph = backend._attack_graph_for_chain(
            chain_nodes=chain_nodes,
            scenario_label=scenario_label or scenario_norm,
            flag_assignments=flag_assignments,
        )
        attack_graph_dot = backend._attack_graph_dot(attack_graph)
        attack_graph_pdf_base64 = backend._attack_graph_pdf_base64(attack_graph_dot or '')
        return jsonify(
            {
                'ok': True,
                'scenario': scenario_label or scenario_norm,
                'length': len(chain_nodes),
                'chain': chain_nodes,
                'flag_assignments': flag_assignments,
                'afb': afb,
                'attack_graph': attack_graph,
                'attack_graph_dot': attack_graph_dot,
                'attack_graph_pdf_base64': attack_graph_pdf_base64,
                'flow_valid': bool(flow_valid),
                'flow_errors': list(flow_errors or []),
                'flags_enabled': bool(flags_enabled),
                **({'flow_errors_detail': flow_errors_detail} if flow_errors_detail else {}),
            }
        )

    mark_routes_registered(app, 'flag_sequencing_exports_routes')