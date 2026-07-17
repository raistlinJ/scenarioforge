from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any

from flask import Response, jsonify, request, stream_with_context

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend_module: Any) -> None:
    if not begin_route_registration(app, 'flag_sequencing_sequence_preview_routes'):
        return

    backend = backend_module

    # Sequencing can take minutes when a catalog is large.  A browser/network
    # timeout must not start another copy of the same mutating request: each
    # copy rescans the catalog and writes the same plan, making every active
    # request slower.  Keep one worker per request signature and let all
    # callers attach to its eventual result.
    _sequence_jobs_lock = threading.Lock()
    _sequence_jobs: dict[str, dict[str, Any]] = {}

    def _sequence_job_key(payload: dict[str, Any]) -> str:
        request_id = str((payload or {}).get('sequence_request_id') or '').strip()
        if request_id:
            # A request ID is stable only for one user-initiated Generate
            # action.  It lets retries attach to the same worker without
            # making a later deliberate Generate reuse an old random chain.
            return f'request:{request_id}'
        stable_payload = dict(payload or {})
        # progress_id identifies a caller/poll stream, not the work itself.
        stable_payload.pop('progress_id', None)
        try:
            encoded = json.dumps(stable_payload, sort_keys=True, separators=(',', ':'), default=str)
        except Exception:
            encoded = repr(sorted((str(key), repr(value)) for key, value in stable_payload.items()))
        return hashlib.sha256(encoded.encode('utf-8', errors='ignore')).hexdigest()

    def _run_sequence_preview_plan(payload_in: dict[str, Any]):
        """Generate a Flow chain from an existing preview plan and persist sequence metadata."""
        payload_in = payload_in if isinstance(payload_in, dict) else {}
        started_at = time.monotonic()
        progress_id = str(payload_in.get('progress_id') or '').strip()

        def _flow_progress(message: str) -> None:
            try:
                elapsed = max(0.0, time.monotonic() - started_at)
                prefix = f'progress_id={progress_id} ' if progress_id else ''
                app.logger.info('[flow.progress] %selapsed=%.2fs %s', prefix, elapsed, str(message or '').strip())
            except Exception:
                pass

        def _short_path(path_value: Any) -> str:
            try:
                text = str(path_value or '').strip()
                if not text:
                    return ''
                return backend.os.path.basename(text) or text
            except Exception:
                return str(path_value or '').strip()

        def _chain_ids(nodes_value: Any, *, limit: int = 16) -> str:
            try:
                ids = [str(node.get('id') or '').strip() for node in (nodes_value or []) if isinstance(node, dict) and str(node.get('id') or '').strip()]
                if len(ids) > limit:
                    return ','.join(ids[:limit]) + f',...(+{len(ids) - limit})'
                return ','.join(ids)
            except Exception:
                return ''

        def _assignment_ids(assignments_value: Any, *, limit: int = 16) -> str:
            try:
                ids = [str(assignment.get('id') or assignment.get('generator_id') or '').strip() for assignment in (assignments_value or []) if isinstance(assignment, dict) and str(assignment.get('id') or assignment.get('generator_id') or '').strip()]
                if len(ids) > limit:
                    return ','.join(ids[:limit]) + f',...(+{len(ids) - limit})'
                return ','.join(ids)
            except Exception:
                return ''

        scenario_label = str(payload_in.get('scenario') or '').strip()
        scenario_norm = backend._normalize_scenario_label(scenario_label)
        preset = str(payload_in.get('preset') or '').strip()
        allow_node_duplicates = str(payload_in.get('allow_node_duplicates') or payload_in.get('allow_duplicates') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        include_all_topology_pivots = str(payload_in.get('include_all_topology_pivots') or '').strip().lower() in ('1', 'true', 'yes', 'y')
        length = 5
        try:
            length = int(payload_in.get('length') or 5)
        except Exception:
            length = 5
        preset_steps = backend._flow_preset_steps(preset)
        if preset_steps:
            length = len(preset_steps)
        length = max(1, min(length, 50))
        requested_length = length
        # Flow expansion is deliberately staged.  No generic Docker host is
        # selected or added unless the browser has made a separate, explicit
        # confirmed request for that stage.
        expansion_mode_raw = str(payload_in.get('chain_expansion_mode') or 'strict').strip().lower()
        expansion_mode_aliases = {
            '': 'strict',
            'strict': 'strict',
            'topology_only': 'strict',
            'existing_docker': 'existing_docker',
            'add_docker': 'add_docker',
        }
        expansion_mode = expansion_mode_aliases.get(expansion_mode_raw, '')
        expansion_request_id = str(payload_in.get('expansion_request_id') or '').strip()
        expected_topology_fingerprint = str(payload_in.get('topology_fingerprint') or '').strip()
        dependency_level = backend._flow_normalize_dependency_level(payload_in.get('dependency_level'))

        _flow_progress(
            f"Sequence start: scenario={scenario_norm or scenario_label or '-'} length={length} "
            f"dependency={dependency_level}/5 preset={preset or 'random'} "
            f"duplicates={'on' if allow_node_duplicates else 'off'} "
            f"expansion={expansion_mode_raw or 'strict'} include_pivots={int(include_all_topology_pivots)}"
        )

        flow_seed_param: int | None = None
        try:
            flow_seed_raw = payload_in.get('flow_seed')
            if flow_seed_raw is not None:
                flow_seed_param = int(flow_seed_raw)
        except (ValueError, TypeError):
            flow_seed_param = None

        if not scenario_norm:
            _flow_progress('Validation failed: no scenario specified')
            return jsonify({'ok': False, 'error': 'No scenario specified.'}), 400

        def _validation_failure(message: str, **extra: Any):
            _flow_progress(f'Validation failed: {message}')
            failure_payload = {'ok': False, 'error': message, 'validation_error': True}
            failure_payload.update(extra)
            return jsonify(failure_payload)

        if not expansion_mode:
            return _validation_failure(
                'Unknown Flow expansion mode. Generate again from the Flag Sequencing page.',
                requested_mode=expansion_mode_raw,
            )

        _flow_progress('Phase: locating preview plan')
        preview_plan_path = str(payload_in.get('preview_plan') or '').strip() or None
        xml_hint = str(payload_in.get('xml_path') or '').strip()
        if preview_plan_path:
            try:
                preview_plan_path = backend.os.path.abspath(preview_plan_path)
                if (not preview_plan_path.lower().endswith('.xml')) or (not backend.os.path.exists(preview_plan_path)):
                    preview_plan_path = None
            except Exception:
                preview_plan_path = None

        if not preview_plan_path and xml_hint:
            try:
                xml_abs = backend.os.path.abspath(xml_hint)
                if backend.os.path.exists(xml_abs) and xml_abs.lower().endswith('.xml'):
                    payload_hint = backend._load_plan_preview_from_xml(xml_abs, scenario_norm)
                    if isinstance(payload_hint, dict):
                        meta_hint = payload_hint.get('metadata') if isinstance(payload_hint.get('metadata'), dict) else {}
                        scenario_hint = str(meta_hint.get('scenario') or '').strip()
                        if (not scenario_hint) or backend._normalize_scenario_label(scenario_hint) == scenario_norm:
                            preview_plan_path = xml_abs
            except Exception:
                pass

        if not preview_plan_path:
            preview_plan_path = backend._latest_xml_path_for_scenario(scenario_norm)

        if not preview_plan_path:
            _flow_progress('Validation failed: no XML/preview plan found')
            return jsonify({'ok': False, 'error': 'No XML found for this scenario. Save XML with a PlanPreview first.'}), 404

        try:
            _flow_progress(f'Phase: loading preview payload from {_short_path(preview_plan_path)}')
            payload = backend._load_preview_payload_from_path(preview_plan_path, scenario_norm)
            if not isinstance(payload, dict):
                _flow_progress('Validation failed: preview plan not embedded in XML')
                return jsonify({'ok': False, 'error': 'Preview plan not embedded in XML.'}), 422
            backend._canonicalize_payload_flow_from_xml(
                payload,
                xml_path=preview_plan_path,
                scenario_label=(scenario_label or scenario_norm),
            )
            try:
                backend._flow_attach_pivoting_plan_from_xml(
                    payload,
                    xml_path=preview_plan_path,
                    scenario_label=(scenario_label or scenario_norm),
                )
            except Exception:
                pass
        except Exception as exc:
            _flow_progress(f'Failed to load preview plan: {exc}')
            return jsonify({'ok': False, 'error': f'Failed to load preview plan: {exc}'}), 422

        preview = payload.get('full_preview') if isinstance(payload, dict) else None
        if not isinstance(preview, dict):
            _flow_progress('Validation failed: preview plan is missing full_preview')
            return jsonify({'ok': False, 'error': 'Preview plan is missing full_preview.'}), 422

        try:
            hosts_count = len(preview.get('hosts') or []) if isinstance(preview.get('hosts'), list) else 0
            routers_count = len(preview.get('routers') or []) if isinstance(preview.get('routers'), list) else 0
            switches_count = len(preview.get('switches') or []) if isinstance(preview.get('switches'), list) else 0
            _flow_progress(f'Preview loaded: hosts={hosts_count} routers={routers_count} switches={switches_count}')
        except Exception:
            pass

        _flow_progress('Phase: building topology graph')

        def _topology_fingerprint(value: Any) -> str:
            """Hash structural preview data, excluding cached Flow metadata."""
            try:
                current = value if isinstance(value, dict) else {}
                structural = {
                    'hosts': current.get('hosts') or [],
                    'routers': current.get('routers') or [],
                    'switches': current.get('switches') or [],
                    'switches_detail': current.get('switches_detail') or [],
                    'host_router_map': current.get('host_router_map') or {},
                    'r2r_links_preview': current.get('r2r_links_preview') or [],
                    'vulnerabilities_by_node': current.get('vulnerabilities_by_node') or {},
                    'flag_node_generators_by_node': current.get('flag_node_generators_by_node') or {},
                }
                encoded = json.dumps(structural, sort_keys=True, separators=(',', ':'), default=str)
                return hashlib.sha256(encoded.encode('utf-8', errors='ignore')).hexdigest()
            except Exception:
                return ''

        def _build_graph_and_requirements(current_preview: dict[str, Any]):
            current_nodes, current_links, current_adj = backend._build_topology_graph_from_preview_plan(current_preview)
            current_stats = backend._flow_compose_docker_stats(current_nodes)
            required_nodes, required_info = backend._flow_expand_chain_for_topology_requirements(
                current_nodes,
                [],
                current_preview,
                include_all_topology_vulns=True,
                include_all_topology_pivots=include_all_topology_pivots,
                pivot_context=payload,
            )
            return current_nodes, current_links, current_adj, current_stats, required_nodes, required_info

        nodes, _links, adj, stats, required_chain_nodes, topology_inclusion_info = _build_graph_and_requirements(preview)
        topology_fingerprint = _topology_fingerprint(preview)
        if expansion_mode in {'existing_docker', 'add_docker'} and not expected_topology_fingerprint:
            return _validation_failure(
                'Flow expansion requires a current confirmation from the Flag Sequencing page. Generate again and confirm the offered step.',
                confirmation_required=True,
                expansion_stage=expansion_mode,
                chain_expansion_offer={
                    'stage': expansion_mode,
                    'topology_fingerprint': topology_fingerprint,
                    'topology_change_required': expansion_mode == 'add_docker',
                },
                topology_fingerprint=topology_fingerprint,
                stats=stats,
            )
        if expansion_mode == 'add_docker' and not expansion_request_id:
            return _validation_failure(
                'Adding Docker nodes requires a confirmed expansion request. Generate again and confirm the offered step.',
                confirmation_required=True,
                expansion_stage='add_docker',
                chain_expansion_offer={
                    'stage': 'add_docker',
                    'topology_fingerprint': topology_fingerprint,
                    'topology_change_required': True,
                },
                topology_fingerprint=topology_fingerprint,
                stats=stats,
            )
        if expected_topology_fingerprint and expected_topology_fingerprint != topology_fingerprint:
            return _validation_failure(
                'Topology changed after the Flow expansion confirmation. Review the new topology and Generate again.',
                stale_confirmation=True,
                topology_fingerprint=topology_fingerprint,
                stats=stats,
            )

        required_specified_count = len({
            str(node.get('id') or '').strip()
            for node in (required_chain_nodes or [])
            if isinstance(node, dict) and str(node.get('id') or '').strip()
        })
        if not preset_steps and length < required_specified_count:
            length = required_specified_count
            requested_length = length
            _flow_progress(
                'Adjusted requested length to mandatory topology items '
                f'(vulnerabilities / flag-node-generators / pivots)={required_specified_count}'
            )
        try:
            _flow_progress(
                f"Topology graph ready: nodes={len(nodes or [])} links={len(_links or [])} "
                f"eligible={stats.get('eligible_total', 'n/a')} vuln={stats.get('vuln_total', 'n/a')} "
                f"topology_fng={stats.get('topology_flag_node_generator_total', 'n/a')} "
                f"docker_nonvuln={stats.get('docker_nonvuln_total', 'n/a')}"
            )
        except Exception:
            pass

        warning: str | None = None
        chain_expansion: dict[str, Any] = {
            'mode': 'preset' if preset_steps else 'strict',
            'requested_mode': expansion_mode,
            'topology_changed': False,
            'topology_fingerprint': topology_fingerprint,
            'strict_node_ids': [
                str(node.get('id') or '').strip()
                for node in (required_chain_nodes or [])
                if isinstance(node, dict) and str(node.get('id') or '').strip()
            ],
            'strict_vulnerability_node_ids': list(topology_inclusion_info.get('added_vuln_node_ids') or []),
            'strict_flag_node_generator_node_ids': list(topology_inclusion_info.get('added_flag_node_generator_node_ids') or []),
            'strict_pivot_node_ids': list(topology_inclusion_info.get('added_pivot_node_ids') or []),
            'converted_existing_docker_node_ids': [],
            'added_docker_nodes': 0,
        }

        if preset_steps:
            _flow_progress('Phase: selecting preset chain nodes')
            chain_nodes = backend._pick_flag_chain_nodes_for_preset(nodes, adj, steps=preset_steps)
            if include_all_topology_pivots:
                topology_inclusion_info['ignored'] = 'preset'
        else:
            required_ids = {
                str(node.get('id') or '').strip()
                for node in (required_chain_nodes or [])
                if isinstance(node, dict) and str(node.get('id') or '').strip()
            }
            pivot_ids = {
                str(value or '').strip()
                for value in (topology_inclusion_info.get('added_pivot_node_ids') or [])
                if str(value or '').strip()
            }

            def _working_node(node: dict[str, Any], *, allow_generic_generator: bool = False) -> dict[str, Any]:
                result = dict(node)
                if allow_generic_generator:
                    # This is set only for an explicitly approved existing
                    # Docker item (or an explicitly configured pivot).  It
                    # lets the assignment resolver choose a node generator
                    # while preserving exact bindings for topology FNG nodes.
                    result['_topology_flag_node_generators_configured'] = False
                    result.pop('flag_node_generator_id', None)
                    result.pop('flag_node_generator_name', None)
                return result

            strict_chain: list[dict[str, Any]] = []
            for node in (required_chain_nodes or []):
                if not isinstance(node, dict):
                    continue
                node_id = str(node.get('id') or '').strip()
                allow_pivot_generator = bool(
                    node_id in pivot_ids
                    and backend._flow_node_is_docker_role(node)
                    and not backend._flow_node_is_vuln(node)
                    and not str(node.get('flag_node_generator_id') or '').strip()
                )
                strict_chain.append(_working_node(node, allow_generic_generator=allow_pivot_generator))

            generic_candidates = [
                _working_node(node, allow_generic_generator=True)
                for node in (nodes or [])
                if isinstance(node, dict)
                and str(node.get('id') or '').strip() not in required_ids
                and backend._flow_node_is_docker_role(node)
                and not backend._flow_node_is_vuln(node)
            ]
            generic_target = max(0, length - len(strict_chain))
            available_existing_docker = len(generic_candidates)

            def _generic_docker_shortfall() -> int:
                if generic_target <= 0:
                    return 0
                # Explicit duplicate permission can reuse one eligible host,
                # but it cannot fabricate an initial eligible Docker host.
                if allow_node_duplicates:
                    return 0 if available_existing_docker > 0 else 1
                return max(0, generic_target - available_existing_docker)

            def _expansion_offer(stage: str, *, additional_needed: int) -> Any:
                return _validation_failure(
                    (
                        'The specified vulnerabilities and flag-node-generators do not fill the requested Flow chain.'
                        if stage == 'existing_docker'
                        else 'The approved existing Docker nodes are not enough to complete the requested Flow chain.'
                    ),
                    confirmation_required=True,
                    expansion_stage=stage,
                    chain_expansion_offer={
                        'stage': stage,
                        'requested_length': requested_length,
                        'effective_required_length': length,
                        'strict_node_count': len(strict_chain),
                        'strict_node_ids': list(chain_expansion.get('strict_node_ids') or []),
                        'existing_docker_available': available_existing_docker,
                        'additional_items_needed': max(0, int(additional_needed or 0)),
                        'topology_fingerprint': topology_fingerprint,
                        'topology_change_required': stage == 'add_docker',
                    },
                    stats=stats,
                    requested_length=requested_length,
                    available=available_existing_docker,
                )

            # Stage 1 is strict: the chain contains only specified topology
            # items.  A longer requested chain pauses for confirmation rather
            # than selecting ordinary Docker hosts behind the user's back.
            if expansion_mode == 'strict' and generic_target > 0:
                return _expansion_offer('existing_docker', additional_needed=generic_target)

            if expansion_mode == 'existing_docker' and _generic_docker_shortfall() > 0:
                return _expansion_offer(
                    'add_docker',
                    additional_needed=_generic_docker_shortfall(),
                )

            if expansion_mode == 'add_docker' and _generic_docker_shortfall() > 0:
                shortfall = _generic_docker_shortfall()
                _flow_progress(f'Phase: applying confirmed Docker topology expansion (+{shortfall})')
                added_ok, added_result, added_error = backend._flow_add_docker_nodes_and_rebuild_preview_in_xml(
                    xml_path=preview_plan_path,
                    scenario_label=scenario_label or scenario_norm,
                    additional_docker_nodes=shortfall,
                    expansion_request_id=expansion_request_id,
                    source_topology_fingerprint=topology_fingerprint,
                    seed=backend._get_flow_seed(preview, flow_seed_param),
                )
                if not added_ok or not isinstance(added_result, dict):
                    return _validation_failure(
                        f'Confirmed Docker topology expansion could not be applied: {added_error}',
                        stats=stats,
                    )
                rebuilt_preview = added_result.get('full_preview')
                if not isinstance(rebuilt_preview, dict):
                    return _validation_failure('Confirmed Docker topology expansion did not produce a valid preview plan.', stats=stats)
                preview = rebuilt_preview
                payload = added_result.get('plan_payload') if isinstance(added_result.get('plan_payload'), dict) else {
                    'full_preview': preview,
                    'metadata': added_result.get('metadata') if isinstance(added_result.get('metadata'), dict) else {},
                }
                nodes, _links, adj, stats, required_chain_nodes, topology_inclusion_info = _build_graph_and_requirements(preview)
                topology_fingerprint = _topology_fingerprint(preview)
                required_ids = {
                    str(node.get('id') or '').strip()
                    for node in (required_chain_nodes or [])
                    if isinstance(node, dict) and str(node.get('id') or '').strip()
                }
                pivot_ids = {
                    str(value or '').strip()
                    for value in (topology_inclusion_info.get('added_pivot_node_ids') or [])
                    if str(value or '').strip()
                }
                strict_chain = []
                for node in (required_chain_nodes or []):
                    if not isinstance(node, dict):
                        continue
                    node_id = str(node.get('id') or '').strip()
                    strict_chain.append(_working_node(
                        node,
                        allow_generic_generator=bool(
                            node_id in pivot_ids
                            and backend._flow_node_is_docker_role(node)
                            and not backend._flow_node_is_vuln(node)
                            and not str(node.get('flag_node_generator_id') or '').strip()
                        ),
                    ))
                generic_candidates = [
                    _working_node(node, allow_generic_generator=True)
                    for node in (nodes or [])
                    if isinstance(node, dict)
                    and str(node.get('id') or '').strip() not in required_ids
                    and backend._flow_node_is_docker_role(node)
                    and not backend._flow_node_is_vuln(node)
                ]
                generic_target = max(0, length - len(strict_chain))
                available_existing_docker = len(generic_candidates)
                if _generic_docker_shortfall() > 0:
                    return _validation_failure(
                        'Confirmed Docker topology expansion completed, but the rebuilt topology still has too few Docker nodes. Review the topology and Generate again.',
                        stats=stats,
                        requested_length=requested_length,
                        available=available_existing_docker,
                    )
                chain_expansion.update({
                    'mode': 'add_docker',
                    'topology_changed': True,
                    'topology_fingerprint': topology_fingerprint,
                    'added_docker_nodes': int(added_result.get('added_docker_nodes') or shortfall),
                    'expansion_request_id': expansion_request_id,
                    'expansion': added_result.get('expansion') if isinstance(added_result.get('expansion'), dict) else {},
                    'already_applied': bool(added_result.get('already_applied')),
                })

            _flow_progress('Phase: selecting approved Flow chain nodes')
            selected_generic: list[dict[str, Any]] = []
            if generic_target > 0:
                seed_val = backend._get_flow_seed(preview, flow_seed_param)
                selected_generic = backend._pick_flow_nonvulnerability_docker_nodes(
                    generic_candidates,
                    adj,
                    length=generic_target,
                    allow_node_duplicates=allow_node_duplicates,
                    seed=seed_val,
                )
            if len(selected_generic) < generic_target:
                # This protects against graph/selection edge cases without
                # silently falling back to a shorter chain.
                if expansion_mode == 'strict':
                    return _expansion_offer('existing_docker', additional_needed=generic_target)
                if expansion_mode == 'existing_docker':
                    return _expansion_offer(
                        'add_docker',
                        additional_needed=(1 if allow_node_duplicates and not selected_generic else max(0, generic_target - len(selected_generic))),
                    )
                return _validation_failure(
                    'The confirmed Docker topology expansion completed, but no eligible Docker Flow item could be selected. Check that an enabled flag-node-generator is available, then Generate again.',
                    stats=stats,
                    requested_length=requested_length,
                    available=len(selected_generic),
                )
            chain_nodes = list(strict_chain) + list(selected_generic or [])
            converted_ids = [
                str(node.get('id') or '').strip()
                for node in (selected_generic or [])
                if isinstance(node, dict) and str(node.get('id') or '').strip()
            ]
            if converted_ids:
                topology_inclusion_info = dict(topology_inclusion_info or {})
                topology_inclusion_info['converted_existing_docker_node_ids'] = list(converted_ids)
                topology_inclusion_info['selected_existing_docker_node_ids'] = list(converted_ids)
                chain_expansion['converted_existing_docker_node_ids'] = list(converted_ids)
                if expansion_mode == 'existing_docker':
                    chain_expansion['mode'] = 'existing_docker'
                elif expansion_mode == 'add_docker':
                    chain_expansion['mode'] = 'add_docker'
            topology_inclusion_info['effective_length'] = len(chain_nodes or [])

        _flow_progress(f'Selected chain nodes: count={len(chain_nodes or [])} ids={_chain_ids(chain_nodes) or "-"}')

        if not chain_nodes:
            return _validation_failure(
                'No eligible Flow nodes found in preview plan.',
                available=0,
                requested_length=requested_length,
                stats=stats,
            )

        host_by_id: dict[str, dict[str, Any]] = {}
        try:
            hosts = preview.get('hosts') if isinstance(preview, dict) else None
            if isinstance(hosts, list):
                for host in hosts:
                    if not isinstance(host, dict):
                        continue
                    host_id = str(host.get('node_id') or host.get('id') or '').strip()
                    if host_id:
                        host_by_id[host_id] = host
        except Exception:
            host_by_id = {}
        try:
            vuln_by_node = preview.get('vulnerabilities_by_node') if isinstance(preview, dict) else None
            if not isinstance(vuln_by_node, dict):
                vuln_by_node = {}
        except Exception:
            vuln_by_node = {}
        try:
            if host_by_id:
                for node in (chain_nodes or []):
                    if not isinstance(node, dict):
                        continue
                    node_id = str(node.get('id') or '').strip()
                    if not node_id:
                        continue
                    host = host_by_id.get(node_id)
                    if not isinstance(host, dict):
                        continue
                    ip_value = backend._preview_host_ip4_any(host)
                    if ip_value:
                        if not (node.get('ip4') or node.get('ipv4') or node.get('ip') or node.get('address')):
                            node['ip4'] = ip_value
                            node['ipv4'] = ip_value
                    interfaces = host.get('interfaces') if isinstance(host.get('interfaces'), list) else None
                    if interfaces and not node.get('interfaces'):
                        node['interfaces'] = interfaces
        except Exception:
            pass

        initial_facts_override = backend._flow_normalize_fact_override(payload_in.get('initial_facts'))
        goal_facts_override = backend._flow_normalize_fact_override(payload_in.get('goal_facts'))
        retry_index = 0
        try:
            retry_index = int(payload_in.get('retry_index') or 0)
        except Exception:
            retry_index = 0

        if preset_steps:
            _flow_progress('Phase: computing generator assignments for preset')
            flag_assignments, preset_err = backend._flow_compute_flag_assignments_for_preset(
                preview,
                chain_nodes,
                scenario_label or scenario_norm,
                preset,
                pivot_context=payload,
            )
            if preset_err:
                return _validation_failure(f'Error: {preset_err}', stats=stats)
        else:
            _flow_progress('Phase: computing generator assignments')
            base_seed = backend._get_flow_seed(preview, flow_seed_param)
            seed_override = base_seed ^ (retry_index * 0x9E3779B1) if retry_index else flow_seed_param
            flag_assignments = backend._flow_compute_flag_assignments(
                preview,
                chain_nodes,
                scenario_label or scenario_norm,
                initial_facts_override=initial_facts_override,
                goal_facts_override=goal_facts_override,
                seed_override=seed_override,
                disallow_generator_reuse=(not allow_node_duplicates),
                dependency_level=dependency_level,
                pivot_context=payload,
            )
            if (not flag_assignments) and (not allow_node_duplicates):
                return _validation_failure(
                    'No distinct compatible generator assignment could be made for every selected Flow node. Check that each topology-selected generator is enabled and that any required inputs are either produced by the sequence or explicitly marked flow_supply_when_first for a parallel branch.',
                    scenario=scenario_label or scenario_norm,
                    length=len(chain_nodes or []),
                    chain=[{'id': str(node.get('id') or ''), 'name': str(node.get('name') or ''), 'type': str(node.get('type') or '')} for node in (chain_nodes or []) if isinstance(node, dict)],
                )

        _flow_progress(f'Generator assignments ready: count={len(flag_assignments or [])} ids={_assignment_ids(flag_assignments) or "-"}')

        try:
            _flow_progress('Phase: applying pivot context')
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
            ids = [str(node.get('id') or '').strip() for node in (chain_nodes or []) if isinstance(node, dict) and str(node.get('id') or '').strip()]
            has_dupes = len(set(ids)) != len(ids)
        except Exception:
            has_dupes = False

        if (not preset_steps) and (not has_dupes):
            try:
                debug_dag = bool(payload_in.get('debug_dag'))
            except Exception:
                debug_dag = False
            _flow_progress('Phase: ordering dependency graph')
            chain_nodes, flag_assignments, _dag_debug = backend._flow_reorder_chain_by_generator_dag(
                chain_nodes,
                flag_assignments,
                scenario_label=(scenario_label or scenario_norm),
                dependency_level=dependency_level,
                return_debug=bool(debug_dag),
                flow_progress=_flow_progress,
            )

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
            _flow_progress('Phase: validating dependency order')
            flow_valid, flow_errors = backend._flow_validate_chain_order_by_requires_produces(
                chain_nodes,
                flag_assignments,
                scenario_label=(scenario_label or scenario_norm),
            )
        except Exception:
            flow_valid, flow_errors = True, []
        _flow_progress(f'Dependency validation: flow_valid={int(bool(flow_valid))} errors={len(flow_errors or [])}')

        if not allow_node_duplicates:
            try:
                generator_ids = [str(assignment.get('id') or assignment.get('generator_id') or '').strip() for assignment in (flag_assignments or []) if isinstance(assignment, dict)]
                generator_ids = [generator_id for generator_id in generator_ids if generator_id]
                if len(set(generator_ids)) != len(generator_ids):
                    return _validation_failure(
                        'Duplicate generators detected while duplicates are disabled. Reduce chain length or enable duplicates.',
                        scenario=scenario_label or scenario_norm,
                        length=len(chain_nodes or []),
                        chain=[{'id': str(node.get('id') or ''), 'name': str(node.get('name') or ''), 'type': str(node.get('type') or '')} for node in (chain_nodes or []) if isinstance(node, dict)],
                        flag_assignments=flag_assignments,
                    )
            except Exception:
                pass

        host_ip_map: dict[str, str] = {}
        try:
            for host_id, host in (host_by_id or {}).items():
                ip_value = backend._preview_host_ip4_any(host)
                if ip_value:
                    host_ip_map[str(host_id)] = ip_value
        except Exception:
            host_ip_map = {}

        chain_payload: list[dict[str, Any]] = []
        try:
            _flow_progress('Phase: building response payload')
            for node in (chain_nodes or []):
                if not isinstance(node, dict):
                    continue
                node_id = str(node.get('id') or '').strip()
                host = host_by_id.get(node_id) if node_id else None
                ip_value = backend._preview_host_ip4_any(host) if isinstance(host, dict) else ''
                if not ip_value:
                    ip_value = backend._first_valid_ipv4(node.get('ip4') or node.get('ipv4') or node.get('ip') or '')
                interfaces = None
                try:
                    interfaces = host.get('interfaces') if isinstance(host, dict) and isinstance(host.get('interfaces'), list) else None
                except Exception:
                    interfaces = None
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
                if (not vulns) and node_id:
                    try:
                        raw_vulns = vuln_by_node.get(node_id)
                        if isinstance(raw_vulns, list):
                            vulns = [str(v).strip() for v in raw_vulns if str(v).strip()]
                    except Exception:
                        vulns = []
                is_vuln = bool(vulns) or bool(node.get('is_vuln')) or bool(node.get('is_vulnerability')) or bool(node.get('is_vulnerable'))
                chain_payload.append(
                    {
                        'id': str(node.get('id') or ''),
                        'name': str(node.get('name') or ''),
                        'type': str(node.get('type') or ''),
                        'is_vuln': bool(is_vuln),
                        'vulnerabilities': list(vulns or []),
                        'ip4': str(ip_value or ''),
                        'ipv4': str(ip_value or ''),
                        'interfaces': list(interfaces or []) if isinstance(interfaces, list) else [],
                    }
                )
        except Exception:
            chain_payload = [
                {
                    'id': str(node.get('id') or ''),
                    'name': str(node.get('name') or ''),
                    'type': str(node.get('type') or ''),
                    'is_vuln': bool(node.get('is_vuln')),
                }
                for node in (chain_nodes or [])
                if isinstance(node, dict)
            ]

        try:
            metadata = payload.get('metadata') if isinstance(payload, dict) else {}
            first_hints = backend._flow_first_hints_from_assignments(flag_assignments)
            flow_meta = {
                'source_preview_plan_path': backend._abs_path_or_original(preview_plan_path),
                'scenario': scenario_label or scenario_norm,
                'length': len(chain_nodes),
                'requested_length': requested_length,
                'dependency_level': dependency_level,
                'allow_node_duplicates': bool(allow_node_duplicates),
                'include_all_topology_pivots': bool(include_all_topology_pivots),
                'topology_inclusion': dict(topology_inclusion_info or {}),
                'chain_expansion': dict(chain_expansion or {}),
                'chain': list(chain_payload or []),
                'flag_assignments': backend._flow_strip_runtime_sensitive_fields(flag_assignments),
                'flags_enabled': bool(flow_valid),
                'flow_valid': bool(flow_valid),
                'flow_errors': list(flow_errors or []),
                'modified_at': backend._iso_now(),
            }
            if first_hints:
                flow_meta['first_hint'] = first_hints[0]
                flow_meta['first_hints'] = list(first_hints)
            if initial_facts_override:
                flow_meta['initial_facts'] = initial_facts_override
            if goal_facts_override:
                flow_meta['goal_facts'] = goal_facts_override
            if warning:
                flow_meta['warning'] = warning
            if isinstance(metadata, dict):
                metadata = dict(metadata)
                metadata['flow'] = flow_meta
            else:
                metadata = {'flow': flow_meta}
            payload['metadata'] = metadata
            if isinstance(preview, dict):
                preview.setdefault('metadata', {})
        except Exception:
            pass

        try:
            _flow_progress('Phase: persisting sequence plan')
            if isinstance(metadata, dict):
                metadata = dict(metadata)
                metadata['updated_at'] = backend._iso_now()
            xml_path_for_plan = None
            try:
                if preview_plan_path and str(preview_plan_path).lower().endswith('.xml'):
                    xml_path_for_plan = backend.os.path.abspath(preview_plan_path)
            except Exception:
                xml_path_for_plan = None
            if not xml_path_for_plan:
                try:
                    metadata_xml = str((metadata or {}).get('xml_path') or '').strip()
                    if metadata_xml:
                        xml_path_for_plan = backend.os.path.abspath(metadata_xml)
                except Exception:
                    xml_path_for_plan = None
            if not xml_path_for_plan and xml_hint:
                try:
                    xml_hint_abs = backend.os.path.abspath(xml_hint)
                    if xml_hint_abs.lower().endswith('.xml'):
                        xml_path_for_plan = xml_hint_abs
                except Exception:
                    xml_path_for_plan = None
            if not xml_path_for_plan:
                try:
                    xml_path_for_plan = backend._latest_xml_path_for_scenario(scenario_norm)
                except Exception:
                    xml_path_for_plan = None
            if not xml_path_for_plan or not backend.os.path.exists(xml_path_for_plan):
                _flow_progress('Failed to persist sequence plan: XML path not found')
                return jsonify({'ok': False, 'error': 'Failed to persist sequence plan: XML path not found.'}), 500

            plan_payload = {
                'full_preview': preview,
                'metadata': metadata,
            }
            ok, err = backend._persist_plan_preview_and_flow_state_in_xml(
                xml_path_for_plan,
                scenario_label or scenario_norm,
                plan_payload,
                flow_meta,
            )
            if not ok:
                _flow_progress(f'Failed to persist sequence plan: {err}')
                return jsonify({'ok': False, 'error': f'Failed to persist sequence plan: {err}'}), 500
            try:
                backend._planner_set_plan(scenario_norm, plan_path=xml_path_for_plan, xml_path=xml_path_for_plan, seed=(metadata or {}).get('seed'))
            except Exception:
                pass
            out_path = xml_path_for_plan
            _flow_progress(f'Persisted sequence plan: {_short_path(out_path)}')
        except Exception as exc:
            _flow_progress(f'Failed to persist sequence plan: {exc}')
            return jsonify({'ok': False, 'error': f'Failed to persist sequence plan: {exc}'}), 500

        response_flow_seed = backend._get_flow_seed(preview, flow_seed_param)
        _flow_progress(f'Phase complete: sequencing preview ready ({max(0.0, time.monotonic() - started_at):.2f}s)')

        return jsonify(
            {
                'ok': True,
                'scenario': scenario_label or scenario_norm,
                'length': len(chain_nodes),
                'requested_length': requested_length,
                'stats': stats,
                'chain': list(chain_payload or []),
                'flag_assignments': flag_assignments,
                'flags_enabled': bool(flow_valid),
                'flow_valid': bool(flow_valid),
                'flow_errors': list(flow_errors or []),
                'flow_seed': response_flow_seed,
                'dependency_level': dependency_level,
                'include_all_topology_pivots': bool(include_all_topology_pivots),
                'topology_inclusion': dict(topology_inclusion_info or {}),
                'chain_expansion': dict(chain_expansion or {}),
                'preview_plan_path': out_path,
                'xml_path': out_path,
                'base_preview_plan_path': preview_plan_path,
                **({'full_preview': preview} if bool(chain_expansion.get('topology_changed')) else {}),
                **({'warning': warning} if warning else {}),
                **({'host_ip_map': host_ip_map} if host_ip_map else {}),
            }
        )

    @app.route('/api/flag-sequencing/sequence_preview_plan', methods=['POST'])
    def api_flow_sequence_preview_plan():
        """Run one sequence job per request signature and stream keep-alives.

        The initial whitespace and one whitespace byte per second are valid JSON
        whitespace.  They let a browser (or an intermediate TCP idle timeout)
        observe response activity while the worker computes the final JSON
        payload.  ``Response.json()`` still receives one normal JSON document
        once the worker is done.
        """
        payload_in = request.get_json(silent=True) or {}
        if not isinstance(payload_in, dict):
            payload_in = {}
        job_key = _sequence_job_key(payload_in)
        now = time.monotonic()

        with _sequence_jobs_lock:
            # Keep finished results briefly: a retry after a dropped response
            # receives the prior result instead of recomputing and rewriting
            # the plan.
            for key, old_job in list(_sequence_jobs.items()):
                completed_at = float(old_job.get('completed_at') or 0.0)
                if completed_at and now - completed_at > 600.0:
                    _sequence_jobs.pop(key, None)

            job = _sequence_jobs.get(job_key)
            if job is None:
                job = {
                    'done': threading.Event(),
                    'payload': dict(payload_in),
                    'body': b'',
                    'completed_at': 0.0,
                }
                _sequence_jobs[job_key] = job

                def _worker() -> None:
                    try:
                        # The route logic only uses the parsed payload, but
                        # jsonify() still needs an application context.
                        with app.app_context():
                            response = app.make_response(_run_sequence_preview_plan(job['payload']))
                            job['body'] = response.get_data()
                    except Exception as exc:
                        try:
                            with app.app_context():
                                job['body'] = jsonify({'ok': False, 'error': f'Sequence preview failed: {exc}'}).get_data()
                        except Exception:
                            job['body'] = b'{"ok":false,"error":"Sequence preview failed."}'
                        try:
                            app.logger.exception('Sequence preview worker failed.')
                        except Exception:
                            pass
                    finally:
                        job['completed_at'] = time.monotonic()
                        job['done'].set()

                threading.Thread(
                    target=_worker,
                    name=f'flow-sequence-{job_key[:8]}',
                    daemon=True,
                ).start()

        def _stream_result():
            # Flush headers immediately, then keep the response active while
            # the worker runs.  JSON permits leading/interstitial whitespace.
            yield b' \n'
            while not job['done'].wait(timeout=1.0):
                yield b' \n'
            yield bytes(job.get('body') or b'{"ok":false,"error":"Sequence preview produced no response."}')

        return Response(
            stream_with_context(_stream_result()),
            status=200,
            content_type='application/json; charset=utf-8',
            headers={'Cache-Control': 'no-store'},
        )

    mark_routes_registered(app, 'flag_sequencing_sequence_preview_routes')
