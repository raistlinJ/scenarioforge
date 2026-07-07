from __future__ import annotations

from typing import Any, Callable

from flask import jsonify, render_template, request, send_file, url_for

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    require_builder_or_admin: Callable[[], None],
    load_vuln_catalogs_state: Callable[[], dict],
    write_vuln_catalogs_state: Callable[[dict], None],
    write_vuln_catalog_csv_from_items: Callable[..., list[str]],
    get_active_vuln_catalog_entry: Callable[[dict], dict | None],
    normalize_vuln_catalog_items: Callable[[dict], list[dict[str, Any]]],
    vuln_catalog_pack_content_dir: Callable[[str], str],
    safe_path_under: Callable[[str, str], str],
    get_repo_root: Callable[[], str],
    load_vuln_catalog: Callable[[str], list[Any]],
    os_module: Any,
) -> None:
    if not begin_route_registration(app, 'vuln_catalog_overview_routes'):
        return

    @app.route('/vuln_catalog_page')
    def vuln_catalog_page():
        require_builder_or_admin()
        state = load_vuln_catalogs_state()
        catalogs = [catalog for catalog in (state.get('catalogs') or []) if isinstance(catalog, dict)]
        active_id = str(state.get('active_id') or '').strip()
        active_label = None
        for catalog in catalogs:
            if str(catalog.get('id') or '').strip() == active_id:
                active_label = str(catalog.get('label') or '').strip() or active_id
                break
        items_count = None
        try:
            items_count = len(load_vuln_catalog(get_repo_root()))
        except Exception:
            items_count = None
        return render_template(
            'vuln_catalog.html',
            catalogs=catalogs,
            active_id=active_id,
            active_label=active_label,
            items_count=items_count,
            active_page='vuln_catalog',
        )

    def _missing_dependency_paths_from_required(required_files: object) -> list[str]:
        missing: list[str] = []
        if not isinstance(required_files, list):
            return missing
        for entry in required_files:
            if not isinstance(entry, dict):
                continue
            if entry.get('required') is False or entry.get('exists') is not False:
                continue
            path = str(entry.get('path') or '').strip()
            if path:
                missing.append(path)
        return sorted(dict.fromkeys(missing))

    def _scan_vuln_item_dependency_metadata(*, base_dir: str, item: dict[str, Any]) -> dict[str, object]:
        try:
            from scenarioforge.compose_dependencies import scan_compose_dependencies
        except Exception as exc:
            return {
                'required_files': [],
                'missing_required_files': [],
                'compose_dependency_warning': f'Dependency scan unavailable: {exc}',
            }
        compose_rel = str(item.get('compose_rel') or '').strip()
        if not compose_rel:
            return {
                'required_files': [],
                'missing_required_files': [],
                'compose_dependency_warning': 'Compose path is missing.',
            }
        try:
            compose_path = safe_path_under(base_dir, compose_rel)
        except Exception as exc:
            return {
                'required_files': [],
                'missing_required_files': [],
                'compose_dependency_warning': f'Compose path could not be resolved: {exc}',
            }
        if not compose_path or not os_module.path.isfile(compose_path):
            return {
                'required_files': [],
                'missing_required_files': [],
                'compose_dependency_warning': 'Compose file is missing.',
            }
        try:
            summary = scan_compose_dependencies(compose_path)
        except Exception as exc:
            return {
                'required_files': [],
                'missing_required_files': [],
                'compose_dependency_warning': f'Compose dependency scan failed: {exc}',
            }
        required_files = summary.get('requires') if isinstance(summary, dict) and isinstance(summary.get('requires'), list) else []
        return {
            'required_files': required_files,
            'missing_required_files': _missing_dependency_paths_from_required(required_files),
            'compose_dependency_warning': str(summary.get('warning') or '').strip() if isinstance(summary, dict) else '',
        }

    def _recheck_active_vuln_dependency_cache() -> dict[str, int | str]:
        state = load_vuln_catalogs_state()
        entry = get_active_vuln_catalog_entry(state)
        if not entry:
            return {'checked': 0, 'missing': 0, 'catalog_id': ''}
        cid = str(entry.get('id') or '').strip()
        catalogs = [catalog for catalog in (state.get('catalogs') or []) if isinstance(catalog, dict)]
        base_dir = vuln_catalog_pack_content_dir(cid)
        checked = 0
        missing_count = 0
        for catalog in catalogs:
            if str(catalog.get('id') or '').strip() != cid:
                continue
            items = normalize_vuln_catalog_items(catalog)
            for item in items:
                metadata = _scan_vuln_item_dependency_metadata(base_dir=base_dir, item=item)
                item['required_files'] = metadata.get('required_files') if isinstance(metadata.get('required_files'), list) else []
                item['missing_required_files'] = metadata.get('missing_required_files') if isinstance(metadata.get('missing_required_files'), list) else []
                item['compose_dependency_warning'] = str(metadata.get('compose_dependency_warning') or '').strip()
                if item['missing_required_files']:
                    item['disabled'] = True
                    item['disabled_due_to_missing_files'] = True
                elif item.get('disabled_due_to_missing_files') is True:
                    item['disabled'] = False
                    item['disabled_due_to_missing_files'] = False
                checked += 1
                missing_count += len(item.get('missing_required_files') or [])
            catalog['compose_items'] = items
            catalog['missing_required_file_count'] = missing_count
            catalog['csv_paths'] = write_vuln_catalog_csv_from_items(catalog_id=cid, items=items)
            state['catalogs'] = catalogs
            write_vuln_catalogs_state(state)
            break
        return {'checked': checked, 'missing': missing_count, 'catalog_id': cid}

    @app.route('/vuln_catalog_items_data')
    def vuln_catalog_items_data():
        require_builder_or_admin()
        state = load_vuln_catalogs_state()
        entry = get_active_vuln_catalog_entry(state)
        if not entry:
            return jsonify({'ok': True, 'active': None, 'items': []})
        cid = str(entry.get('id') or '').strip()
        items = normalize_vuln_catalog_items(entry)
        from_source = str(entry.get('from_source') or entry.get('label') or '').strip()

        def _display_name(item: dict[str, Any]) -> str:
            base = str(item.get('name') or '').strip() or 'root'
            rel_dir = str(item.get('rel_dir') or item.get('dir_rel') or '').strip()
            if not rel_dir or rel_dir in ('', '.', 'root'):
                return base
            parts = [part for part in rel_dir.replace('\\', '/').split('/') if part]
            if len(parts) >= 2:
                return f'{parts[-2]}/{parts[-1]}'
            return parts[-1] if parts else base

        base_dir = vuln_catalog_pack_content_dir(cid)
        out_items: list[dict[str, Any]] = []
        for item in items:
            readme_url = ''
            required_files = item.get('required_files') if isinstance(item.get('required_files'), list) else []
            missing_required_files = item.get('missing_required_files') if isinstance(item.get('missing_required_files'), list) else []
            compose_dependency_warning = str(item.get('compose_dependency_warning') or '').strip()
            try:
                rel_dir = str(item.get('dir_rel') or item.get('rel_dir') or '').strip().replace('\\', '/')
                abs_dir = safe_path_under(base_dir, rel_dir)
                if os_module.path.isdir(abs_dir):
                    best_name = None
                    best_rank = 10**9
                    for name in os_module.listdir(abs_dir):
                        if not isinstance(name, str):
                            continue
                        low = name.lower().strip()
                        if not low.startswith('readme'):
                            continue
                        ext = os_module.path.splitext(low)[1].lstrip('.')
                        if ext not in ('md', 'markdown', 'txt'):
                            continue
                        if low in ('readme.md', 'readme.markdown', 'readme.txt'):
                            rank = 0
                        elif low.startswith('readme.en'):
                            rank = 1
                        else:
                            rank = 2
                        if rank < best_rank:
                            best_rank = rank
                            best_name = name
                    if best_name:
                        rel = os_module.path.relpath(os_module.path.join(abs_dir, best_name), base_dir).replace('\\', '/')
                        readme_url = url_for('vuln_catalog_packs_readme', catalog_id=cid, subpath=rel)
            except Exception:
                readme_url = ''
            log_path = str(item.get('last_test_log_path') or '').strip()
            log_download_url = ''
            if log_path:
                try:
                    outputs_root = os_module.path.abspath(os_module.path.join(get_repo_root(), 'outputs'))
                    abs_log_path = os_module.path.abspath(log_path)
                    if os_module.path.isfile(abs_log_path) and os_module.path.commonpath([outputs_root, abs_log_path]) == outputs_root:
                        log_download_url = url_for('vuln_catalog_item_test_log_download', item_id=int(item.get('id') or 0))
                except Exception:
                    log_download_url = ''
            out_items.append({
                'id': int(item.get('id') or 0),
                'name': _display_name(item),
                'type': 'docker-compose',
                'from_source': from_source,
                'disabled': bool(item.get('disabled', False)),
                'disabled_due_to_missing_files': bool(item.get('disabled_due_to_missing_files') is True),
                'readme_url': readme_url,
                'validated_ok': bool(item.get('validated_ok')) if item.get('validated_ok') is not None else None,
                'validated_incomplete': bool(item.get('validated_incomplete') is True),
                'validated_at': str(item.get('validated_at') or '').strip() or None,
                'log_download_url': log_download_url or None,
                'required_files': required_files,
                'missing_required_files': missing_required_files,
                'missing_required_file_count': len(missing_required_files),
                'compose_dependency_warning': compose_dependency_warning or None,
                'eligible_for_selection': bool(item.get('validated_ok') is True and item.get('validated_incomplete') is not True and not bool(item.get('disabled', False))),
                'persistent': bool(item.get('persistent', False)),
                'cached': item.get('cached') if isinstance(item.get('cached'), bool) else None,
                'cache_checked_at': str(item.get('cache_checked_at') or '').strip() or None,
                'cache_last_core_host': str(item.get('cache_last_core_host') or '').strip() or None,
                'cache_missing_images': item.get('cache_missing_images') if isinstance(item.get('cache_missing_images'), list) else [],
                'cache_error': str(item.get('cache_error') or '').strip() or None,
            })
        return jsonify({
            'ok': True,
            'active': {
                'id': cid,
                'label': str(entry.get('label') or '').strip() or cid,
                'from_source': from_source,
            },
            'items': out_items,
        })

    @app.route('/vuln_catalog_items/recheck_dependencies', methods=['POST'])
    def vuln_catalog_items_recheck_dependencies():
        require_builder_or_admin()
        stats = _recheck_active_vuln_dependency_cache()
        return jsonify({
            'ok': True,
            'catalog_id': stats.get('catalog_id') or '',
            'checked_count': stats.get('checked', 0),
            'missing_required_file_count': stats.get('missing', 0),
        })

    @app.route('/vuln_catalog_items/test/log')
    def vuln_catalog_item_test_log_download():
        require_builder_or_admin()
        try:
            item_id = int(request.args.get('item_id') or 0)
        except Exception:
            item_id = 0
        if item_id <= 0:
            return jsonify({'ok': False, 'error': 'Invalid item id'}), 400

        state = load_vuln_catalogs_state()
        entry = get_active_vuln_catalog_entry(state)
        if not entry:
            return jsonify({'ok': False, 'error': 'No active catalog pack'}), 404

        outputs_root = os_module.path.abspath(os_module.path.join(get_repo_root(), 'outputs'))
        items = normalize_vuln_catalog_items(entry)
        for item in items:
            if int(item.get('id') or 0) != item_id:
                continue
            log_path = str(item.get('last_test_log_path') or '').strip()
            if not log_path:
                return jsonify({'ok': False, 'error': 'Log not available'}), 404
            abs_log_path = os_module.path.abspath(log_path)
            try:
                if os_module.path.commonpath([outputs_root, abs_log_path]) != outputs_root:
                    return jsonify({'ok': False, 'error': 'Refusing path'}), 400
            except Exception:
                return jsonify({'ok': False, 'error': 'Refusing path'}), 400
            if not os_module.path.isfile(abs_log_path):
                return jsonify({'ok': False, 'error': 'Log not available'}), 404
            download_name = str(item.get('last_test_log_filename') or os_module.path.basename(abs_log_path) or f'vuln-item-{item_id}.log').strip()
            return send_file(abs_log_path, as_attachment=True, download_name=download_name, mimetype='text/plain; charset=utf-8')

        return jsonify({'ok': False, 'error': 'Unknown item id'}), 404

    mark_routes_registered(app, 'vuln_catalog_overview_routes')
