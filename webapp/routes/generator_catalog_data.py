from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Callable

from flask import jsonify, request, send_file

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    flag_generators_from_enabled_sources: Callable[[], tuple[list[dict], list[dict]]],
    flag_node_generators_from_enabled_sources: Callable[[], tuple[list[dict], list[dict]]],
    is_installed_generator_view: Callable[[dict], bool],
    annotate_disabled_state: Callable[..., list[dict]],
    load_installed_generator_packs_state: Callable[[], dict],
    save_installed_generator_packs_state: Callable[[dict], None],
    installed_generators_root: Callable[[], str],
) -> None:
    if not begin_route_registration(app, 'generator_catalog_data_routes'):
        return

    def _state_item_matches(item: object, *, kind: str, generator_id: str) -> bool:
        if not isinstance(item, dict):
            return False
        if str(item.get('kind') or '').strip() != kind:
            return False
        gid = str(generator_id or '').strip()
        if not gid:
            return False
        if str(item.get('id') or '').strip() == gid:
            return True
        try:
            pack_path = str(item.get('path') or '').strip()
            if not pack_path:
                return False
            marker_path = os.path.join(pack_path, '.coretg_pack.json')
            if not os.path.isfile(marker_path):
                return False
            marker = json.loads(Path(marker_path).read_text(encoding='utf-8', errors='ignore') or '{}')
            return str(marker.get('source_generator_id') or '').strip() == gid
        except Exception:
            return False

    def _attach_test_metadata(generators: list[dict], *, kind: str) -> list[dict]:
        outputs_root = os.path.abspath(Path(installed_generators_root()).parent)
        out: list[dict] = []
        for generator in (generators or []):
            if not isinstance(generator, dict):
                continue
            item = dict(generator)
            item['validated_ok'] = item.get('_validated_ok')
            item['validated_incomplete'] = bool(item.get('_validated_incomplete') is True)
            item['validated_at'] = item.get('_validated_at')
            item['note'] = item.get('_note')
            item['note_color'] = item.get('_note_color')
            log_path = str(item.get('_last_test_log_path') or '').strip()
            log_download_url = None
            if log_path:
                try:
                    abs_log_path = os.path.abspath(log_path)
                    if os.path.isfile(abs_log_path) and os.path.commonpath([outputs_root, abs_log_path]) == outputs_root:
                        log_download_url = f"/api/generator_catalog/test_log?kind={kind}&generator_id={generator.get('id') or ''}"
                except Exception:
                    log_download_url = None
            item['log_download_url'] = log_download_url
            out.append(item)
        return out

    def _normalize_manifest_io(items, *, fallback_type: str) -> list[dict]:
        normalized: list[dict] = []
        if not isinstance(items, list):
            return normalized
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get('name') or item.get('artifact') or '').strip()
            if not name:
                continue
            entry = {
                'name': name,
                'type': str(item.get('type') or fallback_type).strip() or fallback_type,
            }
            if item.get('required') is False:
                entry['required'] = False
            normalized.append(entry)
        return normalized

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

    def _resolve_manifest_runtime_dir(root_dir: Path, manifest_dir: Path, source_path_value: object) -> Path:
        raw = str(source_path_value or '').replace('\\', '/').strip()
        if not raw:
            return manifest_dir
        parts = [part for part in raw.split('/') if part not in ('', '.')]
        if any(part == '..' for part in parts):
            return manifest_dir
        try:
            candidate = Path(raw).expanduser()
            if not candidate.is_absolute():
                candidate = root_dir.joinpath(*parts)
            candidate = candidate.resolve()
            root_resolved = root_dir.resolve()
            if candidate.exists() and candidate.is_dir() and os.path.commonpath([str(root_resolved), str(candidate)]) == str(root_resolved):
                return candidate
        except Exception:
            return manifest_dir
        return manifest_dir

    def _scan_generator_dependency_metadata(item_path: str) -> dict[str, object]:
        try:
            import yaml  # type: ignore
            from scenarioforge.compose_dependencies import scan_compose_dependencies
        except Exception as exc:
            return {
                'required_files': [],
                'missing_required_files': [],
                'compose_dependency_warning': f'Dependency scan unavailable: {exc}',
            }

        root_dir = Path(str(item_path or '')).expanduser()
        if not root_dir.exists() or not root_dir.is_dir():
            return {
                'required_files': [],
                'missing_required_files': [],
                'compose_dependency_warning': 'Generator path is missing.',
            }

        manifest_path = None
        for filename in ('manifest.yaml', 'manifest.yml'):
            candidate = root_dir / filename
            if candidate.is_file():
                manifest_path = candidate
                break
        if manifest_path is None:
            for filename in ('manifest.yaml', 'manifest.yml'):
                for candidate in sorted(root_dir.rglob(filename)):
                    if candidate.is_file() and '__MACOSX' not in candidate.parts:
                        manifest_path = candidate
                        break
                if manifest_path is not None:
                    break
        if manifest_path is None:
            return {
                'required_files': [],
                'missing_required_files': [],
                'compose_dependency_warning': 'Generator manifest is missing.',
            }

        try:
            document = yaml.safe_load(manifest_path.read_text(encoding='utf-8', errors='ignore'))
        except Exception as exc:
            return {
                'required_files': [],
                'missing_required_files': [],
                'compose_dependency_warning': f'Generator manifest could not be read: {exc}',
            }
        if not isinstance(document, dict):
            return {
                'required_files': [],
                'missing_required_files': [],
                'compose_dependency_warning': 'Generator manifest is invalid.',
            }

        runtime = document.get('runtime') if isinstance(document.get('runtime'), dict) else {}
        runtime_type = str(runtime.get('type') or 'docker-compose').strip().lower()
        if runtime_type not in {'docker-compose', 'compose'}:
            return {'required_files': [], 'missing_required_files': [], 'compose_dependency_warning': ''}

        runtime_dir = _resolve_manifest_runtime_dir(
            root_dir,
            manifest_path.parent,
            document.get('source_path') or (document.get('source', {}).get('path') if isinstance(document.get('source'), dict) else ''),
        )
        compose_name = str(runtime.get('compose_file') or runtime.get('file') or 'docker-compose.yml').strip() or 'docker-compose.yml'
        compose_path = (runtime_dir / compose_name).resolve()
        if not compose_path.is_file():
            return {
                'required_files': [],
                'missing_required_files': [],
                'compose_dependency_warning': f'Compose file is missing: {compose_name}',
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
            'requires_build_network': bool(summary.get('requires_build_network')) if isinstance(summary, dict) else False,
            'build_network_notes': list(summary.get('build_network_notes') or []) if isinstance(summary, dict) else [],
        }

    def _recheck_generator_dependency_cache(kind: str) -> dict[str, int]:
        from scenarioforge.compose_dependencies import apply_dependency_auto_disable
        state = load_installed_generator_packs_state()
        packs = state.get('packs') if isinstance(state, dict) else None
        if not isinstance(packs, list):
            packs = []
        checked = 0
        missing_count = 0
        changed = False
        checked_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        for pack in packs:
            if not isinstance(pack, dict) or pack.get('uninstalled') is True:
                continue
            installed = pack.get('installed') if isinstance(pack.get('installed'), list) else []
            for item in installed:
                if not isinstance(item, dict) or item.get('uninstalled') is True:
                    continue
                if str(item.get('kind') or '').strip() != kind:
                    continue
                metadata = _scan_generator_dependency_metadata(str(item.get('path') or ''))
                for key in ('required_files', 'missing_required_files', 'compose_dependency_warning',
                            'requires_build_network', 'build_network_notes'):
                    if item.get(key) != metadata.get(key):
                        item[key] = metadata.get(key)
                        changed = True
                if item.get('dependency_checked_at') != checked_at:
                    item['dependency_checked_at'] = checked_at
                    changed = True
                checked += 1
                missing = metadata.get('missing_required_files') if isinstance(metadata.get('missing_required_files'), list) else []
                if apply_dependency_auto_disable(
                    item,
                    missing=bool(missing),
                    needs_build_network=bool(metadata.get('requires_build_network')),
                ):
                    changed = True
                missing_count += len(missing)
        if changed:
            state['packs'] = packs
            save_installed_generator_packs_state(state)
        return {'checked': checked, 'missing': missing_count}

    def _normalize_manifest_artifacts(artifacts: object) -> list[dict]:
        normalized: list[dict] = []
        if not isinstance(artifacts, dict):
            return normalized
        produces = artifacts.get('produces')
        if not isinstance(produces, list):
            return normalized
        for item in produces:
            if isinstance(item, dict):
                name = str(item.get('artifact') or item.get('name') or '').strip()
            else:
                name = str(item or '').strip()
            if not name:
                continue
            normalized.append({'name': name, 'type': 'artifact'})
        return normalized

    def _load_duplicate_installed_generator_views(kind: str, visible_manifest_paths: set[str]) -> tuple[list[dict], set[str]]:
        duplicate_manifest_paths: set[str] = set()
        duplicate_views: list[dict] = []
        try:
            import yaml  # type: ignore
        except Exception:
            return duplicate_views, duplicate_manifest_paths
        state = load_installed_generator_packs_state()
        packs = state.get('packs') if isinstance(state, dict) else None
        if not isinstance(packs, list):
            return duplicate_views, duplicate_manifest_paths

        records: list[dict] = []
        for pack in packs:
            if not isinstance(pack, dict):
                continue
            if pack.get('uninstalled') is True:
                continue
            pack_id = str(pack.get('id') or '').strip()
            pack_label = str(pack.get('label') or '').strip()
            pack_disabled = bool(pack.get('disabled') is True)
            installed = pack.get('installed') or []
            if not isinstance(installed, list):
                continue
            for item in installed:
                if not isinstance(item, dict):
                    continue
                if item.get('uninstalled') is True:
                    continue
                if str(item.get('kind') or '').strip() != kind:
                    continue
                item_path = str(item.get('path') or '').strip()
                if not item_path:
                    continue
                manifest_path = ''
                for filename in ('manifest.yaml', 'manifest.yml'):
                    candidate = os.path.join(item_path, filename)
                    if os.path.isfile(candidate):
                        manifest_path = candidate
                        break
                if not manifest_path:
                    continue
                try:
                    document = yaml.safe_load(Path(manifest_path).read_text(encoding='utf-8', errors='ignore'))
                except Exception:
                    continue
                if not isinstance(document, dict):
                    continue
                source_id = str(document.get('id') or '').strip()
                marker_path = os.path.join(item_path, '.coretg_pack.json')
                if os.path.isfile(marker_path):
                    try:
                        marker = json.loads(Path(marker_path).read_text(encoding='utf-8', errors='ignore') or '{}')
                    except Exception:
                        marker = None
                    if isinstance(marker, dict):
                        source_id = str(marker.get('source_generator_id') or source_id).strip()
                if not source_id:
                    continue
                required_files = item.get('required_files') if isinstance(item.get('required_files'), list) else []
                missing_required_files = item.get('missing_required_files') if isinstance(item.get('missing_required_files'), list) else []
                compose_dependency_warning = str(item.get('compose_dependency_warning') or '').strip()
                records.append({
                    'id': source_id,
                    'name': str(document.get('name') or source_id).strip() or source_id,
                    'description': str(document.get('description') or '').strip(),
                    'language': str(document.get('language') or 'python').strip() or 'python',
                    'inputs': _normalize_manifest_io(document.get('inputs'), fallback_type='string'),
                    'outputs': _normalize_manifest_artifacts(document.get('artifacts')),
                    'inject_files': list(document.get('injects') or []) if isinstance(document.get('injects'), list) else [],
                    'source': {
                        'type': 'local-path',
                        'path': item_path,
                        'ref': '',
                        'subpath': '',
                        'entry': '',
                    },
                    '_source_name': pack_label or 'installed',
                    '_source_path': manifest_path,
                    '_pack_id': pack_id,
                    '_pack_label': pack_label,
                    '_installed': True,
                    '_disabled': pack_disabled or bool(item.get('disabled') is True),
                    '_disabled_due_to_missing_files': bool(item.get('disabled_due_to_missing_files') is True),
                    'required_files': required_files,
                    'missing_required_files': missing_required_files,
                    'compose_dependency_warning': compose_dependency_warning,
                    'dependency_checked_at': str(item.get('dependency_checked_at') or '').strip(),
                })

        counts: dict[str, int] = {}
        for record in records:
            counts[record['id']] = counts.get(record['id'], 0) + 1

        for record in records:
            if counts.get(record['id'], 0) < 2:
                continue
            manifest_path = os.path.abspath(str(record.get('_source_path') or '').strip())
            duplicate_manifest_paths.add(manifest_path)
            if manifest_path in visible_manifest_paths:
                continue
            duplicate_record = dict(record)
            duplicate_record['_duplicate_conflict'] = True
            duplicate_record['_duplicate_conflict_note'] = (
                f'Duplicate generator id "{record["id"]}" from installed pack '
                f'{record.get("_pack_label") or record.get("_pack_id") or "(unknown)"}.'
            )
            duplicate_views.append(duplicate_record)

        return duplicate_views, duplicate_manifest_paths

    def _filter_duplicate_installed_errors(errors: object, duplicate_manifest_paths: set[str]) -> list[dict]:
        filtered: list[dict] = []
        installed_root = os.path.abspath(installed_generators_root())
        for error in (errors or []):
            if not isinstance(error, dict):
                continue
            err_text = str(error.get('error') or '').strip().lower()
            err_path_raw = str(error.get('path') or '').strip()
            err_path = os.path.abspath(err_path_raw) if err_path_raw else ''
            if err_text.startswith('duplicate generator id:') and err_path:
                try:
                    if os.path.commonpath([installed_root, err_path]) == installed_root and (not duplicate_manifest_paths or err_path in duplicate_manifest_paths):
                        continue
                except Exception:
                    pass
            filtered.append(error)
        return filtered

    @app.route('/flag_generators_data')
    def flag_generators_data():
        try:
            generators, errors = flag_generators_from_enabled_sources()
            generators = [g for g in (generators or []) if isinstance(g, dict) and is_installed_generator_view(g)]
            generators = annotate_disabled_state(generators, kind='flag-generator')
            generators = [g for g in generators if not g.get('_uninstalled')]
            generators = _attach_test_metadata(generators, kind='flag-generator')
            visible_manifest_paths = {
                os.path.abspath(str(g.get('_source_path') or '').strip())
                for g in generators
                if str(g.get('_source_path') or '').strip()
            }
            duplicates, duplicate_manifest_paths = _load_duplicate_installed_generator_views('flag-generator', visible_manifest_paths)
            generators.extend(duplicates)
            return jsonify({'generators': generators, 'errors': _filter_duplicate_installed_errors(errors, duplicate_manifest_paths)})
        except Exception as exc:
            return jsonify({'generators': [], 'errors': [{'error': str(exc)}]}), 500

    @app.route('/flag_node_generators_data')
    def flag_node_generators_data():
        try:
            generators, errors = flag_node_generators_from_enabled_sources()
            generators = [g for g in (generators or []) if isinstance(g, dict) and is_installed_generator_view(g)]
            generators = annotate_disabled_state(generators, kind='flag-node-generator')
            generators = [g for g in generators if not g.get('_uninstalled')]
            generators = _attach_test_metadata(generators, kind='flag-node-generator')
            visible_manifest_paths = {
                os.path.abspath(str(g.get('_source_path') or '').strip())
                for g in generators
                if str(g.get('_source_path') or '').strip()
            }
            duplicates, duplicate_manifest_paths = _load_duplicate_installed_generator_views('flag-node-generator', visible_manifest_paths)
            generators.extend(duplicates)
            return jsonify({'generators': generators, 'errors': _filter_duplicate_installed_errors(errors, duplicate_manifest_paths)})
        except Exception as exc:
            return jsonify({'generators': [], 'errors': [{'error': str(exc)}]}), 500

    @app.route('/api/generator_catalog/recheck_dependencies', methods=['POST'])
    def generator_catalog_recheck_dependencies():
        payload = request.get_json(silent=True) or {}
        kind = str(payload.get('kind') or '').strip()
        if kind not in {'flag-generator', 'flag-node-generator'}:
            return jsonify({'ok': False, 'error': 'Invalid kind'}), 400
        stats = _recheck_generator_dependency_cache(kind)
        return jsonify({
            'ok': True,
            'kind': kind,
            'checked_count': stats.get('checked', 0),
            'missing_required_file_count': stats.get('missing', 0),
        })

    @app.route('/api/generator_catalog/test_log')
    def generator_catalog_test_log():
        kind = str(request.args.get('kind') or '').strip()
        generator_id = str(request.args.get('generator_id') or '').strip()
        if kind not in {'flag-generator', 'flag-node-generator'}:
            return jsonify({'ok': False, 'error': 'Invalid kind'}), 400
        if not generator_id:
            return jsonify({'ok': False, 'error': 'Missing generator id'}), 400

        outputs_root = os.path.abspath(Path(installed_generators_root()).parent)
        state = load_installed_generator_packs_state()
        packs = state.get('packs') if isinstance(state, dict) else None
        if not isinstance(packs, list):
            packs = []

        for pack in packs:
            if not isinstance(pack, dict):
                continue
            installed = pack.get('installed') if isinstance(pack.get('installed'), list) else []
            for item in installed:
                if not _state_item_matches(item, kind=kind, generator_id=generator_id):
                    continue
                log_path = str(item.get('last_test_log_path') or '').strip()
                if not log_path:
                    return jsonify({'ok': False, 'error': 'Log not available'}), 404
                abs_log_path = os.path.abspath(log_path)
                try:
                    if os.path.commonpath([outputs_root, abs_log_path]) != outputs_root:
                        return jsonify({'ok': False, 'error': 'Refusing path'}), 400
                except Exception:
                    return jsonify({'ok': False, 'error': 'Refusing path'}), 400
                if not os.path.isfile(abs_log_path):
                    return jsonify({'ok': False, 'error': 'Log not available'}), 404
                download_name = str(item.get('last_test_log_filename') or os.path.basename(abs_log_path) or f'{generator_id}.log').strip()
                return send_file(abs_log_path, as_attachment=True, download_name=download_name, mimetype='text/plain; charset=utf-8')

        return jsonify({'ok': False, 'error': 'Unknown generator id'}), 404

    mark_routes_registered(app, 'generator_catalog_data_routes')
