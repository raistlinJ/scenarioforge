from __future__ import annotations

import os
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore


@dataclass(frozen=True)
class ManifestLoadError:
    path: str
    error: str


CANONICAL_INPUT_TYPES: set[str] = {
    'string',
    'int',
    'float',
    'number',
    'boolean',
    'json',
    'file',
    'string_list',
    'file_list',
}

HINT_LEVELS: tuple[str, ...] = ('low', 'medium', 'high')


def normalize_artifact_name(name: Any) -> str:
    raw = str(name or '').strip()
    if not raw:
        return ''
    return raw


def normalize_manifest_input_type(type_value: Any) -> str:
    """Normalize manifest input types to a small, mandatory canonical set.

    Unknown/missing values fall back to "string".
    """
    try:
        t0 = str(type_value or '').strip().lower()
    except Exception:
        t0 = ''
    if not t0:
        return 'string'

    t = t0
    is_list = False
    try:
        if 'list' in t or t.endswith('[]'):
            is_list = True
    except Exception:
        is_list = False

    if t in CANONICAL_INPUT_TYPES:
        return t

    # File/path.
    if t in {'filepath', 'file_path', 'path', 'pathname'}:
        return 'file'
    if is_list and ('file' in t or 'path' in t):
        return 'file_list'
    if (not is_list) and ('file' in t or 'path' in t):
        return 'file'

    # Strings.
    if t in {'str', 'text'}:
        return 'string'
    if is_list and ('string' in t or 'str' in t or 'text' in t):
        return 'string_list'
    if t in {'strings'}:
        return 'string_list'
    if t in {'files'}:
        return 'file_list'
    if t.endswith('[]'):
        return 'string_list'

    # Numbers.
    if t in {'integer'}:
        return 'int'
    if t in {'double'}:
        return 'float'
    if t in {'numeric'}:
        return 'number'

    # Booleans.
    if t == 'bool':
        return 'boolean'

    # JSON-ish.
    if t in {'object', 'dict', 'map'}:
        return 'json'

    return 'string'


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _truthy_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 't', 'yes', 'y', 'on'}
    return False


def _paren_balance(value: Any) -> int:
    text = str(value or '')
    return text.count('(') - text.count(')')


def _repair_split_fact_sequence(value: Any) -> list[Any]:
    """Join fact names split by unquoted commas in YAML flow lists.

    Manifests historically use values such as
    ``produces: [Credential(user, password)]``. PyYAML parses that as two
    list entries: ``Credential(user`` and ``password)``. This repairs only
    obviously unbalanced fact-style strings and leaves ordinary lists intact.
    """
    repaired: list[Any] = []
    pending: list[str] = []
    balance = 0

    for item in _as_list(value):
        if pending:
            if isinstance(item, str):
                token = str(item or '').strip()
                if token:
                    pending.append(token)
                    balance += _paren_balance(token)
                if balance <= 0:
                    repaired.append(', '.join(pending))
                    pending = []
                    balance = 0
                continue
            repaired.append(', '.join(pending))
            pending = []
            balance = 0

        if isinstance(item, str):
            token = str(item or '').strip()
            if token and '(' in token and _paren_balance(token) > 0:
                pending = [token]
                balance = _paren_balance(token)
                continue
        repaired.append(item)

    if pending:
        repaired.append(', '.join(pending))
    return repaired


def _repair_split_fact_mapping_value(item: dict[str, Any], key: str) -> str:
    raw = str(item.get(key) or '').strip()
    if not raw or '(' not in raw or _paren_balance(raw) <= 0:
        return raw

    parts = [raw]
    balance = _paren_balance(raw)
    seen_key = False
    for map_key, map_value in item.items():
        if map_key == key:
            seen_key = True
            continue
        if not seen_key:
            continue
        if balance <= 0:
            break
        if map_value is not None:
            continue
        token = str(map_key or '').strip()
        if not token:
            continue
        parts.append(token)
        balance += _paren_balance(token)

    return ', '.join(parts)


def normalize_artifact_name_list(value: Any) -> list[str]:
    """Normalize a manifest artifact sequence into fact-name strings."""
    out: list[str] = []
    for item in _repair_split_fact_sequence(value):
        if isinstance(item, str):
            artifact = normalize_artifact_name(item)
        elif isinstance(item, dict):
            artifact = normalize_artifact_name(
                _repair_split_fact_mapping_value(item, 'artifact')
                or _repair_split_fact_mapping_value(item, 'name')
                or ''
            )
        else:
            artifact = normalize_artifact_name(item)
        if artifact:
            out.append(artifact)
    return out


def _norm_kind(kind: str) -> str:
    k = str(kind or '').strip().lower().replace('_', '-').replace(' ', '-')
    if k in {'flag-generator', 'flag-generator-plugin', 'generator', 'flaggen'}:
        return 'flag-generator'
    if k in {'flag-node-generator', 'flag-node-generator-plugin', 'node-generator', 'nodegen'}:
        return 'flag-node-generator'
    return k


def _norm_inputs(inputs: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in _as_list(inputs):
        if not isinstance(item, dict):
            continue
        name = normalize_artifact_name(_repair_split_fact_mapping_value(item, 'name'))
        if not name:
            continue
        rec: dict[str, Any] = {
            'name': name,
            'type': normalize_manifest_input_type(item.get('type')),
        }
        if 'required' in item:
            rec['required'] = bool(item.get('required'))
        if 'default' in item:
            rec['default'] = item.get('default')
        if 'sensitive' in item:
            rec['sensitive'] = bool(item.get('sensitive'))
        if 'description' in item:
            rec['description'] = str(item.get('description') or '')
        flow_meta = item.get('flow') if isinstance(item.get('flow'), dict) else {}
        if (
            _truthy_flag(item.get('flow_supply_when_first'))
            or _truthy_flag(item.get('chain_supplied_when_first'))
            or _truthy_flag(item.get('flow_required_when_first'))
            or _truthy_flag(flow_meta.get('supply_when_first'))
            or _truthy_flag(flow_meta.get('required_when_first'))
        ):
            rec['flow_supply_when_first'] = True
        out.append(rec)
    return out


def _norm_string_list(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list):
        candidates = value
    else:
        candidates = []
    for item in candidates:
        text = str(item or '').strip()
        if text:
            out.append(text)
    return out


def _norm_hint_levels(value: Any) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not isinstance(value, dict):
        return out
    for level in HINT_LEVELS:
        values = _norm_string_list(value.get(level))
        if values:
            out[level] = values
    return out


def _norm_artifact_list(value: Any) -> list[dict[str, Any]]:
    """Normalize produces list into list[{artifact, description?}]."""
    out: list[dict[str, Any]] = []
    for item in _repair_split_fact_sequence(value):
        if isinstance(item, str):
            a = normalize_artifact_name(item)
            if a:
                out.append({'artifact': a})
            continue
        if isinstance(item, dict):
            a = normalize_artifact_name(
                _repair_split_fact_mapping_value(item, 'artifact')
                or _repair_split_fact_mapping_value(item, 'name')
                or ''
            )
            if not a:
                continue
            rec: dict[str, Any] = {'artifact': a}
            if 'description' in item:
                rec['description'] = str(item.get('description') or '')
            out.append(rec)
    return out


def _artifact_kind(artifact: str) -> str:
    """Best-effort classification for UI (file vs folder vs other).

    Artifacts are now fact-style (e.g., "File(path)"). We only need a lightweight
    hint so the UI can distinguish file vs folder.
    """
    a = str(artifact or '').strip()
    if not a:
        return ''
    try:
        from scenarioforge.sequencer.facts import parse_fact_ref
        parsed = parse_fact_ref(a)
    except Exception:
        parsed = None
    if parsed:
        name = parsed[0].strip().lower()
        if name in {'file', 'binary', 'pcap', 'backuparchive', 'sourcecode', 'encryptedblob', 'decryptionkey'}:
            return 'file'
        if name in {'directory'}:
            return 'dir'
        return ''
    return ''


def _read_installed_pack_marker_ids(generator_path: Path) -> list[str]:
    marker_path = generator_path / '.coretg_pack.json'
    try:
        marker = json.loads(marker_path.read_text('utf-8', errors='ignore') or '{}')
    except Exception:
        marker = None
    if not isinstance(marker, dict):
        return []
    ids: list[str] = []
    for key in ('source_generator_id', 'generator_id'):
        value = str(marker.get(key) or '').strip()
        if value and value not in ids:
            ids.append(value)
    return ids


def _load_installed_generator_state(installed_root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    state_path = installed_root / '_packs_state.json'
    try:
        state = json.loads(state_path.read_text('utf-8', errors='ignore') or '{}')
    except Exception:
        return {}
    packs = state.get('packs') if isinstance(state, dict) else None
    if not isinstance(packs, list):
        return {}

    by_kind_id: dict[tuple[str, str], dict[str, Any]] = {}
    for pack in packs:
        if not isinstance(pack, dict):
            continue
        pack_id = str(pack.get('id') or '').strip()
        pack_label = str(pack.get('label') or '').strip() or pack_id
        pack_uninstalled = bool(pack.get('uninstalled') is True)
        pack_disabled = bool(pack.get('disabled') is True or pack_uninstalled)
        installed_items = pack.get('installed') or []
        if not isinstance(installed_items, list):
            continue
        for item in installed_items:
            if not isinstance(item, dict):
                continue
            item_id = str(item.get('id') or '').strip()
            item_kind = _norm_kind(str(item.get('kind') or '').strip())
            if not item_id or not item_kind:
                continue
            item_uninstalled = bool(item.get('uninstalled') is True)
            item_disabled = bool(item.get('disabled') is True or item_uninstalled)
            info = {
                'pack_id': pack_id,
                'pack_label': pack_label,
                'pack_disabled': pack_disabled,
                'pack_uninstalled': pack_uninstalled,
                'item_disabled': item_disabled,
                'item_uninstalled': item_uninstalled,
                'disabled': bool(pack_disabled or item_disabled or item_uninstalled),
                'uninstalled': bool(pack_uninstalled or item_uninstalled),
            }
            if isinstance(item.get('required_files'), list):
                info['required_files'] = item.get('required_files') or []
            if isinstance(item.get('missing_required_files'), list):
                info['missing_required_files'] = item.get('missing_required_files') or []
            info['disabled_due_to_missing_files'] = bool(item.get('disabled_due_to_missing_files') is True)
            warning = str(item.get('compose_dependency_warning') or '').strip()
            if warning:
                info['compose_dependency_warning'] = warning
            checked_at = str(item.get('dependency_checked_at') or '').strip()
            if checked_at:
                info['dependency_checked_at'] = checked_at
            ids = [item_id]
            try:
                item_path = Path(str(item.get('path') or '')).expanduser()
                if not item_path.is_absolute():
                    item_path = (installed_root / item_path).resolve()
                for marker_id in _read_installed_pack_marker_ids(item_path):
                    if marker_id not in ids:
                        ids.append(marker_id)
            except Exception:
                pass
            for generator_id in ids:
                by_kind_id.setdefault((item_kind, generator_id), info)
    return by_kind_id


def _lookup_installed_generator_state(
    state_by_kind_id: dict[tuple[str, str], dict[str, Any]],
    *,
    kind: str,
    candidate_ids: list[str],
) -> dict[str, Any] | None:
    norm_kind = _norm_kind(kind)
    seen: set[str] = set()
    for candidate_id in candidate_ids:
        generator_id = str(candidate_id or '').strip()
        if not generator_id or generator_id in seen:
            continue
        seen.add(generator_id)
        info = state_by_kind_id.get((norm_kind, generator_id))
        if info:
            return info
    return None


def discover_generator_manifests(
    *,
    repo_root: str | os.PathLike[str] | Path,
    kind: str,
    include_disabled: bool = True,
    scan_dependencies: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[ManifestLoadError]]:
    """Discover and load generator manifests.

    Returns:
      - generator views (web UI shape)
      - plugin contracts by id (Flow dependency shape)
      - errors

    Manifest file name: manifest.yaml / manifest.yml

    Notes:
      - This is intentionally strict-ish: manifests missing required fields are skipped.
      - We do not attempt to read legacy v3 JSON catalogs here.
    """
    if yaml is None:
        return [], {}, [ManifestLoadError(path='', error='PyYAML not installed')]

    repo_root_p = Path(repo_root).resolve()
    k = _norm_kind(kind)

    installed_root_env = str(os.environ.get('CORETG_INSTALLED_GENERATORS_DIR') or '').strip()
    if installed_root_env:
        installed_root = Path(installed_root_env).expanduser().resolve()
    else:
        installed_root = repo_root_p / 'outputs' / 'installed_generators'

    if k == 'flag-node-generator':
        base_dirs = [repo_root_p / 'flag_node_generators', installed_root / 'flag_node_generators']
        flow_catalog = 'flag_node_generators'
        plugin_type = 'flag-node-generator'
    else:
        base_dirs = [repo_root_p / 'flag_generators', installed_root / 'flag_generators']
        flow_catalog = 'flag_generators'
        plugin_type = 'flag-generator'

    # Filter to existing directories.
    base_dirs = [p for p in base_dirs if p.exists() and p.is_dir()]
    if not base_dirs:
        return [], {}, []

    generators: list[dict[str, Any]] = []
    plugins_by_id: dict[str, dict[str, Any]] = {}
    gen_index_by_id: dict[str, int] = {}
    is_installed_by_id: dict[str, bool] = {}
    errors: list[ManifestLoadError] = []
    installed_state_by_kind_id = _load_installed_generator_state(installed_root)
    disabled_suppressed_ids: set[str] = set()

    for base_dir in base_dirs:
        is_installed_base = False
        try:
            is_installed_base = base_dir.resolve().is_relative_to(installed_root.resolve())  # type: ignore[attr-defined]
        except Exception:
            try:
                is_installed_base = str(base_dir.resolve()).startswith(str(installed_root.resolve()))
            except Exception:
                is_installed_base = False

        manifest_by_dir: dict[Path, Path] = {}
        for nm in ('manifest.yaml', 'manifest.yml'):
            for manifest_candidate in sorted(base_dir.rglob(nm)):
                if not manifest_candidate.is_file():
                    continue
                if '__MACOSX' in manifest_candidate.parts:
                    continue
                manifest_by_dir.setdefault(manifest_candidate.parent, manifest_candidate)

        for child, manifest_path in sorted(manifest_by_dir.items(), key=lambda item: str(item[0])):

            # Installed generator packs rewrite manifest `id` to a numeric value.
            # For UI/Flow sequencing we want stable IDs, so we remap to the
            # original `source_generator_id` when a pack marker is present.
            installed_source_id = ''
            installed_assigned_id = ''
            installed_pack_id = ''
            installed_pack_label = ''
            installed_pack_origin = ''
            if is_installed_base:
                try:
                    import json

                    marker_path = child / '.coretg_pack.json'
                    if marker_path.exists() and marker_path.is_file():
                        marker = json.loads(marker_path.read_text('utf-8', errors='ignore') or '{}')
                        if isinstance(marker, dict):
                            installed_source_id = str(marker.get('source_generator_id') or '').strip()
                            installed_assigned_id = str(marker.get('generator_id') or '').strip()
                            installed_pack_id = str(marker.get('pack_id') or '').strip()
                            installed_pack_label = str(marker.get('pack_label') or '').strip()
                            installed_pack_origin = str(marker.get('origin') or '').strip()
                except Exception:
                    installed_source_id = ''
                    installed_assigned_id = ''
                    installed_pack_id = ''
                    installed_pack_label = ''
                    installed_pack_origin = ''

            try:
                doc = yaml.safe_load(manifest_path.read_text('utf-8', errors='ignore'))
            except Exception as exc:
                errors.append(ManifestLoadError(path=str(manifest_path), error=f'failed to parse yaml: {exc}'))
                continue

            if not isinstance(doc, dict):
                errors.append(ManifestLoadError(path=str(manifest_path), error='manifest must be a mapping/object'))
                continue

            try:
                mv = int(doc.get('manifest_version') or 0)
            except Exception:
                mv = 0
            if mv != 1:
                errors.append(ManifestLoadError(path=str(manifest_path), error='manifest_version must be 1'))
                continue

            gen_id = str(doc.get('id') or '').strip()
            if not gen_id:
                errors.append(ManifestLoadError(path=str(manifest_path), error='missing id'))
                continue

            # Remap installed pack numeric IDs to stable source IDs when possible.
            if is_installed_base and installed_source_id:
                gen_id = installed_source_id

            name = str(doc.get('name') or gen_id).strip() or gen_id
            description = str(doc.get('description') or '').strip()

            declared_kind = _norm_kind(doc.get('kind') or plugin_type)
            if declared_kind != plugin_type:
                # Skip mismatched manifests to avoid mixing catalogs.
                errors.append(
                    ManifestLoadError(
                        path=str(manifest_path),
                        error=f"kind mismatch: expected {plugin_type}, got {declared_kind}",
                    )
                )
                continue

            installed_disabled_info: dict[str, Any] | None = None
            if is_installed_base:
                installed_disabled_info = _lookup_installed_generator_state(
                    installed_state_by_kind_id,
                    kind=plugin_type,
                    candidate_ids=[gen_id, installed_source_id, installed_assigned_id, str(doc.get('id') or '')],
                )
                if (not include_disabled) and installed_disabled_info and installed_disabled_info.get('disabled') is True:
                    disabled_suppressed_ids.add(gen_id)
                    plugins_by_id.pop(gen_id, None)
                    gen_index_by_id.pop(gen_id, None)
                    is_installed_by_id.pop(gen_id, None)
                    continue
            elif (not include_disabled) and gen_id in disabled_suppressed_ids:
                continue

            runtime = doc.get('runtime') if isinstance(doc.get('runtime'), dict) else {}
            runtime_type = str(runtime.get('type') or 'docker-compose').strip().lower()

            # Source: for installed generators, always point at the installed directory.
            # This avoids manifests overriding source_path to a repo path, which breaks deletion/runtime.
            source_path = ''
            if not is_installed_base:
                source_path = str(
                    doc.get('source_path')
                    or (doc.get('source', {}).get('path') if isinstance(doc.get('source'), dict) else '')
                )
            if not source_path:
                try:
                    source_path = str(child.relative_to(repo_root_p)).replace('\\', '/')
                except Exception:
                    source_path = str(child)

            gen: dict[str, Any] = {
                'id': gen_id,
                'name': name,
                'description': description,
                'language': str(doc.get('language') or 'python'),
                'source': {
                    'type': 'local-path',
                    'path': source_path,
                    'ref': '',
                    'subpath': '',
                    'entry': '',
                },
                # Human-facing source label used throughout the web UI.
                # Prefer the containing pack/bundle label for installed generators.
                '_source_name': (
                    installed_pack_label
                    or (f"pack:{installed_pack_id}" if installed_pack_id else '')
                    or ('repo' if (not is_installed_base) else 'installed')
                ),
                '_source_path': str(manifest_path),
                '_flow_kind': plugin_type,
                '_flow_catalog': flow_catalog,
                'description_hints': list(doc.get('description_hints') or []) if isinstance(doc.get('description_hints'), list) else [],
                'hint_levels': _norm_hint_levels(doc.get('hint_levels')),
                'env': dict(doc.get('env') or {}) if isinstance(doc.get('env'), dict) else {},
            }

            try:
                readme_path = child / 'README.md'
                if readme_path.is_file():
                    gen['readme_path'] = str(readme_path)
                    try:
                        gen['readme_rel_path'] = str(readme_path.relative_to(repo_root_p)).replace('\\', '/')
                    except Exception:
                        gen['readme_rel_path'] = str(readme_path)
            except Exception:
                pass

            # Include access instructions if present in manifest
            if isinstance(doc.get('access_instructions'), dict) and doc.get('access_instructions').get('steps'):
                gen['access_instructions'] = dict(doc.get('access_instructions'))

            if is_installed_base:
                if installed_disabled_info:
                    gen['_pack_id'] = installed_disabled_info.get('pack_id')
                    gen['_pack_label'] = installed_disabled_info.get('pack_label')
                    gen['_pack_disabled'] = bool(installed_disabled_info.get('pack_disabled'))
                    gen['_pack_uninstalled'] = bool(installed_disabled_info.get('pack_uninstalled'))
                    gen['_disabled'] = bool(installed_disabled_info.get('disabled'))
                    gen['_item_disabled'] = bool(installed_disabled_info.get('item_disabled'))
                    gen['_disabled_due_to_missing_files'] = bool(installed_disabled_info.get('disabled_due_to_missing_files'))
                    gen['_item_uninstalled'] = bool(installed_disabled_info.get('item_uninstalled'))
                    gen['_uninstalled'] = bool(installed_disabled_info.get('uninstalled'))
                    if isinstance(installed_disabled_info.get('required_files'), list):
                        gen['required_files'] = installed_disabled_info.get('required_files') or []
                    if isinstance(installed_disabled_info.get('missing_required_files'), list):
                        gen['missing_required_files'] = installed_disabled_info.get('missing_required_files') or []
                    if installed_disabled_info.get('compose_dependency_warning'):
                        gen['compose_dependency_warning'] = str(installed_disabled_info.get('compose_dependency_warning') or '')
                    if installed_disabled_info.get('dependency_checked_at'):
                        gen['dependency_checked_at'] = str(installed_disabled_info.get('dependency_checked_at') or '')
                if installed_assigned_id:
                    gen['_installed_assigned_id'] = installed_assigned_id
                if installed_source_id:
                    gen['_installed_source_id'] = installed_source_id
                if installed_pack_id:
                    gen['_installed_pack_id'] = installed_pack_id
                if installed_pack_label:
                    gen['_installed_pack_label'] = installed_pack_label
                if installed_pack_origin:
                    gen['_installed_pack_origin'] = installed_pack_origin

            # Runtime
            if runtime_type in {'docker-compose', 'compose'}:
                compose_file = str(runtime.get('compose_file') or runtime.get('file') or 'docker-compose.yml')
                gen['compose'] = {
                    'file': compose_file,
                    'service': str(runtime.get('service') or 'generator'),
                }
                if scan_dependencies:
                    try:
                        from scenarioforge.compose_dependencies import missing_dependency_paths, scan_compose_dependencies

                        scan_base = child
                        source_candidate = Path(source_path)
                        if source_path:
                            if source_candidate.is_absolute():
                                candidate_dir = source_candidate.resolve()
                            else:
                                candidate_dir = (repo_root_p / source_candidate).resolve()
                            if candidate_dir.exists() and candidate_dir.is_dir():
                                scan_base = candidate_dir
                        compose_path = (scan_base / compose_file).resolve()
                        if compose_path.exists() and compose_path.is_file():
                            dependency_summary = scan_compose_dependencies(compose_path)
                            gen['required_files'] = dependency_summary.get('requires') or []
                            gen['missing_required_files'] = missing_dependency_paths(dependency_summary)
                            if dependency_summary.get('warning'):
                                gen['compose_dependency_warning'] = str(dependency_summary.get('warning') or '')
                    except Exception:
                        gen.setdefault('required_files', [])
                        gen.setdefault('missing_required_files', [])
                else:
                    gen.setdefault('required_files', [])
                    gen.setdefault('missing_required_files', [])
            elif runtime_type in {'run', 'command'}:
                cmd = runtime.get('cmd')
                if isinstance(cmd, list):
                    gen['run'] = {'cmd': [str(x) for x in cmd if x is not None], 'workdir': str(runtime.get('workdir') or '${source.path}')}

            gen['inputs'] = _norm_inputs(doc.get('inputs'))

            # Provide "outputs" list for UI convenience (matches existing view shape).
            artifacts = doc.get('artifacts') if isinstance(doc.get('artifacts'), dict) else {}
            produces_list = _norm_artifact_list(artifacts.get('produces'))
            gen['outputs'] = [
                {
                    'name': str(x.get('artifact') or ''),
                    'type': _artifact_kind(str(x.get('artifact') or '')),
                }
                for x in produces_list
                if str(x.get('artifact') or '').strip()
            ]

            injects = doc.get('injects')
            inject_files: list[str] = []
            for x in _repair_split_fact_sequence(injects):
                s = normalize_artifact_name(x)
                if s:
                    inject_files.append(s)
            gen['inject_files'] = inject_files

            # Candidate injection paths: if specified, the runtime will pick one
            # non-deterministically as the destination for inject specs that have no
            # explicit destination.  Validated as absolute paths; invalid entries dropped.
            candidate_paths_raw = doc.get('inject_candidate_paths')
            inject_candidate_paths: list[str] = []
            for x in _as_list(candidate_paths_raw):
                p = str(x or '').strip()
                if p and p.startswith('/') and '..' not in p.split('/'):
                    inject_candidate_paths.append(p.rstrip('/') or '/')
            gen['inject_candidate_paths'] = inject_candidate_paths

            # Build Flow plugin contract.
            requires = normalize_artifact_name_list(artifacts.get('requires'))

            optional_requires = normalize_artifact_name_list(artifacts.get('optional_requires'))

            plugin_contract: dict[str, Any] = {
                'plugin_id': gen_id,
                'plugin_type': plugin_type,
                'version': str(doc.get('version') or '1.0'),
                'description': description,
                'requires': requires,
                'optional_requires': optional_requires,
                'produces': produces_list,
                # Optional convenience mirror.
                'inputs': {i.get('name'): i for i in (gen.get('inputs') or []) if isinstance(i, dict) and i.get('name')},
            }

            if gen_id in plugins_by_id:
                # Prefer installed generators over repo copies when ids collide.
                # This keeps "installed-only" policies working even when a repo
                # includes template/sample generators with the same id.
                prev_installed = bool(is_installed_by_id.get(gen_id))
                if is_installed_base and (not prev_installed):
                    plugins_by_id[gen_id] = plugin_contract
                    idx = gen_index_by_id.get(gen_id)
                    if isinstance(idx, int) and 0 <= idx < len(generators):
                        generators[idx] = gen
                    else:
                        gen_index_by_id[gen_id] = len(generators)
                        generators.append(gen)
                    is_installed_by_id[gen_id] = True
                    continue

                errors.append(ManifestLoadError(path=str(manifest_path), error=f'duplicate generator id: {gen_id}'))
                continue

            plugins_by_id[gen_id] = plugin_contract
            gen_index_by_id[gen_id] = len(generators)
            is_installed_by_id[gen_id] = bool(is_installed_base)
            generators.append(gen)

    if disabled_suppressed_ids:
        generators = [
            generator
            for generator in generators
            if str(generator.get('id') or '').strip() not in disabled_suppressed_ids
        ]
        plugins_by_id = {
            generator_id: plugin
            for generator_id, plugin in plugins_by_id.items()
            if str(generator_id or '').strip() not in disabled_suppressed_ids
        }

    generators.sort(key=lambda g: (str(g.get('name') or '').lower(), str(g.get('id') or '')))
    return generators, plugins_by_id, errors
