from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore


_INTERPOLATION_RE = re.compile(r'(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*)')
_URI_RE = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*://')


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_path_text(value: Any) -> str:
    return str(value or '').strip().replace('\\', '/')


def _has_interpolation(path: str) -> bool:
    return bool(_INTERPOLATION_RE.search(path or ''))


def _is_remote_or_named_context(path: str) -> bool:
    p = str(path or '').strip()
    if not p:
        return False
    if _URI_RE.match(p):
        return True
    if p.startswith(('git@', 'github.com:', 'docker-image://', 'service:')):
        return True
    return False


def _looks_like_local_volume_source(path: str) -> bool:
    p = str(path or '').strip()
    if not p:
        return False
    if os.path.isabs(p):
        return True
    if p.startswith(('.', '~')):
        return True
    return '/' in p or '\\' in p


def _resolve_path(base_dir: Path, raw_path: str) -> Path | None:
    p = str(raw_path or '').strip()
    if not p or _has_interpolation(p) or _is_remote_or_named_context(p):
        return None
    try:
        if p.startswith('~/') or p == '~':
            return Path(p).expanduser().resolve()
        candidate = Path(p)
        if candidate.is_absolute():
            return candidate.resolve()
        return (base_dir / candidate).resolve()
    except Exception:
        return None


def _entry(
    *,
    kind: str,
    raw_path: str,
    base_dir: Path,
    service: str = '',
    required: bool = True,
) -> dict[str, Any] | None:
    path_text = _normalize_path_text(raw_path)
    if not path_text:
        return None
    resolved = _resolve_path(base_dir, path_text)
    if resolved is None:
        return None
    exists = resolved.exists()
    rec: dict[str, Any] = {
        'kind': kind,
        'path': path_text,
        'resolved_path': str(resolved),
        'exists': bool(exists),
        'required': bool(required),
    }
    try:
        rec['rel_path'] = str(resolved.relative_to(base_dir.resolve())).replace('\\', '/')
    except Exception:
        rec['rel_path'] = path_text
    if service:
        rec['service'] = service
    return rec


def _env_file_path_and_required(entry: Any) -> tuple[str, bool]:
    if isinstance(entry, str):
        return entry.strip(), True
    if isinstance(entry, dict):
        path = str(entry.get('path') or entry.get('file') or '').strip()
        required = entry.get('required')
        if isinstance(required, bool):
            return path, required
        if isinstance(required, str):
            return path, required.strip().lower() not in {'0', 'false', 'no', 'off'}
        return path, True
    return '', True


def _volume_source(volume: Any) -> str:
    if isinstance(volume, str):
        parts = volume.split(':', 2)
        if not parts:
            return ''
        src = str(parts[0] or '').strip()
        if not _looks_like_local_volume_source(src):
            return ''
        return src
    if isinstance(volume, dict):
        vtype = str(volume.get('type') or '').strip().lower()
        src = str(volume.get('source') or volume.get('src') or '').strip()
        if vtype and vtype != 'bind':
            return ''
        if not _looks_like_local_volume_source(src):
            return ''
        return src
    return ''


def _iter_additional_contexts(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for raw in value.values():
            path = str(raw or '').strip()
            if path:
                out.append(path)
    elif isinstance(value, list):
        for raw in value:
            text = str(raw or '').strip()
            if not text:
                continue
            if '=' in text:
                text = text.split('=', 1)[1].strip()
            if text:
                out.append(text)
    return out


def _dedupe(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in entries:
        key = (
            str(item.get('kind') or ''),
            str(item.get('service') or ''),
            str(item.get('resolved_path') or item.get('path') or ''),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def scan_compose_dependencies(compose_path: str | os.PathLike[str] | Path) -> dict[str, Any]:
    """Return local files/directories a compose project references.

    This is deliberately non-fatal. It records files that Docker Compose will
    expect at runtime, especially relative build contexts, env files, bind
    mounts, config/secret files, and include/extends files.
    """
    path = Path(compose_path)
    base_dir = path.parent.resolve()
    summary: dict[str, Any] = {
        'compose_path': str(path),
        'base_dir': str(base_dir),
        'requires': [],
        'missing': [],
        'warning': '',
    }
    if yaml is None:
        summary['warning'] = 'PyYAML not installed'
        return summary
    try:
        doc = yaml.safe_load(path.read_text('utf-8', errors='ignore'))
    except Exception as exc:
        summary['warning'] = f'Unable to parse compose YAML: {exc}'
        return summary
    if not isinstance(doc, dict):
        summary['warning'] = 'Compose document must be a mapping'
        return summary

    entries: list[dict[str, Any]] = []

    def add(kind: str, raw_path: Any, *, service: str = '', required: bool = True, rel_base: Path | None = None) -> None:
        rec = _entry(
            kind=kind,
            raw_path=str(raw_path or ''),
            base_dir=rel_base or base_dir,
            service=service,
            required=required,
        )
        if rec is not None:
            entries.append(rec)

    for include in _as_list(doc.get('include')):
        if isinstance(include, dict):
            add('include', include.get('path') or include.get('file') or '')
        else:
            add('include', include)

    services = doc.get('services')
    if isinstance(services, dict):
        for svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            service_name = str(svc_name or '').strip()

            build = svc.get('build')
            if isinstance(build, str):
                add('build_context', build, service=service_name)
                context_path = _resolve_path(base_dir, build)
                if context_path is not None:
                    add('build_dockerfile', 'Dockerfile', service=service_name, rel_base=context_path)
            elif isinstance(build, dict):
                context_raw = str(build.get('context') or '.').strip() or '.'
                add('build_context', context_raw, service=service_name)
                context_path = _resolve_path(base_dir, context_raw)
                dockerfile_inline = bool(str(build.get('dockerfile_inline') or '').strip())
                if not dockerfile_inline and context_path is not None:
                    dockerfile_raw = str(build.get('dockerfile') or 'Dockerfile').strip() or 'Dockerfile'
                    add('build_dockerfile', dockerfile_raw, service=service_name, rel_base=context_path)
                for additional in _iter_additional_contexts(build.get('additional_contexts')):
                    add('build_additional_context', additional, service=service_name)

            for env_entry in _as_list(svc.get('env_file')):
                env_path, required = _env_file_path_and_required(env_entry)
                add('env_file', env_path, service=service_name, required=required)

            for label_file in _as_list(svc.get('label_file')):
                add('label_file', label_file, service=service_name)

            for volume in _as_list(svc.get('volumes')):
                add('bind_mount', _volume_source(volume), service=service_name)

            extends = svc.get('extends')
            if isinstance(extends, dict):
                add('extends_file', extends.get('file') or '', service=service_name)

            develop = svc.get('develop')
            watches = develop.get('watch') if isinstance(develop, dict) else None
            for watch in _as_list(watches):
                if isinstance(watch, dict):
                    add('develop_watch_path', watch.get('path') or '', service=service_name)

    for section_name, kind in (('configs', 'config_file'), ('secrets', 'secret_file')):
        section = doc.get(section_name)
        if not isinstance(section, dict):
            continue
        for value in section.values():
            if isinstance(value, dict):
                add(kind, value.get('file') or '')

    entries = _dedupe(entries)
    missing = [
        item for item in entries
        if item.get('required') is not False and item.get('exists') is not True
    ]
    summary['requires'] = entries
    summary['missing'] = missing
    return summary


def missing_dependency_paths(summary: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for item in (summary or {}).get('missing') or []:
        if not isinstance(item, dict):
            continue
        text = str(item.get('rel_path') or item.get('path') or '').strip()
        if text:
            out.append(text)
    return sorted(dict.fromkeys(out))
