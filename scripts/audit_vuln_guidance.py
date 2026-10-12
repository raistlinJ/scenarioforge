#!/usr/bin/env python3
"""Audit vulnerability catalog readiness for Flow, guides, and evaluations.

By default this checks the active installed catalog.  Pass ``--catalog-dir`` to
check a source catalog before importing it.  ``--check`` exits nonzero unless
every item is evaluation ready, which makes the audit usable in catalog CI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scenarioforge.vulns import (  # noqa: E402
    audit_vulnerability_guidance,
    guidance_audit_markdown,
    load_vuln_metadata_index,
    summarize_guidance_audits,
)


_COMPOSE_NAMES = ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml')


def _read_active_catalog() -> tuple[dict[str, Any], Path, list[dict[str, Any]]]:
    state_path = REPO_ROOT / 'outputs' / 'installed_vuln_catalogs' / '_catalogs_state.json'
    try:
        state = json.loads(state_path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f'Could not read installed catalog state {state_path}: {exc}') from exc
    active_id = str(state.get('active_id') or '').strip()
    entry = next(
        (row for row in state.get('catalogs') or [] if isinstance(row, dict) and str(row.get('id') or '').strip() == active_id),
        None,
    )
    if entry is None:
        raise SystemExit('No active vulnerability catalog is installed.')
    base = REPO_ROOT / str(entry.get('content_dir') or f'outputs/installed_vuln_catalogs/{active_id}/content')
    items = [row for row in entry.get('compose_items') or [] if isinstance(row, dict)]
    return entry, base, items


def _discover_source_catalog(base: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    compose_dirs = sorted({path.parent for name in _COMPOSE_NAMES for path in base.rglob(name)})
    items = [
        {
            'id': position,
            'dir_rel': directory.relative_to(base).as_posix(),
            'validated_ok': None,
            'disabled': False,
        }
        for position, directory in enumerate(compose_dirs, 1)
    ]
    return {'id': base.name, 'label': base.name, 'from_source': str(base)}, items


def _display_name(item: dict[str, Any]) -> str:
    rel = str(item.get('dir_rel') or item.get('rel_dir') or item.get('name') or '').replace('\\', '/').strip('/')
    parts = [part for part in rel.split('/') if part]
    return '/'.join(parts[-2:]) if len(parts) >= 2 else (parts[-1] if parts else 'root')


def _has_readme(directory: Path) -> bool:
    try:
        return any(
            path.is_file()
            and path.name.lower().startswith('readme')
            and path.suffix.lower() in ('.md', '.markdown', '.txt')
            for path in directory.iterdir()
        )
    except OSError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog-dir', help='Source catalog root; defaults to the active installed catalog')
    parser.add_argument('--json-output', help='Write the detailed JSON report to this path')
    parser.add_argument('--markdown-output', help='Write the readable Markdown report to this path')
    parser.add_argument('--repo-metadata', action='store_true', help='Also apply this ScenarioForge checkout\'s site-wide vuln_metadata.yaml')
    parser.add_argument('--check', action='store_true', help='Exit 1 when any catalog item is not evaluation ready')
    args = parser.parse_args(argv)

    if args.catalog_dir:
        base = Path(args.catalog_dir).expanduser().resolve()
        if not base.is_dir():
            raise SystemExit(f'Catalog directory does not exist: {base}')
        entry, items = _discover_source_catalog(base)
        use_repo_metadata = bool(args.repo_metadata)
    else:
        entry, base, items = _read_active_catalog()
        use_repo_metadata = True

    entry_dirs = [base / str(item.get('dir_rel') or item.get('rel_dir') or '') for item in items]
    index = load_vuln_metadata_index(
        entry_dirs=entry_dirs,
        catalog_dirs=[base, base.parent],
        repo_root=REPO_ROOT if use_repo_metadata else None,
    )

    rows: list[dict[str, Any]] = []
    for item in items:
        rel = str(item.get('dir_rel') or item.get('rel_dir') or '').strip()
        name = _display_name(item)
        directory = base / rel
        facts = index.lookup(item.get('dir_rel'), item.get('rel_dir'), item.get('name'), name)
        rows.append({
            'id': int(item.get('id') or 0),
            'name': name,
            'path': rel,
            'validated_ok': item.get('validated_ok') if isinstance(item.get('validated_ok'), bool) else None,
            'disabled': bool(item.get('disabled')),
            'guidance_audit': audit_vulnerability_guidance(facts, readme_available=_has_readme(directory)),
        })

    summary = summarize_guidance_audits(row['guidance_audit'] for row in rows)
    payload = {
        'schema_version': 1,
        'catalog': {
            'id': str(entry.get('id') or ''),
            'label': str(entry.get('label') or entry.get('id') or base.name),
            'from_source': str(entry.get('from_source') or ''),
            'directory': str(base),
        },
        'summary': summary,
        'metadata_errors': index.errors,
        'items': rows,
    }

    if args.json_output:
        output = Path(args.json_output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    if args.markdown_output:
        output = Path(args.markdown_output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            guidance_audit_markdown(catalog=payload['catalog']['label'], items=rows),
            encoding='utf-8',
        )

    print(json.dumps(summary, indent=2))
    if index.errors:
        print(f'Metadata errors: {len(index.errors)}', file=sys.stderr)
        for error in index.errors:
            print(f'  - {error}', file=sys.stderr)
    if args.check and summary['ready'] != summary['total']:
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
