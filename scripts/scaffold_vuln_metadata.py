#!/usr/bin/env python3
"""Scaffold a vuln_metadata.yaml covering an installed vulnerability catalog.

Every catalog entry is emitted with ``impact: unknown`` so nothing is silently
assumed. Fill in the real impact per entry, then turn on strict enforcement:

    export SCENARIOFORGE_REQUIRE_VULN_METADATA=1

Entries that already have metadata are preserved and reported as covered, so
this is safe to re-run after a catalog is updated.

Usage:
    python scripts/scaffold_vuln_metadata.py                 # active catalog
    python scripts/scaffold_vuln_metadata.py --catalog-id ID
    python scripts/scaffold_vuln_metadata.py --all --output vuln_metadata.yaml
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scenarioforge.vulns import load_vuln_metadata_index  # noqa: E402
from scenarioforge.vulns.metadata import known_impacts  # noqa: E402


def _state_path() -> Path:
    return REPO_ROOT / 'outputs' / 'installed_vuln_catalogs' / '_catalogs_state.json'


def _load_state() -> dict[str, Any]:
    path = _state_path()
    if not path.is_file():
        raise SystemExit(f'No installed vuln catalog state at {path}')
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f'Could not read {path}: {exc}') from exc


def _display_name(item: dict[str, Any]) -> str:
    rel_dir = str(item.get('rel_dir') or item.get('dir_rel') or '').strip()
    if rel_dir:
        return rel_dir.replace('\\', '/').strip('/')
    return str(item.get('name') or '').strip()


def _selectable(item: dict[str, Any]) -> bool:
    if bool(item.get('disabled', False)):
        return False
    if item.get('validated_incomplete') is True:
        return False
    return item.get('validated_ok') is True


def _yaml_quote(value: str) -> str:
    escaped = str(value).replace('\\', '\\\\').replace('"', '\\"')
    return f'"{escaped}"'


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--catalog-id', default='', help='Catalog id (defaults to the active catalog)')
    parser.add_argument('--all', action='store_true', help='Include every installed catalog')
    parser.add_argument('--output', default='', help='Output path (default: <pack dir>/vuln_metadata.yaml)')
    parser.add_argument(
        '--include-unvalidated',
        action='store_true',
        help='Also emit entries that failed or skipped runtime validation',
    )
    parser.add_argument('--force', action='store_true', help='Overwrite an existing output file')
    args = parser.parse_args(argv)

    state = _load_state()
    catalogs = [c for c in (state.get('catalogs') or []) if isinstance(c, dict)]
    if not catalogs:
        raise SystemExit('No installed vuln catalogs found.')

    if args.all:
        selected = catalogs
    else:
        catalog_id = str(args.catalog_id or state.get('active_id') or '').strip()
        selected = [c for c in catalogs if str(c.get('id') or '').strip() == catalog_id]
        if not selected:
            known = ', '.join(str(c.get('id') or '') for c in catalogs)
            raise SystemExit(f'Catalog {catalog_id!r} not found. Installed: {known}')

    index = load_vuln_metadata_index(
        catalog_dirs=[
            REPO_ROOT / 'outputs' / 'installed_vuln_catalogs' / str(c.get('id') or '')
            for c in catalogs
        ],
        repo_root=REPO_ROOT,
    )

    rows: list[tuple[str, bool]] = []
    seen: set[str] = set()
    for catalog in selected:
        for item in (catalog.get('compose_items') or []):
            if not isinstance(item, dict):
                continue
            if not args.include_unvalidated and not _selectable(item):
                continue
            name = _display_name(item)
            if not name or name in seen:
                continue
            seen.add(name)
            rows.append((name, index.lookup(name) is not None))

    if not rows:
        raise SystemExit('No catalog entries matched. Try --include-unvalidated.')

    covered = [name for name, hit in rows if hit]
    missing = [name for name, hit in rows if not hit]

    if args.output:
        out_path = Path(args.output)
    elif args.all:
        out_path = REPO_ROOT / 'vuln_metadata.yaml'
    else:
        out_path = (
            REPO_ROOT
            / 'outputs'
            / 'installed_vuln_catalogs'
            / str(selected[0].get('id') or '')
            / 'vuln_metadata.yaml'
        )

    if out_path.exists() and not args.force:
        raise SystemExit(
            f'{out_path} already exists. Re-run with --force to overwrite, '
            f'or use --output to write elsewhere.'
        )

    label = str(selected[0].get('label') or selected[0].get('id') or '') if not args.all else 'all'
    lines: list[str] = [
        '# ScenarioForge vulnerability capability metadata.',
        '# Schema: schemas/vulns/vuln_metadata_v1.schema.json',
        '#',
        '# Set each entry\'s `impact` to what a solver actually gains. Valid values:',
    ]
    for impact in known_impacts():
        lines.append(f'#   {impact}')
    lines.extend([
        '#',
        '# `impact` expands to a default fact set; add `provides:`/`requires:` to',
        '# extend it. Entries left as `unknown` grant nothing and will be rejected',
        '# once SCENARIOFORGE_REQUIRE_VULN_METADATA=1.',
        '',
        'schema_version: 1',
        f'catalog: {_yaml_quote(label)}',
        'vulns:',
    ])

    for name in missing:
        lines.append(f'  - match: {_yaml_quote(name)}')
        lines.append('    impact: unknown')
    if not missing:
        lines.append('  []')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    print(f'Wrote {out_path}')
    print(f'  entries scanned: {len(rows)}')
    print(f'  already covered: {len(covered)}')
    print(f'  needing impact:  {len(missing)}')
    if covered:
        print('  (covered entries were not re-emitted; existing metadata is preserved)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
