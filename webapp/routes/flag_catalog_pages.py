from __future__ import annotations

from typing import Callable

from flask import render_template

from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(
    app,
    *,
    load_installed_generator_packs_state: Callable[[], dict],
    save_installed_generator_packs_state: Callable[[dict], None] | None = None,
    flag_generators_from_sources: Callable[[], tuple[list[dict], list[dict]]] | None = None,
    flag_node_generators_from_sources: Callable[[], tuple[list[dict], list[dict]]] | None = None,
) -> None:
    if not begin_route_registration(app, 'flag_catalog_pages_routes'):
        return

    def _attach_installed_grouping(packs: list[dict]) -> None:
        for pack in packs:
            if not isinstance(pack, dict):
                continue
            installed = pack.get('installed')
            if not isinstance(installed, list):
                continue
            grouped: dict[str, list[str]] = {}
            for item in installed:
                if not isinstance(item, dict):
                    continue
                if item.get('uninstalled') is True:
                    continue
                kind = str(item.get('kind') or '').strip()
                gid = str(item.get('id') or '').strip()
                if not kind or not gid:
                    continue
                grouped.setdefault(kind, []).append(gid)
            installed_grouped = []
            for kind, ids in grouped.items():
                uniq_ids = []
                seen = set()
                for value in ids:
                    if value in seen:
                        continue
                    seen.add(value)
                    uniq_ids.append(value)
                installed_grouped.append({'kind': kind, 'ids': uniq_ids, 'count': len(uniq_ids)})
            if installed_grouped:
                pack['installed_grouped'] = installed_grouped

    @app.route('/flag_catalog')
    def flag_catalog_page():
        packs_state = load_installed_generator_packs_state()
        try:
            packs = packs_state.get('packs', []) if isinstance(packs_state, dict) else []
            visible_packs = [p for p in packs if isinstance(p, dict) and p.get('uninstalled') is not True]
            _attach_installed_grouping(visible_packs)
        except Exception:
            visible_packs = packs_state.get('packs', []) if isinstance(packs_state, dict) else []
        return render_template(
            'flag_catalog.html',
            packs=visible_packs,
            active_page='flag_catalog',
        )

    @app.route('/data_sources')
    def data_sources_page():
        return render_template('data_sources.html', active_page='')

    mark_routes_registered(app, 'flag_catalog_pages_routes')