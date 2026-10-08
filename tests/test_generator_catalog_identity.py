import json
from pathlib import Path

from flask import Flask

from webapp.routes import flag_catalog_pages


def test_pack_page_uses_same_source_ids_as_flow(monkeypatch, tmp_path):
    from webapp import app_backend as backend

    installed = tmp_path / 'node-generator'
    installed.mkdir()
    (installed / '.coretg_pack.json').write_text(json.dumps({
        'generator_id': '131', 'source_generator_id': 'http-token',
    }))
    state = {'packs': [{'id': 'pack-one', 'label': 'Demo pack', 'installed': [
        {'id': '131', 'kind': 'flag-node-generator', 'path': str(installed)},
        {'id': '132', 'kind': 'flag-node-generator', 'path': str(tmp_path / 'legacy')},
        {'id': '133', 'kind': 'flag-node-generator', 'uninstalled': True},
    ]}]}
    app = Flask(__name__)
    monkeypatch.setattr(flag_catalog_pages, 'render_template', lambda template, **context: context)
    flag_catalog_pages.register(app, load_installed_generator_packs_state=lambda: state,
        installed_generator_source_id=backend._installed_generator_marker_source_id)
    response = app.test_client().get('/flag_catalog')
    group = response.json['packs'][0]['installed_grouped'][0]
    assert group == {'kind': 'flag-node-generator', 'ids': ['http-token', '132'],
                     'installation_ids': ['131', '132'], 'count': 2}
    assert response.json['packs'][0]['installed'][0]['flow_id'] == 'http-token'


def test_catalog_identity_is_visible_and_escaped_in_browser():
    import pytest
    playwright = pytest.importorskip('playwright.sync_api')
    template = (Path(__file__).resolve().parents[1] / 'webapp/templates/flag_catalog.html').read_text()
    identity = template[template.index('  function generatorIdentityHtml('):template.index('  function generatorArchitectureBadge(')]
    escaping = template[template.index('  function escapeHtml('):]
    escaping = escaping[:escaping.index('\n  function ', 10)]
    with playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch(channel='chrome', headless=True)
        try:
            page = browser.new_page()
            page.set_content('<div id="identity"></div>')
            page.add_script_tag(content=escaping + '\n' + identity)
            page.evaluate("document.querySelector('#identity').innerHTML=generatorIdentityHtml({id:'http-token',_installed_assigned_id:'131'})")
            assert page.locator('#identity').inner_text() == 'Flow ID: http-token · Installation ID: 131'
            page.evaluate("document.querySelector('#identity').innerHTML=generatorIdentityHtml({id:'<script>bad</script>',_installed_assigned_id:'131'})")
            assert page.locator('#identity script').count() == 0
            assert '<script>bad</script>' in page.locator('#identity').inner_text()
        finally:
            browser.close()
