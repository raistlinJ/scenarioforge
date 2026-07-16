import json
import os
import re
from pathlib import Path

from webapp.app_backend import app


FULL_PREVIEW_SCRIPTS_PATH = Path(__file__).resolve().parent.parent / 'webapp' / 'templates' / 'full_preview_scripts.html'
TOPOLOGY_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / 'webapp' / 'templates' / 'index.html'


def _sample_xml_path() -> str:
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.abspath(os.path.join(here, os.pardir, 'examples', 'sample.xml'))


def test_full_preview_page_matches_modal_preview():
    app.config['TESTING'] = True
    client = app.test_client()

    sample_xml = _sample_xml_path()
    assert os.path.exists(sample_xml), f"sample xml missing at {sample_xml}"

    # Authenticate with default seeded admin user for protected routes
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    api_resp = client.post('/api/plan/preview_full', json={'xml_path': sample_xml})
    assert api_resp.status_code == 200
    api_payload = api_resp.get_json()
    assert api_payload and api_payload.get('ok'), f"API payload error: {api_payload}"

    api_preview = api_payload['full_preview']
    seed = api_preview.get('seed') or ''

    page_resp = client.post('/plan/full_preview_page', data={'xml_path': sample_xml, 'seed': seed})
    assert page_resp.status_code == 200

    html = page_resp.data.decode('utf-8')
    match = re.search(r'<script id="fpDataJson" type="application/json">(.*?)</script>', html, re.S)
    assert match, 'embedded preview JSON not found in full preview page'

    page_preview = json.loads(match.group(1))

    # Ensure core metrics and detailed structures match between modal and standalone previews
    assert page_preview.get('seed') == api_preview.get('seed')
    for key in (
        'routers',
        'hosts',
        'switches_detail',
        'services_preview',
        'vulnerabilities_preview',
        'segmentation_preview',
        'traffic_summary',
        'r2r_edges_preview',
        'host_router_map',
        'layout_positions',
    ):
        assert page_preview.get(key) == api_preview.get(key), f"Mismatch for key '{key}'"


def test_full_preview_scripts_support_duplicate_sequence_nodes() -> None:
    text = FULL_PREVIEW_SCRIPTS_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'function sequenceIndices(node) {',
        'function sequenceOccurrencesForNode(node, flow) {',
        'const faByIndex = Array.isArray(fas) ? fas : [];',
        'const indexAssignment = (idx < faByIndex.length && faByIndex[idx] && typeof faByIndex[idx] === \'object\')',
        'target.sequence_indices = Array.from(new Set([...',
        'const seqLabel = sequenceRomanLabel(d);',
        '.text(d => sequenceRomanLabel(d));',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing duplicate-sequence preview handling snippets: ' + '; '.join(missing)


def test_full_preview_scripts_use_pre_serialized_preview_json() -> None:
    text = FULL_PREVIEW_SCRIPTS_PATH.read_text(encoding='utf-8', errors='ignore')

    assert '{{ preview_json' in text
    assert "replace('<', '\\\\u003c')" in text
    assert '{{ full_preview | tojson }}' not in text


def test_full_preview_scripts_guard_execute_when_saved_xml_warning_is_active() -> None:
    text = FULL_PREVIEW_SCRIPTS_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "const savedXmlWarningEl = document.getElementById('fpSavedXmlWarning');",
        "function syncSavedXmlGroundTruthAlert() {",
        "(window.top || window).coretgGetSavedXmlGroundTruthWarningState",
        "await ((window.top || window).coretgConfirmSavedXmlGroundTruth?.('Execute', {",
        "allowStored: true,",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing saved-XML execute guard wiring in full_preview_scripts.html: ' + '; '.join(missing)


def test_embedded_preview_executes_in_place_instead_of_redirecting_to_topology() -> None:
    text = FULL_PREVIEW_SCRIPTS_PATH.read_text(encoding='utf-8', errors='ignore')

    assert "event.data?.type !== 'coretg-preview-execute'" in text
    assert 'executeRunBtn.click();' in text
    assert "Preview is an execution surface in its own right." in text
    assert "'?auto_execute=1'" not in text


def test_full_preview_execute_redirect_has_an_outer_scope_scenario_url_builder() -> None:
    text = FULL_PREVIEW_SCRIPTS_PATH.read_text(encoding='utf-8', errors='ignore')

    assert "let scenarioMeta = { scenario: '', xml_basename: '' };" in text
    assert text.index('function buildScenarioUrl(basePath) {') < text.index('function init() {')
    assert text.count('function buildScenarioUrl(basePath) {') == 1
    assert text.count('const reportsHref = buildScenarioUrl') == 2
    assert text.count('presentExecuteSummary(') >= 3
    assert 'presentExecuteSummary(data, reportsHref);' in text
    assert 'presentExecuteSummary(data2, reportsHref);' in text
    assert "type: 'coretg-preview-execution-complete'" in text


def test_preview_execution_modal_shows_summary_generation_and_cannot_be_hidden() -> None:
    page_text = (Path(__file__).resolve().parent.parent / 'webapp' / 'templates' / 'full_preview.html').read_text(encoding='utf-8', errors='ignore')
    script_text = FULL_PREVIEW_SCRIPTS_PATH.read_text(encoding='utf-8', errors='ignore')

    assert 'id="executeProgressHideBtn"' not in page_text
    assert 'id="executeProgressModal"' in page_text
    assert '--bs-modal-width: 1600px' in page_text
    assert 'max-height: 520px' in page_text
    assert 'aria-label="Close"' not in page_text[page_text.index('id="executeProgressModal"'):page_text.index('id="executeSummaryModal"')]
    assert 'id="executeSummaryModal"' in page_text
    assert 'id="executeSummaryList"' in page_text
    assert 'id="executeSummaryCopyBtn"' in page_text
    assert 'id="executeSummaryReportsBtn"' in page_text
    assert script_text.count("status: 'Generating Execution Summary'") == 2
    assert "status: 'Calculating Execution Report Summary, please wait...'" in script_text
    assert "id('executeProgressHideBtn')" not in script_text
    assert 'function renderExecuteSummaryItem(label, ok, detail, items = [])' in script_text
    assert "'Generator inject sources present on CORE VM'" in script_text


def test_topology_has_no_legacy_execution_modals_or_controls() -> None:
    text = TOPOLOGY_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    for marker in (
        'id="executeConfirmModal"',
        'id="runProgressModal"',
        'id="executeSummaryModal"',
        'id="runSuccessModal"',
        'id="fpExecuteBtn"',
    ):
        assert marker not in text


def test_full_preview_page_includes_saved_xml_warning_banner() -> None:
    html_text = (Path(__file__).resolve().parent.parent / 'webapp' / 'templates' / 'full_preview.html').read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'id="fpSavedXmlWarning"',
        'Unsaved edits were present when this preview was opened.',
        'Preview and Execute use the last saved XML until you save again.',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in html_text]
    assert not missing, 'Missing saved-XML warning banner in full_preview.html: ' + '; '.join(missing)


def test_full_preview_scripts_post_ready_after_graph_render_setup() -> None:
    text = FULL_PREVIEW_SCRIPTS_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        "let parentReadyPosted = false;",
        "function notifyParentReady(reason = 'ready') {",
        "window.parent.postMessage({ type: 'full-preview-ready', reason }, window.location.origin);",
        "wrapNode.addEventListener('coretg-graph-ready', () => {",
        "notifyParentReady('graph-ready')",
        "setTimeout(() => notifyParentReady('init-fallback'), 1200);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing delayed full-preview ready signaling snippets: ' + '; '.join(missing)
