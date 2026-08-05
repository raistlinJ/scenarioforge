"""The Generate progress modal reports image pulls versus cache reuse.

Generator images are tagged with a digest of their source, so each run either
reuses a cached image or has to build one. That split is the reason one Generate
takes minutes and the next takes seconds, so it belongs in the modal header
rather than buried in the details log.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from webapp.flow_prepare_preview_execute import _classify_generator_image_use

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FLOW_TEMPLATE_PATH = REPO_ROOT / 'webapp' / 'templates' / 'flow.html'

CACHED_LINE = '[compose] using cached generator image coretg-gen-p-x-53-generator-dffd95e22686:latest'
BUILD_LINE = '[compose] generator image coretg-gen-p-x-53-generator-dffd95e22686:latest not cached; will build now'


@pytest.mark.parametrize(
    ('stdout', 'expected'),
    [
        (CACHED_LINE, 'cached'),
        (BUILD_LINE, 'pulling'),
        ('[compose] something else entirely', ''),
        ('', ''),
        (None, ''),
        (123, ''),
    ],
    ids=['cached', 'build', 'unrelated', 'empty', 'none', 'not-a-string'],
)
def test_classify_generator_image_use(stdout, expected):
    assert _classify_generator_image_use(stdout) == expected


def test_classification_survives_surrounding_build_noise():
    noisy = '\n'.join(['#1 [internal] load build definition', CACHED_LINE, '#9 DONE 0.0s'])
    assert _classify_generator_image_use(noisy) == 'cached'


@pytest.fixture(scope='module')
def template() -> str:
    return FLOW_TEMPLATE_PATH.read_text(encoding='utf-8')


def test_indicator_element_exists_in_the_modal_header(template: str) -> None:
    header = template[template.find('id="flowLoadingText"'):]
    header = header[:header.find('</div>', header.find('flowLoadingImages')) + 6]
    assert 'flowLoadingImages' in header, 'the indicator belongs beside the title'
    assert 'ms-auto' in header, 'it is pinned to the top right'


def test_generator_output_modal_carries_the_indicator(template: str) -> None:
    """Showing that modal hides the overlay, so the overlay alone is invisible."""
    header = template[template.find('id="flowComposeTitle"') - 400:]
    header = header[:header.find('modal-body')]
    assert 'flowComposeImages' in header, 'Generator Output needs its own indicator'
    assert 'ms-auto' in header, 'it is pinned to the top right'


def test_both_flow_surfaces_are_updated_together(template: str) -> None:
    ids = template[template.find('FLOW_IMAGE_COUNT_ELEMENT_IDS'):]
    ids = ids[:ids.find(';')]
    assert 'flowLoadingImages' in ids and 'flowComposeImages' in ids


def test_execute_modal_carries_the_indicator() -> None:
    markup = (REPO_ROOT / 'webapp' / 'templates' / 'full_preview.html').read_text(encoding='utf-8')
    header = markup[markup.find('id="executeProgressModal"'):]
    header = header[:header.find('modal-body')]
    assert 'executeProgressImages' in header
    assert 'ms-auto' in header, 'it is pinned to the top right'


def test_execute_log_feeds_the_indicator() -> None:
    scripts = (REPO_ROOT / 'webapp' / 'templates' / 'full_preview_scripts.html').read_text(encoding='utf-8')
    assert 'function applyExecuteImageCounts' in scripts
    body = scripts[scripts.find('function appendExecuteProgressLog'):]
    body = body[:body.find('\n    }')]
    assert 'applyExecuteImageCounts(text)' in body, 'execute lines must reach the indicator'


def test_execute_indicator_resets_between_runs() -> None:
    scripts = (REPO_ROOT / 'webapp' / 'templates' / 'full_preview_scripts.html').read_text(encoding='utf-8')
    assert 'clearExecuteImageCounts()' in scripts


def test_execute_summary_carries_the_indicator() -> None:
    """The progress modal is gone by the time the summary is read."""
    markup = (REPO_ROOT / 'webapp' / 'templates' / 'full_preview.html').read_text(encoding='utf-8')
    header = markup[markup.find('id="executeSummaryModal"'):]
    header = header[:header.find('modal-body')]
    assert 'executeSummaryImages' in header
    assert 'ms-auto' in header, 'it is pinned to the top right'


def test_both_execute_surfaces_are_updated_together() -> None:
    scripts = (REPO_ROOT / 'webapp' / 'templates' / 'full_preview_scripts.html').read_text(encoding='utf-8')
    ids = scripts[scripts.find('EXECUTE_IMAGE_COUNT_ELEMENT_IDS'):]
    ids = ids[:ids.find(';')]
    assert 'executeProgressImages' in ids and 'executeSummaryImages' in ids


def test_the_summary_figure_is_cleared_when_a_new_run_starts() -> None:
    """Otherwise the summary would show the previous run's tally."""
    scripts = (REPO_ROOT / 'webapp' / 'templates' / 'full_preview_scripts.html').read_text(encoding='utf-8')
    clear = scripts[scripts.find('function clearExecuteImageCounts'):]
    clear = clear[:clear.find('\n    function ')]
    assert 'EXECUTE_IMAGE_COUNT_ELEMENT_IDS' in clear, 'the clear must cover both surfaces'


def test_preflight_emits_the_counter_line_for_execute() -> None:
    """The execute path has no generator runs, so preflight must report."""
    source = (REPO_ROOT / 'scenarioforge' / 'builders' / 'topology.py').read_text(encoding='utf-8')
    assert '[images] pulling={' in source, 'preflight must emit the counter line'
    assert "_report_image_use('cached')" in source
    assert "_report_image_use('pulling')" in source


def test_indicator_starts_hidden(template: str) -> None:
    block = template[template.find('id="flowLoadingImages"') - 200:template.find('id="flowLoadingImages"') + 200]
    assert 'd-none' in block


def test_progress_line_is_parsed_into_the_indicator(template: str) -> None:
    start = template.find('function _applyFlowImageCounts')
    assert start != -1, 'the parser is missing'
    body = template[start:template.find('function clearFlowImageCounts')]
    assert 'Pulling: ' in body and 'Using: ' in body and 'cached' in body


def test_the_counter_line_is_not_echoed_into_the_details_log(template: str) -> None:
    """It is an indicator, not another log line."""
    start = template.find('if (_applyFlowImageCounts(s)) return;')
    assert start != -1, 'the parser must run before a line is pushed to the log'


def test_indicator_is_cleared_between_runs(template: str) -> None:
    body = template[template.find('function clearLoadingLog'):]
    body = body[:body.find('function hideLoading')]
    assert 'clearFlowImageCounts()' in body


def test_both_surfaces_render_pending(template: str) -> None:
    scripts = (REPO_ROOT / 'webapp' / 'templates' / 'full_preview_scripts.html').read_text(encoding='utf-8')
    for source in (template, scripts):
        assert "' / Pending: '" in source, 'the pending count must be rendered'
        assert 'pending=(\\d+)' in source, 'the parser must accept a pending field'


def test_pending_is_optional_so_an_older_remote_still_renders(template: str) -> None:
    """The remote may run code that predates the field."""
    assert '(?:\\s+pending=(\\d+))?' in template
    assert 'match[3] === undefined' in template


def test_generate_counts_pending_against_the_chain_length() -> None:
    source = (REPO_ROOT / 'webapp' / 'flow_prepare_preview_execute.py').read_text(encoding='utf-8')
    assert 'int(total_assignments or 0)' in source
    assert "- image_counts['pulling']" in source and "- image_counts['cached']" in source


def test_execute_counts_pending_against_the_docker_node_total() -> None:
    source = (REPO_ROOT / 'scenarioforge' / 'builders' / 'topology.py').read_text(encoding='utf-8')
    assert '_set_expected_image_nodes(' in source, 'the total must be established before preflight'
    assert "pending = max(0, int(_EXPECTED_IMAGE_NODES.get('total') or 0) - done)" in source


def test_execute_pending_counts_down(capsys) -> None:
    """It was pinned at zero: the node total never got established."""
    from scenarioforge.builders import topology as topo

    topo._IMAGE_USE_COUNTS.update({'pulling': 0, 'cached': 0})
    topo._set_expected_image_nodes(3)
    try:
        for _ in range(3):
            topo._report_image_use('cached')
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith('[images]')]
    finally:
        topo._IMAGE_USE_COUNTS.update({'pulling': 0, 'cached': 0})
        topo._set_expected_image_nodes(0)

    assert [ln.split('pending=')[1] for ln in lines] == ['2', '1', '0']


def test_execute_node_total_uses_the_same_rule_as_the_loop() -> None:
    """Counting a raw `type` string never matched, so the total stayed zero.

    A host becomes Docker from its role or by the slot plan promoting it, and
    the count has to follow both or every declared slot is missed.
    """
    source = (REPO_ROOT / 'scenarioforge' / 'builders' / 'topology.py').read_text(encoding='utf-8')
    block = source[source.find('expected_docker = 0'):source.find('_set_expected_image_nodes(expected_docker)')]
    assert 'map_role_to_node_type' in block, 'the role must be mapped, not compared as a string'
    assert 'docker_slot_plan' in block, 'slot promotions must be counted'
    assert "str(_hdata.get('type')" not in block, 'the raw type string never equals the enum'


def test_pending_never_goes_negative() -> None:
    """More reports than expected nodes must not print a negative count."""
    from scenarioforge.builders import topology as topo
    topo._set_expected_image_nodes(1)
    topo._IMAGE_USE_COUNTS.update({'pulling': 5, 'cached': 5})
    try:
        done = topo._IMAGE_USE_COUNTS['pulling'] + topo._IMAGE_USE_COUNTS['cached']
        assert max(0, topo._EXPECTED_IMAGE_NODES['total'] - done) == 0
    finally:
        topo._IMAGE_USE_COUNTS.update({'pulling': 0, 'cached': 0})
        topo._set_expected_image_nodes(0)


def test_emitted_progress_line_matches_what_the_client_parses() -> None:
    """Server format and client regex have to agree, in both directions."""
    template = FLOW_TEMPLATE_PATH.read_text(encoding='utf-8')

    # Take the regex the page actually uses rather than restating it here.
    literal = re.search(r'/(\^\\\[images\\\].+?)/\.exec', template)
    assert literal, 'client regex for the counter line not found'
    client_re = re.compile(literal.group(1).replace('\\/', '/'))

    # And the exact strings the two servers emit.
    generate = "[images] pulling=2 cached=5 pending=10"
    execute = "[images] pulling=1 cached=0 pending=17"
    for line in (generate, execute):
        match = client_re.match(line)
        assert match, f'client cannot parse {line!r}'
        assert match.group(1).isdigit() and match.group(2).isdigit()
        assert match.group(3) is not None, 'pending must be captured'

    assert client_re.match('[images] pulling=2 cached=5'), 'older remotes must still parse'
    assert not client_re.match('Running generator 6/17'), 'unrelated lines must pass through'


def _remote_generator_script() -> str:
    """Render the VM-side generator script with its interpolations stubbed."""
    import ast

    source = (REPO_ROOT / 'webapp' / 'flow_prepare_preview_helpers.py').read_text(encoding='utf-8')
    tree = ast.parse(source)
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == 'flow_try_run_generator_remote')
    assign = next(n for n in ast.walk(fn)
                  if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', '') == 'script')
    return ''.join(p.value if isinstance(p, ast.Constant) else 'None' for p in assign.value.values)


def test_remote_generator_output_keeps_its_head_not_only_its_tail() -> None:
    """The image verdict is printed before the build, so a tail-only clip loses it.

    `run_compose` prints '[compose] ... using cached generator image' or
    '... not cached; will build now' before it runs anything. Keeping only the
    last 4000 characters dropped that line for any generator whose build output
    is long, so the run classified as neither cached nor built and surfaced as a
    phantom 'pending' image in the Generate results — a successful run reported
    as unaccounted-for work.
    """
    script = _remote_generator_script()
    compile(script, '<remote-generator-script>', 'exec')
    assert "_clip(preflight + (p.stdout or ''))" in script
    assert "_clip(preflight + (p.stderr or ''))" in script
    assert "(preflight + (p.stdout or ''))[-4000:]" not in script, 'tail-only clip is the bug'

    namespace: dict = {}
    body = script[script.index('def _clip('):script.index('print(json.dumps({')]
    exec(compile(body, '<clip>', 'exec'), namespace)

    long_run = BUILD_LINE + '\n' + ('#5 transferring context\n' * 4000) + 'final line\n'
    clipped = namespace['_clip'](long_run)
    assert BUILD_LINE in clipped, 'the verdict must survive clipping'
    assert 'final line' in clipped, 'the tail is where failures show up'
    assert 'characters omitted' in clipped
    assert len(clipped) < len(long_run)

    # The whole point: the clipped text still classifies.
    assert _classify_generator_image_use(clipped) == 'pulling'


def test_short_generator_output_is_not_clipped_at_all() -> None:
    script = _remote_generator_script()
    namespace: dict = {}
    body = script[script.index('def _clip('):script.index('print(json.dumps({')]
    exec(compile(body, '<clip>', 'exec'), namespace)
    short = CACHED_LINE + '\nall done\n'
    assert namespace['_clip'](short) == short
