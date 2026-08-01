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


def test_preflight_emits_the_counter_line_for_execute() -> None:
    """The execute path has no generator runs, so preflight must report."""
    source = (REPO_ROOT / 'scenarioforge' / 'builders' / 'topology.py').read_text(encoding='utf-8')
    assert "f\"[images] pulling={_IMAGE_USE_COUNTS['pulling']} cached={_IMAGE_USE_COUNTS['cached']}\"" in source
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


def test_emitted_progress_line_matches_what_the_client_parses() -> None:
    """Server format and client regex have to agree."""
    template = FLOW_TEMPLATE_PATH.read_text(encoding='utf-8')
    match = re.search(r'/\^\\\[images\\\]\\s\+pulling=\(\\d\+\)\\s\+cached=\(\\d\+\)\$/', template)
    assert match, 'client regex for the counter line not found'

    source = (REPO_ROOT / 'webapp' / 'flow_prepare_preview_execute.py').read_text(encoding='utf-8')
    assert "f\"[images] pulling={image_counts['pulling']} cached={image_counts['cached']}\"" in source

    client_re = re.compile(r'^\[images\]\s+pulling=(\d+)\s+cached=(\d+)$')
    assert client_re.match('[images] pulling=2 cached=5').groups() == ('2', '5')
