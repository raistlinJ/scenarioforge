"""A chain step that also opens a segmented-off subnet says so in the row.

When the pivot is absorbed into an existing challenge it never appears as its
own chain entry, so without a marker the participant has no way to tell that
solving this step buys network reach as well as a flag. The Flow chain rows and
the guides are rendered client-side from the same assignment data, so both need
the marker or the guides drift.
"""

from pathlib import Path

FLOW = Path("webapp/templates/flow.html")
REPORTS = Path("webapp/templates/reports.html")


def _flow():
    return FLOW.read_text(encoding="utf-8")


def _reports():
    return REPORTS.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Flow chain rows
# --------------------------------------------------------------------------- #

def test_chain_row_shows_a_star_badge_for_an_absorbed_pivot():
    html = _flow()
    at = html.index("\\u2605 Pivot")
    block = html[at - 700:at + 500]
    assert "badge" in block
    assert "fw-bold" in block          # the emphasis the marker exists for
    assert "titleRow.appendChild(badge)" in block


def test_the_badge_explains_what_it_opens():
    html = _flow()
    at = html.index("\\u2605 Pivot")
    block = html[at:at + 500]
    assert "badge.title" in block
    assert "opens the way into" in block
    # The point of the marker: it is not a separate challenge.
    assert "not a separate challenge" in block


def test_badge_only_renders_when_the_step_grants_a_pivot():
    html = _flow()
    at = html.index("\\u2605 Pivot")
    block = html[at - 700:at]
    assert "if (grants.length)" in block


def test_flow_reads_the_documented_contract():
    html = _flow()
    fn = html[html.index("function pivotGrantsFor("):]
    fn = fn[:fn.index("function renderChainEditor()")]
    for key in ("pivot_grants", "pivotGrants", "pivot_opens", "PivotGrants"):
        assert key in fn, key
    # The classifier's own output shape is accepted directly.
    assert "pivot_decisions" in fn
    assert "'absorbed'" in fn


def test_flow_reads_from_both_node_and_assignment():
    html = _flow()
    fn = html[html.index("function pivotGrantsFor("):]
    fn = fn[:fn.index("function renderChainEditor()")]
    assert "readFrom(node)" in fn
    assert "readFrom(assignment)" in fn


def test_a_step_with_no_pivot_is_unchanged():
    # Guard against the marker leaking into every row: the badge is built only
    # inside the grants check, never unconditionally.
    html = _flow()
    assert html.count("\\u2605 Pivot") == 1


# --------------------------------------------------------------------------- #
# Guides (must not drift from Flow)
# --------------------------------------------------------------------------- #

def test_guide_marks_the_node_and_explains_the_pivot():
    html = _reports()
    at = html.index("const pivotGrants = reportPivotGrantsFor(")
    block = html[at:at + 900]
    assert "\\u2605" in block                       # star next to the node name
    assert "no separate step" in block
    assert "Solving this step also opens" in block


def test_guide_pivot_row_is_conditional():
    html = _reports()
    at = html.index("const pivotGrants = reportPivotGrantsFor(")
    block = html[at:at + 900]
    assert "if (pivotGrants.length)" in block


def test_guide_reader_is_a_twin_of_the_flow_reader():
    # Same contract on both surfaces, or a scenario shows the pivot in Flow and
    # silently omits it from the participant guide.
    reports = _reports()
    fn = reports[reports.index("function reportPivotGrantsFor("):]
    fn = fn[:fn.index("function buildReportGuideMarkdown(")]
    for key in ("pivot_grants", "pivotGrants", "pivot_opens", "PivotGrants"):
        assert key in fn, key
    assert "pivot_decisions" in fn
    assert "'absorbed'" in fn
    assert "readFrom(node)" in fn and "readFrom(assignment)" in fn


def test_both_surfaces_agree_on_the_absorbed_marker():
    assert "'absorbed'" in _flow()
    assert "'absorbed'" in _reports()
