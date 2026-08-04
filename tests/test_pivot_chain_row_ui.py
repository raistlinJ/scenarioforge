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
    at = html.index("badge.textContent = '\\u2605 Pivot';")
    block = html[at - 700:at + 500]
    assert "badge" in block
    assert "fw-bold" in block          # the emphasis the marker exists for
    assert "titleRow.appendChild(badge)" in block


def test_the_badge_explains_what_it_opens():
    html = _flow()
    at = html.index("badge.textContent = '\\u2605 Pivot';")
    block = html[at:at + 500]
    assert "badge.title" in block
    assert "opens the way into" in block
    # The point of the marker: it is not a separate challenge.
    assert "not a separate challenge" in block


def test_badge_only_renders_when_the_step_grants_a_pivot():
    html = _flow()
    at = html.index("badge.textContent = '\\u2605 Pivot';")
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
    assert html.count("badge.textContent = '\\u2605 Pivot';") == 1


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


# --------------------------------------------------------------------------- #
# own_step pivots render as steps of their own
# --------------------------------------------------------------------------- #

def test_flow_renders_an_own_step_pivot_row():
    html = _flow()
    at = html.index("function appendPivotStepRow(")
    block = html[at:at + 2200]
    assert "Pivot into " in block
    assert "\\u2605 Pivot step" in block
    assert "step of its own" in block
    # Uses the server-computed instruction, falling back to the reason.
    assert "decision.instruction" in block


def test_flow_places_the_pivot_row_before_the_step_it_unlocks():
    html = _flow()
    at = html.index("ownStepPivots.forEach((d) => {")
    block = html[at:at + 220]
    assert "Number(d.insert_before) === idx" in block
    # Emitted before the chain item for that index is built, so the pivot row
    # precedes the step it unlocks.
    forEach_at = html.index("ownStepPivots.forEach((d) => {")
    item_at = html.index("item.className = 'list-group-item';", forEach_at)
    assert forEach_at < item_at


def test_flow_own_step_reader_dedupes_and_filters():
    html = _flow()
    fn = html[html.index("function ownStepPivotsFor("):]
    fn = fn[:fn.index("function renderChainEditor()")]
    assert "'own_step'" in fn
    assert "seen.has(key)" in fn


def test_own_step_pivots_never_enter_the_executable_chain():
    # Chain nodes and flag assignments are aligned by index downstream, and a
    # synthetic step has no generator to resolve.
    html = _flow()
    fn = html[html.index("function ownStepPivotsFor("):]
    fn = fn[:fn.index("function renderChainEditor()")]
    assert "currentChain.push" not in fn
    assert "currentChain.splice" not in fn


def test_guide_emits_the_pivot_as_its_own_step():
    html = _reports()
    at = html.index("reportOwnStepPivots(alignedAssignments).forEach(")
    block = html[at:at + 900]
    assert "Pivot step: reach" in block
    assert "Number(d.insert_before) !== index" in block
    assert "step of its own" in block


def test_guide_own_step_reader_is_a_twin():
    reports = _reports()
    fn = reports[reports.index("function reportOwnStepPivots("):]
    fn = fn[:fn.index("function buildReportGuideMarkdown(")]
    assert "'own_step'" in fn
    assert "seen.has(key)" in fn


# --------------------------------------------------------------------------- #
# One source reaching many targets is one row, not one row per target
# --------------------------------------------------------------------------- #

def _template(name):
    from pathlib import Path
    return Path(f'webapp/templates/{name}').read_text(encoding='utf-8')


def test_the_chain_row_groups_pivot_paths_by_everything_but_the_target():
    # A source that reaches twenty nodes produced twenty rows differing only in
    # the target. The provider and the facts belong to the source, so repeating
    # them per target buried the one line that says anything.
    src = _template('flow.html')
    assert 'pivotGroups' in src
    assert 'MAX_NAMED_TARGETS' in src
    # Grouped on the source and the descriptive parts, never the target.
    assert "JSON.stringify([source, parts])" in src


def test_the_guide_groups_pivot_paths_too():
    # Guides are client-rendered: a rule without a twin drifts.
    src = _template('reports.html')
    assert 'pivotGroups' in src
    assert "JSON.stringify([role, source, facts, provider])" in src
    # The column is now plural, because a row carries every target it reaches.
    assert '| Role | Source | Targets | Facts | Provider |' in src
    assert '| Role | Source | Target | Facts | Provider |' not in src


def test_the_grouped_row_still_names_some_targets():
    # Collapsing must not cost the reader the targets entirely.
    src = _template('flow.html')
    assert 'and ${extra} more' in src
    assert 'group.targets.slice(0, MAX_NAMED_TARGETS)' in src


# --------------------------------------------------------------------------- #
# An input the assignment resolves is not "missing"
# --------------------------------------------------------------------------- #

def _flow_source():
    from pathlib import Path
    return Path('webapp/templates/flow.html').read_text(encoding='utf-8')


def test_a_locally_resolved_input_is_not_counted_missing():
    # The badge flipped from Missing to Config/default across a refresh: the two
    # paths classify an input required-or-optional differently, while both
    # resolve it to the same value. `missing` means "nothing provides this", and
    # a concrete value on the assignment is a provider.
    src = _flow_source()
    assert 'function flowAssignmentResolvesInput(' in src
    # Applied to every missing computation, not just the field one.
    assert src.count('!flowAssignmentResolvesInput(a, k)') == 3


def test_the_resolved_check_looks_at_every_place_a_value_can_land():
    src = _flow_source()
    start = src.index('function flowAssignmentResolvesInput(')
    block = src[start:start + 900]
    for key in ('config_overrides', 'resolved_inputs', 'chain_supplied_input_values'):
        assert key in block, key
    # Reuses the existing meaningfulness test, so a blank or a '-' placeholder
    # still counts as absent.
    assert 'hasMeaningfulFlowInputSourceValue' in block


def test_a_blank_or_placeholder_value_is_still_missing():
    src = _flow_source()
    start = src.index('function hasMeaningfulFlowInputSourceValue(')
    block = src[start:start + 400]
    assert "value.trim() === '-'" in block


# --------------------------------------------------------------------------- #
# A pivot source is one hint, not one hint per target it unlocks
# --------------------------------------------------------------------------- #

def _pivot_rules(targets, provider_label='Flag-Node-Generator',
                 produces='Shell(docker-21), Pivot(docker-21)'):
    return [{
        'source_id': 'docker-21', 'source_name': 'docker-21',
        'target_id': str(t).split(' ')[0], 'target_name': str(t),
        'provider': 'flag-node-generator', 'provider_label': provider_label,
        'produces': produces, 'target_requires': '',
    } for t in targets]


def _hints_for(rules, monkeypatch):
    from webapp import app_backend as ab

    monkeypatch.setattr(ab, '_flow_pivot_rules_for_chain', lambda *a, **k: rules)
    out = ab._flow_apply_pivot_context_to_assignments(
        [{'node_id': 'docker-21', 'name': 'docker-21', 'hints': ['Read the zone export.']}],
        [{'id': 'docker-21', 'name': 'docker-21', 'ip4': '10.95.5.6'}],
        scenario_label='S',
    )
    return [str(h) for h in (out[0].get('hints') or [])]


def test_one_source_unlocking_many_targets_is_one_hint(monkeypatch):
    # A node unlocking twenty-three targets produced twenty-three hints
    # identical but for the target name, burying every other hint the step had.
    # The work is the same whatever it unlocks: get access on this node.
    targets = [f'flaggenslot-{i}' for i in range(1, 24)]
    hints = _hints_for(_pivot_rules(targets), monkeypatch)
    pivot_hints = [h for h in hints if h.startswith('Pivot source:')]
    assert len(pivot_hints) == 1
    assert '23 pivot-only targets' in pivot_hints[0]
    # The step's own hint survives the consolidation.
    assert 'Read the zone export.' in hints


def test_the_consolidated_hint_names_a_few_targets_and_counts_the_rest(monkeypatch):
    targets = [f'flaggenslot-{i}' for i in range(1, 24)]
    hint = [h for h in _hints_for(_pivot_rules(targets), monkeypatch)
            if h.startswith('Pivot source:')][0]
    assert 'flaggenslot-1, flaggenslot-2' in hint
    assert 'and 17 more' in hint
    # Naming all twenty-three would make a hint nobody reads; the Pivot Path
    # rows carry the full list.
    assert 'flaggenslot-23' not in hint


def test_a_single_target_reads_naturally(monkeypatch):
    hint = [h for h in _hints_for(_pivot_rules(['flaggenslot-1']), monkeypatch)
            if h.startswith('Pivot source:')][0]
    assert '1 pivot-only target (flaggenslot-1)' in hint
    assert 'more' not in hint


def test_different_providers_stay_separate_hints(monkeypatch):
    # Grouping is on everything except the target, so two providers are two
    # different pieces of work and keep their own hints.
    rules = (_pivot_rules(['a', 'b'], provider_label='Flag-Node-Generator')
             + _pivot_rules(['c'], provider_label='Docker SSH'))
    pivot_hints = [h for h in _hints_for(rules, monkeypatch) if h.startswith('Pivot source:')]
    assert len(pivot_hints) == 2
    assert any('Flag-Node-Generator' in h and '2 pivot-only targets' in h for h in pivot_hints)
    assert any('Docker SSH' in h and '1 pivot-only target' in h for h in pivot_hints)
