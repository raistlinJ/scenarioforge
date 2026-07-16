from pathlib import Path


FLOW_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "flow.html"
REPORTS_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "reports.html"
LAYOUT_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "layout.html"
SCENARIOS_PREVIEW_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "scenarios_preview.html"


def test_embedded_preview_does_not_show_a_second_navigation_spinner_on_execute() -> None:
    layout_text = LAYOUT_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    preview_text = SCENARIOS_PREVIEW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    assert "{% if not hide_chrome %}\n    <div class=\"coretg-loading-overlay\"" in layout_text
    assert "{% endif %}\n\n    <!-- CORE Daemon Start Modal -->" in layout_text
    assert "hideLoading('execute-navigation');" in preview_text
    assert "type: 'coretg-preview-execute'" in preview_text
    assert "data.type === 'coretg-preview-execution-complete'" in preview_text
    assert "&auto_execute=1" not in preview_text


def test_flow_assignment_persists_resolved_paths() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "'resolved_paths',",
        "const resolvedPaths = (curA && typeof curA.resolved_paths === 'object'",
        "if (resolvedPaths !== undefined) out.resolved_paths = resolvedPaths;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing resolved_paths persistence snippets in flow template: " + "; ".join(missing)


def test_flow_generator_output_shows_phase_timings() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function _renderGeneratorOutputTable(runs, progressLog, phaseTimings)",
        "const timings = (phaseTimings && typeof phaseTimings === 'object'",
        "['solve_chain_and_assignments_s', 'Solve chain']",
        "['run_generators_or_prepare_assignments_s', 'Run generators']",
        "<div class=\"small text-muted mb-2\">Phase Timing</div>",
        "const phaseTimings = (prepData && prepData.phase_timings",
        "_renderGeneratorOutputTable(runs, progressLog, phaseTimings)",
        "_renderGeneratorOutputTable(lastResolvePayload.generator_runs, lastResolvePayload.progress_log || [], lastResolvePayload.phase_timings || {})",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing phase timing display wiring in flow template: " + "; ".join(missing)


def test_flow_sequencing_progress_is_request_scoped_and_visible() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function startFlowProgressPoll(options)",
        "if (opts.progressId) url += '?progress_id=' + encodeURIComponent(String(opts.progressId));",
        "const display = _formatFlowProgressLine(s);",
        "if (newLines.length && opts.loadingLog) newLines.forEach((line) => appendLoadingLog(line));",
        "const sequenceProgressId = `seq-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;",
        "startFlowProgressPoll({ progressId: sequenceProgressId, loadingLog: true, composeLog: false });",
        "progress_id: sequenceProgressId,",
        "if (s.includes('phase: building topology graph')) return 'Building topology graph…';",
        "if (s.includes('phase: computing generator assignments')) return 'Assigning generators…';",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing request-scoped visible sequencing progress snippets: " + "; ".join(missing)


def test_flow_loading_progress_uses_scrollable_container() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'id="flowLoadingSteps"',
        'max-height: 150px; overflow-y: auto;',
        'id="flowComposeSteps"',
        'max-height: 140px; overflow-y: auto;',
        'id="flowLoadingLog"',
        'max-height: 180px; overflow-y: auto;',
        'white-space: pre-wrap; word-break: break-word;',
        '<div class="d-flex align-items-center gap-2 ${cls}">',
        'try { stepsEl.scrollTop = stepsEl.scrollHeight; } catch (e) { }',
        "const entry = document.createElement('div');",
        'entry.textContent = msg;',
        'try { loadingLogEl.scrollTop = loadingLogEl.scrollHeight; } catch (scrollErr) { }',
        "${progress.map(p => `<div>${esc(p)}</div>`).join('')}",
        "appendLoadingLog(`${runIndex + 1}. ${gid}${node ? ` @ ${node}` : ''}: ${ok}${note ? ` (${note})` : ''}`);",
        "<div class=\"small mb-3\">",
        "${summaryRows || '<div class=\"text-muted\">No generator output captured.</div>'}",
        "missing.slice(0, 8).forEach((m, missingIndex) => appendLoadingLog(`${missingIndex + 1}. ${m}`));",
        "More missing files:",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing scrollable loading log snippets: " + "; ".join(missing)

    forbidden_snippets = [
        '<ul id="flowLoadingSteps"',
        '<ul id="flowComposeSteps"',
        "<ul class=\"small mb-3\">${progress.map(p => `<li>${esc(p)}</li>`).join('')}</ul>",
        '<ul class="small mb-3"',
        '<li class="d-flex align-items-center gap-2"',
        '<li class="text-muted">No generator output captured.',
        'appendLoadingLog(`- ',
        "appendLoadingLog('- ",
    ]
    present = [snippet for snippet in forbidden_snippets if snippet in text]
    assert not present, "Progress output should not use bullet-list markup: " + "; ".join(present)


def test_report_guides_include_chain_io_and_pivot_sections() -> None:
    reports_text = REPORTS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    flow_text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "### Chain Inputs / Outputs",
        "### Pivot Path",
        "const pivotEntries = Array.isArray(assignment.pivot)",
        "...normalizeChainFacts(assignment.requires)",
        "...normalizeChainFacts(assignment.produces)",
        "entry.provider_label || entry.provider",
    ]
    reports_missing = [snippet for snippet in expected_snippets if snippet not in reports_text]
    assert not reports_missing, "Missing pivot/chain IO report-guide rendering snippets: " + "; ".join(reports_missing)

    flow_missing = [snippet for snippet in expected_snippets if snippet not in flow_text]
    assert not flow_missing, "Missing pivot/chain IO flow-guide rendering snippets: " + "; ".join(flow_missing)


def test_flow_chain_editor_surfaces_pivot_paths() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function renderPivotPathSummary(assignment)",
        "addRow('Pivot Path', pivotPathSummary);",
        "const pivotEntries = (curA && Array.isArray(curA.pivot))",
        "if (pivotEntries !== undefined && pivotEntries.length) out.pivot = pivotEntries;",
        "if (savedA.pivot && !Array.isArray(curA.pivot)) curA.pivot = savedA.pivot;",
        "if (savedA.pivot_inputs && !Array.isArray(curA.pivot_inputs)) curA.pivot_inputs = savedA.pivot_inputs;",
        "if (savedA.pivot_outputs && !Array.isArray(curA.pivot_outputs)) curA.pivot_outputs = savedA.pivot_outputs;",
        "if (savedA.pivot_hints && !Array.isArray(curA.pivot_hints)) curA.pivot_hints = savedA.pivot_hints;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing Flow chain-card pivot rendering/persistence snippets: " + "; ".join(missing)


def test_flow_chain_editor_hides_synthetic_pivot_noise() -> None:
    flow_text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")
    reports_text = REPORTS_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_flow_snippets = [
        "function isSyntheticChainFactName(name)",
        "function isPivotChainFactName(name)",
        "function pivotFactSourceName(name)",
        "function hasResolvedFactValue(value)",
        "function renderPivotInputResolvedValue(key)",
        "span.textContent = `pivot from ${source}`;",
        "{ isInput: isInputs }",
        "!/^Pivot source:/i.test(String(text || '').trim())",
        "if (isSyntheticChainFactName(name) && !hasResolvedFactValue(entry.resolved)) return;",
        "if (isSyntheticChainFactName(n) && !(resolvedOutputs && hasResolvedFactValue(resolvedOutputs[n]))) return;",
    ]
    missing_flow = [snippet for snippet in expected_flow_snippets if snippet not in flow_text]
    assert not missing_flow, "Missing Flow synthetic pivot display filters: " + "; ".join(missing_flow)

    expected_report_snippets = [
        ".filter((value) => !/^Pivot source:/i.test(value))",
    ]
    missing_reports = [snippet for snippet in expected_report_snippets if snippet not in reports_text]
    assert not missing_reports, "Missing report synthetic pivot hint filter: " + "; ".join(missing_reports)


def test_segmentation_pivot_provider_options_are_curated() -> None:
    text = FLOW_TEMPLATE_PATH.parent.joinpath("index.html").read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const providerNormalized = ['auto', 'none', 'manual'].includes(providerRaw) ? 'random' : providerRaw;",
        "const allowedProviders = new Set(['random', 'vulnerability', 'flag-node-generator', 'ssh-fallback']);",
        "['random', 'Random']",
        "['vulnerability', 'Vulnerability']",
        "['flag-node-generator', 'Flag-Node-Generator']",
        "['ssh-fallback', 'Docker SSH']",
        "['auto', 'none', 'manual'].includes(currentPivotProvider)",
        "const providerOptions = ['vulnerability', 'flag-node-generator', 'ssh-fallback'];",
        "field: 'pivot_provider'",
        '<label class="form-check-label small">Pivot-Accessible</label>',
    ]
    removed_snippets = [
        "['none', 'Manual']",
        "['flag-node-generator', 'flag-node-generator']",
        '<label class="form-check-label small">Pivot</label>',
    ]
    missing = [snippet for snippet in expected_snippets if snippet not in text]
    present = [snippet for snippet in removed_snippets if snippet in text]
    assert not missing, "Missing curated pivot provider option snippets: " + "; ".join(missing)
    assert not present, "Removed pivot provider options/labels should not remain: " + "; ".join(present)


def test_flow_sequence_hints_hide_unresolved_template_variables() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function _fallbackOutputTemplateText(expr)",
        "function _canonicalOutputTemplateKey(expr)",
        "const roCanonical = new Map();",
        "return 'generated credential';",
        "function _applyHintNodeTemplateVars(text, assignment)",
        "const FLOW_TEMPLATE_OPEN = '{' + '{';",
        ": {};\n\n    const roLower = new Map();",
        "if (text.includes(FLOW_TEMPLATE_OPEN) || text.includes(FLOW_TEMPLATE_CLOSE)) return;",
        "if (Array.isArray(out[level]) && out[level].length) return;",
        ".map(x => _applyHintNodeTemplateVars(String(x || '').trim(), fa))",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing unresolved hint template cleanup wiring in flow template: " + "; ".join(missing)


def test_flow_inputs_tab_labels_pivot_requirements() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function _pivotNodeFromFact(expr)",
        "function _singlePivotSourceNode(assignment, fallbackFact)",
        "function _formatPivotInputFact(value, assignment)",
        "pivot from ${sourceNode}",
        "const sourceAssignment = Object.keys(explicitAssignment).length ? explicitAssignment : { requires: rawArtifacts.concat(rawFields), inputs: rawArtifacts.concat(rawFields) };",
        "const formatInputFact = (value) => /(?:input|require)/i.test(label) ? _formatPivotInputFact(value, sourceAssignment) : value;",
        "const collapsedPivotRows = Array.isArray(opts.collapsedPivotRows) ? opts.collapsedPivotRows : [];",
        "summary.textContent = `${collapsedPivotRows.length} other Pivot input${collapsedPivotRows.length === 1 ? '' : 's'}`;",
        "function collapsePivotInputRows(rows)",
        "collapsedPivotRows: pivotRows.slice(1)",
        "collapsePivotInputRows(rows).forEach(addRowVar);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing Pivot(...) input display labels in flow template: " + "; ".join(missing)


def test_flow_inputs_tab_has_source_column_for_chain_and_sequencer_inputs() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function flowInputSourceInfo(row)",
        "function renderFlowInputSourceBadge(row)",
        "function hasMeaningfulFlowInputSourceValue(value)",
        "if (fromChain && fromSeq)",
        "return { text: 'From Chain'",
        "return { text: 'From Sequencer'",
        "return { text: 'Config/default'",
        "return { text: 'Not supplied'",
        "<th style=\"width: 1%; white-space: nowrap;\">Source</th>",
        "tdSource.appendChild(renderFlowInputSourceBadge(row));",
        "tdSource.appendChild(renderFlowInputSourceBadge(v));",
        "resolved: resolvedInputs ? resolvedInputs[n] : undefined,",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing Flow input source column wiring: " + "; ".join(missing)


def test_flow_resolved_columns_scroll_and_optional_badges_are_removed() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function flowResolvedScrollContent(content)",
        "function flowAppendResolvedCell(cell, content)",
        "wrap.style.display = 'block';",
        "wrap.style.width = '100%';",
        "wrap.style.overflow = 'auto';",
        "wrap.style.whiteSpace = 'nowrap';",
        "cell.style.minWidth = '10rem';",
        "cell.style.width = '18rem';",
        "cell.style.maxWidth = '18rem';",
        "function flowStyleCompactTableCell(cell, minWidth)",
        "function flowScrollableTable(tableEl)",
        "tableEl.style.width = 'max-content';",
        "tableEl.style.minWidth = '100%';",
        "flowStyleCompactTableCell(tdVar, '12rem');",
        "flowStyleCompactTableCell(tdSource, '8rem');",
        "return flowScrollableTable(tbl);",
        "addRow('', flowScrollableTable(inTbl));",
        "addRow('', flowScrollableTable(outTbl));",
        "flowAppendResolvedCell(tdRes, renderResolvedInline(row.resolved));",
        "flowAppendResolvedCell(tdRes, renderResolvedValueForKey(isInputs ? resolvedInputs : resolvedOutputs, v.name, { isInput: isInputs }));",
        "flowAppendResolvedCell(tdRes, renderResolvedValueForKey(isInputs ? resolvedInputs : resolvedOutputs, v.name));",
        "inputs without * are optional",
    ]
    removed_snippets = [
        "showOptionalBadge",
        "badge.textContent = 'Optional';",
        "Optional badge = non-blocking for step completion",
        "Optional means non-blocking for step completion",
        "tableLayout = 'fixed'",
        "cell.style.maxWidth = '0';",
        "clamp(10rem, 32vw, 30rem)",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    present = [snippet for snippet in removed_snippets if snippet in text]
    assert not missing, "Missing Flow resolved-cell scroll wiring: " + "; ".join(missing)
    assert not present, "Optional variable badges should be removed: " + "; ".join(present)


def test_flow_template_compiles_with_hint_placeholders() -> None:
    from webapp.app_backend import app

    app.jinja_env.get_template("flow.html")


def test_flow_guide_downloads_show_preparation_progress() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function waitForFlowUiPaint()",
        "let guideDownloadInProgress = false;",
        "function setGuideDownloadLinksBusy(busy)",
        "async function prepareAndDownloadGuide(options)",
        "showLoading(`Preparing ${guideLabel}",
        "setLoadingSteps(guideSteps, 0);",
        "await waitForFlowUiPaint();",
        "startHtmlDownload(html, fname);",
        "await prepareAndDownloadGuide({ facilitator: false });",
        "await prepareAndDownloadGuide({ facilitator: true });",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Guide downloads should show preparation progress before starting: " + "; ".join(missing)


def test_flow_chain_editor_hides_resolved_paths_row() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    removed_snippets = [
        "const resolved = (fa && typeof fa.resolved_paths === 'object'",
        "addPathEntry('artifacts_dir'",
        "inject_source ${srcIdx + 1}",
        "addRow('Resolved Paths', wrapLive",
    ]

    present = [snippet for snippet in removed_snippets if snippet in text]
    assert not present, "Resolved paths row snippets should be removed from flow chain editor: " + "; ".join(present)


def test_flow_injects_table_shows_resolved_path_column() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "headLabel.textContent = 'Resolved path';",
        "viewToggle.title = 'Toggle path view (CORE VM or Container)';",
        "const resolvedInjectSources = (fa && fa.resolved_paths && Array.isArray(fa.resolved_paths.inject_sources))",
        "function resolvedPathsForCandidate(srcValue, resolvedValue)",
        "const destinationOptionValues = destinationOptions();",
        "controlLabel.textContent = 'Destination:';",
        "destSelect = document.createElement('select');",
        "destSelect.value = '/flow_injects';",
        "applyInjectDestinationOverridesFromTable();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing resolved path column wiring in injects table: " + "; ".join(missing)


def test_flow_inject_override_editor_shows_resolved_column() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const h2Label = document.createElement('span');",
        "h2Label.textContent = 'Resolved path';",
        "pathViewToggleBtn.title = 'Toggle path view (CORE VM or Container)';",
        "h3.textContent = 'Destination dir';",
        "function refreshPathHints()",
        "const resolvedInjectSources = (fa && fa.resolved_paths && Array.isArray(fa.resolved_paths.inject_sources))",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing resolved-path column wiring in inject override editor: " + "; ".join(missing)


def test_flow_inject_override_editor_lists_generator_inject_choices() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const generatedInjectSpecs = getGeneratedInjectsFromAssignment();",
        "const listedInjectDefaults = new Map();",
        "const availableListedInjects = [];",
        "const sourceOptions = (() => {",
        "const srcSelect = document.createElement('select');",
        "const listedDefaultDest = String(listedInjectDefaults.get(v) || '').trim();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing listed inject dropdown wiring in inject override editor: " + "; ".join(missing)


def test_flow_inject_candidate_paths_are_visible_and_selectable() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "inject_candidate_paths",
        "out.inject_candidate_paths = injectCandidatePaths;",
        "function destinationDirsFor(destValue)",
        "const effectiveDestOptions = candidateDestOptions.length",
        "destSelect = document.createElement('select');",
        "destSelect.addEventListener('change'",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing inject candidate path UI wiring: " + "; ".join(missing)

    removed_snippets = [
        "Candidate destinations: ",
        "candidateLegend.textContent",
        "injCandidateHelp.textContent",
    ]
    present = [snippet for snippet in removed_snippets if snippet in text]
    assert not present, "Candidate destination labels should not be rendered in flow chains: " + "; ".join(present)


def test_flow_inject_destination_dropdown_selection_is_serialized() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const rowObj = { srcEl: srcSelect, destEl: destSelect };",
        "const destEl = el && el.destEl ? el.destEl : null;",
        "const dest = String((destEl && destEl.value) ?? '').trim();",
        "files.push(`${src} -> ${dest}`);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing inject destination serialization wiring for dropdown selections: " + "; ".join(missing)


def test_flow_inject_destination_disallows_manual_or_blank_input() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const effectiveDestOptions = candidateDestOptions.length",
        ": [initialDest || '/flow_injects'];",
        "destWrap.appendChild(destSelect);",
    ]
    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing dropdown-only inject destination enforcement: " + "; ".join(missing)

    removed_snippets = [
        "destInp = document.createElement('input');",
        "destInp.placeholder = '/flow_injects (default)';",
        "if (destInp) {",
    ]
    present = [snippet for snippet in removed_snippets if snippet in text]
    assert not present, "Manual/blank inject destination input should not remain in flow template: " + "; ".join(present)


def test_flow_inject_source_disallows_manual_picker_or_upload() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const sourceOptions = (() => {",
        "const srcSelect = document.createElement('select');",
        "row.appendChild(srcSelect);",
        "pickWrap.textContent = 'Generator manifest inject path';",
    ]
    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing manifest-constrained inject source selection wiring: " + "; ".join(missing)

    removed_snippets = [
        "function buildVarPicker() {",
        "const srcInp = document.createElement('input');",
        "uploadBtn.textContent = 'Upload';",
        "fetch('/api/flag-sequencing/upload_flow_inject_file'",
        "addGroup('Inputs', Array.from(new Set(availableInputs)));",
        "addGroup('Outputs', Array.from(new Set(availableOutputs)));",
        "addGroup('Resolved outputs', Array.from(new Set(availableResolvedOutputs)));",
        "addBtn.textContent = 'Add inject file';",
    ]
    present = [snippet for snippet in removed_snippets if snippet in text]
    assert not present, "Manual/upload inject source controls should not remain in flow template: " + "; ".join(present)


def test_flow_inject_source_selection_disallows_duplicates() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function updateInjectSourceAvailability() {",
        "if (!used.has(value)) {",
        "const replacement = Array.from(sel.options || []).find((opt) => {",
        "opt.disabled = !!(optValue && optValue !== current && used.has(optValue));",
        "try { updateInjectSourceAvailability(); } catch (e) { }",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing duplicate-prevention wiring for inject source selections: " + "; ".join(missing)


def test_flow_hint_node_ip_rewrites_stale_ip_values() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const ipv4Pattern = '(?:\\\\d{1,3}\\\\.){3}\\\\d{1,3}';",
        "const staleIpPattern = new RegExp(`${escapedName}\\\\s*@\\\\s*(${ipv4Pattern})`, 'g');",
        "const parentheticalIpPattern = new RegExp(`${escapedName}\\\\s*\\\\(\\\\s*(${ipv4Pattern})\\\\s*\\\\)`, 'g');",
        "out = out.replace(parentheticalIpPattern, `${needle} @ ${ip}`);",
        "return dedupeRenderedIps(out);",
        "out = out.replace(staleIpPattern, `${needle} @ ${ip}`);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing stale hint IP rewrite wiring in flow template: " + "; ".join(missing)


def test_flow_initial_facts_start_hint_includes_first_step_context() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const firstHintDetails = [];",
        "firstHintDetails.push('generator: ' + genDisplay);",
        "firstHintDetails.push('type: ' + genType);",
        "firstHintDetails.push('target: ' + Array.from(new Set(vulnNames)).join(', '));",
        "startAssignmentEntries.forEach((entry) => {",
        "entry.assignment.chain_supplied_input_hints.map(x => String(x || '').trim()).filter(Boolean)",
        "sequenceRequiredByName.set(text,",
        "sourceBadge: requiredInfo ? { text: requiredInfo.label, className: 'badge text-bg-warning' } : null,",
        "hintLabel: 'Start Hint',",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing enriched Initial Facts start hint wiring: " + "; ".join(missing)


def test_flow_visualization_groups_parallel_dependency_layers() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function buildFlowDependencyLayout(chain, assignments, dependencyLevelOverride) {",
        "const requestedDependencyLevel = normalizeDependencyLevel(dependencyLevelOverride !== undefined ? dependencyLevelOverride : getFlowDependencyLevel());",
        "const providerIndexes = new Set();",
        "const providerFactsByIndex = new Map();",
        "addProvider(providerFactsByIndex, providerIndex, factName);",
        "addEdge(providerIndex, nodeIndex, providerFactsByIndex.get(providerIndex) || []);",
        "const stageLabel = indices.length > 1 ? 'Parallel' : 'Step';",
        "lines.push(`  subgraph G${stageOrdinal}[",
        "(Array.isArray(layout.edges) ? layout.edges : []).forEach((edge) => {",
        "const edgeLabel = mermaidSafeEdgeLabel(edge && edge.facts);",
        "lines.push(`  N${fromIndex} -->|\"${edgeLabel}\"| N${toIndex}`);",
        "%%{init: {\"flowchart\": {\"nodeSpacing\": 72, \"rankSpacing\": 118, \"padding\": 18, \"curve\": \"basis\"}}}%%",
        "max-height: 70vh; overflow: auto;",
        "function flowDependencyTooltipText(facts) {",
        "const visibleFact = clean[0];",
        "const tooltipFacts = [visibleFact].concat(clean.slice(1).filter((factName) => factName !== visibleFact));",
        "function buildFlowDependencyEdgeTooltips(chain, assignments, dependencyLevelOverride) {",
        "function applyFlowDependencyEdgeTooltips(wrap, chain, assignments, dependencyLevelOverride) {",
        "target.setAttribute('data-dependency-tooltip', tooltip);",
        "target.setAttribute('title', tooltip);",
        "child.setAttribute('data-dependency-tooltip', tooltip);",
        "const titleEl = document.createElementNS('http://www.w3.org/2000/svg', 'title');",
        "applyFlowDependencyEdgeTooltips(wrap, currentChain, currentFlagAssignments);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing dependency-layered flow visualization wiring: " + "; ".join(missing)

    removed_snippets = [
        "lines.push(`  N${i - 1} --> ${safeId}`);",
        "const visualProvidersForIndex = (nodeIndex) => {",
        "lines.push(`  N${previousIndices[0]} -.-> N${currentIndices[0]}`);",
    ]
    present = [snippet for snippet in removed_snippets if snippet in text]
    assert not present, "Flow visualization should not force a linear edge between every adjacent chain item: " + "; ".join(present)


def test_flow_visualization_quotes_dependency_edge_labels() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippet = "lines.push(`  N${fromIndex} -->|\"${edgeLabel}\"| N${toIndex}`);"
    assert expected_snippet in text, (
        "Mermaid edge labels must be quoted so real fact names like "
        "Credential(user, password) render instead of producing a syntax error"
    )

    forbidden_snippet = "lines.push(`  N${fromIndex} -->|${edgeLabel}| N${toIndex}`);"
    assert forbidden_snippet not in text


def test_flow_dependency_slider_and_challenge_label_are_wired() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        '<label class="form-label" for="flowLength">Number of Challenges</label>',
        'data-bs-target="#flowAdvancedOptions" aria-expanded="false" aria-controls="flowAdvancedOptions"',
        '<div class="collapse mt-3" id="flowAdvancedOptions">',
        'id="flowDependencyLevel" class="form-range" type="range" min="1" max="5" step="1" value="3"',
        '<span>Non-dependent</span>',
        '<span>Completely dependent</span>',
        "function normalizeDependencyLevel(value) {",
        "function isTransientFetchError(err) {",
        "function buildResolveInterruptionDiagnostics(err, context) {",
        "async function fetchWithTransientRetry(url, init, opts) {",
        "Transient fetch error; retrying request",
        "requestOpts.networkRetries = 2;",
        "Network request interrupted; retrying",
        "Network request interrupted after request-level retries",
        "let generateInFlight = false;",
        "function setGenerateBusy(value) {",
        "if (generateInFlight) {",
        "Generate ignored: another Generate/Resolve request is already running.",
        "resolveTimeoutSeconds = Math.min(1800, Math.max(600, (chain_ids.length * 150) + 180));",
        "resolveProgressId = `resolve-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;",
        "onLines: (lines) => {",
        "resolveProgressLines = resolveProgressLines.concat(lines || []).slice(-20);",
        "timeout_s: resolveTimeoutSeconds,",
        "progress_id: resolveProgressId,",
        "Resolve request connection was interrupted while generators were running",
        "Meaning: the browser lost its HTTP connection to the ScenarioForge webapp",
        "Request: scenario=${ctx.scenario || '-'} chain=${ctx.chainLength || '-'} progress_id=${ctx.progressId || '-'}",
        "Timing: elapsed=${elapsedSeconds !== null ? elapsedSeconds.toFixed(1) + 's' : '-'}",
        "Last progress: ${progressLines.join(' | ')}",
        "grep outputs/logs/webui-${logPort}.log and the webapp terminal for progress_id=${ctx.progressId || '-'}",
        "dependency_level: getFlowDependencyLevel(),",
        "dependency_level: dependencyLevel,",
        "function vulnerabilityNodeMinimumFromStats(stats)",
        "lengthEl.min = String(minimum);",
        "if (parseInt(lengthEl.value, 10) < minimum) lengthEl.value = String(minimum);",
        'id="flowIncludeAllTopologyPivots"',
        'Include all Topology Pivots',
        'expands the chain beyond Number of Challenges',
        'syncTopologyInclusionOptionsFromUi()',
        "include_all_topology_pivots: !!includeAllTopologyPivots,",
        "params.set('include_all_topology_pivots', '1')",
        "dependencyLevelEl.addEventListener('input'",
        "setFlowDependencyLevel(dependencyLevelEl.value",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing dependency slider/challenge count wiring in flow template: " + "; ".join(missing)

    assert 'flowIncludeAllTopologyVulns' not in text
    assert 'include_all_topology_vulns' not in text
    assert "Max Chain length" not in text


def test_flow_page_does_not_auto_generate_on_load() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    forbidden_snippet = "await generate(false, { autoLoad: true, resolveOnGenerate: false });"
    assert forbidden_snippet not in text, "Flow page should not auto-generate on load; Generate button must be explicit"


def test_flow_inject_path_view_roundtrips_via_flow_state() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "out.inject_path_view = injectPathView;",
        "curA.inject_path_view = String(savedA.inject_path_view).trim().toLowerCase();",
        "fa.inject_path_view = pathView;",
        "persistFlowStateAndXmlBestEffort();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing inject path view XML/state round-trip snippets: " + "; ".join(missing)


def test_flow_inject_path_view_defaults_to_container_when_unset() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "let pathView = (fa && String(fa.inject_path_view || '').trim().toLowerCase() === 'core-vm') ? 'core-vm' : 'container';",
        "let injectsResolvedPathView = (fa && String(fa.inject_path_view || '').trim().toLowerCase() === 'core-vm') ? 'core-vm' : 'container';",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Inject path view should default to Container when unset: " + "; ".join(missing)


def test_flow_chain_variable_tables_dedupe_artifact_field_names() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if (defArtifactSet.has(n)) return;",
        "if (artifactNameSet.has(n)) return;",
        "if (outArtifactSet.has(n)) return;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Flow chain variable tables should not duplicate artifact/input-field names: " + "; ".join(missing)


def test_flow_restore_prefers_xml_authoritative_state() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const xmlAuthoritative = hasAuthoritativeXmlPathForScenario(scenarioName);",
        "if (xmlAuthoritative) {",
        "if (serverUsable) return fromServer;",
        "return null;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing XML-authoritative flow restore snippets: " + "; ".join(missing)


def test_flow_restore_refreshes_xml_only_when_server_state_missing() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const hasServerFlowState = !!getFlowStateForScenario(scenarioName);",
        "if (!hasServerFlowState && hasAuthoritativeXmlPathForScenario(scenarioName) && typeof window.coretgRefreshScenarioStateFromXml === 'function') {",
        "const latest = await window.coretgRefreshScenarioStateFromXml(scenarioName, { updateHidden: true, xml_path: xmlPath });",
        "if (key) flowStateByScenario[key] = fs;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Flow restore should refresh XML-backed state only when server state is missing: " + "; ".join(missing)


def test_flow_scenario_switch_uses_cached_preview_plan_before_background_refresh() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "lastPreviewPlanPath = (typeof window.coretgGetPreviewPlanPathForScenario === 'function')",
        "try { updateMeta(); } catch (e) { }",
        "const latestPreviewPromise = refreshLatestPreviewPlanPathForScenario(activeScenario).catch(() => '');",
        "latestPreviewPromise.then(() => {",
        "updateEmptyFlowStatus();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Flow scenario switching should use cached preview plan before background refresh: " + "; ".join(missing)


def test_flow_initial_boot_uses_cached_preview_plan_before_background_refresh() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "lastPreviewPlanPath = (typeof window.coretgGetPreviewPlanPathForScenario === 'function')",
        "const initialLatestPreviewPromise = refreshLatestPreviewPlanPathForScenario(activeScenario).catch(() => '');",
        "initialLatestPreviewPromise.then(() => {",
        "if (!currentChain.length && !currentFlagAssignments.length) {",
        "updateEmptyFlowStatus();",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Flow initial boot should use cached preview plan before background refresh: " + "; ".join(missing)


def test_flow_generate_sets_preview_plan_path_once() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    assert text.count("window.coretgSetPreviewPlanPathForScenario(scenario, previewPlan);") == 1


def test_flow_preview_does_not_write_disabled_state_twice() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if (!flowEnabled) {",
        "if (shouldPersistFlowState && !(await clearFlowStateInXml())) {",
        "throw new Error('Failed to clear Flag Sequencing state in XML.');",
        "} else if (shouldPersistFlowState) {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Flow preview should clear disabled state once instead of save+clear: " + "; ".join(missing)


def test_set_flow_enabled_skip_xml_persist_when_disable_already_clears() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const skipXmlPersist = (!flowEnabled && clearStateOnDisable);",
        "if (xmlPath && !skipXmlPersist) {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "setFlowEnabled should not clear XML and then immediately save the same disabled state again: " + "; ".join(missing)


def test_flow_latest_preview_refresh_uses_conditional_json_cache() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if (typeof window.CORETG_FETCH_CONDITIONAL_JSON === 'function') {",
        "data = await window.CORETG_FETCH_CONDITIONAL_JSON(url, {",
        "scope: 'flow-latest-preview-plan',",
        "if (!data) {",
        "data = await fetchJson(url);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Flow latest preview refresh should use conditional JSON cache before plain fetch: " + "; ".join(missing)


def test_flow_restore_emits_debug_logs_for_roundtrip_diagnostics() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "console.debug('[flow.restore] start'",
        "console.debug('[flow.restore] xml refresh'",
        "console.debug('[flow.restore] selected state'",
        "console.debug('[flow.restore] attackflow_preview response'",
        "console.error('[flow.restore] failed'",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow restore debug logging snippets: " + "; ".join(missing)


def test_flow_save_to_xml_clears_chain_when_disabled() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const chain_ids = (!flowEnabled)",
        "flag_assignments: (!flowEnabled) ? [] : buildPersistAssignments(chain_ids),",
        "flow_enabled: !!flowEnabled,",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Disabled flow saves should clear chain/assignments in XML payload: " + "; ".join(missing)


def test_flow_state_with_topology_dirty_field_is_usable_on_restore() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippet = "if (Object.prototype.hasOwnProperty.call(state, 'topology_dirty')) return true;"
    assert expected_snippet in text, "Flow restore should treat topology_dirty-bearing flow_state as usable"


def test_flow_restore_requires_resolved_values_for_saved_chain() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const hasResolvedValues = (flowState) => {",
        "const assignments = Array.isArray(flowState.flag_assignments) ? flowState.flag_assignments : [];",
        "return hasResolvedValues(normalized);",
        "setStatus('Chain does not exist. Click Generate to start.', false);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Flow restore should hide partial chain states without resolved values: " + "; ".join(missing)


def test_flow_saved_state_merge_preserves_empty_assignment_metadata_arrays() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if (savedA.input_fields_required && !Array.isArray(curA.input_fields_required)) curA.input_fields_required = savedA.input_fields_required;",
        "if (savedA.input_fields_optional && !Array.isArray(curA.input_fields_optional)) curA.input_fields_optional = savedA.input_fields_optional;",
        "if (savedA.output_fields && !Array.isArray(curA.output_fields)) curA.output_fields = savedA.output_fields;",
        "if (savedA.requires && !Array.isArray(curA.requires)) curA.requires = savedA.requires;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Saved-flow merge should preserve empty current metadata arrays instead of reviving stale values: " + "; ".join(missing)

    forbidden_snippets = [
        "if (savedA.input_fields_required && (!Array.isArray(curA.input_fields_required) || !curA.input_fields_required.length)) curA.input_fields_required = savedA.input_fields_required;",
        "if (savedA.input_fields_optional && (!Array.isArray(curA.input_fields_optional) || !curA.input_fields_optional.length)) curA.input_fields_optional = savedA.input_fields_optional;",
        "if (savedA.output_fields && (!Array.isArray(curA.output_fields) || !curA.output_fields.length)) curA.output_fields = savedA.output_fields;",
        "if (savedA.requires && (!Array.isArray(curA.requires) || !curA.requires.length)) curA.requires = savedA.requires;",
    ]

    present = [snippet for snippet in forbidden_snippets if snippet in text]
    assert not present, "Saved-flow merge should not treat empty metadata arrays as missing: " + "; ".join(present)


def test_flow_refresh_does_not_mark_dirty_from_preview_plan_fetch_errors() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    forbidden_snippet = "setTopologyDirtyState(true, 'topology_or_ip_changed');"
    assert forbidden_snippet not in text, "Transient preview-plan fetch errors should not force topology_dirty on refresh"


def test_flow_preview_tab_persists_flow_state_before_redirect() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "link.addEventListener('click', async (ev) => {",
        "const shouldPersistFlowState = shouldSaveFlowStateToXml(xmlPath);",
        "if (shouldPersistFlowState && !(await saveFlowStateToXml(xmlPath))) {",
        "window.location.href = url;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Preview-tab navigation should persist flow state before redirect: " + "; ".join(missing)


def test_flow_empty_state_uses_placeholder_message_instead_of_mermaid_error() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        '<div id="flowDiagram">Please generate a chain. It will appear here.</div>',
        "const fallbackText = 'Please generate a chain. It will appear here.';",
        "if (!diagramText || !String(diagramText).trim()) {",
        "if (renderedText.includes('syntax error in text')) {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow empty-state placeholder snippets: " + "; ".join(missing)


def test_flow_visualization_self_heals_placeholder_for_existing_chain() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        '<dialog id="flowDiagramWaitDialog"',
        "function showFlowDiagramWait(message) {",
        "flowDiagramWaitDialogEl.showModal();",
        "function hideFlowDiagramWait() {",
        "function renderFlowDiagramError(message) {",
        "let flowDiagramRepairQueued = false;",
        "let flowMermaidRetryQueued = false;",
        "function queueMermaidRenderRetry(attempt) {",
        "const retryAttempt = Number.isFinite(+attempt) ? Math.max(1, +attempt) : 1;",
        "queueMermaidRenderRetry(retryAttempt + 1);",
        "showFlowDiagramWait('Please wait, rendering visualization…');",
        "queueMermaidRenderRetry(attempt + 1);",
        "function ensureFlowDiagramForCurrentChain() {",
        "if (hasSvg) {",
        "hideFlowDiagramWait();",
        "const placeholderVisible = !text || text === fallbackText || text === 'No Chain Exists' || text.includes('Please generate a chain');",
        "ensureFlowDiagramForCurrentChain();",
        "renderFlowDiagramError('Diagram could not render. Try Generate again.');",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing Flow visualization placeholder self-heal snippets: " + "; ".join(missing)


def test_flow_restore_uses_backend_assignments_before_merging_saved_values() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "currentFlagAssignments = Array.isArray(data.flag_assignments) ? data.flag_assignments.slice() : [];",
        "mergeResolvedFromFlowState(saved, currentChain);",
        "if (savedA.id && (!curA.id || !String(curA.id).trim())) curA.id = savedA.id;",
        "if (savedA.flag_generator && (!curA.flag_generator || !String(curA.flag_generator).trim())) curA.flag_generator = savedA.flag_generator;",
        "if (savedA.hint && (!curA.hint || !String(curA.hint).trim())) curA.hint = savedA.hint;",
        "if (savedA.hints && !Array.isArray(curA.hints)) curA.hints = savedA.hints;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing Flow assignment restore snippets: " + "; ".join(missing)


def test_flow_generate_max_retries_defaults_to_ten() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'max="50" value="10" style="width: 90px;">',
        "parseInt(generateMaxRetriesEl.value || '10', 10) || 10",
        "} catch (e) { retriesRemaining = 10; }",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing flow max-retries default snippets: " + "; ".join(missing)


def test_flow_generate_button_and_options_are_wired() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        'id="flowGenerateBtn"',
        'data-bs-target="#flowAdvancedOptions" aria-expanded="false" aria-controls="flowAdvancedOptions"',
        'id="flowGenerateMaxRetries"',
        "if (btnEl) btnEl.addEventListener('click'",
        'generate(true, { savePreviewResolve: true, allow_node_duplicates: !!allowNodeDuplicates, resolveOnGenerate: true });',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing direct generate/options wiring in flow template: " + "; ".join(missing)


def test_flow_non_json_error_classifier_does_not_call_all_html_login() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "function nonJsonResponseError(res, text) {",
        "const loginUrl = /\\/login(?:[?#]|$)/.test(finalUrl);",
        "const looksLikeLogin = status === 401 || status === 403 || loginUrl || (res && res.redirected && lowerText.includes('login'));",
        "new Error(status >= 500 ? `Server error (${status}).`",
        "throw nonJsonResponseError(res, text);",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing Flow non-JSON error classification snippets: " + "; ".join(missing)

    assert "text && text.includes('<html')" not in text


def test_flow_enabled_state_is_declared_before_use() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const flowEnabledToggleEl = document.getElementById('flowEnabledToggle');",
        "let flowEnabled = !!(flowEnabledToggleEl ? flowEnabledToggleEl.checked : true);",
        'const enabled = !!flowEnabled;',
        'if (!flowEnabled) {',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing declared flowEnabled state binding in flow template: " + "; ".join(missing)
