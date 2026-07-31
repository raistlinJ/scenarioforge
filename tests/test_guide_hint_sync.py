"""The participant/facilitator guides re-render hints client-side.

Flow's node cards are rendered by the server; the guides are rebuilt in the
browser from the same assignment payload. That means every hint rule enforced on
the server has a twin in flow.html and reports.html, and the two drift silently
-- a guide keeps showing what the UI stopped showing. These tests pin the twins
together.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FLOW_TEMPLATE_PATH = REPO_ROOT / "webapp" / "templates" / "flow.html"
REPORTS_TEMPLATE_PATH = REPO_ROOT / "webapp" / "templates" / "reports.html"
GUIDE_TEMPLATES = (FLOW_TEMPLATE_PATH, REPORTS_TEMPLATE_PATH)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def test_guides_remap_file_path_to_flag_file_for_node_generators() -> None:
    """File(path) on a flag-node-generator is the compose file, not the artifact.

    The server remaps it at hint-render time in
    flow_prepare_preview_helpers.process_generator_outputs. Guides resolve
    {{OUTPUT.File(path)}} themselves from resolved_outputs, so without the same
    remap a guide prints "docker-compose.yml" where the UI prints the flag file.
    """
    helper_names = {
        FLOW_TEMPLATE_PATH: "hintOutputsForAssignment",
        REPORTS_TEMPLATE_PATH: "reportHintOutputsForAssignment",
    }
    for path in GUIDE_TEMPLATES:
        text = _read(path)
        helper = helper_names[path]
        assert f"function {helper}(" in text, f"{path.name} is missing {helper}()"
        assert "'flag-node-generator'" in text
        assert "'FlagFile(path)'" in text
        assert "{ 'File(path)': flagFile }" in text, (
            f"{path.name} must substitute FlagFile(path) for File(path)"
        )
        # The raw outputs must not be read directly where hints are resolved,
        # or the remap is bypassed.
        assert "addObject(source.resolved_outputs)" not in text, (
            f"{path.name} resolves hint variables from un-remapped outputs"
        )


def test_guides_do_not_point_participants_at_manifests_or_readmes() -> None:
    """Participants get the deployed scenario, not the authoring tree."""
    for path in GUIDE_TEMPLATES:
        text = _read(path)
        assert "README: ${readmeRef}" not in text, (
            f"{path.name} still injects a README hint"
        )
        assert "Use the access instructions for the complete workflow." not in text, (
            f"{path.name} still uses the manifest-referencing high-hint default"
        )
        assert "/^README:/i.test(value)" in text, (
            f"{path.name} must filter README hints out of guide output"
        )
        assert "docker-compose" in text and "generator manifest" in text, (
            f"{path.name} must filter compose/manifest references out of hints"
        )


def test_guides_label_promoted_disclosures_as_helpful_facts() -> None:
    """A promoted line is a given, not a hint, and both views must say so."""
    for path in GUIDE_TEMPLATES:
        text = _read(path)
        assert "'Helpful Fact'" in text, f"{path.name} is missing the Helpful Fact label"
        assert "promoted_first_step_hint_lines" in text, (
            f"{path.name} does not read the server's promoted-line list"
        )
        # Headings come from the grouping helper, not a bare level name, so a
        # promoted line cannot be labelled "Hint Low".
        assert "${group.title}" in text, (
            f"{path.name} still renders hint headings from the raw level name"
        )


def test_promoted_hint_lines_are_emitted_with_the_levels_they_match() -> None:
    """The client matches promoted lines against hint_levels by text.

    Both must therefore survive the same strip-and-re-render pass, or a promoted
    line silently falls back to the "Hint Low" label.
    """
    backend = _read(REPO_ROOT / "webapp" / "app_backend.py")
    assert "'promoted_first_step_hint_lines':" in backend
    assert "assignment_out['promoted_first_step_hint_lines'] = [" in backend, (
        "promoted lines must be re-rendered alongside hint_levels in the post-pass"
    )


def test_hint_level_templates_are_a_fallback_not_an_override() -> None:
    """The server rewrites hint_levels; re-adding raw templates undoes that.

    Stripping a next-node pointer the dependency graph does not impose only
    changes hint_levels, so a view that also merges hint_level_templates puts
    the pre-edit wording back.
    """
    guard = "if (Array.isArray(out[level]) && out[level].length) return;"
    for path in GUIDE_TEMPLATES:
        text = _read(path)
        normalize = re.search(
            r"function normalize(?:Flow|Report)HintLevels\(.*?\n\}", text, re.S
        )
        assert normalize, f"{path.name} has no hint-level normalizer"
        body = normalize.group(0)
        templates_at = body.find("hint_level_templates")
        assert templates_at >= 0, f"{path.name} normalizer ignores hint_level_templates"
        assert guard in body[templates_at:], (
            f"{path.name} merges hint_level_templates over an existing level"
        )
