"""Every custom service must survive CORE's Mako rendering.

CORE renders service files through Mako on every path that creates or displays
them (`create_files`, `get_rendered_templates`). Mako is unforgiving of ordinary
shell syntax, and two of its failure modes are easy to miss:

* `${VAR:-default}` / `${count}s` raise at render time, so the node fails to
  start with a ServiceTemplateError.
* a line starting with `##` is silently deleted, and a line starting with `%`
  is parsed as a control statement.

Wrapping script bodies in `<%text>` makes them verbatim. These tests render
each service the way CORE does so a regression fails here instead of on a node.
"""

import inspect
import re
from pathlib import Path

import pytest
from mako.template import Template

SERVICE_DIR = Path("on_core_machine/custom_services")

# Mirrors core.services.base.CoreService.files for each service.
EXPECTED_FILES = {
    "CoreTGPrereqs": "/runprereqs.sh",
    "DockerComposeService": "runcompose.sh",
    "DockerDefaultRoute": "/defaultroute.sh",
    "Segmentation": "/runsegmentation.sh",
    "TrafficService": "/runtraffic.sh",
}


class FakeNode:
    """Stand-in for the node object CORE passes into the template."""

    id = 7
    name = "docker-2"


def _service_files():
    files = sorted(p for p in SERVICE_DIR.glob("*.py") if p.name != "__init__.py")
    assert files, f"no custom services found under {SERVICE_DIR}"
    return files


def _extract_template(path: Path) -> str:
    """Pull the inline template out of get_text_template."""
    src = path.read_text(encoding="utf-8")
    match = re.search(r'return r?"""(.*?)"""', src, re.S)
    assert match, f"{path.name}: could not locate an inline template"
    return match.group(1)


def _render_like_core(text: str) -> str:
    """Reproduce CoreService.render_text: cleandoc, then Mako."""
    return Template(inspect.cleandoc(text)).render_unicode(node=FakeNode(), config={})


@pytest.mark.parametrize("path", _service_files(), ids=lambda p: p.stem)
def test_service_template_renders(path: Path) -> None:
    rendered = _render_like_core(_extract_template(path))
    assert rendered.strip(), f"{path.name}: rendered to empty output"


@pytest.mark.parametrize("path", _service_files(), ids=lambda p: p.stem)
def test_no_template_syntax_leaks_into_the_script(path: Path) -> None:
    """Mako constructs must be gone; shell `${VAR}` is expected to survive."""
    rendered = _render_like_core(_extract_template(path))
    assert "<%text>" not in rendered and "</%text>" not in rendered
    assert "${node." not in rendered, f"{path.name}: unrendered node expression"


@pytest.mark.parametrize("path", _service_files(), ids=lambda p: p.stem)
def test_node_data_is_interpolated_into_constants(path: Path) -> None:
    """Node references must resolve to real values before reaching the node."""
    template = _extract_template(path)
    if "${node." not in template:
        pytest.skip(f"{path.stem} does not use node data")
    rendered = _render_like_core(template)
    if "${node.id}" in template:
        assert f"NODE_ID='{FakeNode.id}'" in rendered
    if "${node.name}" in template:
        assert f"NODE_NAME='{FakeNode.name}'" in rendered


@pytest.mark.parametrize("path", _service_files(), ids=lambda p: p.stem)
def test_shell_body_is_protected_by_text_block(path: Path) -> None:
    """The script body must be verbatim so plain shell stays safe to write."""
    template = _extract_template(path)
    assert "<%text>" in template, (
        f"{path.name}: script body is not wrapped in <%text>, so shell syntax "
        "like ${VAR:-default} would break Mako rendering"
    )
    assert template.count("<%text>") == template.count("</%text>")
    # Node interpolation belongs in the header, above the verbatim body.
    head = template.split("<%text>", 1)[0]
    body = template.split("<%text>", 1)[1]
    assert "${node." not in body, f"{path.name}: node expression inside <%text> will not render"
    if "${node." in template:
        assert "${node." in head


def test_shell_syntax_inside_text_block_survives_rendering() -> None:
    """Guards the exact property the <%text> wrapper exists to provide."""
    hazards = "wait=${W:-45}\n## comment\n% not a control line\necho ${wait}s"
    rendered = _render_like_core("<%text>" + hazards + "</%text>")
    assert rendered == hazards


def test_unwrapped_shell_syntax_would_fail_without_the_text_block() -> None:
    """Demonstrates why the wrapper is required, not merely stylistic."""
    with pytest.raises(Exception):
        _render_like_core("wait=${W:-45}")
    # The silent one: a `##` line is deleted rather than reported.
    assert _render_like_core("## keep me\necho hi") == "echo hi"


def test_every_service_declares_the_file_it_templates() -> None:
    for path in _service_files():
        expected = EXPECTED_FILES.get(path.stem)
        if expected is None:
            continue
        src = path.read_text(encoding="utf-8")
        assert f'"{expected}"' in src, f"{path.name}: expected to declare {expected}"
