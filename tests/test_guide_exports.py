"""Execute the shipped guide builders, including HTML output and audience boundaries."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def guide_source(name):
    text = (ROOT / f"webapp/templates/{name}.html").read_text()
    if name == "flow":
        def function(function_name):
            return re.search(r"^  function " + function_name + r"\(.*?^  }", text, re.M | re.S).group()

        source = function("escapeHtml") + "\n" + function("alignAssignmentsToChain") + "\n"
        source += text[text.index("  const _OUTPUT_TEMPLATE_PREFIX ="):text.index("  function renderChainEditor()")]
        source += text[text.index("  const guideHtmlBlockRegistry ="):text.index("  /* Shared verification logic */")]
        source += "\nconst buildGuide = buildParticipantGuideMarkdown;\n"
    else:
        source = re.search(r"^function escapeHtml.*$", text, re.M).group() + "\n"
        source += text[text.index("const guideHtmlBlockRegistry ="):text.index("function _reportGuideNormalizeVulnToken")]
        source += "\nconst buildGuide = buildReportGuideMarkdown;\n"
    return 'const window = {}; const activeScenario = ""; const lastParticipantNetworkSetup = null;\n' + source


def render_guides(name, tmp_path, nodes, assignments):
    options = {
        "participantNetworkSetup": {"items": [{"address_cidr": "10.20.0.2/24", "gateway": "10.20.0.1"}]},
        "vulnReadmeEntries": [{"step": 1, "vulnName": "Reference", "content": "Facilitator reference material."}],
    }
    source = guide_source(name) + f"""
const nodes = {json.dumps(nodes)};
const assignments = {json.dumps(assignments)};
const options = {json.dumps(options)};
const result = {{}};
for (const facilitator of [false, true]) {{
  const markdown = buildGuide('Training <lab>', nodes, assignments, {{ ...options, facilitator }});
  result[facilitator ? 'facilitator' : 'participant'] = {{ markdown, html: markdownToHtmlDocument('Training <lab>', markdown) }};
}}
console.log(JSON.stringify(result));
"""
    script = tmp_path / f"{name}-guides.js"
    script.write_text(source)
    run = subprocess.run(["node", str(script)], text=True, capture_output=True, timeout=30)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


def sample_challenges():
    nodes = [{"id": str(i), "name": f"Challenge {i}", "ip4": f"10.20.0.{i + 10}"} for i in range(1, 4)]
    assignments = [{
        "node_id": str(i), "id": "web-token", "type": "flag-node-generator",
        "resolved_inputs": {"username": "analyst", "optional_internal_value": "unused"},
        "resolved_outputs": {"Flag(flag_id)": f"FLAG_ONLY_FOR_FACILITATOR_{i}"},
        "flag_value": f"FLAG_ONLY_FOR_FACILITATOR_{i}",
        "input_fields_required": ["authoring_field"],
        "requires": ["Knowledge(host)"], "produces": ["Flag(flag_id)"],
        "access_instructions": {"title": "Explore the service", "steps": [
            {"title": "Connect to the target", "instructions": "Open the service and inspect the available pages."},
            {"title": "Collect evidence", "instructions": "Record the response that completes the challenge."},
        ]},
        "hint_levels": {"low": ["The event account is analyst.", "Inspect the response headers."], "medium": ["Look for a token in the response."], "high": ["Use the discovered token on the protected endpoint."]},
        "promoted_first_step_hint_lines": ["The event account is analyst."],
        "chain_supplied_input_hints": ["The event account is analyst."],
    } for i in range(1, 4)]
    assignments[1]["pivot_decisions"] = [{
        "disposition": "own_step", "insert_before": 1, "subnet": "10.30.0.0/24",
        "instruction": "Establish a pivot before attempting this target.",
        "provider_node": "FACILITATOR_ONLY_PROVIDER",
        "hint_levels": {"low": ["Look for another reachable host."]},
    }]
    return nodes, assignments


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required to execute guide builders")
@pytest.mark.parametrize("name", ["flow", "reports"])
def test_guides_keep_task_flow_and_audience_boundaries(name, tmp_path):
    guides = render_guides(name, tmp_path, *sample_challenges())
    participant = guides["participant"]
    facilitator = guides["facilitator"]
    for audience, guide in guides.items():
        markdown, html = guide["markdown"], guide["html"]
        assert "Input Requirements" not in markdown
        assert "Chain Inputs / Outputs" not in markdown
        assert "Resolved Facts" not in markdown
        assert "Resolved inputs:" not in markdown
        assert "Next-Step Hint:" not in markdown
        assert markdown.index("Scenario:") < markdown.index("## Participant Network Setup") < markdown.index("## Challenge Steps")
        assert markdown.index("### Access Instructions") < markdown.index("### Check Your Progress") < markdown.index("### Need a Hint?")
        assert 'id="guide-step-1" open' in html
        assert 'id="guide-step-2"' in html
        assert 'href="#guide-step-2"' in html
        assert 'id="guide-completion"' in html
        assert 'aria-label="Guide contents"' in html
        assert 'type="checkbox"' in html
        assert '<details open>\n<summary>Helpful Fact</summary>' in html
        assert '<summary>Hint Low</summary>' in html
        assert not re.search(r"<summary>[^<]*Inspect the response headers", html)
        assert "The event account is analyst." in html
        assert "10.20.0.2/24" in html
        assert 'Training &lt;lab&gt;' in html
        # Direct navigation to the second step must include its prerequisite.
        assert html.index('id="guide-step-2"') < html.index("Establish a pivot before attempting this target.", html.index('id="guide-step-2"')) < html.index('id="guide-step-3"')
        assert "<script>" in html and "</script>" in html
    assert participant["markdown"].startswith("# Participant Steps Guide")
    assert "FLAG_ONLY_FOR_FACILITATOR" not in participant["html"]
    assert "FACILITATOR_ONLY_PROVIDER" not in participant["html"]
    assert "Facilitator reference material." not in participant["html"]
    assert facilitator["markdown"].startswith("# Facilitator Guide")
    assert "FLAG_ONLY_FOR_FACILITATOR_1" in facilitator["html"]
    assert "Facilitator answer check" in facilitator["html"]
    assert "Facilitator reference material." in facilitator["html"]
    assert "FACILITATOR_ONLY_PROVIDER" in facilitator["html"]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required to execute guide builders")
@pytest.mark.parametrize("name", ["flow", "reports"])
def test_empty_guides_have_no_dead_step_links(name, tmp_path):
    guides = render_guides(name, tmp_path, [], [])
    for guide in guides.values():
        assert "No chain is currently generated" in guide["markdown"]
        assert 'href="#guide-step-' not in guide["html"]
        assert 'id="guide-completion"' in guide["html"]
