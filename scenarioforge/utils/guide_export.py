"""Run the Reports page's pure guide renderer without a browser or web server.

The marked regions in reports.html are the shared source of truth. Keep browser
I/O outside those regions; scenario data is passed over stdin, never as code.
"""
from pathlib import Path
import json
import shutil
import subprocess


def render_guides(scenario: str, preview: dict, audiences: list[str]) -> dict:
    return _run_renderer(scenario, preview, audiences)


def participant_hint_plan(scenario: str, preview: dict) -> list[dict]:
    """Collect resolved hint groups from the participant guide, without HTML scraping."""
    return _run_renderer(scenario, preview, ['participant'], hints_only=True)


def facilitator_solution_plan(scenario: str, preview: dict) -> list[dict]:
    """Keep each facilitator challenge walkthrough separate for gated release."""
    return _run_renderer(scenario, preview, ['facilitator'], solutions_only=True)


def _run_renderer(scenario, preview, audiences, *, hints_only=False, solutions_only=False):
    node = shutil.which('node')
    if not node:
        raise RuntimeError('Guide export requires Node.js (node on PATH).')
    template = Path(__file__).resolve().parents[2] / 'webapp' / 'templates' / 'reports.html'
    if not template.is_file():
        raise RuntimeError('Guide export requires the ScenarioForge source checkout with webapp/templates/reports.html.')
    source = template.read_text(encoding='utf-8')
    regions = []
    for name in ('ESCAPE', 'RENDERER'):
        begin, end = f'// GUIDE_{name}_BEGIN', f'// GUIDE_{name}_END'
        regions.append(source.split(begin, 1)[1].split(end, 1)[0])
    script = 'const window = {};\n' + '\n'.join(regions) + '''
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const result = {};
const hintCollector = [];
const solutionCollector = [];
for (const audience of input.audiences) {
  guideHtmlBlockRegistry.clear();
  const markdown = buildReportGuideMarkdown(input.scenario, input.preview.chain,
    input.preview.flag_assignments || [], {
      facilitator: audience === 'facilitator',
      hintCollector,
      solutionCollector,
      participantNetworkSetup: input.preview.participant_network_setup,
      preview: input.preview,
      vulnReadmeEntries: input.preview.vuln_readme_entries || [],
    });
  if (!input.hints_only && !input.solutions_only) result[audience] = {markdown, html: markdownToHtmlDocument(input.scenario, markdown)};
}
process.stdout.write(JSON.stringify(input.solutions_only ? solutionCollector : input.hints_only ? hintCollector : result));
'''
    run = subprocess.run([node, '-e', script], input=json.dumps({
        'scenario': scenario, 'preview': preview, 'audiences': audiences, 'hints_only': hints_only,
        'solutions_only': solutions_only,
    }), text=True, capture_output=True, timeout=60)
    if run.returncode:
        raise RuntimeError(f'Guide renderer failed: {run.stderr.strip()}')
    return json.loads(run.stdout)
