"""Run the Reports page's pure guide renderer without a browser or web server.

The marked regions in reports.html are the shared source of truth. Keep browser
I/O outside those regions; scenario data is passed over stdin, never as code.
"""
from pathlib import Path
import json
import shutil
import subprocess


def render_guides(scenario: str, preview: dict, audiences: list[str]) -> dict:
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
for (const audience of input.audiences) {
  guideHtmlBlockRegistry.clear();
  const markdown = buildReportGuideMarkdown(input.scenario, input.preview.chain,
    input.preview.flag_assignments || [], {
      facilitator: audience === 'facilitator',
      participantNetworkSetup: input.preview.participant_network_setup,
      preview: input.preview,
      vulnReadmeEntries: input.preview.vuln_readme_entries || [],
    });
  result[audience] = {markdown, html: markdownToHtmlDocument(input.scenario, markdown)};
}
process.stdout.write(JSON.stringify(result));
'''
    run = subprocess.run([node, '-e', script], input=json.dumps({
        'scenario': scenario, 'preview': preview, 'audiences': audiences,
    }), text=True, capture_output=True, timeout=60)
    if run.returncode:
        raise RuntimeError(f'Guide renderer failed: {run.stderr.strip()}')
    return json.loads(run.stdout)
