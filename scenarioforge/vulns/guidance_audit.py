"""Audit vulnerability metadata used by Flow, guides, and evaluation exports.

Deploying a compose stack only proves that a vulnerable service starts.  The
rest of ScenarioForge needs reviewed capability facts, progressive hints, and
a participant-ready procedure for reaching the target and recovering the
generated artifact.  Keeping those checks here gives the catalog UI, export
preflight, and tests one definition of "ready".
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Iterable

from .metadata import VulnFacts


_REQUIRED_HINT_LEVELS = ('low', 'medium', 'high')
_ALLOWED_PLACEHOLDERS = {'NODE_IP', 'NODE_NAME', 'ARTIFACT_PATH'}
_PLACEHOLDER_RE = re.compile(r'\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}')
_REMOTE_ACCESS_RE = re.compile(
    r'\b(?:curl|wget|http|https|ssh|nc|netcat|socat|ftp|sftp|smbclient|'
    r'sqlmap|redis-cli|mongo|mysql|psql|nmap|msfconsole|python|ruby|perl|'
    r'GET|POST|PUT|PATCH|DELETE)\b',
    re.IGNORECASE,
)


def _nonempty_hints(facts: VulnFacts | None, level: str) -> list[str]:
    if facts is None or not isinstance(facts.hint_levels, dict):
        return []
    values = facts.hint_levels.get(level)
    if not isinstance(values, list):
        return []
    return [str(value).strip() for value in values if str(value).strip()]


def _access_text(facts: VulnFacts | None) -> tuple[list[dict[str, str]], str]:
    if facts is None or not isinstance(facts.access_instructions, dict):
        return [], ''
    raw_steps = facts.access_instructions.get('steps')
    if not isinstance(raw_steps, list):
        return [], ''
    steps: list[dict[str, str]] = []
    for position, raw in enumerate(raw_steps, 1):
        if not isinstance(raw, dict):
            continue
        instructions = str(raw.get('instructions') or '').strip()
        if not instructions:
            continue
        steps.append({
            'title': str(raw.get('title') or f'Step {position}').strip(),
            'instructions': instructions,
        })
    return steps, '\n'.join(step['instructions'] for step in steps)


def audit_vulnerability_guidance(
    facts: VulnFacts | None,
    *,
    readme_available: bool = False,
) -> dict[str, Any]:
    """Return independent readiness verdicts and actionable issue messages."""
    issues: list[dict[str, str]] = []

    capability_ready = bool(
        facts is not None
        and (
            str(facts.impact or '').strip().lower() not in ('', 'unknown')
            or facts.requires
            or facts.provides
        )
    )
    if facts is None:
        issues.append({
            'code': 'missing_metadata',
            'area': 'attack_graph',
            'message': 'Add scenarioforge.vuln.yaml or a vuln_metadata.yaml entry.',
        })
    elif not capability_ready:
        issues.append({
            'code': 'missing_capability_facts',
            'area': 'attack_graph',
            'message': 'Declare impact or explicit requires/provides facts for the attack graph.',
        })

    missing_hint_levels = [level for level in _REQUIRED_HINT_LEVELS if not _nonempty_hints(facts, level)]
    hints_ready = not missing_hint_levels
    if missing_hint_levels:
        issues.append({
            'code': 'missing_progressive_hints',
            'area': 'guides',
            'message': 'Add reviewed low, medium, and high hint levels; missing: '
            + ', '.join(missing_hint_levels) + '.',
        })

    steps, access_text = _access_text(facts)
    access_ready = bool(steps)
    if not steps:
        issues.append({
            'code': 'missing_access_instructions',
            'area': 'guides',
            'message': 'Add participant-ready access_instructions.steps.',
        })

    placeholders = set(_PLACEHOLDER_RE.findall(access_text))
    unknown_placeholders = sorted(placeholders - _ALLOWED_PLACEHOLDERS)
    target_ready = 'NODE_IP' in placeholders or 'NODE_NAME' in placeholders
    if steps and not target_ready:
        access_ready = False
        issues.append({
            'code': 'missing_target_placeholder',
            'area': 'guides',
            'message': 'Reference {{NODE_IP}} or {{NODE_NAME}} so the guide targets the deployed node.',
        })
    if steps and not _REMOTE_ACCESS_RE.search(access_text):
        access_ready = False
        issues.append({
            'code': 'missing_remote_procedure',
            'area': 'guides',
            'message': 'Give a concrete request, client, or exploit command the participant can run.',
        })
    if unknown_placeholders:
        access_ready = False
        issues.append({
            'code': 'unknown_placeholders',
            'area': 'guides',
            'message': 'Replace unsupported placeholders: ' + ', '.join(unknown_placeholders) + '.',
        })

    # Generic upstream exploit prose may say "read a file" without explaining
    # how to read the artifact ScenarioForge injected for this run.  Requiring
    # the resolved placeholder prevents that prose from being mistaken for an
    # executable challenge solution.
    artifact_ready = bool(steps and 'ARTIFACT_PATH' in placeholders)
    if steps and not artifact_ready:
        issues.append({
            'code': 'missing_artifact_retrieval',
            'area': 'evaluation',
            'message': 'Show how the exploit reads {{ARTIFACT_PATH}} or returns the generated flag/token.',
        })

    guide_ready = hints_ready and access_ready
    evaluation_ready = capability_ready and guide_ready and artifact_ready
    if evaluation_ready:
        status = 'ready'
    elif facts is None:
        status = 'missing'
    else:
        status = 'partial'

    return {
        'status': status,
        'capability_ready': capability_ready,
        'hints_ready': hints_ready,
        'access_ready': access_ready,
        'artifact_retrieval_ready': artifact_ready,
        'guide_ready': guide_ready,
        'evaluation_ready': evaluation_ready,
        'readme_available': bool(readme_available),
        'metadata_source': str(facts.source_path or '') if facts else '',
        'impact': str(facts.impact or '') if facts else '',
        'requires': list(facts.requires) if facts else [],
        'provides': list(facts.provides) if facts else [],
        'missing_hint_levels': missing_hint_levels,
        'issues': issues,
    }


def summarize_guidance_audits(audits: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = [audit for audit in audits if isinstance(audit, dict)]
    statuses = Counter(str(row.get('status') or 'missing') for row in rows)
    issue_counts = Counter(
        str(issue.get('code') or 'unknown')
        for row in rows
        for issue in (row.get('issues') or [])
        if isinstance(issue, dict)
    )
    return {
        'total': len(rows),
        'ready': sum(bool(row.get('evaluation_ready')) for row in rows),
        'attack_graph_ready': sum(bool(row.get('capability_ready')) for row in rows),
        'guide_ready': sum(bool(row.get('guide_ready')) for row in rows),
        'artifact_retrieval_ready': sum(bool(row.get('artifact_retrieval_ready')) for row in rows),
        'partial': statuses.get('partial', 0),
        'missing': statuses.get('missing', 0),
        'issue_counts': dict(sorted(issue_counts.items())),
    }


def guidance_audit_markdown(*, catalog: str, items: Iterable[dict[str, Any]]) -> str:
    """Render a stable, shareable report from catalog API item records."""
    rows = [item for item in items if isinstance(item, dict)]
    summary = summarize_guidance_audits(item.get('guidance_audit') or {} for item in rows)
    lines = [
        f'# Vulnerability guidance audit: {catalog}',
        '',
        '| Catalog items | Evaluation ready | Attack graph ready | Guide ready | Artifact retrieval ready |',
        '| ---: | ---: | ---: | ---: | ---: |',
        f"| {summary['total']} | {summary['ready']} | {summary['attack_graph_ready']} | {summary['guide_ready']} | {summary['artifact_retrieval_ready']} |",
        '',
        'An item is evaluation ready only when it has reviewed capability facts, low/medium/high hints, a concrete participant access procedure, and an artifact retrieval procedure.',
        '',
        '| ID | Vulnerability | Status | Missing requirements |',
        '| ---: | --- | --- | --- |',
    ]
    for item in sorted(rows, key=lambda row: (str(row.get('name') or '').lower(), int(row.get('id') or 0))):
        audit = item.get('guidance_audit') if isinstance(item.get('guidance_audit'), dict) else {}
        issues = audit.get('issues') if isinstance(audit.get('issues'), list) else []
        missing = '<br>'.join(str(issue.get('message') or '') for issue in issues if isinstance(issue, dict)) or 'None'
        name = str(item.get('name') or '').replace('|', '\\|')
        lines.append(f"| {int(item.get('id') or 0)} | {name} | {audit.get('status') or 'missing'} | {missing.replace('|', '\\|')} |")
    lines.append('')
    return '\n'.join(lines)
