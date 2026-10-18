from scenarioforge.vulns.guidance_audit import (
    audit_vulnerability_guidance,
    guidance_audit_markdown,
    summarize_guidance_audits,
)
from scenarioforge.vulns.metadata import VulnFacts


def test_complete_guidance_is_ready_for_graph_guides_and_evaluation() -> None:
    facts = VulnFacts(
        key='demo/CVE-2026-0001',
        impact='remote_code_execution',
        provides=('CodeExecution(host)', 'Shell(host)'),
        hint_levels={
            'low': ['Inspect {{NODE_IP}}.'],
            'medium': ['Use the vulnerable endpoint.'],
            'high': ['Send the exploit request.'],
        },
        access_instructions={
            'title': 'Exploit and retrieve',
            'steps': [{
                'title': 'Run request',
                'instructions': 'curl http://{{NODE_IP}}/run?cmd=cat%20{{ARTIFACT_PATH}}',
            }],
        },
        assistance={'version': 1, 'hints': [{
            'tier': 'low', 'sequence': 1,
            'interpretation': 'The service is reachable.',
            'next_action': 'Inspect it.',
            'success_signal': 'The response contains command output.',
        }], 'solution': {'source': 'access_instructions', 'include_answer': True,
                         'success_signal': 'The response contains command output.'}},
        source_path='/catalog/vuln_metadata.yaml',
    )

    audit = audit_vulnerability_guidance(facts, readme_available=True)

    assert audit['status'] == 'ready'
    assert audit['capability_ready'] is True
    assert audit['guide_ready'] is True
    assert audit['artifact_retrieval_ready'] is True
    assert audit['evaluation_ready'] is True
    assert audit['issues'] == []


def test_missing_metadata_reports_every_required_area() -> None:
    audit = audit_vulnerability_guidance(None, readme_available=True)

    assert audit['status'] == 'missing'
    assert audit['readme_available'] is True
    assert audit['evaluation_ready'] is False
    assert {issue['code'] for issue in audit['issues']} == {
        'missing_metadata',
        'missing_progressive_hints',
        'missing_access_instructions',
        'missing_teammate_assistance',
    }


def test_partial_metadata_explains_target_and_artifact_gaps() -> None:
    facts = VulnFacts(
        key='demo',
        impact='arbitrary_file_read',
        provides=('File(host, path)',),
        hint_levels={'low': ['one'], 'medium': ['two'], 'high': ['three']},
        access_instructions={
            'steps': [{'title': 'Request', 'instructions': 'curl http://example.invalid/readme'}],
        },
    )

    audit = audit_vulnerability_guidance(facts)

    assert audit['status'] == 'partial'
    assert audit['capability_ready'] is True
    assert audit['hints_ready'] is True
    assert audit['access_ready'] is False
    assert audit['artifact_retrieval_ready'] is False
    assert {issue['code'] for issue in audit['issues']} == {
        'missing_target_placeholder',
        'missing_artifact_retrieval',
        'missing_teammate_assistance',
    }


def test_summary_and_markdown_include_all_items() -> None:
    ready = {'status': 'ready', 'evaluation_ready': True, 'capability_ready': True, 'guide_ready': True, 'artifact_retrieval_ready': True, 'issues': []}
    missing = {'status': 'missing', 'evaluation_ready': False, 'capability_ready': False, 'guide_ready': False, 'artifact_retrieval_ready': False, 'issues': [{'code': 'missing_metadata', 'message': 'Add metadata.'}]}

    summary = summarize_guidance_audits([ready, missing])
    report = guidance_audit_markdown(catalog='Demo', items=[
        {'id': 1, 'name': 'ready', 'guidance_audit': ready},
        {'id': 2, 'name': 'missing', 'guidance_audit': missing},
    ])

    assert summary['total'] == 2
    assert summary['ready'] == 1
    assert summary['issue_counts'] == {'missing_metadata': 1}
    assert '# Vulnerability guidance audit: Demo' in report
    assert '| 2 | missing | missing | Add metadata. |' in report
