"""Vulnerability capability metadata and its effect on flag sequencing.

Before this metadata existed a vulnerability collapsed to a single `is_vuln`
boolean, so the solver would happily place a generator requiring
CodeExecution(host) behind a read-only file-disclosure CVE. These tests pin the
fact plumbing that makes a generated chain actually solvable.
"""

from __future__ import annotations

import uuid

import pytest

from webapp import app_backend
from scenarioforge.vulns import (
    canonical_fact_key,
    expand_provided_facts,
    load_vuln_metadata_file,
    load_vuln_metadata_index,
    validate_vuln_metadata_doc,
)
from scenarioforge.vulns.metadata import _index_from_records


# ---------------------------------------------------------------------------
# Fact canonicalization
# ---------------------------------------------------------------------------


def test_canonical_fact_key_ignores_arg_spacing_and_case():
    assert canonical_fact_key('Credential(user, password)') == canonical_fact_key(
        'Credential(user,password)'
    )
    assert canonical_fact_key('Credential(USER, Password)') == canonical_fact_key(
        'Credential(user,password)'
    )


def test_canonical_fact_key_preserves_arity():
    """Shell(host) and Shell(host, user) are distinct ontology signatures."""
    assert canonical_fact_key('Shell(host)') != canonical_fact_key('Shell(host, user)')


def test_expand_provided_facts_respells_to_generator_vocabulary():
    """Vuln facts must enter solver state using the generator's own spelling."""
    out = expand_provided_facts(
        ['Credential(user,password)'],
        ['Credential(user, password)', 'Flag(flag_id)'],
    )
    assert out == {'Credential(user, password)'}


def test_expand_provided_facts_applies_subsumption():
    """Root shell implies shell implies code execution."""
    out = expand_provided_facts(['RootShell(host)'], [])
    assert 'Shell(host)' in out
    assert 'CodeExecution(host)' in out


def test_expand_provided_facts_keeps_unmatched_facts_canonical():
    out = expand_provided_facts(['ExposedSecret(service)'], ['Flag(flag_id)'])
    assert out == {'ExposedSecret(service)'}


# ---------------------------------------------------------------------------
# Document validation
# ---------------------------------------------------------------------------


def test_impact_shorthand_expands_to_facts():
    records, errors = validate_vuln_metadata_doc(
        {
            'schema_version': 1,
            'vulns': [{'match': 'vulhub/activemq/CVE-2015-5254', 'impact': 'remote_code_execution'}],
        }
    )
    assert errors == []
    assert len(records) == 1
    assert set(records[0].provides) == {'CodeExecution(host)', 'Shell(host)'}


def test_privilege_escalation_carries_an_implied_requirement():
    records, errors = validate_vuln_metadata_doc(
        {'schema_version': 1, 'vulns': [{'match': 'x', 'impact': 'privilege_escalation'}]}
    )
    assert errors == []
    assert 'Shell(host)' in records[0].requires
    assert 'RootShell(host)' in records[0].provides


def test_explicit_provides_union_with_impact_defaults():
    records, _ = validate_vuln_metadata_doc(
        {
            'schema_version': 1,
            'vulns': [
                {
                    'match': 'x',
                    'impact': 'remote_code_execution',
                    'provides': ['Credential(user, password)'],
                }
            ],
        }
    )
    provides = set(records[0].provides)
    assert {'CodeExecution(host)', 'Shell(host)', 'Credential(user, password)'} <= provides


def test_unknown_impact_is_rejected():
    records, errors = validate_vuln_metadata_doc(
        {'schema_version': 1, 'vulns': [{'match': 'x', 'impact': 'totally_made_up'}]}
    )
    assert records == []
    assert any('unknown impact' in e for e in errors)


def test_fact_outside_the_ontology_is_rejected():
    records, errors = validate_vuln_metadata_doc(
        {
            'schema_version': 1,
            'vulns': [{'match': 'x', 'impact': 'unknown', 'provides': ['Nonsense(thing)']}],
        }
    )
    assert records == []
    assert any("unknown fact 'Nonsense'" in e for e in errors)


def test_wrong_schema_version_is_rejected():
    records, errors = validate_vuln_metadata_doc({'schema_version': 99, 'vulns': []})
    assert records == []
    assert any('schema_version' in e for e in errors)


def test_entry_needs_a_match_or_cve():
    _records, errors = validate_vuln_metadata_doc(
        {'schema_version': 1, 'vulns': [{'impact': 'remote_code_execution'}]}
    )
    assert any('needs a "match" or "cve"' in e for e in errors)


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def _index(entries):
    records, errors = validate_vuln_metadata_doc({'schema_version': 1, 'vulns': entries})
    assert errors == [], errors
    return _index_from_records(records, source='test')


def test_lookup_matches_exact_suffix_cve_and_glob():
    index = _index(
        [
            {'match': 'vulhub/activemq/CVE-2015-5254', 'cve': 'CVE-2015-5254', 'impact': 'deserialization'},
            {'match': 'vulhub/nginx/*', 'impact': 'arbitrary_file_read'},
        ]
    )
    assert index.lookup('vulhub/activemq/CVE-2015-5254').impact == 'deserialization'
    assert index.lookup('activemq/CVE-2015-5254').impact == 'deserialization'
    assert index.lookup('CVE-2015-5254').impact == 'deserialization'
    assert index.lookup('vulhub/nginx/CVE-2013-4547').impact == 'arbitrary_file_read'
    assert index.lookup('vulhub/redis/CVE-2022-0543') is None


def test_lookup_is_case_and_separator_insensitive():
    index = _index([{'match': 'vulhub/ActiveMQ/CVE-2015-5254', 'impact': 'deserialization'}])
    assert index.lookup('VULHUB\\activemq\\CVE-2015-5254') is not None


def test_file_loading_and_precedence(tmp_path):
    """A per-vuln file overrides the catalog file for the same entry."""
    catalog_dir = tmp_path / 'catalog'
    entry_dir = catalog_dir / 'content' / 'vulhub' / 'app' / 'CVE-2021-1'
    entry_dir.mkdir(parents=True)

    (catalog_dir / 'vuln_metadata.yaml').write_text(
        'schema_version: 1\n'
        'vulns:\n'
        '  - match: "vulhub/app/CVE-2021-1"\n'
        '    impact: information_disclosure\n',
        encoding='utf-8',
    )
    (entry_dir / 'scenarioforge.vuln.yaml').write_text(
        'schema_version: 1\n'
        'vulns:\n'
        '  - match: "vulhub/app/CVE-2021-1"\n'
        '    impact: remote_code_execution\n',
        encoding='utf-8',
    )

    index = load_vuln_metadata_index(entry_dirs=[entry_dir], catalog_dirs=[catalog_dir])
    assert index.lookup('vulhub/app/CVE-2021-1').impact == 'remote_code_execution'


def test_malformed_file_reports_an_error_rather_than_raising(tmp_path):
    bad = tmp_path / 'vuln_metadata.yaml'
    bad.write_text('schema_version: 1\nvulns: "not a list"\n', encoding='utf-8')
    index = load_vuln_metadata_file(bad)
    assert index.errors
    assert not index


# ---------------------------------------------------------------------------
# Solver integration
# ---------------------------------------------------------------------------


_RCE_NAME = 'vulhub/activemq/CVE-2015-5254'
_LEAK_NAME = 'vulhub/app/CVE-2021-info'


def _install_generators(monkeypatch, flag_gens, plugins):
    monkeypatch.setattr(
        app_backend, '_flag_generators_from_enabled_sources', lambda: (flag_gens, [])
    )
    monkeypatch.setattr(
        app_backend, '_flag_node_generators_from_enabled_sources', lambda: ([], [])
    )
    monkeypatch.setattr(
        app_backend, '_flow_enabled_plugin_contracts_by_id', lambda: plugins
    )


def _install_metadata(monkeypatch, entries):
    index = _index(entries)
    monkeypatch.setattr(app_backend, '_load_vuln_metadata_index', lambda **_kw: index)
    return index


def _shell_consumer_setup(monkeypatch, vuln_name):
    """One vuln node and one generator that needs CodeExecution(host)."""
    preview = {
        'seed': 0,
        'hosts': [
            {
                'node_id': 'h1',
                'name': 'dockervuln-1',
                'role': 'Docker',
                'vulnerabilities': [{'name': vuln_name}],
            }
        ],
    }
    gen = {
        'id': 'needs_rce',
        'name': 'Needs RCE',
        'inputs': [{'name': 'CodeExecution(host)', 'required': True}],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'hint_levels': {'low': ['Next: {{NEXT_NODE_ID}}']},
        '_source_name': 'test',
    }
    plugins = {
        'needs_rce': {
            'plugin_id': 'needs_rce',
            'requires': ['CodeExecution(host)'],
            'produces': [{'artifact': 'Flag(flag_id)'}],
        }
    }
    _install_generators(monkeypatch, [gen], plugins)
    chain_nodes = [{'id': 'h1', 'name': 'dockervuln-1', 'type': 'docker', 'is_vuln': True}]
    return preview, chain_nodes


def test_rce_vuln_unlocks_a_generator_that_needs_code_execution(monkeypatch):
    preview, chain_nodes = _shell_consumer_setup(monkeypatch, _RCE_NAME)
    _install_metadata(monkeypatch, [{'match': _RCE_NAME, 'impact': 'remote_code_execution'}])

    assignments = app_backend._flow_compute_flag_assignments(
        preview, chain_nodes, f'zz-vuln-rce-{uuid.uuid4().hex[:8]}'
    )

    assert len(assignments) == 1
    assert assignments[0]['id'] == 'needs_rce'
    assert 'CodeExecution(host)' in assignments[0]['vuln_provides']


def test_info_disclosure_vuln_does_not_unlock_a_code_execution_generator(monkeypatch):
    """The regression this whole feature exists to prevent."""
    preview, chain_nodes = _shell_consumer_setup(monkeypatch, _LEAK_NAME)
    _install_metadata(monkeypatch, [{'match': _LEAK_NAME, 'impact': 'information_disclosure'}])

    assignments = app_backend._flow_compute_flag_assignments(
        preview, chain_nodes, f'zz-vuln-leak-{uuid.uuid4().hex[:8]}'
    )

    assert assignments == []


def test_vuln_without_metadata_grants_nothing(monkeypatch):
    preview, chain_nodes = _shell_consumer_setup(monkeypatch, 'vulhub/unknown/CVE-9999-1')
    _install_metadata(monkeypatch, [{'match': _RCE_NAME, 'impact': 'remote_code_execution'}])

    assignments = app_backend._flow_compute_flag_assignments(
        preview, chain_nodes, f'zz-vuln-none-{uuid.uuid4().hex[:8]}'
    )

    assert assignments == []


def test_vuln_facts_respell_to_the_generator_spelling(monkeypatch):
    """A vuln providing Credential(user,password) satisfies the spaced spelling."""
    preview = {
        'seed': 0,
        'hosts': [
            {
                'node_id': 'h1',
                'name': 'dockervuln-1',
                'role': 'Docker',
                'vulnerabilities': [{'name': _RCE_NAME}],
            }
        ],
    }
    gen = {
        'id': 'needs_cred',
        'name': 'Needs Credential',
        'inputs': [{'name': 'Credential(user, password)', 'required': True}],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'hint_levels': {'low': ['Next: {{NEXT_NODE_ID}}']},
        '_source_name': 'test',
    }
    plugins = {
        'needs_cred': {
            'plugin_id': 'needs_cred',
            'requires': ['Credential(user, password)'],
            'produces': [{'artifact': 'Flag(flag_id)'}],
        }
    }
    _install_generators(monkeypatch, [gen], plugins)
    _install_metadata(
        monkeypatch,
        [{'match': _RCE_NAME, 'impact': 'unknown', 'provides': ['Credential(user,password)']}],
    )

    chain_nodes = [{'id': 'h1', 'name': 'dockervuln-1', 'type': 'docker', 'is_vuln': True}]
    assignments = app_backend._flow_compute_flag_assignments(
        preview, chain_nodes, f'zz-vuln-respell-{uuid.uuid4().hex[:8]}'
    )

    assert len(assignments) == 1
    assert assignments[0]['id'] == 'needs_cred'


def test_vuln_grants_carry_forward_to_later_chain_positions(monkeypatch):
    """An RCE at position 0 satisfies a later generator's shell requirement."""
    preview = {
        'seed': 0,
        'hosts': [
            {
                'node_id': 'h1',
                'name': 'v1',
                'role': 'Docker',
                'vulnerabilities': [{'name': _RCE_NAME}],
            },
            {
                'node_id': 'h2',
                'name': 'v2',
                'role': 'Docker',
                'vulnerabilities': [{'name': _LEAK_NAME}],
            },
        ],
    }
    first = {
        'id': 'plain',
        'name': 'Plain',
        'inputs': [],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'hint_levels': {'low': ['x']},
        '_source_name': 'test',
    }
    second = {
        'id': 'needs_shell',
        'name': 'Needs Shell',
        'inputs': [{'name': 'Shell(host)', 'required': True}],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'hint_levels': {'low': ['x']},
        '_source_name': 'test',
    }
    plugins = {
        'plain': {'plugin_id': 'plain', 'requires': [], 'produces': [{'artifact': 'Flag(flag_id)'}]},
        'needs_shell': {
            'plugin_id': 'needs_shell',
            'requires': ['Shell(host)'],
            'produces': [{'artifact': 'Flag(flag_id)'}],
        },
    }
    _install_generators(monkeypatch, [first, second], plugins)
    _install_metadata(
        monkeypatch,
        [
            {'match': _RCE_NAME, 'impact': 'remote_code_execution'},
            {'match': _LEAK_NAME, 'impact': 'information_disclosure'},
        ],
    )

    chain_nodes = [
        {'id': 'h1', 'name': 'v1', 'type': 'docker', 'is_vuln': True},
        {'id': 'h2', 'name': 'v2', 'type': 'docker', 'is_vuln': True},
    ]
    assignments = app_backend._flow_compute_flag_assignments(
        preview, chain_nodes, f'zz-vuln-carry-{uuid.uuid4().hex[:8]}'
    )

    assert len(assignments) == 2
    assert assignments[1]['id'] == 'needs_shell'


# ---------------------------------------------------------------------------
# Chain validation
# ---------------------------------------------------------------------------


def _validate(monkeypatch, *, node_vulns, plugin_requires, strict):
    plugins = {
        'g1': {
            'plugin_id': 'g1',
            'requires': list(plugin_requires),
            'produces': [{'artifact': 'Flag(flag_id)'}],
        }
    }
    monkeypatch.setattr(app_backend, '_flow_enabled_generator_defs_by_id', lambda: {})
    monkeypatch.setenv(
        'SCENARIOFORGE_REQUIRE_VULN_METADATA', '1' if strict else '0'
    )
    chain_nodes = [
        {'id': 'h1', 'name': 'v1', 'type': 'docker', 'is_vuln': True, 'vulnerabilities': node_vulns}
    ]
    assignments = [{'node_id': 'h1', 'id': 'g1'}]
    return app_backend._flow_validate_chain_order_by_requires_produces(
        chain_nodes,
        assignments,
        scenario_label='zz-validate',
        plugins_by_id_override=plugins,
    )


def test_validation_accepts_a_generator_backed_by_a_matching_vuln(monkeypatch):
    _install_metadata(monkeypatch, [{'match': _RCE_NAME, 'impact': 'remote_code_execution'}])
    ok, errors = _validate(
        monkeypatch,
        node_vulns=[{'name': _RCE_NAME}],
        plugin_requires=['CodeExecution(host)'],
        strict=False,
    )
    assert ok, errors


def test_validation_rejects_a_generator_the_vuln_cannot_support(monkeypatch):
    _install_metadata(monkeypatch, [{'match': _LEAK_NAME, 'impact': 'information_disclosure'}])
    ok, errors = _validate(
        monkeypatch,
        node_vulns=[{'name': _LEAK_NAME}],
        plugin_requires=['CodeExecution(host)'],
        strict=False,
    )
    assert not ok
    assert any('CodeExecution(host)' in e for e in errors)


def test_strict_mode_rejects_a_vuln_with_no_metadata(monkeypatch):
    _install_metadata(monkeypatch, [{'match': _RCE_NAME, 'impact': 'remote_code_execution'}])
    ok, errors = _validate(
        monkeypatch,
        node_vulns=[{'name': 'vulhub/mystery/CVE-9999-2'}],
        plugin_requires=[],
        strict=True,
    )
    assert not ok
    assert any('no capability metadata' in e for e in errors)


def test_non_strict_mode_tolerates_a_vuln_with_no_metadata(monkeypatch):
    _install_metadata(monkeypatch, [{'match': _RCE_NAME, 'impact': 'remote_code_execution'}])
    ok, errors = _validate(
        monkeypatch,
        node_vulns=[{'name': 'vulhub/mystery/CVE-9999-2'}],
        plugin_requires=[],
        strict=False,
    )
    assert ok, errors


def test_validation_flags_a_vuln_whose_own_requirement_is_unmet(monkeypatch):
    """Privilege escalation needs a shell that nothing in the chain provides."""
    _install_metadata(monkeypatch, [{'match': _RCE_NAME, 'impact': 'privilege_escalation'}])
    ok, errors = _validate(
        monkeypatch,
        node_vulns=[{'name': _RCE_NAME}],
        plugin_requires=[],
        strict=False,
    )
    assert not ok
    assert any('before it can be exploited' in e for e in errors)


# ---------------------------------------------------------------------------
# Node authoring facts
# ---------------------------------------------------------------------------


def test_node_authoring_facts_convert_to_signature_strings():
    out = app_backend._flow_node_authoring_fact_strings(
        [{'name': 'Shell', 'args': ['host']}, {'name': 'Credential', 'args': ['user', 'password']}]
    )
    assert out == ['Shell(host)', 'Credential(user, password)']


def test_node_authoring_provides_unlocks_a_generator(monkeypatch):
    """A node declaring logic.provides is credited like vulnerability metadata."""
    preview = {
        'seed': 0,
        'hosts': [{'node_id': 'h1', 'name': 'v1', 'role': 'Docker', 'vulnerabilities': []}],
    }
    gen = {
        'id': 'needs_rce',
        'name': 'Needs RCE',
        'inputs': [{'name': 'CodeExecution(host)', 'required': True}],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'hint_levels': {'low': ['x']},
        '_source_name': 'test',
    }
    plugins = {
        'needs_rce': {
            'plugin_id': 'needs_rce',
            'requires': ['CodeExecution(host)'],
            'produces': [{'artifact': 'Flag(flag_id)'}],
        }
    }
    _install_generators(monkeypatch, [gen], plugins)
    _install_metadata(monkeypatch, [])

    chain_nodes = [
        {
            'id': 'h1',
            'name': 'v1',
            'type': 'docker',
            'is_vuln': True,
            'node_authoring': {
                'node_id': 'v1',
                'template': 't',
                'logic': {
                    'requires': [],
                    'provides': [{'name': 'CodeExecution', 'args': ['host']}],
                },
                'deployment': {},
            },
        }
    ]
    assignments = app_backend._flow_compute_flag_assignments(
        preview, chain_nodes, f'zz-authored-{uuid.uuid4().hex[:8]}'
    )

    assert len(assignments) == 1
    assert assignments[0]['id'] == 'needs_rce'
    assert 'CodeExecution(host)' in assignments[0]['vuln_provides']


def test_node_without_authoring_doc_grants_nothing(monkeypatch):
    """The same node with no authoring doc cannot satisfy the generator."""
    preview = {
        'seed': 0,
        'hosts': [{'node_id': 'h1', 'name': 'v1', 'role': 'Docker', 'vulnerabilities': []}],
    }
    gen = {
        'id': 'needs_rce',
        'name': 'Needs RCE',
        'inputs': [{'name': 'CodeExecution(host)', 'required': True}],
        'outputs': [{'name': 'Flag(flag_id)'}],
        'hint_levels': {'low': ['x']},
        '_source_name': 'test',
    }
    plugins = {
        'needs_rce': {
            'plugin_id': 'needs_rce',
            'requires': ['CodeExecution(host)'],
            'produces': [{'artifact': 'Flag(flag_id)'}],
        }
    }
    _install_generators(monkeypatch, [gen], plugins)
    _install_metadata(monkeypatch, [])

    chain_nodes = [{'id': 'h1', 'name': 'v1', 'type': 'docker', 'is_vuln': True}]
    assignments = app_backend._flow_compute_flag_assignments(
        preview, chain_nodes, f'zz-unauthored-{uuid.uuid4().hex[:8]}'
    )

    assert assignments == []


# ---------------------------------------------------------------------------
# Pivot shell backing
# ---------------------------------------------------------------------------


def _pivot_rules(monkeypatch, *, source_vulns, source_extra=None):
    source = {
        'id': 'n-jump',
        'name': 'jump-web',
        'type': 'docker',
        'is_vuln': bool(source_vulns),
        'vulnerabilities': list(source_vulns),
    }
    source.update(source_extra or {})
    target = {
        'id': 'n-db',
        'name': 'internal-db',
        'type': 'docker',
        'PivotRequires': 'Pivot(jump-web)',
    }
    return app_backend._flow_pivot_rules_for_chain(None, [source, target])


def test_pivot_claims_shell_when_the_source_vuln_yields_one(monkeypatch):
    _install_metadata(monkeypatch, [{'match': _RCE_NAME, 'impact': 'remote_code_execution'}])
    rules = _pivot_rules(monkeypatch, source_vulns=[{'name': _RCE_NAME}])

    assert len(rules) == 1
    assert 'Shell(jump-web)' in rules[0]['produces']
    assert rules[0]['unbacked_shell'] is False


def test_pivot_drops_the_shell_claim_when_the_source_vuln_cannot_back_it(monkeypatch):
    """A file-disclosure jump host is not a shell foothold."""
    _install_metadata(monkeypatch, [{'match': _LEAK_NAME, 'impact': 'information_disclosure'}])
    rules = _pivot_rules(monkeypatch, source_vulns=[{'name': _LEAK_NAME}])

    assert len(rules) == 1
    assert 'Shell(jump-web)' not in rules[0]['produces']
    assert 'Pivot(jump-web)' in rules[0]['produces']
    assert rules[0]['unbacked_shell'] is True


def test_pivot_keeps_the_default_for_an_undeclared_source(monkeypatch):
    """No metadata is not evidence of absence; the old default stands."""
    _install_metadata(monkeypatch, [])
    rules = _pivot_rules(monkeypatch, source_vulns=[{'name': 'vulhub/mystery/CVE-9999-3'}])

    assert len(rules) == 1
    assert 'Shell(jump-web)' in rules[0]['produces']
    assert rules[0]['unbacked_shell'] is False


def test_pivot_keeps_the_default_for_a_non_vuln_source(monkeypatch):
    """A plain jump box has no vuln to declare; do not strip its shell."""
    _install_metadata(monkeypatch, [])
    rules = _pivot_rules(monkeypatch, source_vulns=[])

    assert len(rules) == 1
    assert 'Shell(jump-web)' in rules[0]['produces']


def test_pivot_respects_an_explicit_produces_declaration(monkeypatch):
    """An authored rule is never second-guessed by metadata."""
    _install_metadata(monkeypatch, [{'match': _LEAK_NAME, 'impact': 'information_disclosure'}])
    rules = _pivot_rules(
        monkeypatch,
        source_vulns=[{'name': _LEAK_NAME}],
        source_extra={'PivotProduces': 'Shell(jump-web),Pivot(jump-web)'},
    )

    assert len(rules) == 1
    assert 'Shell(jump-web)' in rules[0]['produces']
    assert rules[0]['unbacked_shell'] is False


def test_pivot_shell_claim_follows_node_authoring_when_present(monkeypatch):
    """A node-authoring doc can back the shell claim without any vuln."""
    _install_metadata(monkeypatch, [])
    rules = _pivot_rules(
        monkeypatch,
        source_vulns=[],
        source_extra={
            'node_authoring': {
                'node_id': 'jump-web',
                'template': 't',
                'logic': {'requires': [], 'provides': [{'name': 'Knowledge', 'args': ['value']}]},
                'deployment': {},
            }
        },
    )

    assert len(rules) == 1
    assert 'Shell(jump-web)' not in rules[0]['produces']
    assert rules[0]['unbacked_shell'] is True


# ---------------------------------------------------------------------------
# First-step secret disclosure
# ---------------------------------------------------------------------------

_CRED_ACCESS = {
    'title': 'Postgres-Style Export',
    'steps': [
        {'step': 1, 'instructions': '```bash\nnc {{NODE}} {{PORT}}\n```'},
        {'step': 2, 'instructions': '```text\nAUTH {{USERNAME}} {{PASSWORD}}\nGET {{FLAG_FILE}}\n```'},
    ],
}


def _gen_def(*, hint_levels, access=_CRED_ACCESS):
    return {
        'id': 'g1',
        'name': 'Credential Gated Service',
        'access_instructions': access,
        'hint_levels': hint_levels,
        'inputs': [
            {'name': 'Credential(user, password)', 'required': True, 'flow_supply_when_first': True},
        ],
        'outputs': [{'name': 'Flag(flag_id)'}],
    }


def _validate_chain(monkeypatch, gen_defs, chain_len=1):
    plugins = {f'g{i+1}': {'plugin_id': f'g{i+1}', 'requires': [], 'produces': [{'artifact': 'Flag(flag_id)'}]}
               for i in range(chain_len)}
    monkeypatch.setattr(app_backend, '_flow_enabled_generator_defs_by_id', lambda: gen_defs)
    monkeypatch.setenv('SCENARIOFORGE_REQUIRE_VULN_METADATA', '0')
    chain_nodes = [{'id': f'h{i+1}', 'name': f'n{i+1}', 'type': 'docker', 'is_vuln': True,
                    'vulnerabilities': [{'name': 'zz/CVE-0000-0000'}]} for i in range(chain_len)]
    assignments = [{'node_id': f'h{i+1}', 'id': f'g{i+1}'} for i in range(chain_len)]
    return app_backend._flow_validate_chain_order_by_requires_produces(
        chain_nodes, assignments, scenario_label='zz-disclose', plugins_by_id_override=plugins,
    )


def test_access_secrets_are_read_from_placeholders_not_the_contract():
    """A generator that produces a credential still gates its service behind it."""
    gen = _gen_def(hint_levels={'low': ['Look around.']})
    pairs = app_backend._flow_access_required_secret_facts(gen)
    assert {p for p, _alts in pairs} == {'USERNAME', 'PASSWORD'}


def test_placeholder_alternatives_are_a_choice_not_a_conjunction():
    """USERNAME is satisfied by either Credential(user) or Credential(user, password)."""
    gen = _gen_def(hint_levels={'low': ['user: {{OUTPUT.Credential(user, password)}}']})
    assert app_backend._flow_first_step_undisclosed_secrets(gen) == []


def test_first_step_without_low_disclosure_is_rejected(monkeypatch):
    gen = _gen_def(hint_levels={
        'low': ['Inspect the export before moving on.'],
        'medium': ['Credential artifact: {{OUTPUT.Credential(user,password)}}'],
    })
    ok, errors = _validate_chain(monkeypatch, {'g1': gen})
    assert not ok
    assert any('first chain step needs' in e for e in errors), errors
    assert any('USERNAME' in e for e in errors), errors


def test_first_step_with_low_disclosure_is_accepted(monkeypatch):
    """Promoting the disclosing hint to low is the intended remedy."""
    gen = _gen_def(hint_levels={
        'low': ['Credential artifact: {{OUTPUT.Credential(user,password)}}'],
    })
    ok, errors = _validate_chain(monkeypatch, {'g1': gen})
    assert ok, errors


def test_later_steps_are_not_checked(monkeypatch):
    """Only the opening step is unenterable; later steps can be fed by earlier ones."""
    plain = {'id': 'g1', 'name': 'Plain', 'hint_levels': {'low': ['go']}, 'outputs': [{'name': 'Flag(flag_id)'}]}
    gated = _gen_def(hint_levels={'low': ['Inspect the export.']})
    gated['id'] = 'g2'
    ok, errors = _validate_chain(monkeypatch, {'g1': plain, 'g2': gated}, chain_len=2)
    assert ok, errors


def test_generator_without_access_secrets_is_unaffected(monkeypatch):
    gen = {
        'id': 'g1', 'name': 'No Secrets',
        'access_instructions': {'steps': [{'step': 1, 'instructions': 'nc {{NODE}} {{PORT}}'}]},
        'hint_levels': {'low': ['go']}, 'outputs': [{'name': 'Flag(flag_id)'}],
    }
    ok, errors = _validate_chain(monkeypatch, {'g1': gen})
    assert ok, errors


# ---------------------------------------------------------------------------
# First-step hint promotion
# ---------------------------------------------------------------------------


def _gated(hint_levels, access=_CRED_ACCESS):
    return {'id': 'g1', 'name': 'Gated', 'access_instructions': access, 'hint_levels': hint_levels}


def test_promotion_moves_the_disclosing_hint_into_low():
    gen = _gated({
        'low': ['Inspect the export.'],
        'medium': ['Credential artifact: {{OUTPUT.Credential(user,password)}}'],
    })
    levels, promoted = app_backend._flow_promote_first_step_hint_levels(
        app_backend._flow_hint_level_templates_from_generator(gen), gen
    )
    assert promoted, 'expected a promotion'
    assert any('OUTPUT.Credential' in line for line in levels['low'])
    # The line moves rather than copies: showing the same disclosure at two
    # depths makes the deeper hint pointless once `low` has given it away.
    assert not any('OUTPUT.Credential' in line for line in levels['medium'])
    assert app_backend._flow_first_step_undisclosed_secrets({**gen, 'hint_levels': levels}) == []


def test_one_promoted_line_can_satisfy_several_placeholders():
    """A Credential(user, password) disclosure covers both USERNAME and PASSWORD."""
    gen = _gated({
        'low': ['Inspect the export.'],
        'medium': ['Credential artifact: {{OUTPUT.Credential(user,password)}}'],
    })
    levels, _ = app_backend._flow_promote_first_step_hint_levels(
        app_backend._flow_hint_level_templates_from_generator(gen), gen
    )
    assert len([l for l in levels['low'] if 'OUTPUT.Credential' in l]) == 1


def test_enumerable_placeholders_are_not_promoted():
    """Ports and paths are discoverable; giving them away is not the point."""
    access = {'steps': [{'step': 1, 'instructions': 'nc {{NODE}} {{PORT}}\nGET {{FLAG_FILE}}'}]}
    gen = _gated({'low': ['Look around.'], 'medium': ['File: {{OUTPUT.File(path)}}']}, access=access)
    levels, promoted = app_backend._flow_promote_first_step_hint_levels(
        app_backend._flow_hint_level_templates_from_generator(gen), gen
    )
    assert promoted == []
    assert levels['low'] == ['Look around.']


def test_promotion_is_a_no_op_when_nothing_discloses_the_secret():
    """A manifest with no disclosing hint cannot be repaired; the validator flags it."""
    gen = _gated({'low': ['Inspect the debug token.'], 'medium': ['File: {{OUTPUT.File(path)}}']},
                 access={'steps': [{'step': 1, 'instructions': 'AUTH {{TOKEN}}'}]})
    levels, promoted = app_backend._flow_promote_first_step_hint_levels(
        app_backend._flow_hint_level_templates_from_generator(gen), gen
    )
    assert promoted == []
    assert app_backend._flow_first_step_undisclosed_secrets({**gen, 'hint_levels': levels}) == ['TOKEN']


def test_only_the_first_assignment_gets_promoted_hints(monkeypatch):
    """Later steps keep the secret gated -- there it is the previous step's reward."""
    gen = {
        'id': 'gated', 'name': 'Gated', '_source_name': 'test',
        'access_instructions': _CRED_ACCESS,
        'hint_levels': {'low': ['Inspect the export.'],
                        'medium': ['Credential artifact: {{OUTPUT.Credential(user,password)}}']},
        'inputs': [], 'outputs': [{'name': 'Flag(flag_id)'}],
    }
    preview = {'seed': 0, 'hosts': [
        {'node_id': 'h1', 'name': 'v1', 'role': 'Docker', 'vulnerabilities': [{'name': 'zz/CVE-0'}]},
        {'node_id': 'h2', 'name': 'v2', 'role': 'Docker', 'vulnerabilities': [{'name': 'zz/CVE-0'}]},
    ]}
    _install_generators(monkeypatch, [gen], {'gated': {'plugin_id': 'gated', 'requires': [],
                                                       'produces': [{'artifact': 'Flag(flag_id)'}]}})
    _install_metadata(monkeypatch, [{'match': 'zz/CVE-0', 'impact': 'remote_code_execution'}])
    chain = [{'id': 'h1', 'name': 'v1', 'type': 'docker', 'is_vuln': True},
             {'id': 'h2', 'name': 'v2', 'type': 'docker', 'is_vuln': True}]
    out = app_backend._flow_compute_flag_assignments(preview, chain, f'zz-promote-{uuid.uuid4().hex[:8]}')
    assert len(out) == 2
    assert out[0].get('promoted_first_step_hints'), 'first step should disclose the credential'
    assert not out[1].get('promoted_first_step_hints'), 'later steps must stay gated'
