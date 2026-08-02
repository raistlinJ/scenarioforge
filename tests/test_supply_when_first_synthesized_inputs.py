"""A synthesized input must not suppress a flow_supply_when_first value.

Flow writes Knowledge(ip), node_name, seed and friends into every generator
config, but no step ever *produces* them, so they never appear in the solver's
fact state. Counting them as unmet requirements made the supply gate false for
any generator declaring one alongside a supply-when-first input: the generator
was placed -- eligibility knows the value is always there -- and then ran without
the supplied value:

    [inputs] required and not supplied: ['Checksum(sha256)']

The two checks have to agree on what "available" means.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

from webapp import app_backend as backend

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _gate(required, supplied, produced, *, use_synthesized=True):
    """The gate exactly as _flow_compute_flag_assignments computes it."""
    available = set(produced)
    unresolved = set(supplied) - available
    required_for_start = set(required) - available - set(supplied)
    if use_synthesized:
        required_for_start -= backend._flow_synthesized_inputs()
    return bool(not required_for_start) and bool(unresolved)


REQUIRED = {'Knowledge(ip)', 'Checksum(sha256)'}
SUPPLIED = {'Checksum(sha256)'}
PRODUCED = {'Credential(user, password)', 'Endpoint(path)'}


def test_knowledge_ip_is_synthesized():
    assert 'Knowledge(ip)' in backend._flow_synthesized_inputs()


def test_a_synthesized_requirement_no_longer_suppresses_supply():
    """The observed failure: placed, then run without its required input."""
    assert _gate(REQUIRED, SUPPLIED, PRODUCED, use_synthesized=False) is False
    assert _gate(REQUIRED, SUPPLIED, PRODUCED) is True


def test_an_upstream_produced_secret_is_still_not_fabricated():
    """A consumer receives the real value through flow_context.

    Fabricating one here would hand over a credential the chain never uses, and
    give away what an earlier challenge was meant to earn.
    """
    assert _gate(REQUIRED, SUPPLIED, PRODUCED | {'Checksum(sha256)'}) is False


def test_a_genuinely_unmet_requirement_still_blocks_supply():
    assert _gate(REQUIRED | {'SSHPrivateKey(path)'}, SUPPLIED, PRODUCED) is False


def test_the_gate_subtracts_synthesized_inputs():
    source = (REPO_ROOT / 'webapp' / 'app_backend.py').read_text(encoding='utf-8', errors='ignore')
    marker = 'unresolved_supplied = supplied_names_for_start - available_now'
    assert marker in source, 'supply gate moved'
    gate = source[source.index(marker):source.index(marker) + 1200]
    assert '_flow_synthesized_inputs()' in gate, (
        'a synthesized input counted as unmet suppresses the supply it gates'
    )


def test_the_real_manifest_gets_its_supplied_value():
    """End to end on the generator that failed in the field."""
    gen_dir = (
        REPO_ROOT / 'outputs' / 'installed_generators' / 'flag_node_generators'
        / 'p_07-01-26-15-10-01-6de4d6__53'
    )
    if not (gen_dir / 'manifest.yaml').is_file():
        pytest.skip('dep_checksum_evidence_gate not installed')
    manifest = yaml.safe_load((gen_dir / 'manifest.yaml').read_text(encoding='utf-8'))
    gen = {'id': '53', 'inputs': manifest.get('inputs'), 'artifacts': manifest.get('artifacts')}

    assert backend._flow_first_step_chain_supplied_input_names(gen) == ['Checksum(sha256)']

    assignment = backend._flow_apply_first_step_chain_supplied_inputs(
        {'id': '53', 'node_id': '16', 'type': 'flag-node-generator'},
        gen,
        scenario_label='Scenario2',
        position=5,
        supply_on_start=True,
    )
    overrides = assignment.get('config_overrides') or {}
    assert 'Checksum(sha256)' in overrides
    assert str(overrides['Checksum(sha256)']).strip()
