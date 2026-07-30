"""Threading required fact values from a producer into a downstream consumer.

A dependency-consumer generator reads its upstream artifact out of the run
config by fact name, e.g. ``cfg["SSHPrivateKey(path)"]``. Two gaps used to stop
that value from arriving, both surfacing at run time as
``[validation error] SSHPrivateKey(path) is required``:

1. The value was only threaded when the fact was declared under ``inputs``. A
   manifest that listed it solely under ``artifacts.requires`` got nothing.
2. When Flow had fabricated a branch-start placeholder for the fact, the
   placeholder occupied the key and blocked the real upstream value, so the
   consumer received a made-up path that did not match what the producer built.
"""

from __future__ import annotations

from typing import Any

from webapp.flow_prepare_preview_helpers import build_generator_run_config

UPSTREAM_KEY_PATH = 'keys/id_ed25519'
PLACEHOLDER = 'key_5212b7e6f42b79f8'


class _BackendStub:
    @staticmethod
    def _flow_synthesized_inputs() -> set[str]:
        return {
            'seed', 'seed_ts', 'secret', 'flag_prefix', 'flag_seed',
            'node_name', 'Knowledge(ip)', 'target_ip', 'host_ip', 'ip4', 'ipv4',
        }


class _TimeStub:
    @staticmethod
    def time() -> float:
        return 1_700_000_000.0


def _build(manifest: dict[str, Any], assignment: dict[str, Any], flow_context: dict[str, Any]):
    _cfg_full, cfg, inputs_mismatch, _gen_def = build_generator_run_config(
        assignment,
        {'name': 'docker-9'},
        preview={},
        preview_ip4='10.0.0.9',
        flow_context=flow_context,
        gen_by_id={str(manifest.get('id')): manifest},
        flow_default_generator_config=lambda _a: {
            'seed': 'seed-value', 'secret': 'secret-value', 'flag_prefix': 'FLAG',
        },
        backend=_BackendStub(),
        time_module=_TimeStub(),
    )
    return cfg, inputs_mismatch


def _bastion_manifest(*, declare_input: bool) -> dict[str, Any]:
    inputs: list[dict[str, Any]] = [{'name': 'seed', 'required': False}]
    if declare_input:
        inputs.append({'name': 'SSHPrivateKey(path)', 'required': True, 'type': 'file'})
    return {'id': 'dep_ssh_key_bastion', 'inputs': inputs, 'requires': ['SSHPrivateKey(path)']}


def test_required_fact_threads_even_when_not_declared_as_an_input() -> None:
    """The reported failure: declared only under artifacts.requires."""
    cfg, _ = _build(
        _bastion_manifest(declare_input=False),
        {'id': 'dep_ssh_key_bastion', 'requires': ['SSHPrivateKey(path)']},
        {'SSHPrivateKey(path)': UPSTREAM_KEY_PATH},
    )
    assert cfg.get('SSHPrivateKey(path)') == UPSTREAM_KEY_PATH


def test_threaded_required_fact_survives_the_input_name_filter() -> None:
    """cfg is filtered to known input names; an undeclared fact must not be dropped."""
    cfg, mismatch = _build(
        _bastion_manifest(declare_input=False),
        {'id': 'dep_ssh_key_bastion', 'requires': ['SSHPrivateKey(path)']},
        {'SSHPrivateKey(path)': UPSTREAM_KEY_PATH},
    )
    assert 'SSHPrivateKey(path)' in cfg
    assert 'SSHPrivateKey(path)' not in (mismatch.get('dropped') or [])


def test_real_upstream_value_supersedes_a_synthesized_placeholder() -> None:
    """A producer ran, so the consumer must get its path -- not Flow's stand-in."""
    assignment = {
        'id': 'dep_ssh_key_bastion',
        'requires': ['SSHPrivateKey(path)'],
        'chain_supplied_input_values': {'SSHPrivateKey(path)': PLACEHOLDER},
        'config_overrides': {'SSHPrivateKey(path)': PLACEHOLDER},
    }
    cfg, _ = _build(
        _bastion_manifest(declare_input=True), assignment, {'SSHPrivateKey(path)': UPSTREAM_KEY_PATH}
    )
    assert cfg.get('SSHPrivateKey(path)') == UPSTREAM_KEY_PATH


def test_placeholder_is_kept_when_nothing_upstream_produced_the_fact() -> None:
    """At a genuine branch start there is no producer, so the stand-in must stay."""
    assignment = {
        'id': 'dep_ssh_key_bastion',
        'requires': ['SSHPrivateKey(path)'],
        'chain_supplied_input_values': {'SSHPrivateKey(path)': PLACEHOLDER},
        'config_overrides': {'SSHPrivateKey(path)': PLACEHOLDER},
    }
    cfg, _ = _build(_bastion_manifest(declare_input=True), assignment, {})
    assert cfg.get('SSHPrivateKey(path)') == PLACEHOLDER


def test_optional_facts_are_still_not_autothreaded() -> None:
    """Threading an optional upstream artifact would change generator behaviour."""
    manifest = {
        'id': 'opt',
        'inputs': [{'name': 'File(path)', 'required': False}, {'name': 'seed', 'required': False}],
        'requires': [],
    }
    cfg, _ = _build(manifest, {'id': 'opt', 'requires': []}, {'File(path)': '/tmp/upstream.json'})
    assert 'File(path)' not in cfg


def test_unrelated_context_facts_are_not_threaded() -> None:
    """Only facts this generator requires may enter its config."""
    cfg, _ = _build(
        _bastion_manifest(declare_input=True),
        {'id': 'dep_ssh_key_bastion', 'requires': ['SSHPrivateKey(path)']},
        {'SSHPrivateKey(path)': UPSTREAM_KEY_PATH, 'Token(service)': 'tok_abc'},
    )
    assert cfg.get('SSHPrivateKey(path)') == UPSTREAM_KEY_PATH
    assert 'Token(service)' not in cfg


class _ContractBackendStub(_BackendStub):
    """Backend whose plugin contracts are the only place `requires` appears."""

    @staticmethod
    def _flow_enabled_plugin_contracts_by_id() -> dict[str, Any]:
        return {'dep_ssh_key_bastion': {
            'plugin_id': 'dep_ssh_key_bastion',
            'requires': ['Knowledge(ip)', 'SSHPrivateKey(path)'],
        }}


def test_requirement_is_found_via_the_plugin_contract(monkeypatch) -> None:
    """A manifest-built gen_def has no `requires` key; a saved assignment may not either.

    `artifacts.requires` lives on the plugin contract, so without consulting it
    the fact is invisible to threading and the generator starts with nothing.
    """
    manifest = {'id': 'dep_ssh_key_bastion', 'inputs': [{'name': 'seed', 'required': False}]}
    assert 'requires' not in manifest, 'fixture must mirror a real manifest-built def'

    _cfg_full, cfg, _mismatch, _gen = build_generator_run_config(
        {'id': 'dep_ssh_key_bastion'},          # saved FlowState style: no 'requires'
        {'name': 'docker-4'},
        preview={},
        preview_ip4='10.0.0.4',
        flow_context={'SSHPrivateKey(path)': UPSTREAM_KEY_PATH},
        gen_by_id={'dep_ssh_key_bastion': manifest},
        flow_default_generator_config=lambda _a: {
            'seed': 'seed-value', 'secret': 'secret-value', 'flag_prefix': 'FLAG',
        },
        backend=_ContractBackendStub(),
        time_module=_TimeStub(),
    )
    assert cfg.get('SSHPrivateKey(path)') == UPSTREAM_KEY_PATH
