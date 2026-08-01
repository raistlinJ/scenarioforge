"""Installed-pack state must survive being synced to another host.

`_packs_state.json` records each item's `path` as an absolute path on the
authoring machine, so on the CORE VM none of them exist. The marker alias ids
were then lost and the state keyed only by the numeric item id, which let one
generator's disabled flag suppress a *different* generator that happened to
share that number:

    remote generator failed (rc=1): Generator not found at requested source:
    126 (.../flag_generators/p_07-01-26-15-10-01-516b21__110)

Locally the state built 265 keys; on the VM the same file built 147.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from scenarioforge.generator_manifests import (
    _load_installed_generator_state,
    _reroot_installed_item_path,
)

FOREIGN_ROOT = '/Users/someone/checkout/outputs/installed_generators'


@pytest.fixture
def installed_root(tmp_path):
    """A minimal installed tree: two packs whose markers carry alias ids."""
    root = tmp_path / 'outputs' / 'installed_generators'
    for kind, pack, gen_id in (
        ('flag_generators', 'p_aaa__110', '110'),
        ('flag_generators', 'p_bbb__126', 'binary_embed_text'),
    ):
        directory = root / kind / pack
        directory.mkdir(parents=True)
        (directory / '.coretg_pack.json').write_text(
            json.dumps({'generator_id': gen_id, 'kind': 'flag-generator'}), encoding='utf-8'
        )
    return root


def _write_state(root, *, item_path_for):
    """State where item '126' is the disabled one, as in the real file."""
    state = {
        'packs': [
            {
                'id': 'pack-a',
                'label': 'A',
                'installed': [
                    {'id': '110', 'kind': 'flag-generator',
                     'path': item_path_for('flag_generators', 'p_aaa__110')},
                    {'id': '126', 'kind': 'flag-generator', 'disabled': True,
                     'path': item_path_for('flag_generators', 'p_bbb__126')},
                ],
            }
        ]
    }
    (root / '_packs_state.json').write_text(json.dumps(state), encoding='utf-8')


def test_reroot_finds_the_pack_under_the_local_root(installed_root):
    foreign = pathlib.Path(FOREIGN_ROOT) / 'flag_generators' / 'p_aaa__110'
    assert _reroot_installed_item_path(foreign, installed_root) == (
        installed_root / 'flag_generators' / 'p_aaa__110'
    )


def test_reroot_leaves_an_unmatched_path_alone(installed_root):
    foreign = pathlib.Path(FOREIGN_ROOT) / 'flag_generators' / 'p_missing__999'
    assert _reroot_installed_item_path(foreign, installed_root) == foreign


def test_foreign_paths_produce_the_same_state_as_local_paths(installed_root):
    _write_state(installed_root, item_path_for=lambda k, p: str(installed_root / k / p))
    local = _load_installed_generator_state(installed_root)

    _write_state(installed_root, item_path_for=lambda k, p: f'{FOREIGN_ROOT}/{k}/{p}')
    foreign = _load_installed_generator_state(installed_root)

    assert set(foreign) == set(local), 'a synced state file must key identically'


def test_marker_alias_ids_survive_foreign_paths(installed_root):
    _write_state(installed_root, item_path_for=lambda k, p: f'{FOREIGN_ROOT}/{k}/{p}')
    state = _load_installed_generator_state(installed_root)

    assert ('flag-generator', 'binary_embed_text') in state, 'alias id was lost'


def test_a_disabled_generator_does_not_suppress_one_sharing_its_number(installed_root):
    """The reported failure: '126' disabled by an unrelated generator."""
    _write_state(installed_root, item_path_for=lambda k, p: f'{FOREIGN_ROOT}/{k}/{p}')
    state = _load_installed_generator_state(installed_root)

    assert state[('flag-generator', 'binary_embed_text')]['disabled'] is True
    assert state[('flag-generator', '110')]['disabled'] is False


def test_relative_paths_are_still_resolved(installed_root):
    _write_state(installed_root, item_path_for=lambda k, p: f'{k}/{p}')
    state = _load_installed_generator_state(installed_root)
    assert ('flag-generator', 'binary_embed_text') in state


def test_missing_state_file_is_not_fatal(tmp_path):
    assert _load_installed_generator_state(tmp_path / 'nope') == {}
