"""A note about a generator belongs with the generator, not with one install.

Notes were only ever carried inside a pack exported from a running instance, so
a lesson recorded in the UI was lost the moment that generator was reinstalled
from the repo it is authored in -- exactly when it is most needed, since the
reinstall is what discards the workaround the note is warning about.

Reading `note`/`note_color` from the manifest lets the note live in the source
repo and reach every install, while a pack that carries its own note still wins.
"""

from webapp import app_backend as ab


def _manifest(tmp_path, **extra):
    import yaml

    gen = tmp_path / 'flag_node_generators' / 'http' / 'demo'
    gen.mkdir(parents=True)
    doc = {
        'manifest_version': 1,
        'id': 'demo_generator',
        'kind': 'flag-node-generator',
        'name': 'Demo',
        'runtime': {'type': 'docker-compose', 'compose_file': 'docker-compose.yml', 'service': 'generator'},
    }
    doc.update(extra)
    (gen / 'manifest.yaml').write_text(yaml.safe_dump(doc), encoding='utf-8')
    (gen / 'docker-compose.yml').write_text('services:\n  generator:\n    image: alpine:3.19\n', encoding='utf-8')
    return gen


def _item_for(tmp_path, **extra):
    _manifest(tmp_path, **extra)
    ok, note, items, _warnings = ab._validate_generator_pack_tree(str(tmp_path))
    assert ok, note
    assert items, 'generator was not discovered'
    return items[0]


def test_manifest_note_is_carried_off_the_manifest(tmp_path):
    item = _item_for(tmp_path, note='wedges on first boot', note_color='red')

    assert item['manifest_note'] == 'wedges on first boot'
    assert item['manifest_note_color'] == 'red'


def test_manifest_without_a_note_carries_none(tmp_path):
    item = _item_for(tmp_path)

    assert item['manifest_note'] == ''
    assert item['manifest_note_color'] is None


def test_an_unknown_note_color_is_rejected(tmp_path):
    """The UI renders three colors; anything else would silently not show."""
    _manifest(tmp_path, note='x', note_color='purple')

    ok, note, _items, _warnings = ab._validate_generator_pack_tree(str(tmp_path))

    assert not ok
    assert 'note_color' in note
