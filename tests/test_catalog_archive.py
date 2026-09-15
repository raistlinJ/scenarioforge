import io
import zipfile

import pytest

from webapp.catalog_archive import read_archive_metadata


@pytest.mark.parametrize('metadata', ['pack.json', '.scenarioforge/catalog_notes.json'])
@pytest.mark.parametrize('prefix', ['', 'repository/', 'download/repository/'])
def test_metadata_location(metadata, prefix):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr(prefix + metadata, '{"note":"preserved"}')
    with zipfile.ZipFile(data) as archive:
        assert read_archive_metadata(archive, metadata) == ('{"note":"preserved"}', prefix)


@pytest.mark.parametrize('metadata', ['pack.json', '.scenarioforge/catalog_notes.json'])
def test_metadata_precedence_and_ambiguity(metadata):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr('a/' + metadata, '{}')
        archive.writestr('b/' + metadata, '{}')
    with zipfile.ZipFile(data) as archive:
        with pytest.raises(ValueError, match='Ambiguous'):
            read_archive_metadata(archive, metadata)
    with zipfile.ZipFile(data, 'a') as archive:
        archive.writestr(metadata, '{"root":true}')
    with zipfile.ZipFile(data) as archive:
        assert read_archive_metadata(archive, metadata) == ('{"root":true}', '')


def test_missing_metadata_is_optional():
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w'):
        pass
    with zipfile.ZipFile(data) as archive:
        with pytest.raises(KeyError):
            read_archive_metadata(archive, 'pack.json')
