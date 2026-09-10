"""Guest catalog packaging must exclude macOS metadata, including binary ._*.py."""
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/provision/proxmox/install-scenarioforge-lab.sh'


@pytest.mark.parametrize('marker', ['GENERATOR_ZIP', 'VULNHUB_ZIP'])
def test_catalog_zip_excludes_appledouble_and_keeps_source(tmp_path, marker):
    root = tmp_path / 'payload'
    catalog = root / 'flag_generators' if marker == 'GENERATOR_ZIP' else root
    catalog.mkdir(parents=True)
    (catalog / 'generate.py').write_text('print("valid")\n')
    (catalog / '._generate.py').write_bytes(b'\x00\x05AppleDouble\x00')
    (catalog / '.DS_Store').write_bytes(b'\x00metadata')
    nested = catalog / '__MACOSX'
    nested.mkdir()
    (nested / 'hidden.py').write_bytes(b'\x00')
    if marker == 'GENERATOR_ZIP':
        (root / 'flag_node_generators').mkdir()
        (root / 'pack.json').write_text('{}')
    text = SOURCE.read_text()
    script = text.split("<<'" + marker + "'\n", 1)[1].split('\n' + marker, 1)[0]
    output = tmp_path / 'catalog.zip'
    subprocess.run([sys.executable, '-', str(root), str(output)], input=script, text=True, check=True)
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        assert any(name.endswith('generate.py') for name in names)
        assert not any('._' in name or '__MACOSX' in name or '.DS_Store' in name for name in names)
        if marker == 'GENERATOR_ZIP':
            assert 'pack.json' in names
