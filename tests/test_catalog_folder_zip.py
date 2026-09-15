"""Exercise browser ZIP output with an independent ZIP reader."""
import base64
import io
from pathlib import Path
import zipfile

import pytest


def test_folder_zip_webkit():
    playwright = pytest.importorskip('playwright.sync_api')
    with playwright.sync_playwright() as p:
        try:
            browser = p.webkit.launch()
        except playwright.Error as exc:
            pytest.skip(f'WebKit unavailable: {exc}')
        try:
            page = browser.new_page()
            page.add_script_tag(path=str(Path(__file__).resolve().parents[1] / 'webapp/static/catalog_upload.js'))
            encoded = page.evaluate('''async () => {
                const files = Array.from({length: 9703}, (_, i) => {
                    const file = new File([`recipe ${i}`], 'file');
                    Object.defineProperty(file, 'webkitRelativePath', {value: i === 0
                        ? 'vulnhub/.scenarioforge/catalog_items.json'
                        : `vulnhub/content/é${i}/docker-compose.yml`});
                    return file;
                });
                const zip = await catalogFolderZip(files);
                const form = new FormData();
                form.append('zip_file', zip, 'catalog.zip');
                const request = new Request('https://example.test/upload', {method: 'POST', body: form});
                if ((await request.arrayBuffer()).byteLength < zip.size) throw Error('Empty multipart body');
                return await new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    reader.onload = () => resolve(reader.result.split(',')[1]);
                    reader.onerror = reject;
                    reader.readAsDataURL(zip);
                });
            }''')
            with zipfile.ZipFile(io.BytesIO(base64.b64decode(encoded))) as archive:
                assert len(archive.namelist()) == 9703
                assert archive.testzip() is None
                assert archive.read('vulnhub/.scenarioforge/catalog_items.json') == b'recipe 0'
                assert archive.read('vulnhub/content/é9702/docker-compose.yml') == b'recipe 9702'
        finally:
            browser.close()
