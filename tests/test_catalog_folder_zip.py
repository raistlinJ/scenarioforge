"""Exercise browser ZIP output with an independent ZIP reader."""
import base64
import io
from pathlib import Path
import zipfile

import pytest


@pytest.mark.parametrize("retry", [False, True])
def test_folder_zip_webkit(retry):
    playwright = pytest.importorskip('playwright.sync_api')
    with playwright.sync_playwright() as p:
        try:
            browser = p.webkit.launch()
        except playwright.Error as exc:
            pytest.skip(f'WebKit unavailable: {exc}')
        try:
            page = browser.new_page()
            page.add_script_tag(path=str(Path(__file__).resolve().parents[1] / 'webapp/static/catalog_upload.js'))
            encoded = page.evaluate('''async (retry) => {
                const files = Array.from({length: 9703}, (_, i) => {
                    const file = new File([`recipe ${i}`], 'file');
                    Object.defineProperty(file, 'webkitRelativePath', {value: i === 0
                        ? 'vulnhub/.scenarioforge/catalog_items.json'
                        : `vulnhub/content/é${i}/docker-compose.yml`});
                    return file;
                });
                if (retry) files[0].arrayBuffer = async () => { throw new Error('I/O operation failed'); };
                let progress = null;
                const zip = await catalogFolderZip(files, item => { progress = item; });
                if (progress.current !== 9703 || progress.total !== 9703) throw Error('Missing progress');
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
            }''', retry)
            with zipfile.ZipFile(io.BytesIO(base64.b64decode(encoded))) as archive:
                assert len(archive.namelist()) == 9703
                assert archive.testzip() is None
                assert archive.read('vulnhub/.scenarioforge/catalog_items.json') == b'recipe 0'
                assert archive.read('vulnhub/content/é9702/docker-compose.yml') == b'recipe 9702'
            error = page.evaluate("""async () => {
                const original = globalThis.FileReader;
                globalThis.FileReader = class {
                    readAsArrayBuffer() { this.error = new Error('I/O operation failed'); this.onerror(); }
                };
                try {
                    await catalogFolderZip([{size: 1, webkitRelativePath: 'vulnhub/broken.txt',
                        arrayBuffer: async () => { throw Error('I/O operation failed'); }}]);
                    return 'unexpected success';
                } catch (error) { return error.message; }
                finally { globalThis.FileReader = original; }
            }""")
            assert 'file 1 of 1: vulnhub/broken.txt' in error
            assert 'I/O operation failed' in error
        finally:
            browser.close()
