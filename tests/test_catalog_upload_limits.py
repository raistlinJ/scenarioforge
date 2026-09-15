import io

import pytest
from flask import Flask, request
from werkzeug.datastructures import MultiDict

from webapp.catalog_upload_limits import configure_catalog_uploads


@pytest.mark.parametrize('endpoint', ['generator_packs_upload', 'vuln_catalog_packs_upload'])
def test_catalog_upload_exceeds_configured_limits(endpoint):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=100, MAX_FORM_PARTS=2, MAX_FORM_MEMORY_SIZE=10)
    configure_catalog_uploads(app)
    configure_catalog_uploads(app)

    def upload():
        return {'files': len(request.files.getlist('repo_files')),
                'paths': len(request.form.getlist('repo_paths'))}

    app.add_url_rule('/upload', endpoint=endpoint, view_func=upload, methods=['POST'])
    app.add_url_rule('/ordinary', endpoint='ordinary', view_func=upload, methods=['POST'])
    parts = MultiDict()
    for i in range(10001):
        parts.add('repo_files', (io.BytesIO(b'content'), f'{i}.txt'))
        parts.add('repo_paths', f'catalog/{i}.txt')
    response = app.test_client().post('/upload', data=parts)
    assert response.status_code == 200
    assert response.json == {'files': 10001, 'paths': 10001}
    response = app.test_client().post('/ordinary', data={'field': 'x' * 200})
    assert response.status_code == 413
