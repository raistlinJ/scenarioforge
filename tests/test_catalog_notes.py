from webapp import app_backend


def _login(client):
    response = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert response.status_code in (200, 302)


def test_generator_notes_are_persisted_with_a_validated_color(monkeypatch, tmp_path):
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))
    state = {
        'packs': [{
            'id': 'pack-1',
            'installed': [{
                'id': 'demo-generator',
                'kind': 'flag-generator',
            }],
        }],
    }
    app_backend._save_installed_generator_packs_state(state)
    _packs_before, generators_before = app_backend._build_installed_disable_maps()
    assert generators_before[('flag-generator', 'demo-generator')]['note'] is None

    ok, message = app_backend._set_generator_note_state(
        kind='flag-generator',
        generator_id='demo-generator',
        note='check login flow',
        note_color='green',
    )

    assert ok is True
    assert 'Saved note' in message
    saved = app_backend._load_installed_generator_packs_state()
    item = saved['packs'][0]['installed'][0]
    assert item['note'] == 'check login flow'
    assert item['note_color'] == 'green'
    assert saved['catalog_notes']['flag-generator:demo-generator'] == {
        'note': 'check login flow',
        'note_color': 'green',
    }
    _packs_after, generators_after = app_backend._build_installed_disable_maps()
    assert generators_after[('flag-generator', 'demo-generator')]['note'] == 'check login flow'
    assert generators_after[('flag-generator', 'demo-generator')]['note_color'] == 'green'

    ok, message = app_backend._set_generator_note_state(
        kind='flag-generator',
        generator_id='demo-generator',
        note='bad',
        note_color='blue',
    )
    assert ok is False
    assert 'red, yellow, or green' in message


def test_generator_notes_can_be_saved_for_a_visible_catalog_id_without_a_pack_state_item(monkeypatch, tmp_path):
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))
    app_backend._save_installed_generator_packs_state({'packs': []})

    ok, message = app_backend._set_generator_note_state(
        kind='flag-node-generator',
        generator_id='manifest-id-not-yet-indexed-in-pack-state',
        note='use the green deployment path',
        note_color='green',
    )

    assert ok is True
    assert 'Saved note' in message
    saved = app_backend._load_installed_generator_packs_state()
    assert saved['catalog_notes']['flag-node-generator:manifest-id-not-yet-indexed-in-pack-state'] == {
        'note': 'use the green deployment path',
        'note_color': 'green',
    }
    _packs, generators = app_backend._build_installed_disable_maps()
    assert generators[('flag-node-generator', 'manifest-id-not-yet-indexed-in-pack-state')]['note'] == 'use the green deployment path'
    assert generators[('flag-node-generator', 'manifest-id-not-yet-indexed-in-pack-state')]['note_color'] == 'green'


def test_generator_color_marker_can_be_saved_without_note_text(monkeypatch, tmp_path):
    install_root = tmp_path / 'installed_generators'
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(install_root))
    app_backend._save_installed_generator_packs_state({'packs': []})

    ok, _message = app_backend._set_generator_note_state(
        kind='flag-generator',
        generator_id='color-only-generator',
        note='',
        note_color='red',
    )

    assert ok is True
    saved = app_backend._load_installed_generator_packs_state()
    assert saved['catalog_notes']['flag-generator:color-only-generator'] == {
        'note': '',
        'note_color': 'red',
    }
    _packs, generators = app_backend._build_installed_disable_maps()
    assert generators[('flag-generator', 'color-only-generator')]['note'] is None
    assert generators[('flag-generator', 'color-only-generator')]['note_color'] == 'red'


def test_vulnerability_note_endpoint_persists_note_and_color(monkeypatch):
    state = {
        'active_id': 'catalog-1',
        'catalogs': [{
            'id': 'catalog-1',
            'compose_items': [{'id': 7, 'name': 'demo', 'compose_rel': 'demo/docker-compose.yml'}],
        }],
    }
    monkeypatch.setattr(app_backend, '_require_builder_or_admin', lambda: None)
    monkeypatch.setattr(app_backend, '_load_vuln_catalogs_state', lambda: state)
    monkeypatch.setattr(app_backend, '_write_vuln_catalogs_state', lambda saved: state.update(saved))
    monkeypatch.setattr(app_backend, '_get_active_vuln_catalog_entry', lambda loaded: loaded['catalogs'][0])

    client = app_backend.app.test_client()
    _login(client)
    response = client.post(
        '/vuln_catalog_items/set_note',
        json={'item_id': 7, 'note': 'needs a stable image', 'note_color': 'yellow'},
    )

    assert response.status_code == 200
    assert (response.get_json() or {}).get('ok') is True
    item = state['catalogs'][0]['compose_items'][0]
    assert item['note'] == 'needs a stable image'
    assert item['note_color'] == 'yellow'

    response = client.post(
        '/vuln_catalog_items/set_note',
        json={'item_id': 7, 'note': '', 'note_color': 'green'},
    )

    assert response.status_code == 200
    assert (response.get_json() or {}).get('ok') is True
    updated_item = state['catalogs'][0]['compose_items'][0]
    assert updated_item['note'] == ''
    assert updated_item['note_color'] == 'green'
