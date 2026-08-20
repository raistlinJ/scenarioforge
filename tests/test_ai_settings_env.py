import json
from types import SimpleNamespace

import scenarioforge.cli as cli
from webapp import ai_settings


def test_env_settings_are_parsed_and_blank_keys_skipped():
    env = {
        'CORETG_AI_PROVIDER': 'litellm',
        'CORETG_AI_MODEL': 'gpt-4.1',
        'CORETG_AI_BASE_URL': 'https://llm.example/v1',
        'CORETG_AI_MODEL_UNUSED': 'ignored',
        'CORETG_AI_TIMEOUT_S': '90.5',
        'CORETG_AI_VERIFY_SSL': 'false',
        'CORETG_AI_API_KEY': '   ',
    }

    settings = ai_settings.ai_settings_from_env(env)

    assert settings['provider'] == 'litellm'
    assert settings['model'] == 'gpt-4.1'
    assert settings['timeout_seconds'] == 90.5
    assert settings['verify_ssl'] is False
    # A blank value is the same as unset, so it must not mask a stored credential.
    assert 'api_key' not in settings


def test_overrides_beat_env_and_stored_credential_only_fills_a_missing_key():
    env = {
        'CORETG_AI_PROVIDER': 'litellm',
        'CORETG_AI_MODEL': 'env-model',
        'CORETG_AI_BASE_URL': 'https://env.example/v1',
        'CORETG_AI_API_KEY_USER': 'coreadmin',
    }
    calls = []

    def loader(username, provider):
        calls.append((username, provider))
        return 'stored-key'

    resolved = ai_settings.resolve_ai_settings(
        {'model': 'flag-model', 'base_url': None},
        environ=env,
        stored_api_key_loader=loader,
    )

    assert resolved['model'] == 'flag-model'
    assert resolved['base_url'] == 'https://env.example/v1'
    assert resolved['api_key'] == 'stored-key'
    assert resolved['api_key_source'] == 'stored_credential'
    assert calls == [('coreadmin', 'litellm')]

    explicit = ai_settings.resolve_ai_settings(
        {'api_key': 'flag-key'},
        environ=env,
        stored_api_key_loader=loader,
    )
    assert explicit['api_key'] == 'flag-key'
    assert explicit['api_key_source'] == 'environment'
    assert calls == [('coreadmin', 'litellm')]


def test_missing_settings_are_reported_as_env_key_names():
    assert ai_settings.missing_ai_settings({'provider': 'litellm'}) == [
        'CORETG_AI_MODEL',
        'CORETG_AI_BASE_URL',
    ]
    assert ai_settings.missing_ai_settings(
        {'provider': 'litellm', 'model': 'm', 'base_url': 'u'}
    ) == []


def test_redaction_never_echoes_the_key_and_payload_shape_is_endpoint_ready():
    settings = {
        'provider': 'litellm',
        'model': 'm',
        'base_url': 'https://llm.example/v1',
        'api_key': 'super-secret-value',
        'timeout_seconds': 30.0,
        'verify_ssl': False,
        'credential_username': 'coreadmin',
    }

    safe = ai_settings.redact_ai_settings(settings)
    assert 'super-secret-value' not in json.dumps(safe)
    assert safe['api_key'] == '<set len=18>'

    payload = ai_settings.ai_settings_as_payload(settings)
    assert payload['provider'] == 'litellm'
    assert payload['api_key'] == 'super-secret-value'
    assert payload['timeout_seconds'] == 30.0
    assert payload['verify_ssl'] is False
    # Not an endpoint field.
    assert 'credential_username' not in payload


def _ai_args(tmp_path, **overrides):
    args = SimpleNamespace(
        xml=str(tmp_path / 'generated.xml'),
        prompt='3 routers and 2 docker hosts',
        scenario='',
        seed=7,
        plan_output=None,
        force=False,
        ai_provider=None,
        ai_model=None,
        ai_base_url=None,
        ai_api_key=None,
        ai_credential_user=None,
        ai_bridge_mode=None,
        ai_timeout_seconds=None,
        ai_skip_bridge=False,
        ai_preview_only=False,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def get_json(self, silent=False):
        return self._payload


class _FakeSessionTransaction:
    def __init__(self, store):
        self._store = store

    def __enter__(self):
        return self._store

    def __exit__(self, *_exc):
        return False


class _FakeClient:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self._status_code = status_code
        self.requests = []
        self.session = {}

    def session_transaction(self):
        return _FakeSessionTransaction(self.session)

    def post(self, path, json=None):
        self.requests.append((path, json))
        return _FakeResponse(self._payload, self._status_code)


def _fake_backend(client, written):
    app = SimpleNamespace(config={}, test_client=lambda: client)

    def _write(payload, xml_path):
        written.append((payload, xml_path))
        with open(xml_path, 'w', encoding='utf-8') as handle:
            handle.write('<Scenarios/>')

    return SimpleNamespace(
        app=app,
        _load_users=lambda: {'users': [{'username': 'coreadmin', 'role': 'admin'}]},
        _normalize_role_value=lambda role: str(role or ''),
        _default_scenarios_payload_for_names=lambda names: {
            'scenarios': [{'name': names[0], 'sections': {}}],
            'core': {},
        },
        _concretize_scenarios_for_save=lambda scenarios, seed=None: scenarios,
        _build_scenarios_xml=lambda payload: None,
        _load_ai_provider_credentials_for_user=lambda username, provider: {'api_key_plain': 'stored-key'},
        _write=_write,
    )


def _install_env(monkeypatch, **extra):
    monkeypatch.setenv('CORETG_AI_PROVIDER', 'litellm')
    monkeypatch.setenv('CORETG_AI_MODEL', 'env-model')
    monkeypatch.setenv('CORETG_AI_BASE_URL', 'https://env.example/v1')
    monkeypatch.setenv('CORETG_AI_API_KEY_USER', 'coreadmin')
    for key, value in extra.items():
        monkeypatch.setenv(key, value)


def test_ai_phase_uses_env_settings_and_writes_xml(tmp_path, monkeypatch, capsys):
    _install_env(monkeypatch)
    client = _FakeClient({
        'success': True,
        'generated_scenario': {'name': 'Generated', 'sections': {'Routing': {'items': []}}},
        'applied_actions': ['Routing=1'],
    })
    written: list = []
    backend = _fake_backend(client, written)
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(cli, '_write_scenarios_payload_xml', lambda b, payload, xml_path: backend._write(payload, xml_path))

    rc = cli._run_ai_phase(_ai_args(tmp_path))

    assert rc == 0
    path, sent = client.requests[0]
    assert path == '/api/ai/generate_scenario_preview'
    assert sent['provider'] == 'litellm'
    assert sent['model'] == 'env-model'
    assert sent['base_url'] == 'https://env.example/v1'
    assert sent['api_key'] == 'stored-key'
    assert sent['prompt'] == '3 routers and 2 docker hosts'
    assert written and written[0][1] == str(tmp_path / 'generated.xml')

    emitted = json.loads(capsys.readouterr().out)
    assert emitted['ok'] is True
    assert emitted['written'] is True
    assert emitted['settings']['api_key'] == '<set len=10>'
    assert 'stored-key' not in json.dumps(emitted)


def test_ai_phase_flags_override_env(tmp_path, monkeypatch, capsys):
    _install_env(monkeypatch)
    client = _FakeClient({'success': True, 'generated_scenario': {'name': 'Generated'}})
    backend = _fake_backend(client, [])
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(cli, '_write_scenarios_payload_xml', lambda b, payload, xml_path: None)

    rc = cli._run_ai_phase(_ai_args(tmp_path, ai_model='flag-model', ai_api_key='flag-key'))
    capsys.readouterr()

    assert rc == 0
    _path, sent = client.requests[0]
    assert sent['model'] == 'flag-model'
    assert sent['api_key'] == 'flag-key'


def test_ai_phase_preview_only_does_not_write_xml(tmp_path, monkeypatch, capsys):
    _install_env(monkeypatch)
    client = _FakeClient({'success': True, 'generated_scenario': {'name': 'Generated'}, 'preview': {'nodes': 3}})
    backend = _fake_backend(client, [])
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)

    def _boom(*_args, **_kwargs):
        raise AssertionError('preview-only must not write XML')

    monkeypatch.setattr(cli, '_write_scenarios_payload_xml', _boom)

    rc = cli._run_ai_phase(_ai_args(tmp_path, ai_preview_only=True))
    emitted = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert emitted['written'] is False
    assert emitted['preview'] == {'nodes': 3}
    assert not (tmp_path / 'generated.xml').exists()


def test_ai_phase_reports_missing_settings_by_env_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv('CORETG_AI_MODEL', raising=False)
    monkeypatch.delenv('CORETG_AI_BASE_URL', raising=False)
    monkeypatch.setenv('CORETG_AI_PROVIDER', 'litellm')
    monkeypatch.delenv('CORETG_AI_API_KEY', raising=False)
    monkeypatch.delenv('CORETG_AI_API_KEY_USER', raising=False)
    backend = _fake_backend(_FakeClient({}), [])
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)

    rc = cli._run_ai_phase(_ai_args(tmp_path))
    err = capsys.readouterr().err
    emitted = json.loads(err)

    assert rc == 1
    assert 'CORETG_AI_MODEL' in emitted['error']
    assert 'CORETG_AI_BASE_URL' in emitted['error']


def test_ai_phase_surfaces_provider_errors(tmp_path, monkeypatch, capsys):
    _install_env(monkeypatch)
    client = _FakeClient({'success': False, 'error': 'model not found'}, status_code=400)
    backend = _fake_backend(client, [])
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)

    rc = cli._run_ai_phase(_ai_args(tmp_path))
    emitted = json.loads(capsys.readouterr().err)

    assert rc == 1
    assert emitted['error'] == 'model not found'
    assert emitted['status'] == 400


def test_ai_endpoint_payload_fills_from_env_without_overriding_the_caller(monkeypatch):
    from webapp import app_backend  # noqa: F401  (registers the ai_provider routes)
    from webapp.routes import ai_provider

    monkeypatch.setenv('CORETG_AI_PROVIDER', 'litellm')
    monkeypatch.setenv('CORETG_AI_MODEL', 'env-model')
    monkeypatch.setenv('CORETG_AI_BASE_URL', 'https://env.example/v1')
    monkeypatch.setenv('CORETG_AI_API_KEY', 'env-key')

    resolver = ai_provider._resolve_payload_with_stored_api_key

    # A headless caller sending only a prompt inherits the whole provider wiring.
    filled = resolver({'prompt': 'demo'})
    assert filled['provider'] == 'litellm'
    assert filled['model'] == 'env-model'
    assert filled['base_url'] == 'https://env.example/v1'
    assert filled['api_key'] == 'env-key'

    # The Web UI always sends its own values, and those must win.
    kept = resolver({
        'prompt': 'demo',
        'provider': 'ollama',
        'model': 'ui-model',
        'base_url': 'http://127.0.0.1:11434',
        'api_key': '',
    })
    assert kept['provider'] == 'ollama'
    assert kept['model'] == 'ui-model'
    assert kept['base_url'] == 'http://127.0.0.1:11434'

    # An explicitly empty field is a choice, not an omission: `model: ''` asks the
    # validate path to discover a model, so the environment must not fill it in.
    explicit_blank = resolver({'prompt': 'demo', 'provider': 'litellm', 'model': ''})
    assert explicit_blank['model'] == ''


def test_acting_user_comes_from_the_local_user_store():
    backend = SimpleNamespace(
        _load_users=lambda: {'users': [
            {'username': 'analyst', 'role': 'builder'},
            {'username': 'root_admin', 'role': 'admin'},
        ]},
        _normalize_role_value=lambda role: str(role or ''),
    )

    assert cli._cli_acting_username(backend, 'analyst') == 'analyst'
    # An unknown name never becomes an identity: it falls back to an admin on record.
    assert cli._cli_acting_username(backend, 'does-not-exist') == 'root_admin'
    assert cli._cli_acting_username(backend, '') == 'root_admin'

    empty_backend = SimpleNamespace(_load_users=lambda: {'users': []})
    assert cli._cli_acting_username(empty_backend, 'anyone') == ''


def test_authenticating_the_cli_client_seeds_a_session_for_a_real_user():
    backend = SimpleNamespace(
        _load_users=lambda: {'users': [{'username': 'coreadmin', 'role': 'admin'}]},
        _normalize_role_value=lambda role: str(role or ''),
    )
    client = _FakeClient({})

    assert cli._cli_authenticate_client(backend, client, 'coreadmin') is True
    assert client.session['user'] == {'username': 'coreadmin', 'role': 'admin'}

    assert cli._cli_authenticate_client(backend, client, 'ghost') is False
    assert cli._cli_authenticate_client(backend, client, '') is False


def test_ai_phase_refuses_to_run_without_a_local_account(tmp_path, monkeypatch, capsys):
    _install_env(monkeypatch)
    client = _FakeClient({'success': True, 'generated_scenario': {'name': 'Generated'}})
    backend = _fake_backend(client, [])
    backend._load_users = lambda: {'users': []}
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)

    rc = cli._run_ai_phase(_ai_args(tmp_path))
    emitted = json.loads(capsys.readouterr().err)

    assert rc == 1
    assert 'No local user account' in emitted['error']
    assert client.requests == []


def test_env_credential_user_survives_the_acting_user_fallback(tmp_path, monkeypatch, capsys):
    # The account that owns the stored API key is not always the account the run
    # acts as: an unknown credential username still selects the credential, while
    # the session falls back to an admin on record.
    _install_env(monkeypatch)
    monkeypatch.setenv('CORETG_AI_API_KEY_USER', 'key_owner')

    client = _FakeClient({'success': True, 'generated_scenario': {'name': 'Generated'}})
    backend = _fake_backend(client, [])
    lookups = []

    def _load_credentials(username, provider):
        lookups.append((username, provider))
        return {'api_key_plain': 'owner-key'}

    backend._load_ai_provider_credentials_for_user = _load_credentials
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: backend)
    monkeypatch.setattr(cli, '_write_scenarios_payload_xml', lambda b, payload, xml_path: None)

    rc = cli._run_ai_phase(_ai_args(tmp_path))
    emitted = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert lookups == [('key_owner', 'litellm')]
    _path, sent = client.requests[0]
    assert sent['api_key'] == 'owner-key'
    # The session still runs as a real local account.
    assert emitted['acting_user'] == 'coreadmin'
    assert emitted['settings']['credential_username'] == 'key_owner'


def test_reading_a_key_does_not_rewrite_the_credential_store(monkeypatch):
    from webapp import app_backend  # noqa: F401  (registers the ai_provider routes)
    from webapp.routes import ai_provider

    saves = []
    monkeypatch.setattr(ai_provider, '_stored_ai_provider_record', lambda provider: None, raising=False)

    resolver = ai_provider._resolve_payload_with_stored_api_key
    monkeypatch.setenv('CORETG_AI_PROVIDER', 'litellm')
    monkeypatch.delenv('CORETG_AI_API_KEY', raising=False)

    # The Web UI's save-on-use behavior is unchanged; only an explicit opt-out skips it.
    opted_out = resolver({'provider': 'litellm', 'api_key': 'one-off-key', 'persist_api_key': False})
    assert opted_out['api_key'] == 'one-off-key'
    assert 'api_key_secret_id' not in opted_out
    assert saves == []


def test_openai_provider_is_served_by_the_openai_compatible_adapter():
    from webapp import app_backend  # noqa: F401
    from webapp.routes import ai_provider

    litellm_adapter = ai_provider._get_provider_adapter('litellm')
    openai_adapter = ai_provider._get_provider_adapter('openai')

    assert type(openai_adapter) is type(litellm_adapter)
    # Same adapter, distinct identity: responses must report the provider in use.
    assert openai_adapter.provider_key == 'openai'
    assert litellm_adapter.provider_key == 'litellm'
    assert openai_adapter.capability.enabled is True
    assert openai_adapter.capability.requires_api_key is True
    assert openai_adapter.capability.default_base_url == 'https://api.openai.com/v1'
    assert litellm_adapter.capability.default_base_url == 'https://localhost:4000/v1'


def test_openai_validate_reports_its_own_provider_id(monkeypatch):
    from webapp import app_backend  # noqa: F401
    from webapp.routes import ai_provider

    monkeypatch.setattr(
        ai_provider,
        '_fetch_json',
        lambda url, timeout=None, headers=None, verify_ssl=True: {'data': [{'id': 'gpt-4.1-mini'}]},
    )

    result = ai_provider._get_provider_adapter('openai').validate({
        'base_url': 'https://api.openai.com/v1',
        'model': 'gpt-4.1-mini',
        'api_key': 'sk-test',
    })

    assert result['success'] is True
    assert result['provider'] == 'openai'
    assert result['models'] == ['gpt-4.1-mini']
    assert result['model_found'] is True
