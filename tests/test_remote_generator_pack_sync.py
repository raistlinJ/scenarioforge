import stat
from pathlib import Path
from types import SimpleNamespace

from webapp import app_backend
from webapp.app_backend import app
from webapp.flow_prepare_preview_execute import (
    _load_prepare_preview_request_context,
    _prepare_remote_generator_execution,
)


def test_prune_remote_installed_generator_packs_uses_local_catalog_names(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / 'outputs' / 'installed_generators' / 'flag_node_generators' / 'current-pack').mkdir(parents=True)
    (tmp_path / 'outputs' / 'installed_generators' / 'flag_generators' / 'flag-pack').mkdir(parents=True)
    commands: list[str] = []

    def _fake_exec(_client, command, **_kwargs):
        commands.append(command)
        return 0, '["flag_node_generators/stale-pack"]\n', ''

    monkeypatch.setattr(app_backend, '_exec_ssh_command', _fake_exec)

    removed = app_backend._prune_remote_installed_generator_packs(
        object(),
        repo_root=str(tmp_path),
        remote_repo='/tmp/scenarioforge',
    )

    assert removed == ['flag_node_generators/stale-pack']
    assert len(commands) == 1
    assert 'current-pack' in commands[0]
    assert 'flag-pack' in commands[0]
    assert '/tmp/scenarioforge' in commands[0]


def test_remote_flow_refuses_to_run_when_selected_generator_has_no_sync_path() -> None:
    deps = SimpleNamespace(
        _flow_required_installed_generator_outputs=lambda *_args, **_kwargs: [],
        _flow_required_generator_repo_paths=lambda *_args, **_kwargs: [],
        _get_repo_root=lambda: '/tmp/local-scenarioforge',
    )

    with app.app_context():
        result = _prepare_remote_generator_execution(
            deps,
            run_generators=True,
            flow_run_remote=True,
            flow_remote_forced=False,
            flow_core_cfg={'ssh_host': 'core.example'},
            flag_assignments=[{'id': 'dep_api_key_admin_endpoint', 'type': 'flag-node-generator'}],
            flow_progress=lambda _message: None,
        )

    response, status = result['response']
    assert status == 500
    assert 'No generator paths resolved for Flow sync' in response.get_json()['error']


def test_vm_flow_adopts_page_ssh_enabled_and_never_silently_falls_back_local(tmp_path: Path) -> None:
    xml_path = tmp_path / 'Scenario2.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')
    deps = SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower(),
        _webui_runtime_mode=lambda: 'vm',
        _coerce_bool=lambda value: bool(value),
        _flow_normalize_dependency_level=lambda value: 3,
        _existing_xml_path_or_none=lambda value: str(value) if Path(value).exists() else None,
        _latest_preview_plan_for_scenario_norm_origin=lambda *_args, **_kwargs: None,
        _latest_preview_plan_for_scenario_norm=lambda *_args, **_kwargs: None,
        _planner_get_plan=lambda *_args, **_kwargs: None,
        _core_config_from_xml_path=lambda *_args, **_kwargs: {'validated': True},
        _select_core_config_for_page=lambda *_args, **_kwargs: {
            'ssh_enabled': True,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'corevm',
            'ssh_password': 'secret',
        },
        _apply_core_secret_to_config=lambda cfg, *_args, **_kwargs: cfg,
        _flow_normalize_fact_override=lambda value: value,
        _load_preview_payload_from_path=lambda *_args, **_kwargs: {'full_preview': {}},
        _canonicalize_payload_flow_from_xml=lambda payload, **_kwargs: ({}, None),
    )

    with app.test_request_context('/'):
        context = _load_prepare_preview_request_context(
            deps=deps,
            flow_progress=lambda _message: None,
            payload={
                'scenario': 'Scenario2',
                'preview_plan': str(xml_path),
                'mode': 'resolve',
            },
        )

    assert context['response'] is None
    assert context['flow_core_cfg']['ssh_enabled'] is True
    assert context['flow_run_remote'] is True
    assert context['flow_remote_forced'] is True


def test_vm_flow_explicit_run_local_remains_local(tmp_path: Path) -> None:
    xml_path = tmp_path / 'Scenario2.xml'
    xml_path.write_text('<Scenarios/>', encoding='utf-8')
    deps = SimpleNamespace(
        _normalize_scenario_label=lambda value: str(value or '').strip().lower(),
        _webui_runtime_mode=lambda: 'vm',
        _coerce_bool=lambda value: bool(value),
        _flow_normalize_dependency_level=lambda value: 3,
        _existing_xml_path_or_none=lambda value: str(value) if Path(value).exists() else None,
        _latest_preview_plan_for_scenario_norm_origin=lambda *_args, **_kwargs: None,
        _latest_preview_plan_for_scenario_norm=lambda *_args, **_kwargs: None,
        _planner_get_plan=lambda *_args, **_kwargs: None,
        _core_config_from_xml_path=lambda *_args, **_kwargs: {'validated': True},
        _select_core_config_for_page=lambda *_args, **_kwargs: {'ssh_enabled': True},
        _apply_core_secret_to_config=lambda cfg, *_args, **_kwargs: cfg,
        _flow_normalize_fact_override=lambda value: value,
        _load_preview_payload_from_path=lambda *_args, **_kwargs: {'full_preview': {}},
        _canonicalize_payload_flow_from_xml=lambda payload, **_kwargs: ({}, None),
    )

    with app.test_request_context('/'):
        context = _load_prepare_preview_request_context(
            deps=deps,
            flow_progress=lambda _message: None,
            payload={
                'scenario': 'Scenario2',
                'preview_plan': str(xml_path),
                'mode': 'resolve',
                'run_local': True,
            },
        )

    assert context['response'] is None
    assert context['flow_run_remote'] is False
    assert context['flow_remote_forced'] is False


def test_core_runtime_sync_removes_matching_core_runtime_directory(tmp_path: Path, monkeypatch) -> None:
    """The remote path a sync deletes must mirror the local layout exactly.

    Uninstall is local-only, so this reconciliation is the only thing that ever
    removes a generator from the CORE VM; building the remote path wrongly
    would either miss the stale copy or delete an unrelated directory.
    """
    repo_root = tmp_path / 'repo'
    install_root = repo_root / 'outputs' / 'installed_generators'
    (install_root / 'flag_node_generators' / 'p_current__51').mkdir(parents=True)
    removed: list[str] = []

    class FakeAttr:
        def __init__(self, name: str) -> None:
            self.filename = name
            self.st_mode = stat.S_IFDIR | 0o755

    remote_root = '/tmp/scenarioforge/outputs/installed_generators'
    tree = {
        '/tmp/scenarioforge': [FakeAttr('outputs')],
        remote_root: [FakeAttr('flag_node_generators')],
        f'{remote_root}/flag_node_generators': [FakeAttr('p_current__51'), FakeAttr('p_removed__52')],
    }

    class FakeSftp:
        def stat(self, path):
            if path not in tree:
                raise IOError(path)
            return object()

        def listdir_attr(self, path):
            if path not in tree:
                raise IOError(path)
            return tree[path]

        def close(self):
            return None

    class FakeClient:
        def open_sftp(self):
            return FakeSftp()

        def close(self):
            return None

    monkeypatch.setattr(app_backend, '_get_repo_root', lambda: str(repo_root))
    monkeypatch.setattr(app_backend, '_installed_generators_root', lambda: str(install_root))
    monkeypatch.setattr(app_backend, '_core_config_for_request', lambda **_kwargs: {'ssh_host': 'core.example'})
    monkeypatch.setattr(app_backend, '_require_core_ssh_credentials', lambda cfg: cfg)
    monkeypatch.setattr(app_backend, '_open_ssh_client', lambda _cfg: FakeClient())
    monkeypatch.setattr(app_backend, '_remote_static_repo_dir', lambda _sftp: '/tmp/scenarioforge')
    monkeypatch.setattr(app_backend, '_remote_remove_path', lambda _client, path: removed.append(path))

    result = app_backend._reconcile_remote_generator_runtime()

    assert result['ok'] is True
    assert result['kept'] == 1
    assert result['removed'] == ['flag_node_generators/p_removed__52']
    assert removed == ['/tmp/scenarioforge/outputs/installed_generators/flag_node_generators/p_removed__52']


def test_remote_runner_binds_execution_to_the_selected_generator_source() -> None:
    helper_text = Path('webapp/flow_prepare_preview_helpers.py').read_text(encoding='utf-8')
    runner_text = Path('scripts/run_flag_generator.py').read_text(encoding='utf-8')

    assert "'--source-dir', SOURCE" in helper_text
    assert 'ap.add_argument("--source-dir"' in runner_text
    assert 'Generator not found at requested source' in runner_text
