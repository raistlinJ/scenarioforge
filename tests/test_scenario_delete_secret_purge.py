"""Scenario deletion must not leave stored CORE credentials behind."""

from webapp import app_backend as backend


def _store(scenario_name):
    payload = {
        'grpc_host': '127.0.0.1',
        'grpc_port': 50051,
        'ssh_host': 'core.local',
        'ssh_username': 'core',
        'ssh_password': 'secret',
    }
    if scenario_name is not None:
        payload['scenario_name'] = scenario_name
    return backend._save_core_credentials(payload)


def _identifiers():
    import os
    return {
        entry[:-5]
        for entry in os.listdir(backend._core_secret_dir())
        if entry.endswith('.json')
    }


def test_purge_removes_only_the_deleted_scenarios_secrets():
    kept = _store('keeper-scenario')
    doomed = _store('doomed-scenario')
    # A record with no scenario_name is shared -- VM mode reads its connection
    # from .scenarioforge.env, so this must survive an unrelated deletion.
    shared = _store(None)

    result = backend._purge_core_secrets_for_scenarios(['doomed-scenario'])

    assert result['core_secrets_removed'] == 1
    remaining = _identifiers()
    assert str(doomed.get('identifier')) not in remaining
    assert str(kept.get('identifier')) in remaining
