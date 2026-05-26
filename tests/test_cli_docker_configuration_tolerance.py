from scenarioforge import cli


def test_docker_compose_node_names_filters_non_compose_entries():
    docker_by_name = {
        'docker-1': {'Type': 'docker-compose'},
        'docker-2': {'Type': 'docker'},
        'docker-3': {'Type': 'docker-compose'},
        'docker-4': {},
        'docker-5': 'not-a-dict',
    }

    assert cli._docker_compose_node_names(docker_by_name) == ['docker-1', 'docker-3']


def test_should_tolerate_configuration_state_for_docker_accepts_running_nodes():
    docker_runtime = {
        'total': 1,
        'running': ['docker-1'],
        'not_running': [],
        'items': [{'name': 'docker-1', 'running': True, 'status': 'running'}],
    }

    assert cli._should_tolerate_configuration_state_for_docker(
        'configuration',
        ['docker-1'],
        docker_runtime,
    ) is True


def test_should_tolerate_configuration_state_for_docker_rejects_pending_or_mismatch():
    pending_runtime = {
        'total': 1,
        'running': [],
        'not_running': ['docker-1'],
        'items': [{'name': 'docker-1', 'running': False, 'status': 'created'}],
    }

    assert cli._should_tolerate_configuration_state_for_docker(
        'configuration',
        ['docker-1'],
        pending_runtime,
    ) is False

    ok_runtime = {
        'total': 1,
        'running': ['docker-1'],
        'not_running': [],
        'items': [{'name': 'docker-1', 'running': True, 'status': 'running'}],
    }
    assert cli._should_tolerate_configuration_state_for_docker(
        'configuration',
        ['docker-1'],
        ok_runtime,
        mismatches=[{'name': 'docker-1'}],
    ) is False

    assert cli._should_tolerate_configuration_state_for_docker(
        'runtime',
        ['docker-1'],
        ok_runtime,
    ) is False