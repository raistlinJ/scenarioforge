from scenarioforge import cli


def test_compose_assignments_summary_preserves_inject_metadata():
    prepared = {
        'docker-1': {
            'Name': 'ExampleVuln',
            'Path': '/tmp/vulns/docker-compose-docker-1.yml',
            'Vector': 'flag',
            'InjectFiles': ['/tmp/vulns/flag_generators_runs/flow-scenario1/01_test/artifacts/secrets.txt -> /flow_injects'],
            'InjectSourceDir': '/tmp/vulns/flag_generators_runs/flow-scenario1/01_test/artifacts',
            'OutputsManifest': '/tmp/vulns/flag_generators_runs/flow-scenario1/01_test/outputs.json',
            'RunDir': '/tmp/vulns/flag_generators_runs/flow-scenario1/01_test',
        }
    }

    summary = cli._compose_assignments_summary(prepared, ['/tmp/vulns/docker-compose-docker-1.yml'], timestamp=123)

    assert summary['timestamp'] == 123
    assert summary['files'] == ['/tmp/vulns/docker-compose-docker-1.yml']
    assert summary['assignments']['docker-1']['InjectFiles'] == [
        '/tmp/vulns/flag_generators_runs/flow-scenario1/01_test/artifacts/secrets.txt -> /flow_injects'
    ]
    assert summary['assignments']['docker-1']['InjectSourceDir'] == '/tmp/vulns/flag_generators_runs/flow-scenario1/01_test/artifacts'
    assert summary['assignments']['docker-1']['OutputsManifest'] == '/tmp/vulns/flag_generators_runs/flow-scenario1/01_test/outputs.json'
    assert summary['assignments']['docker-1']['RunDir'] == '/tmp/vulns/flag_generators_runs/flow-scenario1/01_test'
