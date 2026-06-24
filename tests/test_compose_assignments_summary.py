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


def test_write_compose_assignments_summary_creates_manifest_for_remote_copy(tmp_path):
    prepared = {
        'docker-2': {
            'Name': 'FlowGeneratedNode',
            'Path': '/tmp/vulns/docker-compose-docker-2.yml',
            'InjectFiles': ['/tmp/vulns/flag_node_generators_runs/flow-sanity/01_gen/service -> /flow_injects'],
            'InjectSourceDir': '/tmp/vulns/flag_node_generators_runs/flow-sanity/01_gen',
        }
    }
    files = ['/tmp/vulns/docker-compose-docker-2.yml']

    path = cli._write_compose_assignments_summary(
        prepared,
        files,
        out_base=str(tmp_path),
        timestamp=456,
    )

    assert path == str(tmp_path / 'compose_assignments.json')
    text = (tmp_path / 'compose_assignments.json').read_text(encoding='utf-8')
    assert '"docker-2"' in text
    assert '"InjectSourceDir"' in text
    assert '"files"' in text
