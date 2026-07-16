import pytest

from scenarioforge.planning.full_preview import build_full_preview
from scenarioforge.builders import topology as topo_mod
from tests.test_router_mesh import DummyClient, FakeSession, _patch_safe_create_session


def test_full_preview_no_routers_star_topology():
    role_counts = {
        'Workstation': 4,
        'Server': 1,
    }
    preview = build_full_preview(
        role_counts=role_counts,
        routers_planned=0,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy=None,
        routing_items=None,
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        traffic_plan=None,
        seed=123,
        ip4_prefix='10.50.0.0/16',
    )

    hosts = preview.get('hosts') or []
    routers = preview.get('routers') or []
    switches = preview.get('switches') or []
    switches_detail = preview.get('switches_detail') or []

    assert len(routers) == 0
    assert len(hosts) == sum(role_counts.values())

    # Expect a single-switch star topology when there are no routers.
    assert len(switches) == 1
    assert len(switches_detail) == 1

    detail = switches_detail[0]
    assert detail.get('router_id') is None
    assert detail.get('router_ip') is None
    assert detail.get('rsw_subnet') is None
    assert preview.get('router_switch_subnets') == []

    host_ids = sorted(int(h.get('node_id')) for h in hosts)
    assert sorted(int(x) for x in (detail.get('hosts') or [])) == host_ids

    # Should include a LAN subnet so host IP assignment can be deterministic.
    lan = detail.get('lan_subnet')
    assert isinstance(lan, str) and '/' in lan


def test_star_runtime_realizes_exact_host_addresses_from_preview(monkeypatch):
    """No-router runtime must use the persisted preview address plan verbatim."""
    session = FakeSession()
    _patch_safe_create_session(monkeypatch, session)

    monkeypatch.setattr(topo_mod, '_ensure_docker_node_compose_prepared', lambda *_a, **_k: None)
    monkeypatch.setattr(topo_mod, '_docker_node_add_node_kwargs', lambda *_a, **_k: {})
    monkeypatch.setattr(topo_mod, '_apply_docker_compose_meta', lambda *_a, **_k: None)
    monkeypatch.setattr(topo_mod, '_ensure_default_route_for_docker', lambda *_a, **_k: None)

    preview = build_full_preview(
        role_counts={'Docker': 2},
        routers_planned=0,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy=None,
        routing_items=None,
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        traffic_plan=None,
        seed=123,
        ip4_prefix='172.30.123.0/24',
    )
    expected = [str(host['ip4']) for host in preview['hosts']]

    _session, _switches, host_infos, _svc_assignments, _docker_by_name = topo_mod.build_star_from_roles(
        DummyClient(),
        role_counts={'Docker': 2},
        ip4_prefix='10.0.0.0/24',
        preview_plan=preview,
    )

    assert [host.ip4 for host in host_infos] == expected


def test_star_runtime_rejects_preview_without_host_address(monkeypatch):
    session = FakeSession()
    _patch_safe_create_session(monkeypatch, session)

    with pytest.raises(RuntimeError, match='missing a valid IPv4 address'):
        topo_mod.build_star_from_roles(
            DummyClient(),
            role_counts={'Workstation': 1},
            preview_plan={'hosts': [{'node_id': 1, 'name': 'workstation-1'}]},
        )


def test_star_topology_merges_flow_overlay_from_preview_into_docker_slot(monkeypatch):
    session = FakeSession()
    _patch_safe_create_session(monkeypatch, session)

    monkeypatch.setattr(topo_mod, '_ensure_docker_node_compose_prepared', lambda *_a, **_k: None)
    monkeypatch.setattr(topo_mod, '_docker_node_add_node_kwargs', lambda *_a, **_k: {})
    monkeypatch.setattr(topo_mod, '_apply_docker_compose_meta', lambda *_a, **_k: None)
    monkeypatch.setattr(topo_mod, '_ensure_default_route_for_docker', lambda *_a, **_k: None)

    preview_plan = {
        'hosts': [
            {
                'node_id': 1,
                'name': 'docker-1',
                'ip4': '10.55.0.3/24',
                'metadata': {
                    'flow_flag': {
                        'type': 'flag-generator',
                        'artifacts_dir': '/tmp/vulns/flag_generators_runs/flow-scenario1/02_textfile_username_password_docker-1',
                        'inject_source_dir': '/tmp/vulns/flag_generators_runs/flow-scenario1/02_textfile_username_password_docker-1/artifacts',
                        'inject_files': ['secrets.txt'],
                        'outputs_manifest': '/tmp/vulns/flag_generators_runs/flow-scenario1/02_textfile_username_password_docker-1/outputs.json',
                        'mount_path': '/flow_artifacts',
                        'run_dir': '/tmp/vulns/flag_generators_runs/flow-scenario1/02_textfile_username_password_docker-1',
                    }
                },
            }
        ]
    }
    docker_slot_plan = {
        'slot-1': {
            'Type': 'docker-compose',
            'Name': 'ecshop/collection_list-sqli',
            'Path': '/tmp/scenarioforge/runs/demo/docker-compose.yml',
            'Vector': 'vuln',
        }
    }

    _session, _switches, _hosts, _svc_assignments, docker_by_name = topo_mod.build_star_from_roles(
        DummyClient(),
        role_counts={'docker': 1},
        services=None,
        docker_slot_plan=docker_slot_plan,
        preview_plan=preview_plan,
    )

    record = docker_by_name['docker-1']
    assert record['Name'] == 'ecshop/collection_list-sqli'
    assert record['Path'] == '/tmp/scenarioforge/runs/demo/docker-compose.yml'
    assert record['InjectFiles'] == ['secrets.txt']
    assert record['InjectSourceDir'].endswith('/artifacts')
    assert record['OutputsManifest'].endswith('/outputs.json')
    assert record['ArtifactsMountPath'] == '/flow_artifacts'
