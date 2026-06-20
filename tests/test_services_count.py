from scenarioforge.utils.services import distribute_services
from scenarioforge.types import NodeInfo, ServiceInfo
from scenarioforge.planning.full_preview import build_full_preview


def _hosts(n):
    return [NodeInfo(node_id=i + 1, ip4=f"10.0.0.{i+1}/24", role="Host") for i in range(n)]


def test_service_count_absolute():
    hosts = _hosts(2)
    services = [ServiceInfo(name="SSH", factor=1.0, density=1.0, abs_count=1)]
    assignments = distribute_services(hosts, services)
    # Exactly one node should have SSH
    ssh_count = sum(1 for svcs in assignments.values() if "SSH" in svcs)
    assert ssh_count == 1


def test_service_count_per_item_override():
    hosts = _hosts(3)
    # Two services: SSH count=1, HTTP count=2
    services = [
        ServiceInfo(name="SSH", factor=1.0, density=1.0, abs_count=1),
        ServiceInfo(name="HTTP", factor=1.0, density=2.0, abs_count=2),
    ]
    assignments = distribute_services(hosts, services)
    ssh_count = sum(1 for svcs in assignments.values() if "SSH" in svcs)
    http_count = sum(1 for svcs in assignments.values() if "HTTP" in svcs)
    assert ssh_count == 1
    assert http_count == 2


def test_full_preview_services_skip_docker_hosts():
    preview = build_full_preview(
        role_counts={"Docker": 2},
        routers_planned=0,
        services_plan={"HTTP": 2},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy=None,
        routing_items=None,
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        seed=123,
    )

    assert preview["services_preview"] == {}
