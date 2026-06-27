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


def test_full_preview_repairs_docker_capacity_for_vuln_hosts_without_explicit_docker():
    preview = build_full_preview(
        role_counts={"Workstation": 10},
        routers_planned=0,
        services_plan={"HTTP": 3},
        vulnerabilities_plan={"SSHCreds": 1},
        r2r_policy=None,
        r2s_policy=None,
        routing_items=None,
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        seed=123,
    )

    repair = preview["docker_capacity_repair"]
    assert repair["required_docker_hosts"] == 1
    assert repair["added_docker_hosts"] == 1

    hosts = preview["hosts"]
    docker_ids = {
        int(host["node_id"])
        for host in hosts
        if str(host.get("role") or "").strip().lower() == "docker"
    }
    assert docker_ids

    vuln_ids = {int(node_id) for node_id in (preview["vulnerabilities_by_node"] or {}).keys()}
    assert vuln_ids
    assert vuln_ids.issubset(docker_ids)

    service_ids = {int(node_id) for node_id in (preview["services_preview"] or {}).keys()}
    assert service_ids
    assert service_ids.isdisjoint(docker_ids)
