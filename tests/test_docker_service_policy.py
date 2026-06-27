from scenarioforge.builders import topology


def test_docker_traffic_service_disabled_by_default(monkeypatch):
    monkeypatch.delenv("CORETG_DOCKER_ADD_TRAFFIC", raising=False)
    assert topology._docker_traffic_service_enabled() is False


def test_docker_traffic_service_enabled_via_env(monkeypatch):
    monkeypatch.setenv("CORETG_DOCKER_ADD_TRAFFIC", "1")
    assert topology._docker_traffic_service_enabled() is True


def test_ensure_default_route_for_docker_prunes_traffic(monkeypatch):
    calls = []

    monkeypatch.setenv("CORETG_DOCKER_ADD_DEFAULTROUTE", "1")
    monkeypatch.delenv("CORETG_DOCKER_ADD_TRAFFIC", raising=False)

    def fake_ensure_service(session, node_id, service_name, node_obj=None):
        calls.append(("ensure", int(node_id), service_name))
        return True

    def fake_remove_service(session, node_id, service_name, node_obj=None):
        calls.append(("remove", int(node_id), service_name))
        return True

    monkeypatch.setattr(topology, "ensure_service", fake_ensure_service)
    monkeypatch.setattr(topology, "remove_service", fake_remove_service)

    class _Node:
        id = 34

    topology._ensure_default_route_for_docker(object(), _Node())

    assert ("remove", 34, "DefaultRoute") in calls
    assert ("ensure", 34, "CoreTGPrereqs") in calls
    assert ("ensure", 34, "DockerDefaultRoute") in calls
    assert ("remove", 34, "Traffic") in calls


def test_sanitize_services_for_docker_keeps_only_allowed_policy(monkeypatch):
    monkeypatch.setenv("CORETG_DOCKER_ADD_DEFAULTROUTE", "1")
    monkeypatch.delenv("CORETG_DOCKER_ADD_TRAFFIC", raising=False)

    class _Node:
        id = 7
        type = topology.NodeType.DOCKER
        model = "docker"

    services = topology._sanitize_services_for_node(
        ["DHCPClient", "HTTP", "CoreTGPrereqs", "DefaultRoute", "Traffic"],
        node_id=7,
        node_obj=_Node(),
        context="test",
    )

    assert services == ["CoreTGPrereqs", "DockerDefaultRoute"]


def test_effective_host_role_marks_docker_slot_hosts_as_docker():
    assert topology._effective_host_role("Workstation", topology.NodeType.DOCKER) == "Docker"
    assert topology._effective_host_role("Workstation", topology.NodeType.DEFAULT) == "Workstation"


def test_ensure_services_with_policy_skips_invalid_docker_services(monkeypatch):
    calls = []

    monkeypatch.setenv("CORETG_DOCKER_ADD_DEFAULTROUTE", "1")
    monkeypatch.delenv("CORETG_DOCKER_ADD_TRAFFIC", raising=False)

    def fake_ensure_service(session, node_id, service_name, node_obj=None):
        calls.append((int(node_id), service_name))
        return True

    monkeypatch.setattr(topology, "ensure_service", fake_ensure_service)

    class _Node:
        id = 11
        type = topology.NodeType.DOCKER
        model = "docker"

    assigned = topology._ensure_services_with_policy(
        object(),
        11,
        ["DHCPClient", "HTTP", "DefaultRoute"],
        node_obj=_Node(),
        context="test",
    )

    assert assigned == ["CoreTGPrereqs", "DockerDefaultRoute"]
    assert calls == [(11, "CoreTGPrereqs"), (11, "DockerDefaultRoute")]


def test_ensure_services_with_policy_adds_coretgprereqs_for_docker_traffic(monkeypatch):
    calls = []

    monkeypatch.setenv("CORETG_DOCKER_ADD_DEFAULTROUTE", "0")
    monkeypatch.setenv("CORETG_DOCKER_ADD_TRAFFIC", "1")

    def fake_ensure_service(session, node_id, service_name, node_obj=None):
        calls.append((int(node_id), service_name))
        return True

    monkeypatch.setattr(topology, "ensure_service", fake_ensure_service)

    class _Node:
        id = 12
        type = topology.NodeType.DOCKER
        model = "docker"

    assigned = topology._ensure_services_with_policy(
        object(),
        12,
        ["Traffic"],
        node_obj=_Node(),
        context="test",
    )

    assert assigned == ["CoreTGPrereqs", "Traffic"]
    assert calls == [(12, "CoreTGPrereqs"), (12, "Traffic")]
