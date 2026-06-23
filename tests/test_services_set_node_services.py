from __future__ import annotations

from types import SimpleNamespace

from scenarioforge.utils.services import ensure_service, set_node_services


class _WeirdServices:
    """Simulates a CORE wrapper where services.set(node_id, ...) is a silent no-op.

    Some CORE gRPC wrapper variants expect a node object, not an id. When passed an
    int they may not error but also won't apply the change.
    """

    def __init__(self) -> None:
        self._by_node_id: dict[int, list[str]] = {}

    def set(self, node_id_or_obj, services: tuple[str, ...]) -> None:
        if hasattr(node_id_or_obj, "id"):
            self._by_node_id[int(node_id_or_obj.id)] = list(services)
        else:
            # silent no-op for ids
            return

    def get(self, node_id_or_obj):
        node_id = int(getattr(node_id_or_obj, "id", node_id_or_obj))
        return tuple(self._by_node_id.get(node_id, []))


class _Session:
    def __init__(self) -> None:
        self.services = _WeirdServices()


def test_set_node_services_retries_with_node_obj_when_id_noops() -> None:
    session = _Session()
    node = SimpleNamespace(id=123)

    ok = set_node_services(session, 123, ["IPForward", "zebra", "RIP"], node_obj=node)
    assert ok is True
    assert set(session.services.get(123)) == {"IPForward", "zebra", "RIP"}


def test_set_node_services_normalizes_docker_defaultroute_dependency() -> None:
    session = _Session()
    node = SimpleNamespace(id=321, type="DOCKER")

    ok = set_node_services(session, 321, ["DefaultRoute"], node_obj=node)
    assert ok is True
    assert set(session.services.get(321)) == {"CoreTGPrereqs", "DockerDefaultRoute"}


def test_ensure_service_retries_with_node_obj_when_id_noops() -> None:
    session = _Session()
    node = SimpleNamespace(id=999, type="DOCKER")

    ok = ensure_service(session, 999, "DefaultRoute", node_obj=node)
    assert ok is True
    assert set(session.services.get(999)) == {"CoreTGPrereqs", "DockerDefaultRoute"}


def test_ensure_service_adds_coretgprereqs_for_docker_traffic() -> None:
    session = _Session()
    node = SimpleNamespace(id=1001, type="DOCKER")

    ok = ensure_service(session, 1001, "Traffic", node_obj=node)
    assert ok is True
    assert set(session.services.get(1001)) == {"CoreTGPrereqs", "Traffic"}


def test_ensure_service_adds_coretgprereqs_for_host_traffic() -> None:
    session = _Session()
    node = SimpleNamespace(id=1002, type="DEFAULT")

    ok = ensure_service(session, 1002, "Traffic", node_obj=node)
    assert ok is True
    assert set(session.services.get(1002)) == {"CoreTGPrereqs", "Traffic"}


def test_ensure_service_adds_coretgprereqs_for_segmentation_without_node_obj() -> None:
    session = _Session()
    node = SimpleNamespace(id=1003)
    session.get_node = lambda node_id: node if int(node_id) == node.id else None

    ok = ensure_service(session, 1003, "Segmentation")
    assert ok is True
    assert set(session.services.get(1003)) == {"CoreTGPrereqs", "Segmentation"}


def test_set_node_services_expands_custom_service_dependencies() -> None:
    session = _Session()
    node = SimpleNamespace(id=1004)

    ok = set_node_services(session, 1004, ["Traffic", "Segmentation"], node_obj=node)
    assert ok is True
    assert list(session.services.get(1004)) == [
        "CoreTGPrereqs",
        "Traffic",
        "Segmentation",
    ]
