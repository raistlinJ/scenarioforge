"""A plan with no routers must still wire and address its hosts.

The planner emits a single-switch star for a scenario that asks for no routers,
and records `router_id: None` on that switch detail so no fake router is
materialized. Realization read that field with `int(detail['router_id'])`, which
raised, and the whole switch entry was skipped -- so every host node came up
running but unlinked and unaddressed. The scenario then had no connectivity at
all: traffic flows reported `no route to the destination`, and the artifact
check could not match a single flow endpoint to a running node.
"""

import types

import pytest

from scenarioforge.builders import topology as topo_mod


class FakeNode:
    def __init__(self, node_id, name=""):
        self.id = node_id
        self.name = name or f"n{node_id}"
        self.position = types.SimpleNamespace(x=0, y=0)
        self.services = []
        self.model = ""


class FakeServices:
    def __init__(self):
        self._map = {}

    def add(self, node_id_or_obj, service_name):
        nid = getattr(node_id_or_obj, "id", node_id_or_obj)
        self._map.setdefault(nid, set()).add(service_name)


class FakeLink:
    """Shaped like the builder's link-presence check expects (node1_id/node2_id),
    while keeping the interfaces so addresses can be asserted."""

    def __init__(self, a, b, iface_a, iface_b):
        self.node1_id = a
        self.node2_id = b
        self.iface_a = iface_a
        self.iface_b = iface_b


class FakeSession:
    """Records the interfaces of each link, which is where addresses live."""

    def __init__(self):
        self.nodes = {}
        self.links = []
        self.services = FakeServices()

    def add_node(self, node_id, _type=None, position=None, name=None):
        node = FakeNode(node_id, name or f"n{node_id}")
        self.nodes[node_id] = node
        return node

    def add_link(self, node1=None, node2=None, iface1=None, iface2=None):
        if not node1 or not node2:
            return
        a = getattr(node1, "id", node1)
        b = getattr(node2, "id", node2)
        if a == b:
            return
        self.links.append(FakeLink(a, b, iface1, iface2))

    def add_service(self, node_id=None, service_name=None):
        if node_id is not None:
            self.services.add(node_id, service_name)

    def delete_link(self, node1_id=None, node2_id=None, iface1_id=None, iface2_id=None):
        self.links = [lk for lk in self.links
                      if {lk.node1_id, lk.node2_id} != {node1_id, node2_id}]

    def delete_node(self, node_id):
        self.nodes.pop(node_id, None)
        self.links = [lk for lk in self.links
                      if node_id not in (lk.node1_id, lk.node2_id)]


SWITCH_ID = 90
HOST_IDS = [1, 2, 3, 4, 5]
LAN = "172.30.96.0/24"


def _star_plan():
    """The shape planning.router_host_plan emits when no routers are planned."""
    hosts = [{"node_id": hid, "role": "PC", "ip4": f"172.30.96.{hid + 2}/24"}
             for hid in HOST_IDS]
    return {
        "routers": [],
        "hosts": hosts,
        "switches": [{"node_id": SWITCH_ID, "name": f"sw-{SWITCH_ID}"}],
        "switches_detail": [{
            "switch_id": SWITCH_ID,
            # The planner keeps this null on purpose, so frontends do not
            # materialize a router that the scenario never asked for.
            "router_id": None,
            "hosts": list(HOST_IDS),
            "rsw_subnet": None,
            "lan_subnet": LAN,
            "router_ip": None,
            "host_if_ips": {},
        }],
        "host_router_map": {},
        "services_preview": {},
    }


@pytest.fixture
def built(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(topo_mod, "safe_create_session", lambda core: session)
    result = topo_mod.build_segmented_topology(
        object(),
        role_counts={"PC": len(HOST_IDS)},
        routing_density=0.0,
        routing_items=[],
        base_host_pool=len(HOST_IDS),
        services=None,
        preview_plan=_star_plan(),
    )
    return session, result


def _host_ifaces(session):
    """Map host node id -> the interface it was linked to the switch with."""
    out = {}
    for link in session.links:
        for near, far, iface in ((link.node1_id, link.node2_id, link.iface_a),
                                 (link.node2_id, link.node1_id, link.iface_b)):
            if far == SWITCH_ID and near in HOST_IDS:
                out[near] = iface
    return out


def test_every_host_is_linked_to_the_switch(built):
    session, _ = built
    attached = _host_ifaces(session)
    assert sorted(attached) == HOST_IDS, (
        "a router-less star left hosts unlinked, so nothing could reach anything")


def test_every_host_gets_an_ipv4_address(built):
    session, _ = built
    for hid, iface in _host_ifaces(session).items():
        assert getattr(iface, "ip4", None), f"host {hid} was linked with no address"


def test_hosts_keep_the_addresses_the_plan_published(built):
    # Reports, guides and the traffic flows all quote the plan's host
    # addresses, so realizing different ones would break every reference.
    session, _ = built
    actual = {hid: getattr(iface, "ip4", None)
              for hid, iface in _host_ifaces(session).items()}
    assert actual == {hid: f"172.30.96.{hid + 2}" for hid in HOST_IDS}


def test_no_router_node_is_invented(built):
    # The null router_id exists precisely so a star does not grow a fake router.
    session, result = built
    routers = result[1]
    assert routers == []
    models = {getattr(n, "model", "") for n in session.nodes.values()}
    assert "router" not in models


def test_returned_host_info_carries_the_realized_address(built):
    # Traffic flows are rebound to these addresses at execute, so a NodeInfo
    # left without one would silently keep a stale planned address.
    _session, result = built
    hosts_info = result[2]
    by_id = {info.node_id: info.ip4 for info in hosts_info}
    for hid in HOST_IDS:
        assert by_id.get(hid) == f"172.30.96.{hid + 2}/24"


def _plan_without_addresses():
    """A switch detail with neither a LAN subnet nor per-host addresses.

    Nothing can be assigned from it, which is exactly the state the guard has to
    report instead of returning a topology that quietly cannot work.
    """
    plan = _star_plan()
    plan["hosts"] = [{"node_id": hid, "role": "PC"} for hid in HOST_IDS]
    plan["switches_detail"][0]["lan_subnet"] = None
    return plan


def test_unaddressed_hosts_are_reported_on_the_session(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(topo_mod, "safe_create_session", lambda core: session)
    topo_mod.build_segmented_topology(
        object(),
        role_counts={"PC": len(HOST_IDS)},
        routing_density=0.0,
        routing_items=[],
        base_host_pool=len(HOST_IDS),
        services=None,
        preview_plan=_plan_without_addresses(),
    )
    stats = getattr(session, "topo_stats", {})
    # The run metadata and the scenario report both read topo_stats, so the
    # finding travels with the run rather than living only in a log line.
    assert stats.get("hosts_unaddressed") == HOST_IDS
    assert stats.get("hosts_unaddressed_total") == len(HOST_IDS)


def test_unaddressed_hosts_are_logged_as_an_error(monkeypatch, caplog):
    session = FakeSession()
    monkeypatch.setattr(topo_mod, "safe_create_session", lambda core: session)
    with caplog.at_level("ERROR", logger=topo_mod.logger.name):
        topo_mod.build_segmented_topology(
            object(),
            role_counts={"PC": len(HOST_IDS)},
            routing_density=0.0,
            routing_items=[],
            base_host_pool=len(HOST_IDS),
            services=None,
            preview_plan=_plan_without_addresses(),
        )
    assert any("no IPv4 address" in r.getMessage() for r in caplog.records)


def test_a_healthy_build_records_no_finding(built):
    session, _ = built
    stats = getattr(session, "topo_stats", {})
    assert not stats.get("hosts_unaddressed")
