import pytest

from scenarioforge.builders import topology as topo_mod
from scenarioforge.types import RoutingInfo
from tests.test_router_mesh import DummyClient, FakeSession, _patch_safe_create_session


def test_preview_payload_failure_is_fatal_by_default(monkeypatch):
    session = FakeSession()
    _patch_safe_create_session(monkeypatch, session)

    # A preview-like payload that cannot be realized. Realization bails only when
    # neither routers nor hosts are present, so declaring just a switch is enough
    # to be recognised as a preview while being impossible to build from.
    #
    # This used to declare a router and omit hosts, but that is realizable now:
    # a preview with no hosts is honoured exactly, producing a zero-host topology
    # rather than counting as a failure to realize.
    preview_plan = {
        "switches": [{"node_id": 5, "name": "sw1"}],
    }

    routing_items = [RoutingInfo(protocol="OSPFv2", factor=1.0, abs_count=1, r2s_mode="Exact", r2s_edges=1)]

    with pytest.raises(RuntimeError, match=r"Preview plan was provided but could not be realized exactly"):
        topo_mod.build_segmented_topology(
            DummyClient(),
            role_counts={"Workstation": 1},
            routing_density=0.0,
            routing_items=routing_items,
            base_host_pool=1,
            services=None,
            preview_plan=preview_plan,
        )


def test_preview_fallback_can_be_enabled(monkeypatch):
    session = FakeSession()
    _patch_safe_create_session(monkeypatch, session)

    monkeypatch.setenv("CORETG_ALLOW_PREVIEW_FALLBACK", "1")

    preview_plan = {
        "switches": [{"node_id": 5, "name": "sw1"}],
    }

    routing_items = [RoutingInfo(protocol="OSPFv2", factor=1.0, abs_count=1, r2s_mode="Exact", r2s_edges=1)]

    sess, routers, hosts, *_ = topo_mod.build_segmented_topology(
        DummyClient(),
        role_counts={"Workstation": 1},
        routing_density=0.0,
        routing_items=routing_items,
        base_host_pool=1,
        services=None,
        preview_plan=preview_plan,
    )

    # Reaching here at all is the assertion: with the flag set, an unrealizable
    # preview falls back to a randomized build instead of raising.
    assert sess is session
    assert len(routers) >= 1
    # Host count is deliberately not asserted. The CORE client double used here
    # does not create hosts -- build_segmented_topology returns zero of them even
    # with no preview at all -- so a count here would be testing the stub, not
    # the fallback.
    assert isinstance(hosts, list)
