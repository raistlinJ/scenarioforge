from scenarioforge.planning.full_preview import build_full_preview


def _reachable_router_ids(edges, start):
    adjacency = {}
    for left, right in edges:
        adjacency.setdefault(int(left), set()).add(int(right))
        adjacency.setdefault(int(right), set()).add(int(left))
    reached = {int(start)}
    pending = [int(start)]
    while pending:
        node_id = pending.pop()
        for peer_id in adjacency.get(node_id, set()):
            if peer_id not in reached:
                reached.add(peer_id)
                pending.append(peer_id)
    return reached


def test_uniform_degree_one_is_raised_to_connected_router_backbone():
    preview = build_full_preview(
        role_counts={"Workstation": 12},
        routers_planned=4,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy={"mode": "Uniform", "target_degree": 1},
        r2s_policy={"mode": "Exact", "target_per_router": 1},
        routing_items=[],
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        traffic_plan=[],
        seed=202608044,
        ip4_prefix="10.0.0.0/24",
    )

    router_ids = {int(router["node_id"]) for router in preview["routers"]}
    edges = preview["r2r_edges_preview"]

    assert preview["r2r_policy_preview"]["target_degree"] == 2
    assert _reachable_router_ids(edges, min(router_ids)) == router_ids
    assert set(preview["r2r_degree_preview"].values()) == {2}


def test_uniform_preview_is_connected_across_feasible_degrees_and_sizes():
    for router_count in range(2, 9):
        for requested_degree in range(1, router_count):
            preview = build_full_preview(
                role_counts={"Workstation": router_count * 2},
                routers_planned=router_count,
                services_plan={},
                vulnerabilities_plan={},
                r2r_policy={"mode": "Uniform", "target_degree": requested_degree},
                r2s_policy={"mode": "Exact", "target_per_router": 1},
                routing_items=[],
                routing_plan={},
                segmentation_density=0.0,
                segmentation_items=[],
                traffic_plan=[],
                seed=9000 + router_count * 10 + requested_degree,
                ip4_prefix="10.0.0.0/24",
            )
            router_ids = {int(router["node_id"]) for router in preview["routers"]}
            assert _reachable_router_ids(
                preview["r2r_edges_preview"], min(router_ids)
            ) == router_ids
