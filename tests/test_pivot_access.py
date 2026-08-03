"""The "accessible by pivot" toggle keeps segmented-off subnets reachable.

Segmentation can wall a subnet off so completely that nothing can get in, which
makes any challenge inside it unsolvable. These cover the planner that
guarantees each walled-off subnet keeps one reachable provider.
"""

from scenarioforge.types import NodeInfo
from scenarioforge.utils import pivot_access as pa


def _rule(node_id, **rule):
    return {"node_id": node_id, "service": "Segmentation", "rule": rule}


def _block(node_id=1, src="10.0.140.0/24", dst="172.21.240.0/24"):
    return _rule(node_id, type="subnet_block", src=src, dst=dst, default_deny=True)


# --------------------------------------------------------------------------- #
# Finding what segmentation walled off
# --------------------------------------------------------------------------- #

def test_walled_off_collects_destinations_and_their_sources():
    rules = [
        _block(src="10.0.140.0/24"),
        _block(src="10.0.173.0/24"),
        _rule(1, type="allow", chain="FORWARD", proto="tcp", port=5011),
    ]
    assert pa.walled_off_subnets(rules) == {
        "172.21.240.0/24": ["10.0.140.0/24", "10.0.173.0/24"],
    }


def test_protect_internal_blocks_from_everywhere():
    plan = pa.walled_off_subnets([_rule(1, type="protect_internal", subnet="10.9.0.0/24")])
    assert plan == {"10.9.0.0/24": ["*"]}


def test_host_block_does_not_wall_off_anything():
    # It stops one host reaching one host; the rest of the subnet is still
    # reachable both ways, so nothing is isolated and no provider is owed. The
    # only node in a /32 is the blocked host, so a "provider" there would be an
    # SSH allow straight back into the host the rule exists to block.
    assert pa.walled_off_subnets([_rule(1, type="host_block", src="10.0.1.5", dst="10.0.2.7")]) == {}


def test_host_block_alongside_a_subnet_block_does_not_add_a_provider():
    rules = [_block(src="10.0.1.0/24", dst="10.0.2.0/24"),
             _rule(1, type="host_block", src="10.0.1.5", dst="10.0.2.7")]
    assert list(pa.walled_off_subnets(rules)) == ["10.0.2.0/24"]


def test_non_blocking_rules_are_ignored():
    assert pa.walled_off_subnets([_rule(1, type="nat", internal="10.0.0.0/24")]) == {}
    assert pa.walled_off_subnets([]) == {}


def test_bare_rule_dicts_are_accepted_too():
    # Callers hold both the summary shape and bare rules.
    assert pa.walled_off_subnets([{"type": "subnet_block", "src": "10.0.1.0/24",
                                   "dst": "10.0.2.0/24"}]) == {"10.0.2.0/24": ["10.0.1.0/24"]}


# --------------------------------------------------------------------------- #
# Provider selection: prefer what already exists, never spend a slot
# --------------------------------------------------------------------------- #

def _subnet_nodes():
    return [
        NodeInfo(node_id=2, ip4="172.21.240.2/24", role="FlagGenSlot"),
        NodeInfo(node_id=5, ip4="172.21.240.5/24", role="VulnerabilitySlot"),
        NodeInfo(node_id=6, ip4="172.21.240.6/24", role="Docker"),
        NodeInfo(node_id=9, ip4="10.0.140.6/24", role="Docker"),   # outside
    ]


def test_a_vulnerability_is_preferred_over_everything_else():
    entries = {
        5: [pa.PivotEntry(kind=pa.ENTRY_VULNERABILITY, port=8080, label="CVE-x")],
        2: [pa.PivotEntry(kind=pa.ENTRY_FLAG_GEN, port=5011)],
        6: [pa.PivotEntry(kind=pa.ENTRY_SSH, port=22)],
    }
    plan = pa.plan_pivot_access([_block()], _subnet_nodes(), entry_points=entries)
    provider = plan.providers[0]
    assert provider.node_id == 5
    assert provider.entry.kind == pa.ENTRY_VULNERABILITY
    assert provider.reused is True
    assert provider.added is False and provider.needs_service is False


def test_flag_generator_is_next_best():
    entries = {
        2: [pa.PivotEntry(kind=pa.ENTRY_FLAG_GEN, port=5011)],
        6: [pa.PivotEntry(kind=pa.ENTRY_SSH, port=22)],
    }
    plan = pa.plan_pivot_access([_block()], _subnet_nodes(), entry_points=entries)
    assert plan.providers[0].node_id == 2
    assert plan.providers[0].entry.kind == pa.ENTRY_FLAG_GEN


def test_existing_ssh_is_used_before_changing_anything():
    entries = {6: [pa.PivotEntry(kind=pa.ENTRY_SSH, port=22)]}
    plan = pa.plan_pivot_access([_block()], _subnet_nodes(), entry_points=entries)
    assert plan.providers[0].node_id == 6
    assert plan.providers[0].reused is True


def test_a_subnet_serving_nothing_gets_an_added_ssh_node():
    # There is no "switch SSH on for whatever Docker node is there" tier: node
    # images are built offline-safe with no package manager, so a minimal image
    # cannot grow an sshd and enabling the service would open a path to a closed
    # port. A node that really serves SSH is tier 3 instead.
    plan = pa.plan_pivot_access([_block()], _subnet_nodes(), entry_points={})
    provider = plan.providers[0]
    assert provider.added is True
    assert provider.needs_service is False
    assert provider.entry.kind == pa.ENTRY_SSH
    assert provider.image == pa.PIVOT_SSH_IMAGE
    assert provider.consumes_slot is False


def test_subnet_of_only_empty_slots_gets_an_added_node():
    hosts = [
        NodeInfo(node_id=2, ip4="172.21.240.2/24", role="FlagGenSlot"),
        NodeInfo(node_id=5, ip4="172.21.240.5/24", role="VulnerabilitySlot"),
    ]
    plan = pa.plan_pivot_access([_block()], hosts, entry_points={})
    provider = plan.providers[0]
    assert provider.added is True
    assert provider.node_id is None
    assert provider.consumes_slot is False
    # No address yet, so no rules can be written for it until it is allocated.
    assert plan.allow_rules == []
    assert plan.added_nodes == [provider]


def test_adding_can_be_refused_and_is_reported_not_silently_dropped():
    hosts = [NodeInfo(node_id=2, ip4="172.21.240.2/24", role="FlagGenSlot")]
    plan = pa.plan_pivot_access([_block()], hosts, entry_points={}, allow_add_nodes=False)
    assert plan.providers == []
    assert len(plan.unresolved) == 1
    assert "adding nodes is disabled" in plan.unresolved[0]["reason"]
    assert plan.unresolved[0]["subnet"] == "172.21.240.0/24"


def test_provider_never_reports_consuming_a_slot():
    entries = {5: [pa.PivotEntry(kind=pa.ENTRY_VULNERABILITY, port=8080)]}
    plan = pa.plan_pivot_access([_block()], _subnet_nodes(), entry_points=entries)
    assert all(p.consumes_slot is False for p in plan.providers)
    assert all(p.as_dict()["consumes_slot"] is False for p in plan.providers)


# --------------------------------------------------------------------------- #
# The allow rules that actually open the path
# --------------------------------------------------------------------------- #

def test_allow_rules_open_the_provider_from_every_blocked_source():
    rules = [_block(src="10.0.140.0/24"), _block(src="10.0.173.0/24")]
    entries = {6: [pa.PivotEntry(kind=pa.ENTRY_SSH, port=22)]}
    plan = pa.plan_pivot_access(rules, _subnet_nodes(), entry_points=entries, router_ids=[1])

    forwards = [r for r in plan.allow_rules if r["rule"]["chain"] == "FORWARD"]
    inputs = [r for r in plan.allow_rules if r["rule"]["chain"] == "INPUT"]
    assert len(forwards) == 2 and len(inputs) == 2
    assert {r["rule"]["src"] for r in forwards} == {"10.0.140.0/24", "10.0.173.0/24"}
    assert all(r["rule"]["dst"] == "172.21.240.6" for r in plan.allow_rules)
    assert all(r["rule"]["port"] == 22 and r["rule"]["proto"] == "tcp" for r in plan.allow_rules)
    # FORWARD lands on the router carrying the block; INPUT on the provider.
    assert all(r["node_id"] == 1 for r in forwards)
    assert all(r["node_id"] == 6 for r in inputs)
    # Tagged so the rule's purpose survives into the runtime summary.
    assert all(r["rule"]["reason"] == "pivot-access" for r in plan.allow_rules)


def test_protect_internal_opens_the_provider_to_everyone():
    rules = [_rule(1, type="protect_internal", subnet="172.21.240.0/24")]
    entries = {6: [pa.PivotEntry(kind=pa.ENTRY_SSH, port=22)]}
    plan = pa.plan_pivot_access(rules, _subnet_nodes(), entry_points=entries, router_ids=[1])
    assert {r["rule"]["src"] for r in plan.allow_rules} == {"0.0.0.0/0"}


def test_a_vulnerability_entry_opens_its_own_port_not_ssh():
    entries = {5: [pa.PivotEntry(kind=pa.ENTRY_VULNERABILITY, port=8080, label="CVE-x")]}
    plan = pa.plan_pivot_access([_block()], _subnet_nodes(), entry_points=entries, router_ids=[1])
    assert {r["rule"]["port"] for r in plan.allow_rules} == {8080}


def test_nothing_blocked_means_nothing_to_do():
    plan = pa.plan_pivot_access([_rule(1, type="nat", internal="10.0.0.0/24")], _subnet_nodes())
    assert plan.providers == [] and plan.allow_rules == []
    assert plan.as_dict()["provider_count"] == 0


def test_added_provider_records_the_image_to_build_from():
    plan = pa.plan_pivot_access([_block()], [], entry_points={})
    assert plan.providers[0].image == pa.PIVOT_SSH_IMAGE
    assert plan.providers[0].as_dict()["image"] == pa.PIVOT_SSH_IMAGE


def test_reused_providers_need_no_image():
    entries = {5: [pa.PivotEntry(kind=pa.ENTRY_VULNERABILITY, port=8080)]}
    plan = pa.plan_pivot_access([_block()], _subnet_nodes(), entry_points=entries)
    assert plan.providers[0].image == ""


def test_each_walled_off_subnet_gets_its_own_provider():
    rules = [
        _block(src="10.0.1.0/24", dst="172.21.240.0/24"),
        _block(src="10.0.1.0/24", dst="10.99.0.0/24"),
    ]
    hosts = _subnet_nodes() + [NodeInfo(node_id=20, ip4="10.99.0.4/24", role="Docker")]
    entries = {6: [pa.PivotEntry(kind=pa.ENTRY_SSH, port=22)],
               20: [pa.PivotEntry(kind=pa.ENTRY_SSH, port=22)]}
    plan = pa.plan_pivot_access(rules, hosts, entry_points=entries)
    assert {p.subnet for p in plan.providers} == {"172.21.240.0/24", "10.99.0.0/24"}
    assert {p.node_id for p in plan.providers} == {6, 20}


# --------------------------------------------------------------------------- #
# Building the entry-point inventory
# --------------------------------------------------------------------------- #

def test_inventory_reads_ports_from_records():
    entries = pa.entry_points_from_inventory(
        vulnerable_nodes={5: [{"name": "CVE-x", "ports": [8080, 8443]}]},
        flag_gen_nodes={2: [{"name": "gen", "port": 5011}]},
        ssh_nodes=[6],
    )
    assert [e.port for e in entries[5]] == [8080, 8443]
    assert all(e.kind == pa.ENTRY_VULNERABILITY for e in entries[5])
    assert entries[2][0].kind == pa.ENTRY_FLAG_GEN and entries[2][0].port == 5011
    assert entries[6][0].kind == pa.ENTRY_SSH and entries[6][0].port == 22


def test_inventory_skips_records_with_no_usable_port():
    entries = pa.entry_points_from_inventory(
        vulnerable_nodes={5: [{"name": "no-port"}, {"name": "bad", "ports": ["x", 0, 99999]}]},
    )
    assert entries == {}


def test_inventory_is_empty_without_input():
    assert pa.entry_points_from_inventory() == {}


# --------------------------------------------------------------------------- #
# The router fallback: a subnet of only empty slots still has a way in
# --------------------------------------------------------------------------- #

def test_a_router_is_never_a_provider():
    # Routers are vnodes: they share the CORE VM filesystem, so SSH on one is a
    # host escape rather than a pivot. A subnet of only empty slots must grow a
    # Docker node instead of borrowing the router sitting right there.
    hosts = [
        NodeInfo(node_id=2, ip4="172.21.240.2/24", role="FlagGenSlot"),
        NodeInfo(node_id=5, ip4="172.21.240.5/24", role="VulnerabilitySlot"),
    ]
    routers = [NodeInfo(node_id=1, ip4="172.21.240.1/24", role="Router")]
    plan = pa.plan_pivot_access([_block()], hosts, routers=routers, entry_points={})
    provider = plan.providers[0]
    assert provider.added is True
    assert provider.node_id is None
    assert provider.role == "Docker"


def test_vnode_hosts_are_not_eligible_either():
    # PC/Server/Workstation are vnodes too, however host-like they look.
    for role in ("PC", "Server", "Workstation"):
        hosts = [NodeInfo(node_id=6, ip4="172.21.240.6/24", role=role)]
        plan = pa.plan_pivot_access([_block()], hosts, entry_points={})
        assert plan.providers[0].added is True, role


def test_a_docker_node_that_already_serves_ssh_is_preferred_over_adding_one():
    hosts = [
        NodeInfo(node_id=2, ip4="172.21.240.2/24", role="FlagGenSlot"),
        NodeInfo(node_id=6, ip4="172.21.240.6/24", role="Docker"),
        NodeInfo(node_id=7, ip4="172.21.240.7/24", role="Server"),
    ]
    routers = [NodeInfo(node_id=1, ip4="172.21.240.1/24", role="Router")]
    entries = {6: [pa.PivotEntry(kind=pa.ENTRY_SSH, port=22)]}
    plan = pa.plan_pivot_access([_block()], hosts, routers=routers, entry_points=entries)
    assert plan.providers[0].node_id == 6
    assert plan.providers[0].added is False
    assert plan.providers[0].reused is True
    # Nothing to build: it already serves SSH.
    assert plan.providers[0].image == ""


def test_an_offer_on_a_vnode_is_ignored():
    # Even an existing service on a vnode must not be used as the way in.
    hosts = [NodeInfo(node_id=7, ip4="172.21.240.7/24", role="Server")]
    entries = {7: [pa.PivotEntry(kind=pa.ENTRY_VULNERABILITY, port=8080)]}
    plan = pa.plan_pivot_access([_block()], hosts, entry_points=entries)
    assert plan.providers[0].added is True
    assert plan.providers[0].reused is False


def test_router_ids_are_derived_so_forward_rules_land_correctly():
    hosts = [NodeInfo(node_id=6, ip4="172.21.240.6/24", role="Docker")]
    routers = [NodeInfo(node_id=1, ip4="172.21.240.1/24", role="Router")]
    entries = {6: [pa.PivotEntry(kind=pa.ENTRY_SSH, port=22)]}
    # router_ids not passed explicitly; they come from the routers themselves.
    plan = pa.plan_pivot_access([_block()], hosts, routers=routers, entry_points=entries)
    forwards = [r for r in plan.allow_rules if r["rule"]["chain"] == "FORWARD"]
    assert forwards and all(r["node_id"] == 1 for r in forwards)


def test_added_node_remains_the_last_resort():
    hosts = [NodeInfo(node_id=2, ip4="172.21.240.2/24", role="FlagGenSlot")]
    plan = pa.plan_pivot_access([_block()], hosts, routers=[], entry_points={})
    assert plan.providers[0].added is True
    # An added provider is a Docker SSH node, never a vnode.
    assert plan.providers[0].role == "Docker"
    assert plan.providers[0].entry.kind == pa.ENTRY_SSH


def test_forward_rules_go_to_every_router_not_just_the_enforcer():
    # Narrowing to the enforcing router is wrong: segmentation leaves every
    # router with -P FORWARD DROP, so a packet that survives the enforcer still
    # dies at an upstream hop. Verified live -- the enforcer passed the SYN and
    # an intermediate router dropped it.
    rules = [_rule(1, type="subnet_block", src="10.0.140.0/24",
                   dst="172.21.240.0/24", default_deny=True)]
    hosts = [NodeInfo(node_id=6, ip4="172.21.240.6/24", role="Docker")]
    routers = [NodeInfo(node_id=i, ip4=f"10.{i}.0.1/24", role="Router") for i in (1, 2, 3, 4, 5)]
    entries = {6: [pa.PivotEntry(kind=pa.ENTRY_SSH, port=22)]}
    plan = pa.plan_pivot_access(rules, hosts, routers=routers, entry_points=entries)
    forwards = [r for r in plan.allow_rules if r["rule"]["chain"] == "FORWARD"]
    assert sorted(r["node_id"] for r in forwards) == [1, 2, 3, 4, 5]


def test_all_routers_are_used_when_the_block_names_no_enforcer():  # noqa: D103
    rules = [{"type": "subnet_block", "src": "10.0.140.0/24", "dst": "172.21.240.0/24"}]
    hosts = [NodeInfo(node_id=6, ip4="172.21.240.6/24", role="Docker")]
    routers = [NodeInfo(node_id=i, ip4=f"10.{i}.0.1/24", role="Router") for i in (1, 2)]
    entries = {6: [pa.PivotEntry(kind=pa.ENTRY_SSH, port=22)]}
    plan = pa.plan_pivot_access(rules, hosts, routers=routers, entry_points=entries)
    forwards = [r for r in plan.allow_rules if r["rule"]["chain"] == "FORWARD"]
    assert sorted(r["node_id"] for r in forwards) == [1, 2]


def test_details_expose_who_enforces_each_block():
    rules = [_rule(1, type="subnet_block", src="10.0.1.0/24", dst="10.0.2.0/24"),
             _rule(4, type="subnet_block", src="10.0.3.0/24", dst="10.0.2.0/24")]
    detail = pa.walled_off_details(rules)["10.0.2.0/24"]
    assert detail["sources"] == ["10.0.1.0/24", "10.0.3.0/24"]
    assert detail["enforced_by"] == [1, 4]
