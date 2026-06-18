from __future__ import annotations
import ipaddress
from types import SimpleNamespace
from typing import Any

from scenarioforge.types import NodeInfo
import scenarioforge.utils.hitl as hitl_mod
from scenarioforge.utils.hitl import attach_hitl_rj45_nodes
from scenarioforge.builders.topology import NodeType, Position, Interface


class OptionsDict(dict):
    def set(self, name: str, value: str) -> None:
        self[name] = value

    def set_value(self, name: str, value: str) -> None:
        self[name] = value


class StubSession:
    def __init__(self) -> None:
        self.nodes: dict[int, Any] = {}
        self.links: list[tuple[int, int, Any, Any]] = []
        self.session_options: OptionsDict = OptionsDict()
        self.services = _StubServices()

    def add_service(self, node_id: int, service_name: str) -> None:
        self.services.add(node_id, service_name)

    def add_node(self, node_id: int, _type: Any = None, position: Any = None, name: str | None = None) -> Any:
        node = SimpleNamespace(id=node_id, name=name or f"node-{node_id}", type=_type, position=position, ifaces=[], options=None)
        self.nodes[node_id] = node
        return node

    def get_node(self, node_id: int) -> Any:
        return self.nodes[node_id]

    def add_link(self, *args, **kwargs) -> None:
        node1 = kwargs.get("node1")
        node2 = kwargs.get("node2")
        if node1 is None and args:
            node1 = self._resolve_node(args[0])
        if node2 is None and len(args) > 1:
            node2 = self._resolve_node(args[1])
        if node1 is None:
            node1 = self._resolve_node(kwargs.get("node1_id"))
        if node2 is None:
            node2 = self._resolve_node(kwargs.get("node2_id"))
        iface1 = kwargs.get("iface1")
        iface2 = kwargs.get("iface2")
        if iface1 is not None:
            node1.ifaces.append(iface1)
        if iface2 is not None:
            node2.ifaces.append(iface2)
        self.links.append((node1.id, node2.id, iface1, iface2))

    def edit_node(self, node_id: int, options: Any = None) -> Any:
        node = self.nodes[node_id]
        node.options = options
        return node

    def delete_node(self, node_id: int) -> None:
        self.nodes.pop(node_id, None)

    def _resolve_node(self, value: Any) -> Any:
        if value is None:
            raise ValueError("node reference required")
        if hasattr(value, "id"):
            return value
        return self.nodes[int(value)]


class _StubServices:
    def __init__(self) -> None:
        self._by_node_id: dict[int, list[str]] = {}

    def get(self, node_id_or_obj: Any) -> tuple[str, ...]:
        node_id = int(getattr(node_id_or_obj, "id", node_id_or_obj))
        return tuple(self._by_node_id.get(node_id, []))

    def set(self, node_id_or_obj: Any, services: tuple[str, ...]) -> None:
        node_id = int(getattr(node_id_or_obj, "id", node_id_or_obj))
        self._by_node_id[node_id] = list(services)

    def add(self, node_id_or_obj: Any, service_name: str) -> None:
        node_id = int(getattr(node_id_or_obj, "id", node_id_or_obj))
        cur = self._by_node_id.setdefault(node_id, [])
        if service_name not in cur:
            cur.append(service_name)

    def clear(self, node_id_or_obj: Any) -> None:
        node_id = int(getattr(node_id_or_obj, "id", node_id_or_obj))
        self._by_node_id[node_id] = []


def test_attach_hitl_rj45_nodes_creates_router_when_requested(monkeypatch) -> None:
    session = StubSession()
    routers: list[NodeInfo] = []
    hosts: list[NodeInfo] = []
    hitl_config = {
        "enabled": True,
        "interfaces": [
            {"name": "eth1", "attachment": "new_router"},
        ],
        "scenario_key": "RouterPref",
    }

    def _fixed_rng(seed: str):
        def _next() -> float:
            return 0.0

        return _next

    monkeypatch.setattr(hitl_mod, "_make_deterministic_rng", _fixed_rng)

    summary = attach_hitl_rj45_nodes(session, routers, hosts, hitl_config)

    entry = summary["interfaces"][0]
    assert entry["assignment"] == "router"
    assert entry["attachment"] == "new_router"
    assert entry["linked"] is True

    created_router_ids = summary.get("created_router_nodes", [])
    assert created_router_ids, "expected a new router node to be created"
    router_id = created_router_ids[0]
    assert router_id == entry["target_node_id"] == entry.get("router_node_id")
    assert router_id in session.nodes

    router_node = session.nodes[router_id]
    assert getattr(router_node, "type", None) == getattr(NodeType, "ROUTER", getattr(NodeType, "DEFAULT", None))
    assert any({entry["rj45_node_id"], router_id} == {link[0], link[1]} for link in session.links)


def test_attach_hitl_rj45_nodes_creates_link_and_option() -> None:
    session = StubSession()
    router_type = getattr(NodeType, "ROUTER", getattr(NodeType, "DEFAULT", None))
    router = session.add_node(10, _type=router_type, position=Position(x=250, y=250), name="router-1")
    router.ifaces.append(Interface(id=0, name="eth0"))

    routers = [NodeInfo(node_id=router.id, ip4="10.0.0.1/24", role="Router")]
    hosts: list[NodeInfo] = []
    hitl_config = {
        "enabled": True,
        "interfaces": [
            {"name": "en0", "mac": "aa:bb:cc:dd:ee:ff", "attachment": "existing_router"},
        ],
        "scenario_key": "Demo",
    }

    summary = attach_hitl_rj45_nodes(session, routers, hosts, hitl_config)

    assert summary["enabled"] is True
    assert summary["session_option_enabled"] is True
    assert summary["interfaces"][0]["linked"] is True
    assert summary["interfaces"][0]["peer_node_id"] == router.id
    assert summary["interfaces"][0]["attachment"] == "existing_router"
    created_id = summary["created_nodes"][0]
    hitl_node = session.nodes[created_id]
    assert getattr(hitl_node.options, "interface", None) == "en0"
    assert (router.id, created_id) in {(a, b) for a, b, *_ in session.links} or (created_id, router.id) in {(a, b) for a, b, *_ in session.links}
    assert session.session_options["enablerj45"] == "1"


def test_attach_hitl_rj45_nodes_skips_unresolved_proxmox_interface_ids() -> None:
    session = StubSession()
    router_type = getattr(NodeType, "ROUTER", getattr(NodeType, "DEFAULT", None))
    router = session.add_node(10, _type=router_type, position=Position(x=250, y=250), name="router-1")
    routers = [NodeInfo(node_id=router.id, ip4="10.0.0.1/24", role="Router")]
    hitl_config = {
        "enabled": True,
        "interfaces": [
            {
                "name": "net0",
                "attachment": "existing_router",
                "core_bridge": "vmbr-core",
                "proxmox_target": {"interface_id": "net0", "bridge": "vmbr-core"},
            },
        ],
        "scenario_key": "Demo",
    }

    summary = attach_hitl_rj45_nodes(session, routers, [], hitl_config)

    assert summary["created_nodes"] == []
    assert summary["interfaces"][0]["created"] is False
    assert summary["interfaces"][0]["reason"] == "unresolved-proxmox-interface-id"


def test_validate_hitl_interface_names_for_execute_accepts_explicit_guest_ifnames(monkeypatch) -> None:
    from webapp import app_backend as backend

    monkeypatch.setattr(
        backend,
        '_enumerate_core_vm_interfaces_from_secret',
        lambda secret_id, **kwargs: [
            {
                'name': 'ens18',
                'mac': 'aa:bb:cc:dd:ee:ff',
                'bridge': 'vmbr-core',
                'proxmox': {
                    'id': 'net0',
                    'macaddr': 'aa:bb:cc:dd:ee:ff',
                    'bridge': 'vmbr-core',
                },
            }
        ],
    )

    resolved, errors, changes = backend._validate_hitl_interface_names_for_execute(
        {
            'enabled': True,
            'interfaces': [
                {
                    'name': 'ens18',
                    'attachment': 'existing_router',
                    'proxmox_target': {
                        'interface_id': 'net0',
                        'macaddr': 'aa:bb:cc:dd:ee:ff',
                    },
                }
            ],
        },
        {
            'core_secret_id': 'core-secret-1',
            'ssh_enabled': True,
        },
    )

    assert errors == []
    assert changes == []
    assert resolved['interfaces'][0]['name'] == 'ens18'
    assert resolved['interfaces'][0]['attachment'] == 'existing_router'


def test_validate_hitl_interface_names_for_execute_resolves_net_slot_selectors(monkeypatch) -> None:
    from webapp import app_backend as backend

    monkeypatch.setattr(
        backend,
        '_enumerate_core_vm_interfaces_from_secret',
        lambda secret_id, **kwargs: [
            {
                'name': 'ens18',
                'ifindex': 2,
                'bridge': 'vmbr-core',
                'proxmox': {'id': 'net0', 'bridge': 'vmbr-core'},
            },
            {
                'name': 'ens19',
                'ifindex': 3,
                'bridge': 'vmbr-core',
                'proxmox': {'id': 'net1', 'bridge': 'vmbr-core'},
            }
        ],
    )

    resolved, errors, changes = backend._validate_hitl_interface_names_for_execute(
        {
            'enabled': True,
            'interfaces': [
                {
                    'name': 'net1',
                    'attachment': 'existing_router',
                }
            ],
        },
        {
            'core_secret_id': 'core-secret-1',
            'ssh_enabled': True,
        },
    )

    assert errors == []
    assert resolved['interfaces'][0]['name'] == 'ens19'
    assert changes == [{'index': 0, 'from': 'net1', 'to': 'ens19', 'selector': 'net1'}]


def test_validate_hitl_interface_names_for_execute_rejects_out_of_range_slot_selector(monkeypatch) -> None:
    from webapp import app_backend as backend

    monkeypatch.setattr(
        backend,
        '_enumerate_core_vm_interfaces_from_secret',
        lambda secret_id, **kwargs: [
            {'name': 'ens18', 'ifindex': 2},
            {'name': 'ens19', 'ifindex': 3},
        ],
    )

    resolved, errors, changes = backend._validate_hitl_interface_names_for_execute(
        {
            'enabled': True,
            'interfaces': [
                {
                    'name': 'net2',
                    'attachment': 'existing_router',
                }
            ],
        },
        {
            'core_secret_id': 'core-secret-1',
            'ssh_enabled': True,
        },
    )

    assert resolved['interfaces'][0]['name'] == 'net2'
    assert changes == []
    assert len(errors) == 1
    assert 'did not match any CORE VM interface discovered over SSH' in errors[0]


def test_attach_hitl_new_router_clones_peer_router_services(monkeypatch) -> None:
    session = StubSession()
    router_type = getattr(NodeType, "ROUTER", getattr(NodeType, "DEFAULT", None))
    peer_router = session.add_node(10, _type=router_type, position=Position(x=250, y=250), name="router-1")

    # Give the peer router a representative routing stack.
    for svc in ("IPForward", "zebra", "OSPFv2", "OSPFv3", "RIP"):
        session.services.add(peer_router.id, svc)

    routers = [NodeInfo(node_id=peer_router.id, ip4="10.0.0.1/24", role="Router")]
    hosts: list[NodeInfo] = []
    hitl_config = {
        "enabled": True,
        "interfaces": [
            {"name": "eth1", "attachment": "new_router"},
        ],
        "scenario_key": "RouterPref",
    }

    def _fixed_rng(seed: str):
        def _next() -> float:
            return 0.0

        return _next

    monkeypatch.setattr(hitl_mod, "_make_deterministic_rng", _fixed_rng)

    summary = attach_hitl_rj45_nodes(session, routers, hosts, hitl_config)

    created_router_ids = summary.get("created_router_nodes", [])
    assert created_router_ids, "expected a new router node to be created"
    new_router_id = created_router_ids[0]

    peer_services = set(session.services.get(peer_router.id))
    new_services = set(session.services.get(new_router_id))

    assert new_services == peer_services


def test_hitl_get_node_services_normalizes_service_objects() -> None:
    class _Svc:
        def __init__(self, name: str) -> None:
            self.name = name

    class _Services:
        def get(self, node_id_or_obj):
            return (_Svc("IPForward"), _Svc("zebra"), _Svc("RIP"))

    class _Session:
        services = _Services()

    names = hitl_mod._get_node_services_best_effort(_Session(), 1, None)
    assert set(names) == {"IPForward", "zebra", "RIP"}


def test_attach_hitl_new_router_falls_back_to_peer_routing_protocol(monkeypatch) -> None:
    # Force the service read helper to return empty, simulating wrappers that can set
    # services but cannot read them.
    monkeypatch.setattr(hitl_mod, "_get_node_services_best_effort", lambda *args, **kwargs: [])

    session = StubSession()
    router_type = getattr(NodeType, "ROUTER", getattr(NodeType, "DEFAULT", None))
    peer_router = session.add_node(10, _type=router_type, position=Position(x=250, y=250), name="router-1")
    setattr(peer_router, "routing_protocol", "RIP")

    routers = [NodeInfo(node_id=peer_router.id, ip4="10.0.0.1/24", role="Router")]
    hosts: list[NodeInfo] = []
    hitl_config = {
        "enabled": True,
        "interfaces": [{"name": "eth1", "attachment": "new_router"}],
        "scenario_key": "RouterPref",
    }

    def _fixed_rng(seed: str):
        def _next() -> float:
            return 0.0

        return _next

    monkeypatch.setattr(hitl_mod, "_make_deterministic_rng", _fixed_rng)

    summary = attach_hitl_rj45_nodes(session, routers, hosts, hitl_config)
    created_router_ids = summary.get("created_router_nodes", [])
    assert created_router_ids
    new_router_id = created_router_ids[0]

    # Should include RIP when peer routing_protocol is RIP.
    assert set(session.services.get(new_router_id)) == {"IPForward", "zebra", "RIP"}


def test_hitl_preview_router_added_to_full_preview(monkeypatch) -> None:
    from webapp import app_backend as backend

    monkeypatch.setattr(
        backend,
        'predict_hitl_link_ips_unique',
        lambda scenario_key, iface_name, idx, used: {
            'network': '10.254.100.0',
            'network_cidr': '10.254.100.0/24',
            'prefix_len': 24,
            'netmask': '255.255.255.0',
            'existing_router_ip4': '10.254.100.1',
            'new_router_ip4': '10.254.100.2',
            'rj45_ip4': '10.254.100.3',
        },
    )

    hitl_cfg = backend._sanitize_hitl_config(
        {
            'enabled': True,
            'interfaces': [{'name': 'uplink0', 'attachment': 'new_router'}],
        },
        'DemoScenario',
        'demo_scenario',
    )

    preview_routers = hitl_cfg.get('preview_routers') or []
    assert preview_routers, 'expected preview routers in sanitized HITL config'
    preview_router = preview_routers[0]
    assert preview_router['ip4'] == '10.254.100.2/24'
    assert preview_router['metadata'].get('hitl_preview') is True

    full_preview = {
        'routers': [
            {
                'node_id': 101,
                'name': 'r1',
                'role': 'router',
                'kind': 'router',
                'ip4': '10.0.0.1',
                'r2r_interfaces': {},
                'vulnerabilities': [],
                'is_base_bridge': False,
                'metadata': {},
            }
        ]
    }

    backend._merge_hitl_preview_with_full_preview(full_preview, hitl_cfg)

    router_names = [router['name'] for router in full_preview['routers']]
    assert any(name.startswith('hitl-router-') for name in router_names), 'expected HITL router in preview routers list'
    assert full_preview.get('hitl_router_count', 0) >= 1

    hitl_entry = next(router for router in full_preview['routers'] if router.get('metadata', {}).get('hitl_preview'))
    existing_entry = next(router for router in full_preview['routers'] if router.get('node_id') == 101)
    hitl_node_id = hitl_entry['node_id']

    assert hitl_entry['metadata'].get('peer_router_node_id') == 101
    assert hitl_entry['r2r_interfaces'].get(str(101)) == '10.254.100.2/24'
    assert existing_entry['r2r_interfaces'].get(str(hitl_node_id)) == '10.254.100.1/24'

    edges = full_preview.get('r2r_edges_preview', [])
    normalized_edges = {tuple(sorted(edge)) for edge in edges}
    assert (101, hitl_node_id) in normalized_edges

    links = full_preview.get('r2r_links_preview', [])
    assert any(link.get('hitl_preview') and {router['id'] for router in link.get('routers', [])} == {101, hitl_node_id} for link in links)

    subnets = full_preview.get('r2r_subnets', [])
    assert '10.254.100.0/24' in subnets

    degree_preview = full_preview.get('r2r_degree_preview', {})
    assert degree_preview.get(101) == 1
    assert degree_preview.get(hitl_node_id) == 1


def test_hitl_config_prefers_explicit_ipv4_for_new_router_preview() -> None:
    from webapp import app_backend as backend

    hitl_cfg = backend._sanitize_hitl_config(
        {
            'enabled': True,
            'interfaces': [
                {
                    'name': 'uplink0',
                    'attachment': 'new_router',
                    'ipv4': ['192.0.2.10/24'],
                },
            ],
        },
        'PriorityScenario',
        'priority_scenario',
    )

    iface_entry = hitl_cfg['interfaces'][0]
    assert iface_entry.get('link_network_cidr') == '192.0.2.0/24'
    assert iface_entry.get('existing_router_ip4') == '192.0.2.1'
    assert iface_entry.get('new_router_ip4') == '192.0.2.2'
    assert iface_entry.get('rj45_ip4') == '192.0.2.10'
    assert iface_entry.get('ipv4') == ['192.0.2.10/24']

    preview_routers = hitl_cfg.get('preview_routers') or []
    assert preview_routers
    assert preview_routers[0].get('ip4') == '192.0.2.2/24'


def test_build_full_preview_reserves_explicit_hitl_subnet_and_ips() -> None:
    from scenarioforge.planning.full_preview import build_full_preview
    from webapp import app_backend as backend

    hitl_cfg = backend._sanitize_hitl_config(
        {
            'enabled': True,
            'interfaces': [
                {
                    'name': 'uplink0',
                    'attachment': 'existing_router',
                    'ipv4': ['10.1.5.10/24'],
                },
            ],
        },
        'ReservedScenario',
        'reserved_scenario',
    )

    reservations = hitl_mod.collect_hitl_preview_ip_reservations(hitl_cfg)
    preview = build_full_preview(
        role_counts={'Host': 3},
        routers_planned=1,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy={'mode': 'Exact', 'target_per_router': 1},
        routing_items=None,
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        traffic_plan=None,
        seed=77,
        ip4_prefix='10.1.5.0/24',
        reserved_ipv4_addrs=sorted(reservations['ip_addresses']),
        reserved_ipv4_networks=sorted(reservations['network_cidrs']),
    )
    backend._apply_hitl_config_to_full_preview(preview, hitl_cfg, 'ReservedScenario')

    reserved_net = ipaddress.ip_network('10.1.5.0/24', strict=False)
    reserved_ips = {'10.1.5.1', '10.1.5.2', '10.1.5.10'}

    for router in preview.get('routers', []):
        metadata = router.get('metadata') or {}
        ip4 = router.get('ip4')
        if not ip4 or metadata.get('hitl_preview'):
            continue
        iface = ipaddress.ip_interface(str(ip4))
        assert iface.ip not in reserved_net
        assert str(iface.ip) not in reserved_ips

    for host in preview.get('hosts', []):
        ip4 = host.get('ip4')
        if not ip4:
            continue
        iface = ipaddress.ip_interface(str(ip4))
        assert iface.ip not in reserved_net
        assert str(iface.ip) not in reserved_ips

    for detail in preview.get('switches_detail', []):
        router_ip = detail.get('router_ip')
        if router_ip:
            iface = ipaddress.ip_interface(str(router_ip))
            assert iface.ip not in reserved_net
            assert str(iface.ip) not in reserved_ips
        for cidr in (detail.get('host_if_ips') or {}).values():
            iface = ipaddress.ip_interface(str(cidr))
            assert iface.ip not in reserved_net
            assert str(iface.ip) not in reserved_ips

    for subnet_key in ('router_switch_subnets', 'lan_subnets', 'ptp_subnets'):
        for subnet in preview.get(subnet_key, []):
            assert not ipaddress.ip_network(str(subnet), strict=False).overlaps(reserved_net)

    for link in preview.get('r2r_links_preview', []):
        subnet = link.get('subnet')
        if not subnet:
            continue
        link_net = ipaddress.ip_network(str(subnet), strict=False)
        if link.get('hitl_preview'):
            assert link_net == reserved_net
            continue
        assert not link_net.overlaps(reserved_net)


def test_hitl_config_normalizes_new_switch_attachment() -> None:
    from webapp import app_backend as backend

    hitl_cfg = backend._sanitize_hitl_config(
        {
            'enabled': True,
            'interfaces': [
                {'name': 'uplink-switch0', 'attachment': 'new_switch'},
            ],
        },
        'SwitchScenario',
        'switch_scenario',
    )

    iface_entry = hitl_cfg['interfaces'][0]
    assert iface_entry['attachment'] == 'existing_router'
    assert not hitl_cfg.get('preview_switches')


def test_hitl_existing_router_attachment_populates_router_interfaces(monkeypatch) -> None:
    from webapp import app_backend as backend

    monkeypatch.setattr(
        backend,
        'predict_hitl_link_ips_unique',
        lambda scenario_key, iface_name, idx, used: {
            'network': '10.254.200.0',
            'network_cidr': '10.254.200.0/24',
            'prefix_len': 24,
            'netmask': '255.255.255.0',
            'existing_router_ip4': '10.254.200.1',
            'new_router_ip4': '10.254.200.2',
            'rj45_ip4': '10.254.200.3',
        },
    )

    hitl_cfg = backend._sanitize_hitl_config(
        {
            'enabled': True,
            'interfaces': [
                {'name': 'uplink1', 'attachment': 'existing_router'},
            ],
        },
        'ExistingRouterScenario',
        'existing_router_scenario',
    )

    iface_entry = hitl_cfg['interfaces'][0]
    assert iface_entry.get('existing_router_ip4') == '10.254.200.1'
    assert iface_entry.get('rj45_ip4') == '10.254.200.3'

    full_preview = {
        'routers': [
            {
                'node_id': 301,
                'name': 'r-existing',
                'role': 'router',
                'kind': 'router',
                'ip4': '10.0.0.1/24',
                'r2r_interfaces': {},
                'vulnerabilities': [],
                'is_base_bridge': False,
                'metadata': {},
            }
        ],
        'r2r_links_preview': [],
    }

    backend._merge_hitl_preview_with_full_preview(full_preview, hitl_cfg)

    router_entry = full_preview['routers'][0]
    slug = iface_entry.get('slug') or 'uplink1'
    hitl_keys = [key for key in router_entry['r2r_interfaces'].keys() if key == slug]
    assert hitl_keys, 'expected HITL RJ45 interface on router'
    peer_key = hitl_keys[0]
    assert router_entry['r2r_interfaces'][peer_key] == '10.254.200.1/24'

    metadata_list = router_entry['metadata'].get('hitl_existing_router_interfaces') or []
    assert metadata_list, 'expected router metadata for HITL interface'
    metadata_entry = metadata_list[0]
    assert metadata_entry['ip'] == '10.254.200.1/24'
    assert metadata_entry['rj45_ip'] == '10.254.200.3/24'
    assert metadata_entry['router_id'] == 301

    assert hitl_cfg['interfaces'][0]['target_router_id'] == 301
    assert hitl_cfg['interfaces'][0]['existing_router_ip4_cidr'] == '10.254.200.1/24'

    links = full_preview.get('r2r_links_preview', [])
    assert any(
        link.get('hitl_attachment') == 'existing_router'
        and any(router.get('id') == peer_key for router in link.get('routers', []))
        for link in links
    )


def test_attach_hitl_rj45_nodes_can_attach_to_switch(monkeypatch) -> None:
    session = StubSession()
    switch_type = getattr(NodeType, "SWITCH", getattr(NodeType, "DEFAULT", None))
    switch = session.add_node(5, _type=switch_type, position=Position(x=100, y=100), name="agg-sw")
    routers: list[NodeInfo] = []
    hosts: list[NodeInfo] = []
    hitl_config = {
        "enabled": True,
        "interfaces": [
            {"name": "enp3s0", "attachment": "existing_switch"},
        ],
        "scenario_key": "SwitchPref",
    }

    def _fixed_rng(seed: str):  # Always select switch path
        values = iter([0.0, 0.0, 0.0])

        def _next() -> float:
            try:
                return next(values)
            except StopIteration:
                return 0.1

        return _next

    monkeypatch.setattr(hitl_mod, "_make_deterministic_rng", _fixed_rng)

    summary = attach_hitl_rj45_nodes(session, routers, hosts, hitl_config)

    entry = summary["interfaces"][0]
    assert entry["assignment"] == "switch"
    assert entry["target_node_id"] == switch.id
    assert entry["attachment"] == "existing_switch"
    assert entry["linked"] is True
    assert session.links



def test_attach_hitl_rj45_nodes_assigns_ipv4_for_new_router(monkeypatch) -> None:
    session = StubSession()
    existing_router = session.add_node(5, _type=getattr(NodeType, "ROUTER", getattr(NodeType, "DEFAULT", None)), position=Position(x=100, y=100), name="edge-router")
    existing_router.ifaces.append(Interface(id=0, name="eth0"))

    routers = [NodeInfo(node_id=existing_router.id, ip4="10.0.0.1/24", role="Router")]
    hosts: list[NodeInfo] = []
    hitl_config = {
        "enabled": True,
        "interfaces": [
            {"name": "en5", "attachment": "new_router"},
        ],
        "scenario_key": "IpAssignment",
    }

    def _fixed_rng(seed: str):
        def _next() -> float:
            return 0.0

        return _next

    monkeypatch.setattr(hitl_mod, "_make_deterministic_rng", _fixed_rng)

    summary = attach_hitl_rj45_nodes(session, routers, hosts, hitl_config)

    entry = summary["interfaces"][0]
    assert entry["assignment"] == "router"
    assert entry.get("link_network_cidr")
    assert entry.get("existing_router_ip4")
    assert entry.get("new_router_ip4")
    assert entry.get("rj45_ip4")
    assert entry.get("prefix_len") == 24

    router_id = entry["router_node_id"]
    router_node = session.nodes[router_id]
    assert any(getattr(iface, "ip4", None) for iface in router_node.ifaces)
    assert any(getattr(iface, "ip4_mask", None) == 24 for iface in router_node.ifaces)

    rj45_node = session.nodes[entry["rj45_node_id"]]
    assert any(getattr(iface, "ip4", None) == entry["rj45_ip4"] for iface in rj45_node.ifaces)


def test_attach_hitl_rj45_nodes_prefers_explicit_ipv4_for_existing_router() -> None:
    session = StubSession()
    router_type = getattr(NodeType, "ROUTER", getattr(NodeType, "DEFAULT", None))
    router = session.add_node(10, _type=router_type, position=Position(x=250, y=250), name="router-1")
    router.ifaces.append(Interface(id=0, name="eth0"))

    routers = [NodeInfo(node_id=router.id, ip4="10.0.0.1/24", role="Router")]
    hitl_config = {
        "enabled": True,
        "interfaces": [
            {
                "name": "en0",
                "attachment": "existing_router",
                "ipv4": ["192.0.2.10/24"],
            },
        ],
        "scenario_key": "PreferredIp",
    }

    summary = attach_hitl_rj45_nodes(session, routers, [], hitl_config)

    entry = summary["interfaces"][0]
    assert entry.get("link_network_cidr") == "192.0.2.0/24"
    assert entry.get("existing_router_ip4") == "192.0.2.1"
    assert entry.get("new_router_ip4") == "192.0.2.2"
    assert entry.get("rj45_ip4") == "192.0.2.10"

    rj45_node = session.nodes[entry["rj45_node_id"]]
    assert any(getattr(iface, "ip4", None) == "192.0.2.10" for iface in rj45_node.ifaces)


def test_attach_hitl_new_router_reuses_preview_router(monkeypatch) -> None:
    session = StubSession()
    router_type = getattr(NodeType, "ROUTER", getattr(NodeType, "DEFAULT", None))
    peer_router = session.add_node(5, _type=router_type, position=Position(x=100, y=100), name="router-5")
    preview_router = session.add_node(860421, _type=router_type, position=Position(x=200, y=200), name="hitl-router-ens19")
    session.links.append((peer_router.id, preview_router.id, Interface(id=0, name="r5-proto-860421"), Interface(id=0, name="r860421-proto-5")))

    routers = [
        NodeInfo(node_id=peer_router.id, ip4="10.0.0.1/24", role="Router"),
        NodeInfo(node_id=preview_router.id, ip4="10.254.99.2/24", role="Router"),
    ]
    hitl_config = {
        "enabled": True,
        "interfaces": [{"name": "ens19", "attachment": "new_router"}],
        "scenario_key": "PreviewReuse",
    }

    monkeypatch.setattr(
        hitl_mod,
        "_compute_hitl_link_ips_unique",
        lambda *args, **kwargs: {
            "network": "10.254.99.0",
            "network_cidr": "10.254.99.0/24",
            "prefix_len": 24,
            "existing_router_ip4": "10.254.99.1",
            "new_router_ip4": "10.254.99.2",
            "rj45_ip4": "10.254.99.3",
        },
    )

    summary = attach_hitl_rj45_nodes(session, routers, [], hitl_config)

    entry = summary["interfaces"][0]
    assert entry["assignment"] == "router"
    assert entry["router_node_id"] == preview_router.id
    assert entry["target_node_id"] == preview_router.id
    assert entry["reused_router_node"] is True
    assert summary.get("created_router_nodes", []) == []
    assert [node.name for node in session.nodes.values()].count("hitl-router-ens19") == 1

    new_links = [link for link in session.links if {link[0], link[1]} == {entry["rj45_node_id"], preview_router.id}]
    assert len(new_links) == 1
    assert any(getattr(iface, "ip4", None) == "10.254.99.2" for iface in preview_router.ifaces)
