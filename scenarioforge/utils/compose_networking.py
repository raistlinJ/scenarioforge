"""Whether a raw, as-authored docker-compose stack needs a shared network.

CORE gives every node its own veth, and every generated compose service runs
with `network_mode: none` by default so an exploited node cannot reach a
Docker-managed gateway to the host or another node. That default silently
breaks any multi-service stack whose *own* services talk to each other over
Compose's implicit default network -- nginx reaching a `php` upstream by
service-name DNS is the textbook case, and it is the common one: vulhub
recipes pairing an app with its own db/redis/php-fpm sidecar rarely declare
`depends_on` or `links` for it, because vanilla `docker-compose up` needs
neither -- every service in a compose file shares one network by default.

A real run picked exactly such a recipe (nginx/CVE-2013-4547): nginx crashed
immediately and permanently trying to resolve "php" as an upstream, and CORE's
own daemon then threw an unhandled exception wiring a veth into that already-dead
container's PID -- which aborted the rest of session boot, including starting
the Quagga/FRR daemons on three unrelated routers. One incompatible
vulnerability took the whole scenario down. A scan of the installed vulhub
catalog found 82 of 306 recipes (about a quarter) share this shape.

This has to run against the RAW, upstream compose file -- before ScenarioForge
injects its own `inject_copy` service and the `depends_on` that wires it in,
which would make an explicit-marker check (depends_on/links/networks) true for
almost every multi-service vuln node regardless of whether the *vulnerability's
own* services need to talk to each other. Multi-service-and-not-already-self-isolated
is the accurate signal on the unprocessed file.
"""

from __future__ import annotations

from typing import Any


def compose_stack_needs_shared_network(compose_obj: Any) -> bool:
    """Whether this raw compose stack relies on Compose's default network.

    True for any multi-service stack unless the upstream author already
    isolated every service themselves (each service already sets
    ``network_mode: none``) -- that is an explicit signal the services were
    never meant to reach each other over the network, so nothing here would
    regress by leaving it alone.
    """
    if not isinstance(compose_obj, dict):
        return False
    services = compose_obj.get("services")
    if not isinstance(services, dict):
        return False
    # `inject_copy*` is ScenarioForge's own one-shot helper, not part of the
    # recipe: it only populates a shared volume and talks to nothing. Counting
    # it made every single-service node look like a stack needing
    # service-to-service networking, which then reported "this node is expected
    # to fail" for nodes that were entirely healthy.
    peers = {
        name: svc for name, svc in services.items()
        if not str(name).startswith("inject_copy")
    }
    if len(peers) <= 1:
        return False
    already_isolated = all(
        isinstance(svc, dict) and svc.get("network_mode") == "none"
        for svc in peers.values()
    )
    return not already_isolated


def service_container_ports(service: Any) -> set[str]:
    """Container-side ports a service is expected to bind, from `expose`/`ports`."""
    found: set[str] = set()
    if not isinstance(service, dict):
        return found
    for key in ("expose", "ports"):
        raw = service.get(key)
        if raw is None:
            continue
        entries = raw if isinstance(raw, list) else [raw]
        for entry in entries:
            text = str(entry or "").strip()
            if not text:
                continue
            # "8080:80", "80", "127.0.0.1:8080:80/tcp", "80/tcp"
            text = text.split("/", 1)[0]
            container_port = text.rsplit(":", 1)[-1].strip()
            if container_port:
                found.add(container_port)
    return found


def _depends_on_names(service: Any) -> set[str]:
    """Service names this one declares a Compose dependency on."""
    if not isinstance(service, dict):
        return set()
    raw = service.get("depends_on")
    if isinstance(raw, dict):
        return {str(k) for k in raw}
    if isinstance(raw, list):
        return {str(v) for v in raw}
    if raw:
        return {str(raw)}
    return set()


def compose_stack_shared_netns_plan(compose_obj: Any, main_service: str | None = None) -> dict:
    """How to fit this stack into one network namespace, or why it cannot.

    One namespace is one port space, so two services binding the same container
    port collide. In practice that shape is not an app plus a sidecar at all --
    it is a recipe shipping *two independent instances* side by side for
    comparison (vulhub's `php/xdebug-rce` runs xdebug 2 and xdebug 3; its
    `ecshop/xianzhi-...` runs ecshop 2.7.3 and 3.6.0, both against one shared
    mysql). A CORE node is a single host with a single address, so only one of
    those instances can be it.

    Rather than discarding the whole recipe, the duplicate instance is dropped
    and the rest -- including any genuine sidecar the survivor needs -- is kept.
    Dropping is refused when something being kept depends on the service, since
    that would leave a dangling `depends_on` and a broken stack.

    Returns ``{"drop": [names], "blockers": [ports]}``. ``blockers`` is empty
    when the stack can be made to work. Kept here rather than in
    ``vuln_process`` so catalog/manifest discovery can ask without importing
    that far heavier module.
    """
    empty: dict = {"drop": [], "blockers": []}
    if not isinstance(compose_obj, dict):
        return empty
    services = compose_obj.get("services")
    if not isinstance(services, dict) or len(services) <= 1:
        return empty

    considered = [
        name for name, svc in services.items()
        if isinstance(svc, dict) and not str(name).startswith("inject_copy")
    ]
    # The node's own service is never a candidate for dropping; without one
    # named, fall back to file order so the answer stays deterministic.
    primary = str(main_service) if main_service in considered else None
    ordered = ([primary] if primary else []) + [n for n in considered if n != primary]

    claimed: dict[str, str] = {}
    drop: list[str] = []
    blockers: set[str] = set()
    for name in ordered:
        ports = service_container_ports(services[name])
        clashing = sorted(p for p in ports if p in claimed)
        if not clashing:
            for port in ports:
                claimed[port] = name
            continue
        # Something already owns these ports. Drop this duplicate instance --
        # unless a service we are keeping needs it.
        needed_by = [
            other for other in considered
            if other != name and other not in drop and name in _depends_on_names(services[other])
        ]
        if needed_by:
            blockers.update(clashing)
            continue
        drop.append(name)
    return {"drop": drop, "blockers": sorted(blockers)}


def compose_stack_shared_netns_blockers(compose_obj: Any, main_service: str | None = None) -> list[str]:
    """Ports that stop this stack from sharing one namespace, after dropping
    any duplicate instance that safely can be. Empty when it can be made to work."""
    return compose_stack_shared_netns_plan(compose_obj, main_service)["blockers"]
