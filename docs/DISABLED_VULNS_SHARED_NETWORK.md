# Multi-Service Vulnerabilities Under CORE-Only Networking

> **Snapshot, not a live view.** Counts reflect the vulhub catalog installed at
> `outputs/installed_vuln_catalogs/05-27-26-14-40-12-f61521` and the generator
> packs under `outputs/installed_generators` as of 2026-08-09. Both are local,
> machine-specific state (not version controlled), so a different catalog
> install or a future vulhub sync can change these numbers. Recompute with
> `tests/test_compose_shared_network_exclusion.py`'s batch scans, or
> `load_vuln_catalog()` / `discover_generator_manifests()` directly.

## Summary

| Catalog | Total | Disabled | Selectable |
| --- | ---: | ---: | ---: |
| Vulnerabilities | 295 | **0** | 295 |
| flag-generators | 60 | **0** | 60 |
| flag-node-generators | 87 | **0** | 87 |

*(One flag-generator, `binary_embed_text`, is disabled for an unrelated,
pre-existing reason — not this check.)*

## What the problem was

ScenarioForge runs every generated Docker service with `network_mode: none`, so
an exploited node cannot reach the host or another node through a
Docker-managed gateway. A vulnerability whose app talks to its **own** sidecar
by service name — nginx → php-fpm, app → db, app → redis — could then never
reach it and crash-looped permanently.

That is not merely a broken node. In a real eval run, `nginx/CVE-2013-4547`
crashed on `host not found in upstream "php"`, and CORE's own daemon then threw
an unhandled exception wiring a veth into the dead container's stale PID —
which aborted the rest of session boot, including starting the Quagga/FRR
daemons on three unrelated routers. **One incompatible vulnerability took the
whole scenario down.**

This affects roughly a quarter of the vulhub catalog, because a plain
multi-service compose file needs no `depends_on`, `links` or `networks` entry
for service-name DNS to work under vanilla `docker-compose up` — every service
shares one network by default.

## How it is fixed

Sidecars join the node's **own network namespace** (`network_mode:
service:<node>`) and reach each other over loopback. `extra_hosts` maps each
sidecar's service name to `127.0.0.1`, so the recipe's own configuration
(`fastcgi_pass php:9000`) resolves unchanged with no edits to the vulnerability
content.

Two ordering details make this work, both found by exercising the real
generation pipeline rather than the transform alone:

- the repair runs **after** the alias step that renames the node's service to
  its CORE name, so the sidecars' `network_mode: service:<node>` names the right
  service;
- the "does this stack need service networking?" verdict is captured **before**
  the transform that forces every service to `network_mode: none`, which would
  otherwise make the answer `False` by the time the repair is reached.

A namespace-sharing sidecar is also started explicitly during preflight.
`docker compose up -d <node>` — what CORE runs — starts only the node and what
the node depends on, and the dependency here runs the other way (the sidecar
joins the node's namespace, so it depends on the node). Declaring it in reverse
is a cycle Compose rejects outright (`dependency cycle detected`), so without
that explicit start the node comes up alone and every request to its own
sidecar is refused.

Isolation is preserved exactly as before — verified directly against Docker:

| Property | Result |
| --- | --- |
| Sidecar reachable by service name | yes |
| Interfaces in the namespace | `lo` only — CORE still owns `eth0` |
| Routing table | empty — no gateway |
| Internet reachable | no |
| Services on the Docker host reachable | no |

A Docker `internal: true` network was evaluated first and **rejected**: it was
measured to still reach services on the Docker host via the bridge gateway
address, which is the exact exposure `network_mode: none` exists to prevent.
The shared-namespace approach has the additional benefit of needing no
interface renumbering, since Docker creates no interface at all.

## Recipes that ship two independent instances

One namespace is one port space, so two services binding the same container
port collide. In practice that shape is never an app plus a sidecar — it is a
recipe running **two independent instances side by side for comparison**:

| Recipe | Instances | Real sidecar |
| --- | --- | --- |
| `ecshop/xianzhi-2017-02-82239600` | ecshop 2.7.3 and 3.6.0, both on port 80 | `mysql`, shared by both |
| `php/xdebug-rce` | xdebug 7.1 and 7.4, both on port 80 | none |

A CORE node is a single host with a single address, so only one instance can be
it. Rather than discarding the recipe, the duplicate is dropped and everything
else is kept — including any genuine sidecar the survivor needs. `ecshop`
becomes ecshop 2.7.3 plus its mysql; `php/xdebug-rce` becomes the 7.1 target.
Both remain valid vulnerable targets; only the side-by-side version comparison
is lost.

Dropping is refused — and the recipe excluded — if something being kept
declares a `depends_on` for the duplicate, since that would leave a dangling
reference and a broken stack. No recipe in the current catalog hits that case.

Note the compose files themselves are **not** broken: under vanilla
`docker compose up` each service gets its own namespace and its own address, so
two services binding `:80` is no conflict at all. The constraint comes entirely
from mapping a stack onto one CORE node.

## Escape hatch

`CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING=1` skips this handling entirely and
restores Docker-managed service networking, which is the way to run a
two-instance recipe with both instances intact. It
grants those nodes a Docker gateway with a route to the host, so it is a
deliberate security trade-off rather than a general-purpose switch — pair it
with `CORETG_DOCKER_IFID_START=1`, since Docker then creates the container's
`eth0` and CORE's interfaces must start at `eth1`.

## Note on CPU architecture

Architecture is unrelated to any of this — the check never inspects image
architecture, and the behaviour is identical on arm64 and x86. Of the 80
recipes that were excluded before this work, 63 were also amd64-only (needing
qemu emulation on an arm64 CORE VM) and 17 were already arm64-native; both
groups were excluded, and both now work, which is the clearest demonstration
that the two properties are independent.
