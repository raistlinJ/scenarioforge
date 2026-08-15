# Installing CORE for ScenarioForge

ScenarioForge drives CORE over gRPC and SSH, and it expects a CORE installation
that carries ScenarioForge's fixes and updates. There are two ways to get one.

---

## Recommended: install the ScenarioForge CORE fork

Install CORE from **<https://github.com/raistlinJ/core>**.

It is a fork of [coreemu/core](https://github.com/coreemu/core) that already
carries the fixes and updates ScenarioForge depends on, so nothing extra has to
be patched in afterwards. Follow the fork's own README for the install itself
(package install from the release artifacts, or the script install), on whichever
machine will run `core-daemon`:

- **VM mode** — the CORE VM. See [VM Mode Setup](VM_MODE_SETUP.md).
- **Native mode** — the local machine, or whichever remote host you point
  `CORE_HOST` at. See [Native Mode Setup](NATIVE_MODE_SETUP.md).

---

## Using upstream CORE instead

Upstream ("vanilla") CORE 9.2 or newer works, but only after you apply the same
updates yourself. Skipping this step does not fail at connection time: gRPC
connects, the session starts, and the scenario then comes up without
segmentation, without traffic, and without its Docker compose targets.

### 1. Install ScenarioForge's custom CORE services

The service modules live in this repository under
[`on_core_machine/custom_services/`](../on_core_machine/custom_services):

| Module | What it provides |
| --- | --- |
| `CoreTGPrereqs.py` | Installs tool prerequisites inside each node's namespace/container, and a process-wide Mako template lock that keeps concurrent node boots from hitting a spurious recursion error on some Python 3.11 releases. The other services depend on it. |
| `Segmentation.py` | Applies the scenario's per-node segmentation rules. |
| `TrafficService.py` | Starts the background traffic agents on nodes that generate traffic. |
| `DockerComposeService.py` | Brings up the per-node compose file at `/tmp/vulns/docker-compose-<node>.yml` — this is how vulnerability targets start. |
| `DockerDefaultRoute.py` | Default-route service using absolute script paths, replacing CORE's built-in `DefaultRoute` whose relative paths fail when a Docker node's working directory differs. |

**The easy path — let ScenarioForge install them.** On the **CORE Management**
page, enable **Install custom services** before validating the CORE connection.
It copies the modules from `on_core_machine/custom_services` to the CORE host,
restarts `core-daemon`, and verifies that each module imports. The remote path
needs the SSH password because the destination is root-owned; the same toggle
installs into a local CORE install when CORE runs on the ScenarioForge machine.

**The manual equivalent.** Copy the modules into the installed `core.services`
package directory, or into a directory listed as `custom_services_dir` in
`core.conf` (`/opt/core/etc/core.conf` or `/etc/core/core.conf`), then restart
`core-daemon`. When `core.conf` lists no such directory, ScenarioForge adds
`custom_services_dir = /opt/core/custom_services` and installs there.

### 2. Docker daemon settings on the CORE host

Docker's default bridge and iptables rules interfere with CORE-emulated
networking. The **CORE Management** page's advanced action **Fix Docker daemon
for CORE (disable default bridge + iptables)** applies the required daemon
settings; apply the equivalent configuration by hand if you manage the daemon
yourself.

### 3. Re-apply after updates

These service modules are versioned with ScenarioForge and change as it changes.
After pulling repository updates, re-run **Install custom services** (or re-copy
the files) and restart `core-daemon` — CORE imports service classes inside the
daemon, so an updated file on disk has no effect until the daemon restarts.

---

## Related

- [Quick Start](QUICK_START.md)
- [VM Mode Setup](VM_MODE_SETUP.md)
- [Native Mode Setup](NATIVE_MODE_SETUP.md)
- [Operating Modes](OPERATING_MODES.md)
- [Troubleshooting](TROUBLESHOOTING.md)
