# Native Mode Setup

Native mode is the default non-VM application mode (`CORETG_WEBUI_MODE=native`).
It is **not** a local-only deployment: CORE may run on the same machine or on
another reachable host. What "native" actually selects is that VM-mode HITL
defaults stay off and the CORE connection is chosen **in the UI** rather than
supplied by `.scenarioforge.env`.

That last point is the practical difference from
[VM mode](VM_MODE_SETUP.md), and it is why Proxmox setup matters here: in native
mode the Web UI's **VM / Access** tab is where you assign a Proxmox resource,
pick the CORE VM, and store its credentials. VM mode hides that tab because env
variables already answer those questions.

---

## 1. Choose A CORE Target

| Situation | CORE endpoint |
| --- | --- |
| CORE 9.2 on the same machine | `127.0.0.1:50051` — used automatically when no `CORE_HOST` override is set |
| CORE on another host, no Proxmox workflow | Explicit remote host over gRPC + SSH |
| Proxmox-hosted CORE VM, but you want UI-driven selection | Remote host, assigned through the VM / Access tab |

The launcher scripts have `auto`, `local`, and `remote` CORE target selectors.
Those choose the endpoint; they are independent of `CORETG_WEBUI_MODE`.

Whichever host ends up running `core-daemon`, install CORE from **our fork**,
<https://github.com/raistlinJ/core>, which already carries the fixes and updates
ScenarioForge depends on. With an upstream/vanilla CORE 9.2 install you have to
apply those updates yourself — see [CORE Install](CORE_INSTALL.md).

---

## 2. `.scenarioforge.env` Settings

Copy the versioned template and edit the local copy:

```bash
cp .scenarioforge.env.example .scenarioforge.env
```

`.scenarioforge.env` is gitignored. Docker Compose and direct Python launches
both read it when present. `.scenarioforge.env.example` is a template and copy
source — for direct Python launches it is **not** loaded at runtime. Precedence:
real process environment variables, then `.scenarioforge.env`, then (Compose
only) `.scenarioforge.env.example`, then built-in Python defaults.

### Mode selector

| Variable | Purpose |
| --- | --- |
| `CORETG_WEBUI_MODE` | `native` (the default) keeps VM-mode HITL defaults disabled and shows the **VM / Access** tab. |

### CORE connection

| Variable | Local CORE | Remote CORE | Purpose |
| --- | --- | --- | --- |
| `CORE_HOST` | `127.0.0.1` | `10.0.0.50` | CORE gRPC host |
| `CORE_PORT` | `50051` | `50051` | CORE gRPC port |
| `CORE_SSH_HOST` | `127.0.0.1` | `10.0.0.50` | SSH host for shell/file operations |
| `CORE_SSH_PORT` | `22` | `22` | SSH port |
| `CORE_SSH_USERNAME` | — | `corevm` | SSH user |
| `CORE_SSH_PASSWORD` | — | — | SSH password. Prefer a real environment variable or the UI secret store over a file value. |

These values are **defaults**, not the final word. A CORE VM assigned through
the VM / Access tab stores its own connection record and overrides them for that
scenario.

Set `CORE_SSH_HOST` to the VM's reachable SSH address whenever `CORE_HOST`
points at something local — for example when an SSH tunnel exposes a remote
`core-daemon` on `127.0.0.1:50051`, the gRPC host is local but the SSH host is
not.

Under Docker Compose in native bridge mode, a container-local CORE target such
as `127.0.0.1` is rewritten to `host.docker.internal`. Set
`CORETG_KEEP_CONTAINER_LOCAL_CORE=1` only when CORE genuinely runs inside the
web container. (VM mode does the opposite and preserves `127.0.0.1`.)

### SSH behavior

| Variable | Default | Purpose |
| --- | --- | --- |
| `CORETG_SSH_CONNECT_TIMEOUT` | `30` | Seconds per SSH connect attempt |
| `CORETG_SSH_CONNECT_RETRIES` | `2` | Attempts per operation |

A host that drops packets rather than refusing the connection blocks for the
full timeout on every attempt, costing `timeout × retries` seconds of silence.
Lower both when running the test suite or working off the lab network — several
tests reach this path.

### Web server

| Variable | Default | Purpose |
| --- | --- | --- |
| `CORETG_HOST` | `0.0.0.0` | Flask bind address for direct Python launches. Use `127.0.0.1` to keep the UI local-only. |
| `CORETG_PORT` | `9090` | Flask port |
| `CORETG_USE_RELOADER` | — | Set `0` when generating scenarios. Sequencing and generator workflows write XML, logs, and artifacts during a request, and the development reloader can restart the process mid-request. |

### HITL

| Variable | Purpose |
| --- | --- |
| `CORETG_HITL_CORE_IFX_IPV4` | IPv4 or CIDR applied to a HITL interface entry that exists and has no IPv4 set. In native mode it fills only the **first** such entry. It does **not** create a HITL interface or enable HITL. Leave blank for deterministic auto-allocation. |

The `CORETG_VM_MODE_HITL_*` variables have no effect in native mode. HITL
interfaces are added through the UI instead.

### Timeouts and execute hygiene

`CORETG_FLOW_SEQUENCE_TIMEOUT_S`, `CORETG_FLOW_EXECUTE_TIMEOUT_S`,
`CORETG_NGINX_PROXY_READ_TIMEOUT_S`, `CORETG_SKIP_STALE_DOCKER_CLEANUP`, and
`CORETG_REPAIR_DOCKER_HOME_PERMS` behave identically in both modes; see
[VM Mode Setup](VM_MODE_SETUP.md#timeouts). The one mode-dependent default is
`CORETG_WEBUI_CORE_START_TIMEOUT_S`, which falls back to the CLI's `120`
seconds in native mode instead of VM mode's `300`.

### Minimal local-CORE override

```dotenv
CORE_HOST=127.0.0.1
CORE_PORT=50051
CORETG_WEBUI_MODE=native
CORETG_HOST=0.0.0.0
CORETG_PORT=9090
```

### Minimal remote-CORE override

```dotenv
CORE_HOST=10.0.0.50
CORE_PORT=50051
CORE_SSH_HOST=10.0.0.50
CORE_SSH_PORT=22
CORE_SSH_USERNAME=corevm
CORETG_WEBUI_MODE=native
```

---

## 3. Launch

```bash
uv sync --extra dev
CORETG_USE_RELOADER=0 uv run python webapp/app_backend.py
```

With pip/venv:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python webapp/app_backend.py
```

Helper scripts:

```bash
bash scripts/run_webui_local.sh --web-port 9090
bash scripts/run_webui_remote.sh --core-host 10.0.0.50 --core-port 50051 --web-port 9090
```

Or Compose, which serves the same app behind nginx with TLS on `https://localhost`:

```bash
docker compose up -d --build
```

---

## 4. Proxmox Setup

In native mode the **CORE Management** page is gated: opening it requires a
CORE VM selected from a Proxmox inventory, and then a CORE connection that has
tested successfully. Clicking the nav link without a selection shows *"You must
first select a CORE VM in the Scenarios Page to view this page."*

This gate applies to the Web UI only. The CLI takes CORE connection details
from flags or `.scenarioforge.env` and needs no Proxmox account.

### Proxmox account and privileges

ScenarioForge authenticates with a username/password pair (`root@pam`, or a
dedicated user in any realm) and calls a small, fixed set of API endpoints:

| Endpoint | Method | Used for | Privilege |
| --- | --- | --- | --- |
| `/version` | GET | Credential validation | Any authenticated user |
| `/nodes` | GET | Node enumeration | `Sys.Audit` on `/nodes` |
| `/nodes/{node}/qemu` | GET | VM inventory | `VM.Audit` |
| `/nodes/{node}/qemu/{vmid}/config` | GET | Reading `netX` adapters | `VM.Audit` |
| `/nodes/{node}/qemu/{vmid}/config` | POST | Rewriting `bridge=` on HITL apply | `VM.Config.Network` |
| `/nodes/{node}/network` | GET | Confirming the target bridge exists | `Sys.Audit` |

A dedicated role carrying `Sys.Audit`, `VM.Audit`, and `VM.Config.Network` is
enough; ScenarioForge never creates, starts, stops, or deletes a VM, and never
creates a bridge.

The integration requires the `proxmoxer` package. Without it, validation returns
*"Proxmox integration unavailable: install proxmoxer package"*.

### Create the participant bridge first

Create the internal bridge on the Proxmox node **before** applying HITL wiring.
ScenarioForge verifies the bridge exists and fails with `Bridge <name> not found
on node <node>. Create the bridge manually before applying HITL mappings.`
otherwise. It does not create bridges.

Bridge names are normalized: lowercased, non-alphanumeric characters folded to
`-`, truncated to **10 characters**, and required to match
`[a-z0-9][a-z0-9_-]*`. Choose a name that survives that transformation.

### The VM / Access tab

Scenarios page → **VM / Access**. Admin privileges are required for the Proxmox
and credential steps; the builder view is read-only and shows *"CORE VM
selection and credentials are managed by an admin."*

**Step 1 — Proxmox Resource.** *Assign Proxmox Resource* opens a dialog for the
base URL (`https://proxmox.example.local`), port (default `8006`), username
(`root@pam`), password, and an **Enforce SSL certificate validation** switch —
uncheck it for self-signed certificates. *Save credentials after validation*
stores the password in ScenarioForge's secret vault so later operations can
reconnect without re-prompting; uncheck it to validate without persisting
secrets. Validation performs a live login. Afterwards, *Refresh VM List* pulls
the inventory and *Clear Proxmox Resource* removes the assignment.

**Step 2 — CORE VM & Credentials.** Unlocked once Step 1 validates. Pick the
CORE VM from the inventory dropdown; VMs tagged as ScenarioForge in their
Proxmox notes are sorted first. *Configure Connection* sets the gRPC host/port
and SSH host/port/username/password for that VM, and *Test CORE Connection*
verifies both. A VM reporting zero interfaces in Proxmox is rejected — add an
adapter and refresh the list.

**Step 3 — Hardware in the Loop.** Requires Steps 1 and 2 to be authenticated;
the toggle stays disabled otherwise, and re-authentication is required if they
lapse. Each HITL interface entry names a CORE VM guest interface, an attachment
mode (`existing_router`, `existing_switch`, `new_router`, or `proxmox_vm`), an
optional IPv4/CIDR, and the Proxmox adapter (`net0`, `net1`, …) the interface
corresponds to.

Interface enumeration reaches into the CORE VM over SSH and lists only names
with a `/sys/class/net/<name>/device` entry — physical/virtio NICs. Bridges,
veth pairs, and `lo` never appear. If SSH enumeration fails, the list falls back
to synthesizing entries from the Proxmox VM config.

**Step 4 — CTF Participant VM.** Selects the VM that connects a participant to
the scenario, and its adapter. It must live on the same Proxmox node as the CORE
VM. *Apply Internal Bridge* then rewrites the `bridge=` token in the chosen
`netX` line on both the CORE VM and the participant VM so they land on the same
bridge, leaving MAC address and model untouched.

**Step 5 — Participant UI (optional).** A Proxmox console or landing URL for
participants. Applying it adds a Participant UI navigation tab so facilitators
and players open the same console. This step is native-mode only; VM mode uses
`CORETG_VM_MODE_PARTICIPANT_URL` instead.

### CORE VM interfaces

The three-interface layout described in
[VM Mode Setup](VM_MODE_SETUP.md#2-core-vm-network-interfaces) — management,
HITL/participant, and uplink — applies equally to a Proxmox-hosted CORE VM
driven from native mode. The difference is only in how ScenarioForge learns
about them: enumerated over SSH and chosen in Step 3, rather than declared in
`.scenarioforge.env`.

---

## 5. Verify

1. **Proxmox** — Step 1 reports *"Proxmox validated for `<user>` @ `<url>:<port>`"*.
2. **CORE VM** — Step 2's *Test CORE Connection* succeeds; the CORE nav link
   then opens without prompting.
3. **Artifact checks** — probes run over SSH against the CORE host using the
   saved credentials, and reach Docker-backed nodes with `docker exec` and CORE
   vnodes with `vcmd`. Port reachability is measured across the emulated
   network, not through published host ports.
4. **Participant reachability** — test the scenario's own protocol and port.
   Segmentation is default-deny with per-flow allows, so ICMP failing across a
   working path is expected.

---

## Related

- [VM Mode Setup](VM_MODE_SETUP.md) — Proxmox lab deployment with env-supplied
  CORE connection
- [Operating Modes](OPERATING_MODES.md) — mode comparison, Compose notes, image
  retention, CLI
- [Quick Start](QUICK_START.md)
- [Troubleshooting](TROUBLESHOOTING.md)
