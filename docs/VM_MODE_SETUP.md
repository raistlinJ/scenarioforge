# VM Mode Setup

VM mode is the Proxmox lab deployment: ScenarioForge runs as the control
application on one host, CORE 9.2 runs in a dedicated VM, and participants
attach to the emulated network through Hardware-in-the-Loop (HITL).

The defining difference from [native mode](NATIVE_MODE_SETUP.md) is **where the
CORE connection comes from**. In VM mode it is supplied by `.scenarioforge.env`
at process start, so the Web UI hides the **VM / Access** tab and never asks an
operator to pick a CORE VM out of a Proxmox inventory. Native mode does the
opposite. Everything below assumes `CORETG_WEBUI_MODE=vm`.

---

## 1. Lab Layout

Three roles, which may be three physical machines or three VMs:

| Role | What it runs | Talks to |
| --- | --- | --- |
| **ScenarioForge application host** | This repository, the Web UI, optional Docker Compose/nginx wrapper | CORE VM over gRPC `50051` and SSH `22` |
| **CORE VM** | CORE 9.2, `core-daemon`, Docker, SSH | Container registries (image pulls); the participant network |
| **Participant machine** | Kali or another attacker host | The emulated scenario network, through HITL |

The Proxmox server hosts the CORE VM and (usually) the participant VM, and owns
the bridges that connect them.

---

## 2. CORE VM Network Interfaces

Give the CORE VM **three interfaces**. They serve three unrelated purposes and
collapsing them causes problems that are hard to diagnose later — a participant
who can reach the management address can reach the ScenarioForge API and the
scenario's own answer key.

| Purpose | Proxmox slot (typical) | Guest name (typical) | Addressed by | Configured in ScenarioForge? |
| --- | --- | --- | --- | --- |
| **Management** — gRPC + SSH from the ScenarioForge host | `net0` | `ens18` | Static IPv4 in the guest OS | Indirectly, as `CORE_HOST` / `CORE_SSH_HOST` |
| **HITL / participant** | `net1` | `ens19` | Left unconfigured in the guest; CORE addresses it | Yes — `CORETG_VM_MODE_HITL_CORE_IFX_NAME` |
| **Uplink / internet** | `net2` | `ens20` | DHCP or static, with a default route | No |

Guest interface names follow the order the NICs were added in Proxmox, not the
slot number, and `ens18`/`ens19`/`ens20` are only the common result of adding
`net0`/`net1`/`net2` in order on a modern Debian/Ubuntu guest. Confirm the real
names inside the VM before configuring anything:

```bash
ip -br link
```

### Management interface

This is the only interface the ScenarioForge application host needs to reach.
It carries two things:

- **gRPC to `core-daemon`** on port `50051` → `CORE_HOST` / `CORE_PORT`
- **SSH** on port `22` → `CORE_SSH_HOST` / `CORE_SSH_PORT`

SSH is not optional in VM mode. Remote setup, artifact checks, Docker
preflight, repo sync, and generator execution all run shell commands on the
CORE VM over SSH, so a VM reachable by gRPC but not SSH will fail partway
through an execute rather than at connection time.

Put this interface on a lab/management bridge that the participant machine
cannot reach.

### HITL / participant interface

This is the interface CORE attaches to the emulated topology. Two constraints
come from the code, not from convention:

- **It must be a physical (PCI) NIC as the guest sees it.** Interface
  enumeration lists only names that have a `/sys/class/net/<name>/device` entry,
  so Proxmox virtio NICs appear while bridges, veth pairs, and `lo` do not. A
  guest-side bridge built on top of the NIC is not selectable.
- **Configure it by guest interface name, not by Proxmox slot id.**
  `CORETG_VM_MODE_HITL_CORE_IFX_NAME=ens19` is correct; `net1` is not.

Leave the interface unaddressed in the guest OS (no DHCP, no static IP). CORE
takes it over when the session starts, and `CORETG_HITL_CORE_IFX_IPV4` seeds the
CORE-side address on the scenario's HITL interface entry — leave that variable
blank to let ScenarioForge allocate deterministically instead.

### Uplink interface

Nothing in ScenarioForge configures this one, but scenario execution needs it:
the CORE VM pulls vulnerability base images and builds generator/wrapper images
with Docker. Without a working default route and DNS on the CORE VM, execution
fails at image preflight.

For a deliberately air-gapped CORE VM, this interface can be omitted — but then
every image must be staged in advance. Framework prerequisite images are
auto-pinned and pre-seedable; scenario content is not. See the air-gap notes in
[Feature Deep Dive](FEATURE_DEEP_DIVE.md) and the image retention table in
[Operating Modes](OPERATING_MODES.md#image-retention-and-offline-runs).

Note that this is separate from container networking inside a scenario:
generated services run with `network_mode: none` and reach their own sidecars
over loopback, so an exploited node has no route to the host or the internet
regardless of the CORE VM's own uplink.

---

## 3. Proxmox Bridges

Create one bridge per interface role on the Proxmox node, then attach the CORE
VM's NICs to them:

| Bridge | Attaches | Notes |
| --- | --- | --- |
| Management bridge (e.g. `vmbr0`) | CORE VM `net0` | Reachable from the ScenarioForge host |
| Participant bridge | CORE VM `net1`, participant VM `netX` | An isolated internal bridge with no uplink |
| Uplink bridge (e.g. `vmbr0`) | CORE VM `net2` | Routes to the internet |

**The participant bridge must already exist before you apply HITL wiring.**
ScenarioForge validates that the bridge is present on the node and fails with
`Bridge <name> not found on node <node>. Create the bridge manually before
applying HITL mappings.` if it is not. It does not create bridges.

Bridge names are normalized before use: lowercased, non-alphanumeric characters
folded to `-`, truncated to **10 characters**, and required to match
`[a-z0-9][a-z0-9_-]*`. Pick a name that survives that transformation so the name
you type is the name Proxmox needs.

Applying HITL wiring rewrites the `bridge=` token in the selected `netX` line of
both the CORE VM and the external/participant VM configs, leaving the MAC
address and model untouched. Both VMs must live on the same Proxmox node.

---

## 4. `.scenarioforge.env` Settings

Copy the versioned template and edit the local copy:

```bash
cp .scenarioforge.env.example .scenarioforge.env
```

`.scenarioforge.env` is gitignored. Both Docker Compose and direct Python
launches read it when present. `.scenarioforge.env.example` is a template and a
copy source — for direct Python launches it is **not** loaded at runtime.
Precedence is: real process environment variables, then `.scenarioforge.env`,
then (Compose only) `.scenarioforge.env.example`, then built-in Python defaults.

### Mode selector

| Variable | Purpose |
| --- | --- |
| `CORETG_WEBUI_MODE` | `vm` enables VM-mode UI behavior and HITL defaults. Anything else (default `native`) does not. |

Setting this to `vm` has three visible effects: the **VM / Access** tab
disappears from the Scenarios page, the CORE Management page stops requiring a
Proxmox-selected CORE VM, and Step 5 (Participant UI URL) is hidden.

### CORE connection

| Variable | Example | Purpose |
| --- | --- | --- |
| `CORE_HOST` | `12.0.0.100` | CORE gRPC host, on the management interface |
| `CORE_PORT` | `50051` | CORE gRPC port |
| `CORE_SSH_HOST` | `12.0.0.100` | SSH host; usually identical to `CORE_HOST` |
| `CORE_SSH_PORT` | `22` | SSH port |
| `CORE_SSH_USERNAME` | `corevm` | SSH user on the CORE VM |
| `CORE_SSH_PASSWORD` | — | SSH password. Prefer a real environment variable or the UI secret store over a file value. |

`CORETG_VM_MODE_CORE_HOST`, `CORETG_VM_MODE_CORE_PORT`, and the
`CORETG_VM_MODE_SSH_*` family are accepted as fallbacks, but the `CORE_*` names
win and are the ones to use — VM and native mode deliberately share them.

In VM mode, `CORE_HOST=127.0.0.1` is **preserved as-is** under Docker Compose
rather than being rewritten to `host.docker.internal`, because in this mode it
means `core-daemon` on the remote CORE host reached over the SSH transport. Set
`CORETG_KEEP_CONTAINER_LOCAL_CORE=1` only when CORE genuinely runs inside the
web container.

### SSH behavior

| Variable | Default | Purpose |
| --- | --- | --- |
| `CORETG_SSH_CONNECT_TIMEOUT` | `30` | Seconds per SSH connect attempt |
| `CORETG_SSH_CONNECT_RETRIES` | `2` | Attempts per operation |

A CORE VM that **drops** packets rather than refusing the connection blocks for
the full timeout on every attempt, so an unreachable host costs
`timeout × retries` seconds of silence. Lower both when working off the lab
network.

### HITL defaults

| Variable | Example | Purpose |
| --- | --- | --- |
| `CORETG_VM_MODE_HITL_ENABLED` | `true` | Enables participant-facing HITL defaults (default `true` in VM mode) |
| `CORETG_VM_MODE_HITL_CORE_IFX_NAME` | `ens19` | Guest interface name of the participant NIC. **Required** — no HITL interface entry is created without it. |
| `CORETG_VM_MODE_HITL_CORE_IFX_ATTACHMENT` | `existing_router` | How the interface joins the topology: `existing_router`, `existing_switch`, `new_router`, or `proxmox_vm` |
| `CORETG_VM_MODE_HITL_CORE_IFX_DESCRIPTION` | `Scenario HITL participant network` | Label shown in the UI |
| `CORETG_HITL_CORE_IFX_IPV4` | `10.254.200.3/24` | IPv4 or CIDR seeded onto the HITL interface entry. Blank ⇒ deterministic auto-allocation. |
| `CORETG_VM_MODE_PARTICIPANT_URL` | — | Optional participant UI URL surfaced in VM-mode flows |

`CORETG_HITL_CORE_IFX_IPV4` applies in both modes, but only reaches the
runtime-managed VM-mode interface when `CORETG_VM_MODE_HITL_CORE_IFX_NAME` is
also set. Setting the IPv4 alone neither creates a HITL interface nor enables
HITL.

### Web server

| Variable | Default | Purpose |
| --- | --- | --- |
| `CORETG_HOST` | `0.0.0.0` | Flask bind address for direct Python launches. Use `127.0.0.1` to keep the UI local-only. |
| `CORETG_PORT` | `9090` | Flask port |
| `CORETG_USE_RELOADER` | — | Set `0` on lab hosts. Sequencing and generator workflows write XML, logs, and artifacts during a request, and the development reloader can restart the process mid-request. Does not affect VM mode or CORE connectivity. |

### Timeouts

| Variable | Default | Purpose |
| --- | --- | --- |
| `CORETG_FLOW_SEQUENCE_TIMEOUT_S` | `300` | Minimum browser-side timeout for the Flag Sequencing **Sequence** step |
| `CORETG_FLOW_EXECUTE_TIMEOUT_S` | `3600` | Upper cap for the **Resolve**/Execute step; the actual value scales with chain length (150s/node + 180s, floor 600s) |
| `CORETG_NGINX_PROXY_READ_TIMEOUT_S` | `3700` | nginx `proxy_read_timeout`, **Compose only**. Keep ≥ `CORETG_FLOW_EXECUTE_TIMEOUT_S` so nginx does not cut a long Resolve before the browser would. |
| `CORETG_WEBUI_CORE_START_TIMEOUT_S` | `300` in VM mode | How long to wait for a CORE session to reach runtime (bounded 5–600) |

These bound client-side waits only; they do not change the Flow data model.

### Execute-time hygiene

| Variable | Default | Purpose |
| --- | --- | --- |
| `CORETG_SKIP_STALE_DOCKER_CLEANUP` | off (sweep runs) | Set `1` to skip removing containers left by earlier runs. Only containers Compose labels as CORE/ScenarioForge projects (`/tmp/pycore.*`, `/tmp/vulns/`) are considered. |
| `CORETG_REPAIR_DOCKER_HOME_PERMS` | `1` | Repairs root-owned files under the SSH user's `~/.docker` before execute. Running any Docker command as root seeds root-owned state — `buildx/.lock` usually — after which builds fail with a bare `permission denied` that Compose reports only as `rc=1`. |

### Minimum VM-mode override

```dotenv
CORE_HOST=10.0.0.50
CORE_PORT=50051
CORE_SSH_HOST=10.0.0.50
CORE_SSH_PORT=22
CORE_SSH_USERNAME=corevm
CORE_SSH_PASSWORD=change-me
CORETG_WEBUI_MODE=vm
CORETG_VM_MODE_HITL_ENABLED=true
CORETG_VM_MODE_HITL_CORE_IFX_NAME=ens19
CORETG_VM_MODE_HITL_CORE_IFX_ATTACHMENT=existing_router
CORETG_HITL_CORE_IFX_IPV4=10.254.200.3/24
```

---

## 5. Launch

Compose (recommended — includes Graphviz, so attack graph PDF export works):

```bash
docker compose up -d --build
```

Open `https://localhost` and check `curl -k https://localhost/healthz`. nginx
publishes `80/443`; the backend is also on `127.0.0.1:9090`.

Direct Python, for development:

```bash
uv sync --extra dev
CORETG_USE_RELOADER=0 uv run python webapp/app_backend.py
```

---

## 6. Verify

1. **CORE Management page** — it should open without asking you to select a CORE
   VM. If it shows *"VM mode CORE defaults are incomplete"*, the `CORE_*`
   variables did not reach the process; check that `.scenarioforge.env` exists
   (not just `.scenarioforge.env.example`) and that no stale real environment
   variable is overriding it.
2. **CORE connectivity** — validate the connection from the CORE Management
   view. This exercises gRPC and SSH separately.
3. **HITL interface** — the participant interface should appear pre-populated
   with the name from `CORETG_VM_MODE_HITL_CORE_IFX_NAME`. If the list is empty,
   the name does not match a physical NIC in the guest (`ip -br link`), or SSH
   enumeration failed.
4. **Participant reachability** — test the scenario's own protocol and port.
   Segmentation is default-deny with per-flow allows, so ICMP failing across a
   working path is expected and is not evidence of a wiring problem.

---

## Related

- [Native Mode Setup](NATIVE_MODE_SETUP.md) — non-VM mode, including the
  Proxmox VM / Access workflow
- [Operating Modes](OPERATING_MODES.md) — mode comparison, Compose notes, image
  retention, CLI
- [Quick Start](QUICK_START.md)
- [Troubleshooting](TROUBLESHOOTING.md)
