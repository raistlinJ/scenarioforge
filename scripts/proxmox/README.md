# Proxmox three-VM installer

`install-scenarioforge-lab.sh` provisions the recommended ScenarioForge VM-mode
lab on one Proxmox VE node:

- Debian 12 with CORE built from `raistlinJ/core` by the
  `coreemu-minimal --from-source` path.
- Ubuntu 24.04 with `raistlinJ/scenarioforge` running behind its Docker Compose
  nginx service.
- A minimal Debian 12 participant machine connected only to the HITL network.

The installer uses official Debian and Ubuntu cloud images, Proxmox Cloud-Init,
and VirtIO interfaces. It supports amd64 Proxmox hosts in this first release.

## Network layout

```text
vmbr0 (existing LAN/Internet bridge)
├── ScenarioForge net0 / ens18 (DHCP; Web UI)
└── CORE          net2 / ens20 (DHCP; image/package downloads)

sfmgmt0 (new isolated bridge)
├── ScenarioForge net1 / ens19  172.31.250.2/24
└── CORE          net0 / ens18  172.31.250.3/24 (SSH + gRPC)

sfhitl0 (new isolated bridge)
├── CORE          net1 / ens19  no guest OS address
└── Participant   net0 / ens18  10.254.200.10/24
```

The CORE management and participant networks are deliberately separate. The
participant cannot reach CORE SSH/gRPC or ScenarioForge management data.

## Before running

Run on the target Proxmox node as `root`. The node needs:

- Proxmox VE with `qm`, `pvesh`, and Cloud-Init support.
- The Proxmox-packaged `ifupdown2`, used for safe live bridge reloads. An
  upstream or otherwise incompatible `ifupdown2` build is rejected before the
  installer changes the node.
- An existing uplink bridge, normally `vmbr0`, providing DHCP and Internet
  access to the CORE and ScenarioForge VMs.
- VM storage that accepts `images`, normally `local-lvm`.
- Directory-backed storage for Cloud-Init snippets, normally `local`. The
  installer enables its `snippets` content type without removing existing
  content types.
- About 14 GiB of guest RAM and 140 GiB of provisioned guest storage with the
  defaults. Thin-provisioned storage does not consume all of that immediately.

The installer refuses to overwrite an existing VMID. Adding the two portless
bridges applies the Proxmox node's pending network configuration. Run from a
local console while changing node networking. The installer refuses to proceed
when it detects pre-existing unapplied network changes, so it cannot accidentally
apply another administrator's staged edit along with its bridge additions.
Only one installer-managed lab is supported per node state directory; an
existing `/etc/scenarioforge-lab/state.env` also stops a new installation.
The installer isolates host-tool execution from activated Conda environments,
virtual environments, `PYTHONHOME`, and `PYTHONPATH`, because Proxmox network
tools must load Debian's system Python modules.

## Install

Copy or clone the repository onto the Proxmox host, inspect the dry run, and
then install:

```bash
cd scenarioforge
sudo scripts/proxmox/install-scenarioforge-lab.sh install --dry-run
sudo scripts/proxmox/install-scenarioforge-lab.sh install --verbose
```

The confirmation prompt requires typing `INSTALL`. Use `--yes` for an
unattended invocation. CORE and ScenarioForge build concurrently and commonly
take 20–60 minutes depending on the node and Internet connection. The default
timeout is 90 minutes.

Output is timestamped and classified as `PROGRESS`, `INFO`, `WARN`, `ERROR`,
`DEBUG`, or `DRY-RUN`. Normal mode reports every major stage, image download,
VM creation, and the recurring CORE/ScenarioForge readiness state. Add
`--verbose` to also show safe command diagnostics, repository/checksum details,
Proxmox task activity, and the latest available bootstrap-log line from each
guest. Verbose mode deliberately does not enable shell tracing because tracing
could expose generated passwords.

Progress output includes an overall percentage and elapsed time. Percentages
represent completed milestones rather than an estimated finish time: host VM
and network preparation accounts for the first 55%, then the parallel CORE and
ScenarioForge bootstraps contribute the remainder. Each guest reports its own
percentage and named phase. During long source or container-image builds, the
installer emits a heartbeat every 20 seconds even when the milestone percentage
has not changed, making it clear that readiness monitoring is still active.

To use different VMIDs, storage, uplink, and an SSH public key:

```bash
sudo scripts/proxmox/install-scenarioforge-lab.sh install \
  --storage fast-lvm \
  --snippet-storage local \
  --uplink-bridge vmbr0 \
  --core-vmid 2201 \
  --app-vmid 2202 \
  --participant-vmid 2203 \
  --ssh-public-key /root/.ssh/id_ed25519.pub
```

Use `--no-wait` to return after starting the VMs. Check progress later with:

```bash
sudo scripts/proxmox/install-scenarioforge-lab.sh status
```

For a continuously updating view in a second Proxmox shell—even while the
original installer is still running—use:

```bash
sudo scripts/proxmox/install-scenarioforge-lab.sh status --watch
```

It reports each VM's power state, QEMU guest-agent availability, readiness
marker, overall and per-guest percentage, elapsed time, current host-installer
phase, explicit guest bootstrap phase, and latest available guest/Cloud-Init log
activity. The installer writes state immediately
after a successful preflight and confirmation, before creating bridges or
downloading images. Until that happens, the watcher reports that it is waiting;
it reads a root-only runtime status under `/run` to show the active installer
PID and preflight phase. If the installer exits before creating state, the
watcher displays the recorded error—or warns that no installer process is
active—instead of waiting indefinitely. It begins detailed VM status
automatically when state becomes available. The default refresh interval is 10
seconds; change it with `--interval 5`. Stop watching with `Ctrl-C`; this does
not stop provisioning.

For CORE and the app, `bootstrap=in-progress` means the ready marker has not
been written and no explicit bootstrap failure has been recorded;
`bootstrap=failed` is accompanied by a `CORE progress` or `APP progress` line
containing the exit code and guest-script line. The participant has no required
bootstrap workload, so its guest agent may be reported as `optional` while its
bootstrap state remains `n/a`.

After restarting `core-daemon`, the CORE bootstrap waits up to two minutes for
gRPC to listen on the IPv4 wildcard port 50051 (`ss` may render this as either
`0.0.0.0:50051` or `*:50051`). If it cannot become ready, the bootstrap log
includes the systemd status, recent `core-daemon` journal, and listening
sockets instead of failing on a one-shot startup race.

Bootstrap logs are available inside the guests:

```text
/var/log/scenarioforge-core-bootstrap.log
/var/log/scenarioforge-app-bootstrap.log
/var/log/cloud-init-output.log
```

Generated VM and Web UI passwords are written only to:

```text
/etc/scenarioforge-lab/credentials.env
```

The file and its containing directory are root-only. The ScenarioForge VM also
stores the CORE SSH password in `/opt/scenarioforge/.scenarioforge.env`, mode
`0600`, because the current remote execution path uses password authentication.

## Important options and environment variables

Every option has an `SF_` environment equivalent. Useful values include:

| Environment variable | Default |
| --- | --- |
| `SF_VM_STORAGE` | `local-lvm` |
| `SF_SNIPPET_STORAGE` | `local` |
| `SF_UPLINK_BRIDGE` | `vmbr0` |
| `SF_MANAGEMENT_BRIDGE` | `sfmgmt0` |
| `SF_HITL_BRIDGE` | `sfhitl0` |
| `SF_CORE_VMID` / `SF_APP_VMID` / `SF_PARTICIPANT_VMID` | `9401` / `9402` / `9403` |
| `SF_CORE_MEMORY_MB` / `SF_APP_MEMORY_MB` / `SF_PARTICIPANT_MEMORY_MB` | `8192` / `4096` / `2048` |
| `SF_CORE_DISK_GB` / `SF_APP_DISK_GB` / `SF_PARTICIPANT_DISK_GB` | `80` / `40` / `20` |
| `SF_APP_MANAGEMENT_CIDR` | `172.31.250.2/24` |
| `SF_CORE_MANAGEMENT_CIDR` | `172.31.250.3/24` |
| `SF_CORE_HITL_CIDR` | `10.254.200.3/24` |
| `SF_PARTICIPANT_CIDR` | `10.254.200.10/24` |
| `SF_CORE_MINIMAL_REF` | `main` |
| `SF_CORE_REPO_REF` | `master` |
| `SF_SCENARIOFORGE_REF` | `main` |
| `SF_WAIT_MINUTES` | `90` |
| `SF_VERBOSE` | `0` (`1` enables verbose diagnostics) |
| `SF_STATUS_INTERVAL` | `10` seconds |

Repository and image URLs can also be overridden with
`SF_CORE_MINIMAL_URL`, `SF_CORE_REPO_URL`, `SF_SCENARIOFORGE_URL`,
`SF_DEBIAN_IMAGE_URL`, `SF_DEBIAN_SUMS_URL`, `SF_UBUNTU_IMAGE_URL`, and
`SF_UBUNTU_SUMS_URL`.

## Failure behavior and cleanup

The installer intentionally leaves created VMs and guest logs intact after a
bootstrap failure so the failure can be inspected. To preview and then remove a
partial, stopped, or incomplete installation, run:

```bash
sudo scripts/proxmox/install-scenarioforge-lab.sh cleanup --dry-run
sudo scripts/proxmox/install-scenarioforge-lab.sh cleanup
```

`--cleanup` is an alias for the `cleanup` command. Cleanup displays its exact
scope and requires typing `CLEANUP`; use `--yes` for unattended recovery. It
gracefully shuts down running target VMs, force-stops them only when needed,
then removes their disks, the six installer Cloud-Init snippets, saved state and
credentials, and installer-created bridges that no other VM or container uses.
Downloaded Debian and Ubuntu base images remain cached for a faster retry.

Cleanup refuses to make further changes when Proxmox already has an unapplied
`/etc/network/interfaces.new`, including after a failed live reload. Inspect
the staged diff and explicitly apply or revert it in Proxmox before retrying;
the installer keeps its state and credentials until bridge removal succeeds.
Network reload errors include both output streams so package-version and
configuration failures are visible instead of appearing as a generic line
number.

Deletion is intentionally identity-checked. With a state file, each recorded
VMID must still have its expected ScenarioForge name or installer Cloud-Init
snippet. Without a state file, cleanup only recognizes the configured VMIDs
when their names exactly match `scenarioforge-core`, `scenarioforge-app`, and
`scenarioforge-participant` (or the corresponding `SF_*_NAME` overrides).
Unrelated VMs and pre-existing bridges are preserved.

A complete lab with all three VMs running is protected from ordinary cleanup.
To intentionally remove one, supply `--force` in addition to the normal
confirmation (or `--yes`):

```bash
sudo scripts/proxmox/install-scenarioforge-lab.sh cleanup --force
```

Cleanup is permanent. Always inspect `cleanup --dry-run` before using `--yes`.

## Security notes

- The participant has no uplink or management NIC.
- CORE gRPC listens on `0.0.0.0`, but only on the isolated management bridge.
- The Web UI listens on the ScenarioForge VM's uplink so an operator can reach
  it. Protect that LAN and use the generated admin password.
- Passwords are randomly generated for each run and are not printed to normal
  command output.
- Pin repository refs to release tags or stable branches if you need a
  frozen deployment. The defaults follow the maintained branches.
