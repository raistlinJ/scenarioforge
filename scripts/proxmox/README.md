# Proxmox three-VM installer

`install-scenarioforge-lab.sh` provisions the recommended ScenarioForge VM-mode
lab on one Proxmox VE node:

- Debian 12 with CORE built from `raistlinJ/core` by the
  `coreemu-minimal --from-source` path, including its XFCE desktop and
  `core-gui` graphical client.
- Ubuntu 24.04 with an XFCE desktop and `raistlinJ/scenarioforge` installed
  natively in a Python virtual environment, managed by systemd, and published
  through the distribution nginx service. The desktop includes the native
  Epiphany browser and a launcher for the local ScenarioForge Web GUI.
- Debian 12 with a minimal XFCE participant desktop, connected only to the
  HITL network after provisioning.

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

The CORE management and participant networks are deliberately separate. After
provisioning, the participant cannot reach CORE SSH/gRPC or ScenarioForge
management data.
While the participant downloads XFCE packages, it temporarily has `net1` on
the uplink bridge. The installer removes that virtual NIC before declaring the
lab complete. Even with `--no-wait`, it waits for this isolation-critical step;
only the longer CORE and app provisioning continue in the background.

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

All three VMs use standard virtual VGA while retaining a serial port for
diagnostics. Their XFCE login screens are therefore available through the
Proxmox **Console** / noVNC view after provisioning, with the VNC clipboard
enabled by default for copy and paste. Proxmox notes that VNC clipboard mode
prevents live migration when a VM uses a QEMU machine version older than 10.1.
The installer refuses to overwrite an existing VMID. Adding the two portless
bridges applies the Proxmox node's pending network configuration. Run from a
local console while changing node networking. The installer refuses to proceed
when it detects pre-existing unapplied network changes, so it cannot accidentally
apply another administrator's staged edit along with its bridge additions.
Only one installer-managed lab is supported per node state directory; an
existing `/etc/scenarioforge-lab/state.env` also stops a new installation.
The initial progress event never rewrites an existing lab state; preflight
reports it and directs the operator to status or explicit cleanup.
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
unattended invocation. CORE, ScenarioForge, and the participant desktop build
concurrently and commonly take 20–60 minutes depending on the node and Internet
connection. The default timeout is 90 minutes.

Output is timestamped and classified as `PROGRESS`, `INFO`, `WARN`, `ERROR`,
`DEBUG`, or `DRY-RUN`. Normal mode reports every major stage, image download,
VM creation, and the recurring readiness state of all three guests. Add
`--verbose` to also show safe command diagnostics, repository/checksum details,
Proxmox task activity, and the latest available bootstrap-log line from each
guest. Verbose mode deliberately does not enable shell tracing because tracing
could expose generated passwords.

Progress output includes an overall percentage and elapsed time. Percentages
represent completed milestones rather than an estimated finish time: host VM
and network preparation accounts for the first 55%, then the parallel CORE,
ScenarioForge, and participant bootstraps contribute the remainder. Each guest
reports its own percentage and named phase. During long source builds and Python
dependency installs, the installer emits a heartbeat every 20 seconds even when
the milestone percentage has not changed, making it clear that readiness
monitoring is still active.

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

### Custom credentials

Passwords remain randomly generated by default as 10-character alphanumeric
values. To assign known credentials when creating a new lab, provide any or all
of these options:

```bash
sudo scripts/proxmox/install-scenarioforge-lab.sh install \
  --core-password 'CORE-VM-password' \
  --app-password 'APP-VM-password' \
  --participant-password 'participant-password' \
  --web-admin-password 'ScenarioForge-admin-password'
```

The usernames remain fixed as `corevm`, `scenarioforge`, `participant`, and
`coreadmin`, respectively. Omitted passwords are generated independently, so
specifying one does not disable generation for the others.

Command-line password values may be retained in shell history or briefly
visible in the host process list. For unattended installation, prefer the
corresponding `SF_CORE_PASSWORD`, `SF_APP_PASSWORD`,
`SF_PARTICIPANT_PASSWORD`, and `SF_WEB_ADMIN_PASSWORD` environment variables.
Regardless of how they are supplied, the final values are written to the same
root-only credentials file and printed in the completion summary.

### Optional flag-generator and Vulhub catalogs

The installer can populate a fresh APP VM from the private
`raistlinJ/flag-generators` repository:

```bash
# Install flag and flag-node generator catalogs.
sudo scripts/proxmox/install-scenarioforge-lab.sh --flag-generators

# Import the repository's pinned Vulhub recipe snapshot into ScenarioForge.
sudo scripts/proxmox/install-scenarioforge-lab.sh --vulnhub

# Install both optional content sets.
sudo scripts/proxmox/install-scenarioforge-lab.sh --flag-generators --vulnhub
```

Authenticate GitHub on the Proxmox host before running one of these options.
An existing Git credential helper works with the default HTTPS URL, or use an
SSH identity and URL:

```bash
export SF_FLAG_GENERATORS_URL=git@github.com:raistlinJ/flag-generators.git
```

Do not place a token or password in `SF_FLAG_GENERATORS_URL`; the installer
rejects credentials embedded in an HTTPS URL. It clones the private repository
only into its root-only temporary work area, packages just the requested
directories, and sends them to APP with a generated one-time SSH key. GitHub
credentials are never copied into a VM, and the transfer key is removed from
APP after the archive is verified.

`--flag-generators` imports both `flag_generators/` and
`flag_node_generators/` through ScenarioForge's pack importer. The resulting
catalog and pack state live under
`/opt/scenarioforge/outputs/installed_generators`; APP provisioning fails
instead of claiming readiness unless both catalog kinds are visible.
`--vulnhub` similarly imports the repository's `vulnhub/` snapshot through
ScenarioForge's vulnerability-catalog importer; on a fresh VM that catalog
becomes active. These flags add download, transfer, disk, and import time. They
can be pinned with `--flag-generators-ref REF` or
`SF_FLAG_GENERATORS_REF`.

The optional repository contains deliberately vulnerable recipes and challenge
key material. Use it only in an isolated, trusted lab, and do not expose the
participant or CORE exercise network to untrusted networks.

Use `--no-wait` to return after the participant desktop is installed and its
temporary uplink is removed, without waiting for CORE and ScenarioForge to
finish. Check progress later with:

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

For each guest, `bootstrap=in-progress` means the ready marker has not been
written and no explicit bootstrap failure has been recorded;
`bootstrap=failed` is accompanied by its progress line containing the exit code
and guest-script line. The participant is not ready until LightDM is running;
its temporary uplink is then removed from the VM hardware.

After restarting `core-daemon`, the CORE bootstrap waits up to two minutes for
an actual IPv4 TCP connection to the CORE management address on port 50051.
This avoids depending on how `ss` renders gRPC's dual-stack wildcard socket. If
it cannot become ready, the bootstrap log includes the systemd status, recent
`core-daemon` journal, and listening sockets instead of failing on a one-shot
startup race. Explicit bootstrap failures and a failed `cloud-final` service
are surfaced immediately to the host installer rather than waiting for the
full provisioning timeout.

Bootstrap logs are available inside the guests:

```text
/var/log/scenarioforge-core-bootstrap.log
/var/log/scenarioforge-app-bootstrap.log
/var/log/scenarioforge-participant-bootstrap.log
/var/log/cloud-init-output.log
```

If APP provisioning reaches the HTTPS health check and then reports exit code
`3` from `systemctl is-active --quiet lightdm`, the native web application is
already healthy but the XFCE display manager is inactive. Installer version
0.5.1 explicitly installs the X.Org input/video drivers, retries LightDM, and
includes its service journal and Xorg log when it still cannot start. Inspect an
existing affected VM with:

```bash
qm guest exec 9402 -- bash -lc '
systemctl status lightdm --no-pager -l || true
journalctl -u lightdm -n 100 --no-pager || true
tail -n 100 /var/log/lightdm/lightdm.log /var/log/lightdm/x-0.log 2>/dev/null || true
'
```

After repairing a failed guest and writing its normal readiness marker, a
manually removed participant `net1` is recognized by `status` even though the
failed host installer did not get to update its saved state.

## Graphical consoles and native services

Open any VM in the Proxmox GUI and select **Console** to reach its XFCE login.
Use the VM usernames and passwords printed at completion. The CORE desktop has a
**CORE Network Emulator** launcher that runs `core-gui`; `core-daemon` starts
automatically in the background. The app and participant desktops start through
LightDM as soon as their bootstrap completes, without an additional VM reboot.
The noVNC clipboard control is available because each VM is created with
`vga: std,clipboard=vnc`.
The APP desktop includes Epiphany and a **ScenarioForge** launcher that opens
`https://localhost/`; the self-signed certificate produces an expected warning.

ScenarioForge itself is not containerized on the app VM. Its source and Python
environment live under `/opt/scenarioforge`; systemd starts the backend on
`127.0.0.1:9090`, and native nginx publishes HTTPS on port 443. Useful checks
inside that VM are:

```bash
sudo systemctl status scenarioforge-web nginx
sudo journalctl -u scenarioforge-web -u nginx -n 100 --no-pager
curl -k https://127.0.0.1/healthz
```

The TLS certificate is self-signed, so browsers show a trust warning until it is
replaced with a certificate trusted by the operator's environment.

These desktop and native-service changes apply when the VMs are created. A
`git pull` does not retrofit an already-installed serial-console/Docker lab. Use
the documented cleanup flow and run a fresh install to adopt the complete new
layout. Changing only an existing VM's Proxmox VGA hardware would also require a
full VM stop/start and would not migrate the app out of Docker.

Generated VM and Web UI passwords are persisted only in:

```text
/etc/scenarioforge-lab/credentials.env
```

The file and its containing directory are root-only. The ScenarioForge VM also
stores the CORE SSH password in `/opt/scenarioforge/.scenarioforge.env`, mode
`0600`, because the current remote execution path uses password authentication.
At successful installer completion, a one-time summary prints the CORE VM, app
VM, participant VM, and web-admin usernames and passwords together with their
addresses and VMIDs. The same summary identifies the root-only credentials file
above. Subsequent `status` commands show only its path and do not reprint the
secrets; use `sudo cat /etc/scenarioforge-lab/credentials.env` when they must be
retrieved again.

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
| `SF_INSTALL_FLAG_GENERATORS` / `SF_INSTALL_VULNHUB` | `0` / `0` |
| `SF_FLAG_GENERATORS_URL` | `https://github.com/raistlinJ/flag-generators.git` |
| `SF_FLAG_GENERATORS_REF` | `main` |
| `SF_CORE_PASSWORD` / `SF_APP_PASSWORD` | empty (generate independently) |
| `SF_PARTICIPANT_PASSWORD` / `SF_WEB_ADMIN_PASSWORD` | empty (generate independently) |
| `SF_WAIT_MINUTES` | `90` |
| `SF_VERBOSE` | `0` (`1` enables verbose diagnostics) |
| `SF_STATUS_INTERVAL` | `10` seconds |

Repository and image URLs can also be overridden with
`SF_CORE_MINIMAL_URL`, `SF_CORE_REPO_URL`, `SF_SCENARIOFORGE_URL`,
`SF_FLAG_GENERATORS_URL`, `SF_DEBIAN_IMAGE_URL`, `SF_DEBIAN_SUMS_URL`,
`SF_UBUNTU_IMAGE_URL`, and `SF_UBUNTU_SUMS_URL`.

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
Successful bridge absence is treated as cleanup success, so a metadata-only
retry can finish safely after an interrupted or older cleanup run.

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
- The participant receives a temporary uplink only while installing XFCE; the
  installer removes it before successful completion.
- CORE gRPC listens on `0.0.0.0`, but only on the isolated management bridge.
- The Web UI listens on the ScenarioForge VM's uplink so an operator can reach
  it. Protect that LAN and use the generated admin password.
- Default passwords are independently generated as 10-character alphanumeric
  values for each run and printed once at successful installer completion.
  Protect terminal logs and output captures. Later status output does not
  reveal them.
- Pin repository refs to release tags or stable branches if you need a
  frozen deployment. The defaults follow the maintained branches.
- Treat content installed by `--flag-generators` and `--vulnhub` as sensitive,
  intentionally unsafe lab material. Keep it on isolated, trusted systems.
