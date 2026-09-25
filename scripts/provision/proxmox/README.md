# Proxmox three-VM installer

Omit both `llm_interface_cidr` and `llm_gateway` for automatic DHCP on the
dedicated LLM interface. The selected bridge must provide DHCP. The guest ignores
DHCP default routes and DNS settings and maintains only a route to the provider
IP, refreshed after lease changes. Provider address/URL must still be supplied.
Both static fields remain advanced overrides: **do not change them unless you
understand the network's addressing and routing**. Windows JSON does not support
comments; these fields are therefore omitted from its example.

CyberAgentFlow provisioning installs and verifies the guest Python environment,
Docker, Docker Compose (`docker compose` and `docker-compose`), and the native
Claude Code CLI before marking the participant ready. It creates a **CyberAgentFlow Web** launcher on the
participant desktop and in its applications menu. These changes apply when the
guest is provisioned; existing VMs are not automatically updated.

Management uses a separate bridge and explicit guest CIDRs; it does not derive
addresses from the Proxmox host uplink. Both guest management CIDRs must share a
subnet. This server installer does not create desktop shortcuts on your workstation.

Proxmox network configuration matches each provisioned NIC's MAC address and
explicitly assigns its interface name (`ens18`, `ens19`, `ens20`). Some guest
images initially use `eth0`, `eth1`, and `eth2`; name-only matching against
`ens18`/`ens19` leaves those guests without networking. The optional LLM NIC
also uses MAC matching and its explicit guest interface name.

APP and CORE uplinks on `uplink_bridge` (default `vmbr0`) and the participant's
temporary bootstrap uplink use DHCP with a MAC-based client identifier.
Clones assigned new MAC addresses need corresponding updates to their custom
network snippets and saved guest network configuration. Separate cloned labs
must use separate management and HITL bridges/VLANs when reusing static IPs.

This correction applies to new provisioning and reinstalls; updating the host
script does not repair an existing guest. Do not reinstall merely to update a
template: reinstall recreates the selected VM.

`install-scenarioforge-lab.sh` provisions the recommended ScenarioForge VM-mode
lab on one Proxmox VE node:

- Debian 12 with CORE built from `raistlinJ/core` by the
  `coreemu-minimal --from-source` path, including its XFCE desktop and
  `core-gui` graphical client.
- Ubuntu 24.04 with an XFCE desktop and `raistlinJ/scenarioforge` installed
  natively in a Python virtual environment, managed by systemd, and published
  through the distribution nginx service. The desktop includes the native
  Epiphany browser and a launcher for the local ScenarioForge Web GUI, plus
  Terminator, Evince for PDFs, xdot for Graphviz files, and Mousepad/`jq` for
  graphical and terminal JSON inspection.
  Node.js is installed and verified for CLI HTML and Markdown guide export.
- Debian 12 with a minimal XFCE participant desktop (default), or Kali Linux
  with XFCE and the standard Kali tools, connected only to the
  HITL network after provisioning.

The installer uses official Debian, Ubuntu, and optional Kali cloud images, Proxmox Cloud-Init,
and VirtIO interfaces. It supports amd64 Proxmox hosts in this first release.

The APP guest bootstrap is shared with the VMware Workstation (Linux and Windows)
and VMware Fusion provisioners, so they also install Node.js. For existing guests,
install it with `sudo apt update && sudo apt install -y nodejs`, then verify
`node --version` before running guide export.

## Choose the participant operating system

Choose **Debian 12** (the default) for a minimal XFCE desktop, or **Kali Linux**
for XFCE plus the standard Kali tools. This changes only the participant VM;
CORE uses Debian and APP uses Ubuntu.

In your `scenarioforge-lab.conf` config, set one of:

```ini
# Minimal desktop (default)
participant_os=debian
```

```ini
# Desktop with the standard Kali tools
participant_os=kali
```

You can also pass `--participant-os debian` or `--participant-os kali` to the installer.
Enabling `cyber_agent_flow=true` automatically selects Kali and allocates at least
4096 MB RAM, even if `participant_os=debian`.

The default participant disk is 80 GB for both Kali and Debian. The installer starts from a cloud
image and downloads and installs the desktop/tools during provisioning, so Kali
usually takes longer. You do not need to build a template yourself.

This choice applies to new labs; changing the config does not convert an existing
participant VM. See the example config alongside this README for the other options.


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

For Kali, the installer replaces the cloud kernel with the full architecture
kernel and reboots before finishing desktop setup. The cloud kernel can leave
LightDM running without a graphical seat or X server. The installer checks both
before marking the participant ready and removing its temporary Internet adapter.
After adapter removal, it reboots the participant into the graphical login.
Use Proxmox's noVNC console to view the desktop; the serial console remains text-only.

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
- About 14 GiB of guest RAM and 240 GiB of provisioned guest storage with the
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
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh install --dry-run
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh install --verbose
```

The confirmation prompt requires typing `INSTALL`. Use `--yes` for an
unattended invocation. CORE, ScenarioForge, and the participant desktop build
concurrently and commonly take 20–60 minutes depending on the node and Internet
connection. The default timeout is 180 minutes (three hours) to allow for
Kali tool downloads, package installation, and the kernel reboot. Override it
with `--wait-minutes N` or `wait_minutes=N` in your config file.

### Config file

Every provisioning option can also be stored in a non-executable `key=value`
config file. Start from the tracked example, restrict its permissions if it
contains credentials, and pass it to any installer command:

```bash
cp scripts/provision/proxmox/scenarioforge-lab.conf.example /root/scenarioforge-lab.conf
chmod 600 /root/scenarioforge-lab.conf
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh install \
  --config /root/scenarioforge-lab.conf \
  --verbose
```

The precedence is **built-in defaults < config file < `SF_*` environment
variables < CLI flags**, so the example above enables verbose output even when
`verbose=false` is saved in the file. Use lowercase names matching the long
options without leading dashes, replacing dashes with underscores—for example
`core_vmid=2201`, `flag_generators=true`, and `no_wait=true`. Blank lines and
full-line `#` comments are ignored. Values may be unquoted or enclosed in
matching single or double quotes; contents are treated literally, with no shell
expansion or command execution. Unknown keys, malformed lines, unmatched
quotes, and invalid boolean values stop before Proxmox validation or mutation.
Only one `--config` file may be supplied per invocation.

Output is timestamped and classified as `PROGRESS`, `INFO`, `WARN`, `ERROR`,
`DEBUG`, or `DRY-RUN`. Normal mode reports every major stage, image download,
VM creation, the recurring readiness state of all three guests, and the latest
bootstrap-log line whenever it changes. This includes package activity during
long Kali installs, without requiring `--verbose`. Until a guest's bootstrap
log is available, it samples `/var/log/cloud-init-output.log`. Add
`--verbose` to also show safe command diagnostics, repository/checksum details,
and Proxmox task activity. Verbose mode deliberately does not enable shell tracing because tracing
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
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh install \
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
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh install \
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
The root-readable config file described above is also suitable for credentials.
Regardless of how they are supplied, the final values are written to the same
root-only credentials file and printed in the completion summary.

### Optional flag-generator and Vulhub catalogs

The installer can populate a fresh APP VM from the private
`raistlinJ/flag-generators` repository:

```bash
# Install flag and flag-node generator catalogs.
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh --flag-generators

# Import the repository's pinned Vulhub recipe snapshot into ScenarioForge.
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh --vulnhub

# Install both optional content sets.
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh --flag-generators --vulnhub
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
instead of claiming readiness unless both catalog kinds are visible. The
default repository revision is the tested metadata snapshot
`5f612eecb8ff5df74a0e517d0de1e54385a62044`. Its `pack.json` travels through
the normal pack importer and records 147 successfully tested generators. The
enabled catalog contains 144 generators overall and exactly the 85 enabled
flag-node generators exercised by the paper and resolved dataset. Three working
`Sample:` generators remain catalog-disabled, while
`http_support_ticket_portal` remains disabled and unvalidated because no
successful test evidence is recorded. All 148 generators carry an imported
note explaining their evidence and current catalog state.
`--vulnhub` similarly imports the repository's `vulnhub/` snapshot through
ScenarioForge's vulnerability-catalog importer; on a fresh VM that catalog
becomes active. Its `.scenarioforge/catalog_items.json` metadata enables and
records success for the 294 self-contained recipes represented by the IEEE TPS
paper and `scenarioforge-dataset`. Twelve recipes remain disabled and
unvalidated: 10 require build-time Internet access, one has missing required
paths, and one is outside the validated research catalog. All 306 recipes carry
an authored note; green notes summarize validation and resolved-dataset usage,
while red notes explain each exception. A custom `--flag-generators-ref REF` or
`SF_FLAG_GENERATORS_REF` imports whatever portable metadata that revision
contains; it is never silently granted the tested snapshot's status. These
flags add download, transfer, disk, and import time.

Catalog downloads preserve validation status, enabled/disabled state,
provenance, and operator-authored notes (including note color). Re-importing
either a generator pack or a vulnerability catalog therefore retains both the
repository's defaults and later user curation.

The optional repository contains deliberately vulnerable recipes and challenge
key material. Use it only in an isolated, trusted lab, and do not expose the
participant or CORE exercise network to untrusted networks.

Use `--no-wait` to return after the participant desktop is installed and its
temporary uplink is removed, without waiting for CORE and ScenarioForge to
finish. Check progress later with:

```bash
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh status
```

For a continuously updating view in a second Proxmox shell—even while the
original installer is still running—use:

```bash
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh status --watch
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
`vga: std,clipboard=vnc`. Cloud-Init installs `spice-vdagent` in all three
guests and starts its system daemon; its standard XDG autostart entry launches
the per-user clipboard agent at each XFCE login. Use the clipboard button in
noVNC's left-side control panel to transfer text to or from the guest clipboard.
The APP desktop includes Epiphany and a **ScenarioForge** launcher that opens
`https://localhost/`; the self-signed certificate produces an expected warning.
Its XFCE session requests an initial 1600x900 display when available and leaves
an already larger display alone.
It also includes Terminator, the Evince PDF viewer, the xdot Graphviz viewer,
and a **JSON Viewer** application backed by Mousepad. The `jq` command is
available for structured JSON inspection in a terminal.

ScenarioForge itself is not containerized on the app VM. A complete Git clone
and its Python environment live under `/opt/scenarioforge`; systemd starts the
backend on `127.0.0.1:9090`, and native nginx publishes HTTPS on port 443. The
installer puts `uv` and `uvx` in `/usr/local/bin` and synchronizes `.venv` from
the committed `pyproject.toml` and `uv.lock`. Useful checks inside that VM are:

```bash
sudo systemctl status scenarioforge-web nginx
sudo journalctl -u scenarioforge-web -u nginx -n 100 --no-pager
curl -k https://127.0.0.1/healthz
```

To update application code and locked runtime dependencies on the APP VM:

```bash
sudo -u scenarioforge git -C /opt/scenarioforge pull --ff-only origin main
sudo -u scenarioforge env HOME=/home/scenarioforge UV_CACHE_DIR=/home/scenarioforge/.cache/uv \
  uv sync --frozen --no-dev --project /opt/scenarioforge
sudo systemctl restart scenarioforge-web
curl -fsS http://127.0.0.1:9090/healthz
```

An APP VM provisioned by an older installer may not have `uv` yet. Install it
once without changing the ScenarioForge environment, then use the update steps
above:

```bash
sudo python3 -m venv /opt/uv
sudo /opt/uv/bin/python -m pip install --disable-pip-version-check --no-cache-dir --upgrade uv
sudo ln -sfn /opt/uv/bin/uv /usr/local/bin/uv
sudo ln -sfn /opt/uv/bin/uvx /usr/local/bin/uvx
uv --version
```

The pull and sync leave `.scenarioforge.env` and `outputs/` intact because both
are excluded from Git. Installer-owned systemd, nginx, OS-package, and desktop
changes still require manual application or fresh provisioning; `uv sync`
updates only the repository-managed Python environment.

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
| `SF_PARTICIPANT_OS` | `debian` (or `kali`) |
| `SF_CORE_MEMORY_MB` / `SF_APP_MEMORY_MB` / `SF_PARTICIPANT_MEMORY_MB` | `8192` / `4096` / `2048` |
| `SF_CORE_DISK_GB` / `SF_APP_DISK_GB` / `SF_PARTICIPANT_DISK_GB` | `80` / `80` / `80` |
| `SF_APP_MANAGEMENT_CIDR` | `172.31.250.2/24` |
| `SF_CORE_MANAGEMENT_CIDR` | `172.31.250.3/24` |
| `SF_CORE_HITL_CIDR` | `10.254.200.3/24` |
| `SF_PARTICIPANT_CIDR` | `10.254.200.10/24` |
| `SF_CORE_MINIMAL_REF` | `main` |
| `SF_CORE_REPO_REF` | `master` |
| `SF_SCENARIOFORGE_REF` | `main` |
| `SF_INSTALL_FLAG_GENERATORS` / `SF_INSTALL_VULNHUB` | `0` / `0` |
| `SF_FLAG_GENERATORS_URL` | `https://github.com/raistlinJ/flag-generators.git` |
| `SF_FLAG_GENERATORS_REF` | `5f612eecb8ff5df74a0e517d0de1e54385a62044` (tested metadata snapshot) |
| `SF_CORE_PASSWORD` / `SF_APP_PASSWORD` | empty (generate independently) |
| `SF_PARTICIPANT_PASSWORD` / `SF_WEB_ADMIN_PASSWORD` | empty (generate independently) |
| `SF_WAIT_MINUTES` | `180` |
| `SF_VERBOSE` | `0` (`1` enables verbose diagnostics) |
| `SF_STATUS_INTERVAL` | `10` seconds |

Repository and image URLs can also be overridden with
`SF_CORE_MINIMAL_URL`, `SF_CORE_REPO_URL`, `SF_SCENARIOFORGE_URL`,
`SF_FLAG_GENERATORS_URL`, `SF_DEBIAN_IMAGE_URL`, `SF_DEBIAN_SUMS_URL`,
`SF_UBUNTU_IMAGE_URL`, `SF_UBUNTU_SUMS_URL`, `SF_KALI_IMAGE_URL`, and
`SF_KALI_SUMS_URL`.

## Failure behavior and cleanup

The installer intentionally leaves created VMs and guest logs intact after a
bootstrap failure so the failure can be inspected. To preview and then remove a
partial, stopped, or incomplete installation, run:

```bash
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh cleanup --dry-run
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh cleanup
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
sudo scripts/provision/proxmox/install-scenarioforge-lab.sh cleanup --force
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


### Kali participant option

For a new lab, add `--participant-os kali` to the installer command:

```bash
bash scripts/provision/proxmox/install-scenarioforge-lab.sh install --participant-os kali --dry-run
bash scripts/provision/proxmox/install-scenarioforge-lab.sh install --participant-os kali --yes
```

Alternatively set `participant_os=kali` in the config file or
`SF_PARTICIPANT_OS=kali` in the environment. Precedence is config, environment,
then CLI. Debian remains the default; CORE continues to use Debian 12.

Kali uses the official 2026.2 amd64 generic cloud archive, verifies its SHA256
against the published checksum list, and extracts its sparse `disk.raw`.
It installs `kali-desktop-xfce` and `kali-linux-default` during first boot.
The login remains `participant` with the generated or supplied participant
password. Its defaults are 2048 MB RAM, 2 CPUs, and an 80 GB disk; override with
`SF_PARTICIPANT_MEMORY_MB`, `SF_PARTICIPANT_CORES`, and
`SF_PARTICIPANT_DISK_GB`.

The temporary uplink stays attached until desktop/tool provisioning succeeds,
then is removed through the existing isolation workflow, including with
`--no-wait`. Allow additional download time for the Kali tools; increase
`--wait-minutes` on slower connections.

For another Kali release, override both `SF_KALI_IMAGE_URL` and
`SF_KALI_SUMS_URL`. Use an amd64 generic cloud `.tar.xz` containing
`disk.raw`, as linked from [Kali's official downloads](https://www.kali.org/get-kali/#kali-cloud).
These settings are independent of the CORE Debian image settings.

This option provisions new VMs; it does not convert an existing Debian VM.
Validate desktop login, tool availability, HITL connectivity, and uplink removal
on your Proxmox host before using the Kali lab with participants.


### Force cleanup and network ownership

`cleanup --force` removes bridges recorded as successfully created by this
installer even if their descriptive comments changed. It still preserves
pre-existing bridges, the uplink bridge, bridges with configured ports, and
bridges referenced by other VMs or containers. Without an ownership record,
changed comments are not enough to identify a bridge for forced removal.

If a tracked bridge cannot be removed, cleanup retains installer state and
credentials so you can resolve its remaining dependencies and retry. A bridge
already removed manually does not need to be recreated for cleanup.

## Optional CyberAgentFlow on Kali

Set `cyber_agent_flow=true` in the grouped example config section (Windows JSON
uses `"cyber_agent_flow": true`). This selects a Kali participant automatically.
The shell installers also accept
`--cyber-agent-flow`; Windows accepts `-CyberAgentFlow`.

Setup clones `https://github.com/raistlinJ/cyber-agent-flow.git`, the upstream
of the sibling `../cyber-agent-flow` checkout. Override `cyber_agent_flow_url`
and `cyber_agent_flow_ref` to select a repository/ref or commit. Uncommitted local
changes are not copied. The guest needs access to that repository during bootstrap;
private-repository host credentials are not copied into Kali.

Configure these values before enabling the option:

| Setting | Meaning |
| --- | --- |
| `llm_provider_address` | Fixed IPv4 address of the external LLM provider |
| `llm_provider_url` | Full HTTP(S) endpoint, using the IP or a hostname that resolves to it |
| `llm_provider_type` | `ollama_direct`, `litellm`, `openai`, or `claude` |
| `llm_model` | Model name used by CyberAgentFlow |
| `llm_interface_cidr` | Advanced static override; omit with gateway for automatic DHCP |
| `llm_gateway` | Advanced static router override; supply only together with interface CIDR |
| `llm_vmnet` | VMware: existing egress vmnet, default `vmnet8` |
| `llm_bridge` | Proxmox: existing egress bridge; empty uses `uplink_bridge` |

Use the gateway/subnet actually configured on your chosen vmnet/bridge. The LLM
network must differ from HITL and management. A third Kali NIC is matched by MAC
and named `ens20`; cloud-init persists its static address and a provider-specific
`/32` route via the gateway (direct link route for a provider in the same subnet).
Automatic mode uses DHCP for its address and gateway, ignoring general DHCP routes
and DNS settings. Neither mode enables IPv6 autoconfiguration or a default route.
The ordinary bootstrap
NIC `ens19` is still removed after provisioning; the new LLM NIC remains. Guest
readiness checks `ip -4 route get ADDRESS` and refuses to mark setup complete if
that route does not use `ens20`. This checks routing, not provider availability or
authentication. The dedicated NIC is not a firewall: other addresses on its local
subnet remain reachable, and guests with sudo can change routing.

CyberAgentFlow is installed in `/opt/cyber-agent-flow` using its prerequisites
script while the temporary Internet connection is available. Docker is enabled
at boot, and `participant` is added to the `docker` group. The native Claude CLI
is installed under `/home/participant/.local/bin` and is available to the web
launcher. Provisioning verifies Docker daemon access, both Compose commands,
and Claude CLI as `participant`, including when retrying setup. CyberAgentFlow
itself is not started automatically. Log in as `participant` and run `cyber-agent-flow` in a terminal
to launch web mode through `start_ws.sh`.
Provisioning adds the configured LLM provider IP and its route gateway (if any)
to CyberAgentFlow's `network_policy.disallow` in `configs/cli.json`. These are
excluded as agent targets; the LLM connection remains available. The destination
update utility and DHCP route refresh keep these exclusions current. Existing
user-defined allow/deny entries are preserved; only obsolete entries added by
the utility are removed when the endpoint or gateway changes.

The generated `configs/cli.json` contains the endpoint/provider/model; set
`MCP_API_KEY` in your guest session when authentication is needed. No API keys are
placed in the provisioning config. The WebUI uses `configs/cli.json` for initial
provider, URL, model, TLS, and limit settings; existing browser-saved settings
take precedence. API keys are not embedded in the page.

This option applies to new labs; cleanup removes the extra NIC with its VM and
preserves the pre-existing egress vmnet/bridge. Reinstall to add it to an existing
lab. When disabled, the original two-interface participant layout is unchanged.


## Participant HITL address and gateway

The default addresses have separate roles:

| Setting | Default | Purpose |
| --- | --- | --- |
| CORE HITL interface | `10.254.200.3/24` | CORE-side HITL/RJ45 address seeded into the scenario |
| Participant address | `10.254.200.10/24` | Participant VM's own address |
| Participant gateway | `10.254.200.1` | Scenario router used as the participant's default next-hop |

The CORE HITL interface address is not the participant gateway. An empty
`participant_gateway` derives the first usable address in the HITL subnet other
than the CORE HITL interface address, matching the default existing-router
allocation. If the scenario uses another router (for example `.2`), set its IP
explicitly. The gateway must be in the participant subnet and distinct from
the participant and CORE HITL interface addresses.

Use `participant_gateway=10.254.200.1` in the config,
`SF_PARTICIPANT_GATEWAY` in the environment, or `--participant-gateway 10.254.200.1`
for a new installation. CLI overrides environment, which overrides config.
The resolved gateway is saved with the lab. Older saved labs without this
setting use the corrected default when rebuilt. `core_hitl_cidr` and
`participant_cidr` still control their respective interface addresses.

Provisioning writes `/opt/scenarioforge/.scenarioforge.env` on the APP VM,
including the CORE connection credentials, HITL interface/subnet, and resolved
`CORETG_HITL_GATEWAY` (default `10.254.200.1`). The service and normal CLI/app
startup load this file, so later runs from that checkout use the saved gateway
without rerunning provisioning or manually exporting it. The router address is
applied to the configured HITL interface and subnet; other scenario networks
keep their own allocation. Config/flag gateway overrides are saved here too.
The file is owned by `scenarioforge` with mode `0600`.

For an existing APP VM, add `CORETG_HITL_GATEWAY=10.254.200.1` (or your configured
router IP) to that file after updating the application code, then restart
`scenarioforge-web`. A new application process reads the updated file; an
already-running scenario must be recreated to change its router address.
Editing this file does not update the participant VM's persistent Netplan route;
keep that route consistent if you change the gateway later.

The HITL default route has metric 2000 so the temporary NAT route takes
precedence during provisioning. This change applies when generating guest
network configuration; it does not edit an already-running VM's Netplan files.

## Configure VM disk sizes

CORE, APP, and participant disks each default to **80 GB**, for both Debian
and Kali participants. To override them for a new installation, set these keys
in your `--config` file:

```ini
core_disk_gb=80
app_disk_gb=100
participant_disk_gb=120
```

Or pass `--core-disk-gb 80 --app-disk-gb 100 --participant-disk-gb 120` to
`install`. Precedence is **defaults < config < environment < CLI**; the matching
environment variables are `SF_CORE_DISK_GB`, `SF_APP_DISK_GB`, and
`SF_PARTICIPANT_DISK_GB`. Kali requires at least 25 GB. These options do not
resize existing VMs; reinstall retains the saved/existing disk sizes.

## Reinstall selected VMs using cached images

All three roles—CORE, APP, and participant—receive freshly generated Cloud-Init
configuration and bootstrap scripts from the provisioner's current repository
checkout. Run `git pull --ff-only` in that checkout before reinstalling to pick
up the latest provisioning changes. Reinstall does not update the host checkout
automatically or reuse a previous guest's bootstrap/Cloud-Init files. Cached
base images remain reusable; they do not determine which setup scripts run.

CORE reruns its CORE installation and ScenarioForge service setup; APP reruns
its application/dependency setup and writes `.scenarioforge.env`; participant
reruns its selected software setup. All retain saved lab settings and repository
refs: a branch fetches its current code, while a pinned version stays pinned.

Use `--reinstall core`, `--reinstall app`, `--reinstall participant`, or `--reinstall all` to rebuild selected guests with the current provisioning scripts:

Run on the provision host from the repository root, using the same account as
for the original installation (root/sudo on Proxmox):

```bash
# Preview, then rebuild only the participant VM.
sudo bash scripts/provision/proxmox/install-scenarioforge-lab.sh --reinstall participant --dry-run
sudo bash scripts/provision/proxmox/install-scenarioforge-lab.sh --reinstall participant

# Rebuild all three VMs.
sudo bash scripts/provision/proxmox/install-scenarioforge-lab.sh --reinstall all
```

Replace `participant` with `core` or `app` to rebuild either of those VMs alone.
Do not run `cleanup` first: reinstall uses the existing VMs, saved state, and
credentials to identify and recreate the selected guests.

While waiting, reinstall reports the guest's bootstrap phase, reported
percentage, and elapsed time. It also prints the latest bootstrap-log line
when it changes, so package activity is visible without a second terminal:

```text
participant reinstall: [25%] installing Kali XFCE and the default Kali tools (elapsed 00h:04m:00s)
participant guest: Unpacking chromium-common ...
```

The percentage tracks setup stages, not individual packages; it can stay at
25% while many packages install. Log lines are sampled on each poll, so this
is not a complete log stream. Before the guest agent is available, the message
reports that it is waiting for the guest agent / Cloud-Init. Reinstall falls
back to `/var/log/cloud-init-output.log` until the guest bootstrap log is
available. Normal `install` runs also show sampled guest log activity by
default, including while waiting for participant isolation with `--no-wait`.

**This erases the selected VMs' disks and guest data.** It retains saved login
credentials and lab network settings. Other VMs and host networks are not
recreated. The command asks you to type `REINSTALL`; `--yes` accepts that
replacement without prompting. Stop any active exercises first.

After confirmation, reinstall gives each running selected VM 120 seconds to
shut down gracefully. If it remains running, the installer rechecks ownership
and forcibly stops it before recreation. It verifies that all selected VMs are
stopped before replacing any disks. This shutdown timeout is separate from
the guest provisioning timeout controlled by `--wait-minutes`.

Normal installation caches base images, and cleanup preserves that cache.
Reinstall verifies the required images **before replacing any VM**. If an image is missing,
it shows the download source and asks `Download and verify this image before
reinstalling? [y/N]`. Answer `y` to download it; declining or having no input
stops with the existing VMs intact. `--yes` does not bypass this separate download
prompt. Dry runs report missing images without prompting or downloading.

Downloads record a checksum receipt, allowing reinstalls to reuse that verified
release even when an upstream `latest` URL changes. Older caches without a
receipt are checked against the upstream checksum list. Without `--force`, existing images that
fail verification stop the reinstall; they are not automatically replaced.
A failed download or checksum check also stops before any VM is replaced.

To force fresh base-image downloads for the selected VMs, use `--force`:

```bash
./install-scenarioforge-lab.sh --reinstall app --force
```

This authorizes the required downloads without the separate download prompt,
even when an image is already cached. Fresh images must pass upstream checksum
verification before replacing cache files or any VM. A failed download keeps
the previous cached file and the existing VMs. `--force` never bypasses image
verification, VM ownership checks, or the `REINSTALL` confirmation; use `--yes`
for the latter. With `--dry-run`, it only reports the planned image refresh.
The existing cleanup meaning of `--force` is unchanged.


Guest packages, Git repositories, and optional catalogs still require Internet
access. Software is fetched from the saved branches/refs (`main` by default for
CyberAgentFlow). Participant rebuilds automatically restore temporary NAT for
setup and remove it after readiness succeeds. Reinstall waits for the selected
guests even when the original installation used the no-wait option. On failure,
check the guest console and bootstrap log; a participant that fails setup keeps
its temporary NAT adapter for diagnosis.

If a Kali participant stays at `80%: rebooting into the full Kali kernel`, the
message is the last saved bootstrap phase, not confirmation that it is still
rebooting. Inspect the running kernel, resume service, and bootstrap log from
the Proxmox host (replace `9403` with your participant VMID):

```bash
qm guest exec 9403 -- bash -lc 'uname -r; uptime; systemctl status scenarioforge-participant-bootstrap.service scenarioforge-participant-reboot.service scenarioforge-participant-reboot.timer cloud-final.service --no-pager -l; tail -n 80 /var/log/scenarioforge-participant-bootstrap.log'
qm guest exec 9403 -- journalctl -b -u scenarioforge-participant-bootstrap.service -u scenarioforge-participant-reboot.service --no-pager -n 100
```

If the guest agent is unavailable, run the commands after `--` in the participant
console as root. The host detects failed reboot/resume services as well as
Cloud-Init failures. A unit that never started may still require checking the
boot journal. Preserve this evidence before retrying `--reinstall participant`,
which recreates the VM rather than resuming the retained guest.

Use the same state directory as the original installation. Its default is
`/etc/scenarioforge-lab`; if you originally set `SCENARIOFORGE_LAB_STATE_DIR`, set it to
the same directory for reinstall. On Proxmox, ensure the variable is passed to
the root process when using sudo.

For older labs whose state predates saved image-cache/source settings, also
pass `--config /path/to/original.conf` or the original environment overrides so
the installer finds the same cache and source refs. Reinstall uses the saved
participant OS; it does not convert Debian to Kali or change pinned source refs
to the latest branch.

See the [cross-platform command reference](../../../README.md#reinstall-one-vm-or-the-whole-lab)
for equivalent commands on other hosts.

### CORE desktop kernel

CORE guests booting a Debian cloud kernel install the standard architecture
kernel before building CORE. Provisioning selects the newest installed standard
kernel in GRUB, reboots once, and resumes automatically. This provides the mouse
and USB drivers needed by the graphical console; keep Proxmox's tablet pointer
enabled. The cloud kernel remains installed as a fallback. A failed handoff is
reported instead of repeatedly rebooting or marking CORE ready.

This applies to new installs and CORE reinstalls, including the shared Linux
guest bootstrap used by VMware. Existing guests are not changed by updating the
host scripts. Reinstalling CORE replaces its guest disk.
