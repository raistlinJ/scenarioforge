# ScenarioForge three-VM installer for VMware Workstation on Linux

This installer creates the same graphical lab as the Proxmox installer on an
x86_64 Linux workstation:

| VM | Operating system and software | Interfaces |
|---|---|---|
| CORE | Debian 12, XFCE, CORE GUI, CORE 9.2.1 built from `raistlinJ/core` with `coreemu-minimal --from-source`, Docker | `ens18` management, `ens19` isolated HITL with no IP, `ens20` NAT uplink |
| APP | Ubuntu 24.04, XFCE, Epiphany browser, native ScenarioForge systemd service, nginx/TLS | `ens18` NAT uplink, `ens19` management |
| PARTICIPANT | Debian 12, minimal XFCE | `ens18` isolated HITL; temporary NAT `ens19` is removed after XFCE installs |

The APP VM receives a private `.scenarioforge.env` configured with the CORE
VM's management address, SSH credentials, gRPC port `50051`, and CORE's HITL
interface name `ens19`. ScenarioForge is installed natively, not with Docker.

The APP desktop has a **ScenarioForge** launcher that opens the local Web GUI
in Epiphany at `https://localhost/`. Its self-signed certificate causes an
expected browser warning; no VM restart is required after provisioning.

## Requirements

- An x86_64 Linux host with VMware Workstation installed and runnable by your
  desktop user. The installer uses `vmrun` and `vmware-vdiskmanager`; it must not
  be run as root.
- Approximately 140 GB of free disk space for the default expanded VM disks,
  plus enough RAM to run the selected guests. The defaults allocate 8 GB to
  CORE, 4 GB to APP, and 2 GB to PARTICIPANT.
- `qemu-img`, `xorriso` (or `genisoimage`), `curl`, `openssl`, Python 3,
  GNU `timeout`, `sha256sum`, and `sha512sum`.
- Internet access from VMware's NAT network while the guests provision.

On Debian or Ubuntu hosts, the non-VMware dependencies can usually be installed
with:

```bash
sudo apt-get update
sudo apt-get install -y qemu-utils xorriso curl openssl python3 coreutils
```

On Fedora-family hosts:

```bash
sudo dnf install -y qemu-img xorriso curl openssl python3 coreutils
```

VMware documents its [supported Workstation host operating systems](https://knowledge.broadcom.com/external/article/315653/supported-host-operating-systems-for-wor.html),
[network types](https://knowledge.broadcom.com/external/article?legacyId=1006480),
and [Virtual Network Editor](https://knowledge.broadcom.com/external/article/339371)
separately.

## One-time network setup

Open **Edit > Virtual Network Editor** in VMware Workstation. Keep the normal
`vmnet1` host-only network for APP-to-CORE management, then create `vmnet2` as a
host-only/custom network with all of these disabled:

- **Use local DHCP service to distribute IP addresses to VMs**
- **Connect a host virtual adapter to this network**
- NAT

`vmnet2` is the participant exercise wire and must not reach the host, LAN, or
Internet. The installer refuses a `vmnet2` that `vmrun` reports as NAT, bridged,
or DHCP-enabled. It also checks `/etc/vmware/networking` for enabled DHCP, NAT,
or a host adapter when that file is readable.

The installer intentionally does not edit `/etc/vmware/networking` or restart
VMware networking. Those are host-global operations that could interrupt other
running VMs.

## Install

Run from a clone of this repository as your graphical desktop user:

```bash
cd scripts/vmware-workstation
./install-scenarioforge-lab.sh --verbose
```

The script asks for an `INSTALL` confirmation. Use `--yes` for unattended host
setup. It downloads and verifies current Debian 12 and Ubuntu 24.04 cloud
images, converts them to VMDKs, creates NoCloud seed ISOs and VMX files, starts
the VMs, and prints percentage heartbeats while Cloud-Init works. This can take
well over an hour when CORE is built from source.

VMware Workstation windows open by default so each XFCE desktop is visible. Use
`--headless` to start the VMs with `nogui`. Opening a headless VM in Workstation
later does not require a guest reboot.

Default VM files are stored in:

```text
~/vmware/ScenarioForge-Lab/
```

Change that location with `--lab-dir /absolute/path` or
`SF_VMWARE_LAB_DIR=/absolute/path`.

### Custom credentials

Passwords are generated as 10-character alphanumeric values by default. Supply
any subset when creating a lab:

```bash
./install-scenarioforge-lab.sh \
  --core-password 'CORE-VM-password' \
  --app-password 'APP-VM-password' \
  --participant-password 'participant-password' \
  --web-admin-password 'ScenarioForge-admin-password'
```

The corresponding usernames stay fixed as `corevm`, `scenarioforge`,
`participant`, and `coreadmin`. Every omitted password is still generated
independently. Because command-line secrets can appear in shell history and the
host process list, unattended installations should prefer
`SF_CORE_PASSWORD`, `SF_APP_PASSWORD`, `SF_PARTICIPANT_PASSWORD`, and
`SF_WEB_ADMIN_PASSWORD`. Final credentials are still printed at completion and
saved in the installer credentials file.

### Optional flag-generator and Vulhub catalogs

Populate a fresh APP VM from the private `raistlinJ/flag-generators`
repository with either or both flags:

```bash
./install-scenarioforge-lab.sh --flag-generators
./install-scenarioforge-lab.sh --vulnhub
./install-scenarioforge-lab.sh --flag-generators --vulnhub
```

Authenticate GitHub on the Linux host first. The default HTTPS URL uses the
host's existing Git credential helper; for SSH, set:

```bash
export SF_FLAG_GENERATORS_URL=git@github.com:raistlinJ/flag-generators.git
```

Never embed a token or password in that URL. The installer rejects HTTPS URLs
containing credentials, clones into its private temporary directory, sends
only the selected content with a generated one-time SSH key, and removes that
key from APP after verification. GitHub credentials are not copied into any
guest.

`--flag-generators` imports the flag and flag-node generator catalogs through
ScenarioForge's pack importer. Their files and pack state live under
`/opt/scenarioforge/outputs/installed_generators`, and provisioning verifies
that both catalog kinds are visible. The default revision is the previously
tested metadata snapshot `5f612eecb8ff5df74a0e517d0de1e54385a62044`.
Its portable `pack.json` records 147 successfully tested generators, with 144
enabled overall and exactly the 85 enabled flag-node generators represented by
the paper and resolved dataset. Three working samples remain catalog-disabled;
the one generator without successful evidence remains disabled and unvalidated.
All 148 generators include portable notes describing their evidence and state.
`--vulnhub` imports the same snapshot through the vulnerability-catalog
importer, makes it active, and imports portable success state for 294
self-contained recipes. Twelve documented recipes remain disabled and
unvalidated: 10 require build-time Internet access, one has missing required
paths, and one is outside the validated research catalog. All 306 recipes carry
portable notes: green for validated evidence and usage, red for exclusions. A custom
`--flag-generators-ref REF` or `SF_FLAG_GENERATORS_REF=REF` imports only the
portable metadata present in that revision. Both options add install time and
disk usage.

Catalog downloads retain validation status, enabled/disabled state,
provenance, and user-authored notes and note colors. Re-importing either catalog
type therefore preserves subsequent operator curation as well as source
metadata.

The optional repository contains intentionally vulnerable recipes and
challenge key material. Run this content only in the isolated, trusted lab
network described above.

### Observe a running installation

From another terminal:

```bash
./install-scenarioforge-lab.sh status
./install-scenarioforge-lab.sh status --watch --interval 5
```

Status shows overall and per-guest percentages, the current bootstrap phase,
power state, network layout, participant isolation state, and detected APP IP.
If `--watch` starts before install has written its state, it follows the runtime
status file instead of silently waiting.

`--no-wait` still waits for the participant's XFCE installation and removes its
temporary NAT adapter before returning. CORE and APP continue provisioning in
the background; use `status --watch` to follow them.

### Credentials and UI

At completion the installer prints credentials for all three Linux accounts and
the ScenarioForge administrator, followed by their storage path. They are kept
in a mode-`0600` file owned by the installing user:

```text
~/.local/state/scenarioforge-vmware-lab/credentials.env
```

The default accounts are:

- CORE VM: `corevm`
- APP VM: `scenarioforge`
- PARTICIPANT VM: `participant`
- ScenarioForge Web GUI: `coreadmin`

Passwords are independently generated as 10-character alphanumeric values on
each fresh install. The Web GUI is available at `https://<app-nat-ip>/`; its
certificate is locally generated, so a browser warning is expected. The APP
VM's own runtime configuration is stored at
`/opt/scenarioforge/.scenarioforge.env`, readable only by its `scenarioforge`
account.

## Cleanup and retry

Remove an incomplete or failed installation with:

```bash
./install-scenarioforge-lab.sh cleanup
```

For a complete, running lab, explicit force is required:

```bash
./install-scenarioforge-lab.sh cleanup --force
```

Use `--dry-run` to inspect the exact scope or `--yes` to skip the typed
confirmation. Cleanup verifies both the saved state identity and a private VMX
ownership marker before removing a VM directory. Downloaded base images remain
in `~/.cache/scenarioforge-vmware-lab/images` for reuse.

## Configuration overrides

The commonly useful settings are:

| Environment variable | Default |
|---|---|
| `SF_VMWARE_LAB_DIR` | `~/vmware/ScenarioForge-Lab` |
| `SCENARIOFORGE_VMWARE_STATE_DIR` | `~/.local/state/scenarioforge-vmware-lab` |
| `SF_VMWARE_MANAGEMENT_VMNET` | `vmnet1` |
| `SF_VMWARE_HITL_VMNET` | `vmnet2` |
| `SF_IMAGE_CACHE` | `~/.cache/scenarioforge-vmware-lab/images` |
| `SF_WAIT_MINUTES` | `90` |
| `SF_VERBOSE` | `0` |
| `SF_CORE_MEMORY_MB` / `SF_CORE_CORES` / `SF_CORE_DISK_GB` | `8192` / `4` / `80` |
| `SF_APP_MEMORY_MB` / `SF_APP_CORES` / `SF_APP_DISK_GB` | `4096` / `2` / `40` |
| `SF_PARTICIPANT_MEMORY_MB` / `SF_PARTICIPANT_CORES` / `SF_PARTICIPANT_DISK_GB` | `2048` / `2` / `20` |
| `SF_APP_MANAGEMENT_CIDR` | `172.31.250.2/24` |
| `SF_CORE_MANAGEMENT_CIDR` | `172.31.250.3/24` |
| `SF_CORE_HITL_CIDR` | `10.254.200.3/24` |
| `SF_PARTICIPANT_CIDR` | `10.254.200.10/24` |
| `SF_CORE_MINIMAL_URL` / `SF_CORE_MINIMAL_REF` | `raistlinJ/coreemu-minimal.git` / `main` |
| `SF_CORE_REPO_URL` / `SF_CORE_REPO_REF` | `raistlinJ/core.git` / `master` |
| `SF_SCENARIOFORGE_URL` / `SF_SCENARIOFORGE_REF` | `raistlinJ/scenarioforge.git` / `main` |
| `SF_INSTALL_FLAG_GENERATORS` / `SF_INSTALL_VULNHUB` | `0` / `0` |
| `SF_FLAG_GENERATORS_URL` / `SF_FLAG_GENERATORS_REF` | `raistlinJ/flag-generators.git` / `5f612eecb8ff5df74a0e517d0de1e54385a62044` (tested metadata snapshot) |
| `SF_CORE_PASSWORD` / `SF_APP_PASSWORD` | empty (generate independently) |
| `SF_PARTICIPANT_PASSWORD` / `SF_WEB_ADMIN_PASSWORD` | empty (generate independently) |

Image and checksum URLs can also be pinned with `SF_DEBIAN_IMAGE_URL`,
`SF_DEBIAN_SUMS_URL`, `SF_UBUNTU_IMAGE_URL`, and `SF_UBUNTU_SUMS_URL`.

## Current scope

This first version targets VMware Workstation on x86_64 Linux. It does not yet
cover VMware Fusion on macOS, Workstation on Windows, ARM guests, or automatic
host-network creation. VM lifecycle and guest-status behavior depend on the
current Workstation `vmrun` CLI, including `listHostNetworks`,
`listNetworkAdapters`, and `deleteNetworkAdapter`.
