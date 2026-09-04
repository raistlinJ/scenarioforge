# ScenarioForge three-VM installer for VMware Fusion on macOS

This installer provisions the same graphical ScenarioForge lab as the Proxmox
and VMware Workstation installers, using VMware Fusion on either Apple silicon
or Intel Macs.

| VM | Operating system and software | Interfaces |
|---|---|---|
| CORE | Debian 12, XFCE, CORE GUI, CORE 9.2.1 built from `raistlinJ/core` with `coreemu-minimal --from-source`, Docker | `ens18` management, `ens19` isolated HITL with no IP, `ens20` NAT uplink |
| APP | Ubuntu 24.04, XFCE, Epiphany, Terminator, PDF/DOT/JSON viewers, native ScenarioForge systemd service, nginx/TLS | `ens18` NAT uplink, `ens19` management |
| PARTICIPANT | Debian 12, minimal XFCE | `ens18` isolated HITL; temporary NAT `ens19` is removed after XFCE installs |

The APP VM receives `/opt/scenarioforge/.scenarioforge.env` with the CORE
management address, SSH credentials, gRPC port `50051`, and HITL interface
`ens19`. ScenarioForge and `core-daemon` start automatically on boot. VMware
Tools integration is installed in every guest for guest operations, display
integration, and clipboard support.

## Host and architecture support

- VMware Fusion 13 or newer, installed in `/Applications/VMware Fusion.app`.
  Set `SF_FUSION_APP` when using a differently named application bundle.
- Apple silicon uses the Debian and Ubuntu ARM64 cloud images, the Fusion ARM
  guest types, UEFI, NVMe disks, and `vmxnet3` adapters.
- Intel Macs use AMD64 cloud images and SCSI disks.
- About 140 GB of free space for the default expanded disks, plus enough RAM to
  run the selected guests. Defaults are 8 GB CORE, 4 GB APP, and 2 GB
  PARTICIPANT.
- Python 3, `curl`, `openssl`, `shasum`, and `hdiutil`, which macOS provides.
- `qemu-img`, installed with Homebrew:

```bash
brew install qemu
```

Fusion cannot run x86 guests on Apple silicon, so this installer selects ARM64
guests there. CORE and ScenarioForge themselves are installed natively for that
architecture. The optional catalog metadata can also be installed, but some
Vulhub recipes or third-party container images are x86-only and may not execute
on Apple silicon. VMware documents the architecture restriction and recommends
UEFI, NVMe, and `vmxnet3` for ARM Linux guests in its
[Apple-silicon compatibility guidance](https://knowledge.broadcom.com/external/article/315602/compatibility-considerations-for-arm-gue.html).

## Automatic isolated network setup

The installer checks the requested HITL network before creating any VMs. If it
is missing or has DHCP, NAT, or host-Mac access enabled, an interactive install
automatically proposes the first unused `vmnet` instead of modifying the
existing network. It prints the complete change and requires you to type
`INSTALL+NETWORK` before proceeding. macOS then asks for administrator
credentials when the change is applied.

For example, if `vmnet2` is already used by another VM, the installer may
create `vmnet3` with:

- DHCP disabled.
- NAT disabled.
- Host Mac access/virtual adapter disabled.

Fusion's networking services restart briefly after the change, so networking
in already-running VMs may disconnect momentarily. The installer verifies the
result and restores the previous configuration if activation fails. Cleanup
removes only an unchanged, installer-created network; it will preserve a
network that somebody modified or attached to another running VM.

For explicitly authorized unattended network creation, combine:

```bash
./install-scenarioforge-lab.sh --manage-hitl-network --yes --verbose
```

`--yes` by itself never authorizes a host-network change. Use
`--no-manage-hitl-network` to require a manually prepared network instead. To
prepare one manually, open **VMware Fusion > Settings > Network**, unlock the
pane, create a custom network, and disable the three settings above.

Keep `vmnet1` as the management network. DHCP may remain enabled on `vmnet1`;
the APP and CORE management NICs use static addresses and only require shared
Layer-2 connectivity.

The installer validates both networks through Fusion's `vmrun` interface and
also inspects `/Library/Preferences/VMware Fusion/networking`. It refuses to
use a HITL network with DHCP, NAT, or a host adapter because the participant
network must not reach macOS, the LAN, or the Internet. Automated changes are
limited to a newly selected, previously unused `vmnet`.

VMware describes custom Fusion networks and the Network settings pane in its
[Fusion DHCP/network editor guidance](https://knowledge.broadcom.com/external/article/311759/modifying-the-dhcp-settings-of-vmnet1-an.html).

## Install

Run from this repository as your normal macOS desktop user, not with `sudo`:

```bash
cd scripts/vmware-fusion
./install-scenarioforge-lab.sh --verbose
```

The installer asks you to type `INSTALL`. Add `--yes` for unattended setup. It
downloads and verifies the correct cloud-image architecture, creates three
`.vmwarevm` bundles and Cloud-Init seed ISOs, starts the graphical VMs, and
prints percentage heartbeats while provisioning. Building CORE from source can
take well over an hour.

VMs are stored by default under:

```text
~/Virtual Machines.localized/ScenarioForge-Lab/
```

Use `--lab-dir /absolute/path` or `SF_FUSION_LAB_DIR` to change it. Use
`--headless` to start with `nogui`; opening those VMs later in Fusion does not
require a guest restart.

### Config file

```bash
mkdir -p "$HOME/.config"
cp scenarioforge-lab.conf.example "$HOME/.config/scenarioforge-fusion-lab.conf"
chmod 600 "$HOME/.config/scenarioforge-fusion-lab.conf"

./install-scenarioforge-lab.sh install \
  --config "$HOME/.config/scenarioforge-fusion-lab.conf" \
  --verbose
```

Precedence is **built-in defaults < config file < environment < CLI flags**.
The config is parsed as data and is never executed. Matching quotes are removed
without shell expansion, and unknown keys are rejected.

### Credentials

Passwords default to independent random 10-character alphanumeric values. You
can set any subset with:

```bash
./install-scenarioforge-lab.sh \
  --core-password 'CORE-password' \
  --app-password 'APP-password' \
  --participant-password 'participant-password' \
  --web-admin-password 'Web-admin-password'
```

The usernames are `corevm`, `scenarioforge`, `participant`, and `coreadmin`.
Completion prints every credential and stores them with mode `0600` at:

```text
~/Library/Application Support/ScenarioForge/fusion-lab/credentials.env
```

Prefer a protected config file or `SF_CORE_PASSWORD`, `SF_APP_PASSWORD`,
`SF_PARTICIPANT_PASSWORD`, and `SF_WEB_ADMIN_PASSWORD` for unattended installs;
literal command-line passwords can appear in shell history and process lists.

### Optional catalogs

```bash
./install-scenarioforge-lab.sh --flag-generators
./install-scenarioforge-lab.sh --vulnhub
./install-scenarioforge-lab.sh --flag-generators --vulnhub
```

These use the same tested `raistlinJ/flag-generators` snapshot and portable
success/enabled/notes metadata as the Proxmox and Workstation installers. The
private repository is cloned on the Mac using its existing GitHub credentials;
credentials are not copied into a guest. For SSH access, set:

```bash
export SF_FLAG_GENERATORS_URL=git@github.com:raistlinJ/flag-generators.git
```

The installer transfers only the requested content to APP with a generated
one-time SSH key and removes that key after provisioning.

## Status

From another Terminal window:

```bash
./install-scenarioforge-lab.sh status
./install-scenarioforge-lab.sh status --watch --interval 5
```

Status reports overall and per-guest percentages, Cloud-Init phases, VM power,
the APP IP and Web URL, network layout, and whether the participant's temporary
NAT adapter has been removed.

`--no-wait` still waits for participant XFCE provisioning and removes its NAT
adapter before returning; CORE and APP continue in the background.

## Access after installation

- CORE desktop: `corevm`
- APP desktop: `scenarioforge`
- Participant desktop: `participant`
- ScenarioForge Web GUI: `coreadmin` at `https://<app-nat-ip>/`

The certificate is self-signed, so the browser warning is expected. The APP
desktop includes a ScenarioForge launcher, Epiphany, Terminator, Evince, xdot,
Mousepad, and `jq`. No VM restart is required after installation.

## Cleanup

Remove an incomplete or stopped installer-owned lab with:

```bash
./install-scenarioforge-lab.sh cleanup
```

A complete, running lab additionally requires:

```bash
./install-scenarioforge-lab.sh cleanup --force
```

Cleanup verifies the owner marker in every VMX before stopping and removing its
`.vmwarevm` bundle. It removes saved installer state and credentials but keeps
the verified base-image cache under
`~/Library/Caches/ScenarioForge/fusion-lab/images` for reuse.

## Troubleshooting

- If `vmnet2 has DHCP enabled`, correct it in Fusion's Network settings; do not
  bypass the check, or let the interactive installer propose a new network.
- If Fusion tools are elsewhere, set `SF_FUSION_APP` to the application bundle.
- Guest logs are `/var/log/scenarioforge-{core,app,participant}-bootstrap.log`.
- Use `status --watch --interval 5` while CORE builds from source.
- On Apple silicon, failures limited to a particular vulnerability container
  may indicate that its upstream image is available only for x86_64.
