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


The shared APP guest bootstrap installs Node.js and verifies `node --version`
for CLI HTML and Markdown guide export. For existing APP guests, run
`sudo apt update && sudo apt install -y nodejs`, then verify `node --version`.

## Host and architecture support

- VMware Fusion 13 or newer, installed in `/Applications/VMware Fusion.app`.
  Set `SF_FUSION_APP` when using a differently named application bundle.
- Apple silicon uses Debian's hardware-compatible generic ARM64 image and the
  Ubuntu ARM64 cloud image, the Fusion ARM guest types, UEFI, NVMe disks, and
  `vmxnet3` adapters. The ARM64 CORE guest installs static QEMU user emulation
  and an amd64 `binfmt_misc` handler so Docker can execute images that publish
  only `linux/amd64`.
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
architecture. The optional catalog metadata can also be installed; amd64-only
(x86-only) container processes run through QEMU and are slower than native
ARM64 images. Some workloads can still depend on architecture-specific kernel
or hardware behavior and remain incompatible. VMware documents the guest
architecture restriction and recommends UEFI, NVMe, and `vmxnet3` for ARM Linux
guests in its
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
normally removes only an unchanged, installer-created network. With `cleanup
--force`, it also removes that tracked vmnet if its settings changed. A network
referenced by another running VM is always preserved.

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
cd scripts/provision/vmware-fusion-mac
./install-scenarioforge-lab.sh --verbose
```

The installer asks you to type `INSTALL`. Add `--yes` for unattended setup. It
downloads and verifies the correct cloud-image architecture, creates three
`.vmwarevm` bundles, and supplies Cloud-Init through both VMware GuestInfo and
fallback seed ISOs. It then starts the graphical VMs and
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

The installer creates two shortcuts on your host desktop by default:

- **ScenarioForge** checks that the CORE and APP VMs are running, then opens
  the APP VM's HTTPS site in your default browser.
- **ScenarioForge Participant VM** checks that the CORE and participant VMs
  are running, then opens the participant console in VMware.

If required VMs are stopped, the launcher lists them and asks whether to start
those VMs. Canceling opens nothing and leaves them stopped. Accepting starts
only the missing VMs, with CORE first, and checks that they are running before
continuing. Startup or VMware status errors are shown instead of opening the
browser or console. Shortcut starts use VMware's GUI mode so you can see the
VMs resume and respond to any startup questions. On macOS, the launcher also
connects the required VMs to Fusion, including VMs previously started headlessly,
so its dashboard and VMware Tools checks reflect their current state.
The browser launcher waits up to two minutes for the APP
VM's current network address; it does not use an old saved address. The web
service may need a little longer to finish booting after the browser opens.

Both shortcuts use `.command` files on macOS and `.desktop` files on Linux.
They open a terminal for progress and use a native macOS dialog or Linux Zenity
confirmation when available, with a terminal confirmation as the fallback.
The installed launcher does not need the repository checkout or guest passwords.

Set `desktop_shortcut=false` in the config or pass `--no-desktop-shortcut` to
skip both shortcuts; `--desktop-shortcut` enables them explicitly. The environment
equivalent is `SF_DESKTOP_SHORTCUT=0` or `1`. This setting is independent of
`--headless`. Linux uses the desktop directory reported by `xdg-user-dir`,
falling back to `~/Desktop` when that tool is unavailable.

For an existing lab, run `./install-scenarioforge-lab.sh status` to update the
shortcuts and install the VM checks. On macOS, an unchanged installer-created
`ScenarioForge.webloc` is replaced with `ScenarioForge.command`. Browser shortcut
creation no longer requires the APP VM to have an IP address at install time.
Cleanup removes unchanged installer-created shortcuts and their unused runtime
helper. Existing or edited shortcuts and helpers are preserved. On Linux,
the desktop may ask you to allow launching a shortcut the first time you open it.


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

The installer ends with an **Open ScenarioForge** block showing the APP VM's
current URL for your Mac's browser, such as `https://<app-nat-ip>/`. You can
retrieve the current address later with `./install-scenarioforge-lab.sh status`.

- CORE desktop: `corevm`
- APP desktop: `scenarioforge`
- Participant desktop: `participant`
- ScenarioForge Web GUI: `coreadmin` at `https://<app-nat-ip>/`

Inside the APP VM, open ScenarioForge using the **ScenarioForge** desktop icon
or navigate to [https://localhost](https://localhost) in the VM's browser.
Log in to the Web GUI as `coreadmin`.

The certificate is self-signed, so the browser warning is expected. The APP
desktop includes a ScenarioForge launcher, Epiphany, Terminator, Evince, xdot,
Mousepad, and `jq`. Its XFCE session requests an initial 1600x900 display when
the virtual display supports it, without shrinking a larger display. No VM
restart is required after installation.

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


## Kali participant

For a new lab, add `--participant-os kali` to the installer command, or set
`participant_os=kali` in the config file (`SF_PARTICIPANT_OS=kali` also works).
Config values are overridden by environment values, then CLI flags.
Debian remains the default; CORE continues to use Debian 12.

Kali gets XFCE, `kali-linux-default`, **2048 MB RAM**, 2 CPUs, and a 40 GB
disk. Resource overrides remain `SF_PARTICIPANT_MEMORY_MB`,
`SF_PARTICIPANT_CORES`, and `SF_PARTICIPANT_DISK_GB` (Kali minimum: 25 GB).
The username remains `participant`.

The installer verifies the official Kali 2026.2 cloud archive, extracts its raw
disk, and converts it to VMDK. The Kali participant uses an NVMe controller.
During VMware provisioning, it installs the full Kali kernel for graphics and
reboots automatically before checking the desktop. Its temporary NAT adapter
remains attached until provisioning finishes; `--no-wait` also waits for this
isolation step. Allow extra time for tool downloads with `--wait-minutes`.

Image overrides are `SF_KALI_IMAGE_URL` and `SF_KALI_SUMS_URL`; use a matching
official generic cloud archive containing `disk.raw` and its SHA256 list.
Existing Debian VMs are not converted by this option.

Apple silicon uses the ARM64 Kali image; Intel Macs use amd64. Image URL
overrides must match the host architecture.


### Cleanup after a manually removed or changed vmnet

Fusion may still report a vmnet after it was removed, or the same vmnet number
may now describe a different network. Normal cleanup preserves networks whose
settings no longer match the installer-owned HITL network.

To remove the tracked network and finish cleanup, run:

```bash
bash scripts/provision/vmware-fusion-mac/install-scenarioforge-lab.sh cleanup --force
```

This stops Fusion networking, removes the tracked vmnet's configuration and
per-network directory, restarts networking, and verifies removal. The installer
attempts rollback if removal fails. It does not remove management/default vmnets
or a network referenced by another running VM.

To keep the current network and finish cleaning up the old lab, run:

```bash
bash scripts/provision/vmware-fusion-mac/install-scenarioforge-lab.sh cleanup --keep-hitl-network
```

This preserves the host vmnet and skips networking service restarts while
releasing the old lab's network ownership. Normal cleanup still applies to
installer-owned VMs, shortcuts, and state. Add `--dry-run` to preview.
The option is valid only for Fusion cleanup.

## Optional CyberAgentFlow on Kali

Set `participant_os=kali` and `cyber_agent_flow=true` in the grouped example
config section (Windows JSON uses `"participant_os": "kali"` and
`"cyber_agent_flow": true`). The shell installers also accept
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
| `llm_provider_url` | Full HTTP(S) endpoint using that same IP, including port/path |
| `llm_provider_type` | `ollama_direct`, `litellm`, `openai`, or `claude` |
| `llm_model` | Model name used by CyberAgentFlow |
| `llm_interface_cidr` | Reserved, unused static address/prefix for Kali on the egress network |
| `llm_gateway` | Reachable router address in that network |
| `llm_vmnet` | VMware: existing egress vmnet, default `vmnet8` |
| `llm_bridge` | Proxmox: existing egress bridge; empty uses `uplink_bridge` |

Use the gateway/subnet actually configured on your chosen vmnet/bridge. The LLM
network must differ from HITL and management. A third Kali NIC is matched by MAC
and named `ens20`; cloud-init persists its static address and a provider-specific
`/32` route via the gateway (direct link route for a provider in the same subnet).
It has no DHCP, IPv6 autoconfiguration, or default route. The ordinary bootstrap
NIC `ens19` is still removed after provisioning; the new LLM NIC remains. Guest
readiness checks `ip -4 route get ADDRESS` and refuses to mark setup complete if
that route does not use `ens20`. This checks routing, not provider availability or
authentication. The dedicated NIC is not a firewall: other addresses on its local
subnet remain reachable, and guests with sudo can change routing.

CyberAgentFlow is installed in `/opt/cyber-agent-flow` using its prerequisites
script while the temporary Internet connection is available. It is not started
automatically. Log in as `participant` and run `cyber-agent-flow` in a terminal
to launch web mode through `start_ws.sh`.
The generated `configs/cli.json` contains the endpoint/provider/model; set
`MCP_API_KEY` in your guest session when authentication is needed. No API keys are
placed in the provisioning config. The WebUI uses `configs/cli.json` for initial provider, URL, model, TLS, and
limit settings; existing browser-saved settings take precedence. API keys are
not embedded in the page. Provisioning applies a bundled compatibility patch
for this behavior and skips it if the same patch is already present upstream.

This option applies to new labs; cleanup removes the extra NIC with its VM and
preserves the pre-existing egress vmnet/bridge. Reinstall to add it to an existing
lab. When disabled, the original two-interface participant layout is unchanged.
