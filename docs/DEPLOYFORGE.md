# DeployForge / Proxmox deployment

The first automated deployment target is now available as the
[Proxmox three-VM installer](../scripts/provision/proxmox/README.md). Run it in the shell
of a single Proxmox VE node to provision:

- A ScenarioForge Ubuntu application VM.
- A Debian 12 CORE VM installed from [our CORE fork](https://github.com/raistlinJ/core)
  through the `coreemu-minimal --from-source` path.
- A minimal Debian 12 participant VM, or Kali Linux with XFCE and standard tools
  when selected with `--participant-os kali`.
- Separate management, participant/HITL, and uplink networks.

The installer uses Proxmox Cloud-Init rather than a separate DeployForge file.
It includes a dry-run, refuses to overwrite existing VMIDs, verifies cloud-image
checksums, generates credentials, installs ScenarioForge's custom CORE services,
and waits for guest-side health markers.

See [VM Mode Setup](VM_MODE_SETUP.md) for the architecture and
[the installer guide](../scripts/provision/proxmox/README.md) for requirements, options,
failure recovery, and security notes.

To rebuild an existing participant VM with the current provisioning scripts,
run from the repository root on the Proxmox node:

```bash
sudo bash scripts/provision/proxmox/install-scenarioforge-lab.sh --reinstall participant --dry-run
sudo bash scripts/provision/proxmox/install-scenarioforge-lab.sh --reinstall participant
```

Use `core`, `app`, or `all` to select other guests. **This erases the selected
VMs' disks and guest data.** Keep the original installer state and credentials;
do not run cleanup first. Reinstall verifies cached base images before replacing
VMs and asks before downloading any missing image. Software downloads still
require Internet access. See the [reinstall guide](../scripts/provision/proxmox/README.md#reinstall-selected-vms-using-cached-images)
for confirmation, state-directory, and recovery details, or the
[cross-platform commands](../README.md#reinstall-one-vm-or-the-whole-lab) for VMware hosts.
