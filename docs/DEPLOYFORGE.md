# DeployForge / Proxmox deployment

The first automated deployment target is now available as the
[Proxmox three-VM installer](../scripts/provision/proxmox/README.md). Run it in the shell
of a single Proxmox VE node to provision:

- A ScenarioForge Ubuntu application VM.
- A Debian 12 CORE VM installed from [our CORE fork](https://github.com/raistlinJ/core)
  through the `coreemu-minimal --from-source` path.
- A minimal Debian 12 participant VM.
- Separate management, participant/HITL, and uplink networks.

The installer uses Proxmox Cloud-Init rather than a separate DeployForge file.
It includes a dry-run, refuses to overwrite existing VMIDs, verifies cloud-image
checksums, generates credentials, installs ScenarioForge's custom CORE services,
and waits for guest-side health markers.

See [VM Mode Setup](VM_MODE_SETUP.md) for the architecture and
[the installer guide](../scripts/provision/proxmox/README.md) for requirements, options,
failure recovery, and security notes.
