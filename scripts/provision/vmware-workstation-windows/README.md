# ScenarioForge lab on VMware Workstation for Windows

This PowerShell installer creates the same three graphical Linux guests as the
[Linux Workstation installer](../vmware-workstation-linux/README.md):

| VM | Guest | Purpose | Default RAM / CPUs / disk |
| --- | --- | --- | --- |
| CORE | Debian 12 + XFCE | CORE emulator and GUI, built from the ScenarioForge fork | 8 GB / 4 / 80 GB |
| APP | Ubuntu 24.04 + XFCE | Native ScenarioForge, nginx, browser, and document tools | 4 GB / 2 / 40 GB |
| Participant | Debian 12 + XFCE | Participant desktop on the isolated HITL network | 2 GB / 2 / 20 GB |

The complete installation runs on Windows. **No WSL, Ubuntu host installation,
or Git Bash is required.** Windows Python creates the Cloud-Init seed ISOs and
VMX files; native `qemu-img.exe` converts the cloud disks. The existing guest
bootstrap scripts are read as text and run later inside the Linux VMs.
PowerShell and `vmrun.exe` control the VMs and desktop shortcuts.

## 1. Prepare the host

Use an x64 Windows host supported by your Workstation release, with VMware
Workstation Pro, PowerShell **7.4 or newer** (`pwsh`), and enough resources for
14 GB of guest RAM plus Windows. Allow room for up to 140 GB of growing
VM disks, plus cached cloud images. Windows ARM is not supported by this script.

Install PowerShell using [Microsoft's Windows installation instructions](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows).
Use `pwsh`, not the built-in Windows PowerShell 5.1.

Install [Python for Windows](https://www.python.org/downloads/windows/) (3.11 or
newer). You can let the lab installer download QEMU when needed, or install the
Windows build linked from [QEMU's official download page](https://www.qemu.org/download/#windows)
yourself. Only `qemu-img.exe` is used; QEMU does not run the lab VMs.

When `qemu-img.exe` is missing, a separate **[y/N] confirmation** offers to download
QEMU 11.1.0 (2026-08-11, about 200 MB) from `qemu.weilnetz.de`. The script checks
the downloaded installer against its pinned upstream SHA-512 before opening it.
Windows requests administrator approval, then QEMU's setup wizard opens. Keep
**Tools** and **Libraries (DLL)** selected. Once setup finishes, the script
redetects `qemu-img.exe` and continues automatically. Custom installation paths
are discovered through QEMU's registry entry; you can also set `qemu_img`.

Declining stops setup before a download or any VM creation. `-Yes` does **not**
bypass this download confirmation. `-DryRun` reports the missing dependency
without prompting, downloading, or opening setup. Interrupted downloads, failed
checksum checks, and canceled setup stop the lab installation and remove its
temporary download. QEMU itself remains installed when the lab is cleaned up.

Clone the **whole ScenarioForge repository** onto a local Windows drive, then
open PowerShell 7 in this installer directory and prepare a Windows Python
environment:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\requirements-installer.txt
```

The two Python packages create ISO files and Linux-compatible password hashes.
No Linux commands or OpenSSL installation are needed on the host. The adjacent
Linux/Proxmox installer file supplies the shared guest bootstrap text; the native
builder never executes that file on Windows.

The lab installer runs as your normal Windows user. Only the optional QEMU
setup wizard requests elevation. The script does not install Workstation or
modify host networks.

## 2. Configure Workstation networking

Open **Edit → Virtual Network Editor → Change Settings** and configure:

| Network | Type and subnet | DHCP | Host virtual adapter |
| --- | --- | --- | --- |
| VMnet1 | Host-only, `172.31.250.0/24` | Off | May remain enabled |
| VMnet2 | Host-only, `10.254.200.0/24` | Off | **Off** |
| VMnet8 | NAT, your existing subnet | On | Default |

Use a spare custom network if VMnet1 or VMnet2 is already in use, and set
`management_vmnet` / `hitl_vmnet` in the config. This version uses fixed guest
management and HITL addresses, so the corresponding subnets must match the table.
The installer checks the networks and rejects a bridged/NAT/DHCP-enabled HITL
network or an active host adapter on it.

CORE connects to management, HITL, and NAT. APP connects to NAT and management.
Participant connects to HITL and gets a **temporary** NAT adapter for package
installation. The installer shuts down participant after its bootstrap finishes,
removes NAT, saves that state, and starts it again. If installation is interrupted,
run `resume` to finish this step. The participant shortcut refuses to open a lab
whose temporary NAT adapter is still attached.

## 3. Install

Open PowerShell 7 in this directory. Copy the example and change `lab_dir` to an
unused directory under your Windows account:

```powershell
Copy-Item .\scenarioforge-lab.json.example .\lab.json
notepad .\lab.json
.\install-scenarioforge-lab.ps1 install -ConfigFile .\lab.json -PythonExe .\.venv\Scripts\python.exe -DryRun
.\install-scenarioforge-lab.ps1 install -ConfigFile .\lab.json -PythonExe .\.venv\Scripts\python.exe
```

If your execution policy blocks locally reviewed scripts, allow them for this
terminal session with `Set-ExecutionPolicy -Scope Process RemoteSigned`. Do not
change machine policy just for this installer.

Built-in defaults are overridden by JSON settings, then command-line overrides:
`-LabDir`, `-VmwareDir`, `-PythonExe`, `-QemuImg`, `-NoDesktopShortcut`, and
`-NoWait`. Alternatively, set `python_exe` and `qemu_img` in JSON to their full
Windows executable paths. Python is otherwise discovered through `py -3` or
PATH; install the requirements into whichever environment you select. VMware's
installation directory is detected from the registry; set `vmware_dir` if needed.
Verified base images are cached under `%LOCALAPPDATA%\ScenarioForge\image-cache`;
use the optional `image_cache` JSON setting to choose another local directory.

`-DryRun` checks prerequisites and prints the plan without downloading images,
creating files, starting VMs, or changing networks. `-Yes` accepts the installation
confirmation. CORE builds from source and can take over an hour; increase
`wait_minutes` if needed. `no_wait=true` still waits for participant setup and
removes its NAT adapter, while CORE and APP continue provisioning.

Both **ScenarioForge.lnk** and **ScenarioForge Participant VM.lnk** are created
on your Windows desktop by default. Set `desktop_shortcut=false` in JSON or use
`-NoDesktopShortcut` to skip both.

- ScenarioForge checks CORE + APP, then opens the APP's current HTTPS address.
- Participant checks CORE + participant, then opens the participant console.
- Stopped/suspended VMs are listed in a Yes/No prompt. Declining starts nothing.
- Accepted starts use GUI mode, resume suspended VMs, and watch their actual
  running state so a lingering `vmrun` client does not block the launcher.
- Shortcuts need neither Python, QEMU, the repository checkout, nor guest passwords.
  APP's web service may take longer to boot than its network address.

### Optional catalogs

The first installation works without access to private Git repositories.
`flag_generators` and `vulnhub` default to `false` on Windows. Enable either in JSON
to include the corresponding private catalogs. Authenticate Git for
`https://github.com/raistlinJ/flag-generators.git` using **Git for Windows** first.
Git is only required for these optional catalogs; it is discovered on PATH or
through the `git_exe` setting. The native builder archives the tested snapshot
with its Unix file permissions intact. Windows transfers the archive through
VMware Tools, and APP verifies its checksum.
GitHub credentials are not copied into a guest.

## 4. Status, recovery, and passwords

```powershell
.\install-scenarioforge-lab.ps1 status
.\install-scenarioforge-lab.ps1 status -Watch
.\install-scenarioforge-lab.ps1 resume
.\install-scenarioforge-lab.ps1 credentials
```

`resume` starts the owned VMs, retries an unfinished catalog transfer, waits for
bootstrap, completes participant isolation, and refreshes unchanged shortcuts.
It uses saved configuration and credentials. `status` observes state and does not
start VMs or change networking. Stop watching with Ctrl+C.

Guest accounts are `corevm`, `scenarioforge`, and `participant`; the web
administrator is `coreadmin`. Blank config passwords are generated randomly.
Passwords are saved as encrypted SecureStrings using Windows DPAPI, readable by
the installing Windows account on that machine. Use the `credentials` command to
display them when needed. Avoid putting passwords in a shared config file.

State and installed launcher files live in
`%LOCALAPPDATA%\ScenarioForge\workstation-lab`. Use `-StateDir` consistently for
all commands if you choose another location. The state and VM directories receive
restricted Windows ACLs. A temporary plaintext build request is removed even when
the build fails; seed images and VM guest configuration still contain provisioning
secrets and should stay private.

For bootstrap failures, inspect the guest console and
`/var/log/cloud-init-output.log` or `/var/log/scenarioforge-*-bootstrap.log`.
If image preparation failed before VM creation completed, clean up the partial
installation and reinstall; `resume` requires all three VMX files.

## 5. Remove the lab

```powershell
.\install-scenarioforge-lab.ps1 cleanup -DryRun
.\install-scenarioforge-lab.ps1 cleanup
```

Cleanup lists and removes only verified installer-owned VM directories. Shut down
running VMs first, or use `-Force` to permit a graceful shutdown before deletion.
An unresponsive VM stops cleanup; it is not forcibly powered off. `-Yes` skips the
`CLEANUP` confirmation. Host networks and cached base images are preserved.
Locally edited/untracked shortcuts and helpers are preserved too.

## Validation

Run `pwsh -NoProfile -File tests/test_vmware_windows.ps1` from the repository root.
These tests exercise native argument quoting, configuration validation, state
ownership, startup consent, dependency selection, network checks, and participant
isolation using simulated VMware commands. QEMU download tests cover separate
consent, dry-run behavior, checksum verification, cancellation, and cleanup
without downloading or executing a real installer. CI runs them on Windows without
VMware or SSH credentials. Native image-builder tests run with pytest and the installer requirements. They
create and read real seed ISOs, verify download checksums and catalog permissions,
and convert a small real disk when `qemu-img` is available.
A complete Windows Workstation installation still needs verification on a real
Windows host; the test suite does not boot VMs.
