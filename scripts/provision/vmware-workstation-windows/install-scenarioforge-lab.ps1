#requires -Version 5.1
<#
.SYNOPSIS
Provision the graphical CORE, ScenarioForge APP, and participant lab on Windows.
.EXAMPLE
.\install-scenarioforge-lab.ps1 install -ConfigFile .\lab.json
.EXAMPLE
.\install-scenarioforge-lab.ps1 status -Watch
.EXAMPLE
.\install-scenarioforge-lab.ps1 cleanup -DryRun
#>
[CmdletBinding()]
param(
    [ValidateSet('install', 'status', 'resume', 'cleanup', 'credentials', 'help')][string]$Command = 'install',
    [string]$ConfigFile,
    [string]$LabDir,
    [string]$StateDir = $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'ScenarioForge/workstation-lab' } else { '' }),
    [string]$VmwareDir,
    [string]$PythonExe,
    [string]$QemuImg,
    [ValidateSet('debian', 'kali')][string]$ParticipantOS,
    [switch]$NoDesktopShortcut,
    [switch]$NoManageHitlNetwork,
    [switch]$KeepHitlNetwork,
    [switch]$NoWait,
    [switch]$Watch,
    [switch]$DryRun,
    [switch]$Yes,
    [switch]$Force
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion -lt [version]'7.4') {
    try {
        . (Join-Path $PSScriptRoot 'powershell-bootstrap.ps1')
        Invoke-PowerShellBootstrap -ScriptPath $PSCommandPath -Parameters $PSBoundParameters -Preview:$DryRun
        exit $LASTEXITCODE
    } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
Import-Module (Join-Path $PSScriptRoot 'ScenarioForge.VMware.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot 'host-networks.ps1')

function Read-InstallerConfig {
    param([string]$Path, [string]$ParticipantOSOverride)
    $provided = @{}
    $config = @{
        lab_dir = $(if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'Virtual Machines/ScenarioForge-Lab' } else { '' })
        vmware_dir = ''; python_exe = ''; qemu_img = ''; git_exe = ''
        image_cache = $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'ScenarioForge/image-cache' } else { '' }); management_vmnet = 'vmnet1'; hitl_vmnet = 'vmnet2'
        desktop_shortcut = $true; no_wait = $false; wait_minutes = 90; manage_hitl_network = $true
        participant_os = 'debian'; kali_image_url = ''; kali_sums_url = ''
        core_memory_mb = 8192; app_memory_mb = 4096; participant_memory_mb = 2048
        core_cores = 4; app_cores = 2; participant_cores = 2
        core_disk_gb = 80; app_disk_gb = 40; participant_disk_gb = 20
        core_password = ''; app_password = ''; participant_password = ''; web_admin_password = ''; ssh_public_key = ''
        core_minimal_ref = 'main'; core_ref = 'master'; scenarioforge_ref = 'main'
        flag_generators = $false; vulnhub = $false; flag_generators_ref = '5f612eecb8ff5df74a0e517d0de1e54385a62044'
    }
    if ($Path) {
        $provided = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
        if ($provided -isnot [Collections.IDictionary]) { throw 'Config must be a JSON object.' }
        foreach ($key in $provided.Keys) {
            if (-not $config.ContainsKey($key)) { throw "Unknown configuration key: $key" }
            if ($null -eq $provided[$key]) { throw "Configuration value cannot be null: $key" }
            $config[$key] = $provided[$key]
        }
    }
    if ($env:SF_PARTICIPANT_OS) { $config.participant_os = $env:SF_PARTICIPANT_OS }
    if ($ParticipantOSOverride) { $config.participant_os = $ParticipantOSOverride }
    if ($config.participant_os -cnotin @('debian', 'kali')) { throw 'participant_os must be debian or kali.' }
    if ($config.participant_os -eq 'kali' -and -not $provided.ContainsKey('participant_disk_gb')) {
        $config.participant_disk_gb = 40
    }
    return $config
}

function Assert-InstallerConfig {
    param($Config)
    if ($Config.participant_os -cnotin @('debian', 'kali')) { throw 'participant_os must be debian or kali.' }
    if ($Config.participant_os -eq 'kali' -and $Config.participant_disk_gb -lt 25) {
        throw 'Kali participant_disk_gb must be at least 25 (default: 40).'
    }
    foreach ($key in @('desktop_shortcut', 'no_wait', 'flag_generators', 'vulnhub', 'manage_hitl_network')) {
        if ($Config[$key] -isnot [bool]) { throw "$key must be a JSON boolean." }
    }
    foreach ($key in @('core_memory_mb', 'app_memory_mb', 'participant_memory_mb', 'core_cores', 'app_cores', 'participant_cores', 'core_disk_gb', 'app_disk_gb', 'participant_disk_gb', 'wait_minutes')) {
        if ($Config[$key] -isnot [long] -and $Config[$key] -isnot [int]) { throw "$key must be a positive integer." }
        if ($Config[$key] -lt 1 -or $Config[$key] -gt 1048576) { throw "Invalid $key." }
    }
    foreach ($role in @('core', 'app', 'participant')) {
        if ($Config["${role}_memory_mb"] -lt 1024 -or $Config["${role}_disk_gb"] -lt 20 -or $Config["${role}_cores"] -gt 64) { throw "Insufficient or invalid $role resources." }
    }
    foreach ($key in @('management_vmnet', 'hitl_vmnet')) {
        if ($Config[$key] -notmatch '^vmnet([1-7]|9|1[0-9])$') { throw "$key must be a custom vmnet1..19 network, excluding NAT vmnet8." }
    }
    if ($Config.management_vmnet -eq $Config.hitl_vmnet) { throw 'Management and HITL networks must differ.' }
    foreach ($key in @('participant_os', 'kali_image_url', 'kali_sums_url', 'lab_dir', 'vmware_dir', 'python_exe', 'qemu_img', 'git_exe', 'image_cache', 'ssh_public_key', 'core_minimal_ref', 'core_ref', 'scenarioforge_ref', 'flag_generators_ref', 'core_password', 'app_password', 'participant_password', 'web_admin_password')) {
        if ($Config[$key] -isnot [string] -or $Config[$key] -match '[\r\n\x00]') { throw "Invalid text value: $key" }
    }
    # Host VM files belong on a local Windows drive, not a UNC share or a drive root.
    if ($Config.lab_dir -notmatch '^[A-Za-z]:[\\/].+' -or $Config.lab_dir.Substring(2) -match '[:"<>|?*]') { throw 'lab_dir must be an absolute local Windows directory.' }
    $full = [IO.Path]::GetFullPath($Config.lab_dir)
    if ($full -eq [IO.Path]::GetPathRoot($full)) { throw 'The lab directory cannot be a drive root.' }
}

function Find-Workstation {
    param([string]$Directory)
    $candidates = @($Directory)
    foreach ($key in @('HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation', 'HKLM:\SOFTWARE\VMware, Inc.\VMware Workstation')) {
        $item = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if ($item -and $item.PSObject.Properties['InstallPath']) { $candidates += $item.InstallPath }
    }
    if (${env:ProgramFiles(x86)}) { $candidates += Join-Path ${env:ProgramFiles(x86)} 'VMware/VMware Workstation' }
    if ($env:ProgramFiles) { $candidates += Join-Path $env:ProgramFiles 'VMware/VMware Workstation' }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath (Join-Path $candidate 'vmrun.exe')) -and
            (Test-Path -LiteralPath (Join-Path $candidate 'vmware.exe'))) { return $candidate }
    }
    throw 'VMware Workstation was not found. Install Workstation Pro or set vmware_dir.'
}

function Assert-HostNetworks {
    param($State)
    $result = Invoke-HostCommand $State.Vmrun @('-T', 'ws', 'listHostNetworks')
    foreach ($item in @(@($State.Config.management_vmnet, '172.31.250.0'), @($State.Config.hitl_vmnet, '10.254.200.0'))) {
        if ($item[0] -eq $State.Config.hitl_vmnet -and $State.ContainsKey('HitlNetworkPlan') -and $State.HitlNetworkPlan) { continue }
        $pattern = '^\s*\d+\s+' + [regex]::Escape($item[0]) + '\s+hostOnly\s+false\s+' + [regex]::Escape($item[1]) + '\s+255\.255\.255\.0\s*$'
        if (-not @($result.Out -split '\r?\n' | Where-Object { $_ -match $pattern }).Count) {
            throw "Configure $($item[0]) as host-only, subnet $($item[1])/24, with DHCP disabled in Workstation's Virtual Network Editor. No host networks were changed."
        }
    }
    $hitl = $State.Config.hitl_vmnet
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object {
        ($_.Name -match "\b$hitl\b" -or $_.InterfaceDescription -match "\b$hitl\b") -and $_.Status -ne 'Disabled'
    })
    if ($adapters.Count) { throw "Disable the host virtual adapter for $hitl in Virtual Network Editor so the participant network stays isolated." }
    if ($result.Out -notmatch '(?im)^\s*\d+\s+vmnet8\s+nat\s+true\s+') { throw 'Enable vmnet8 NAT and DHCP for bootstrap and APP internet access.' }
}

function Get-QemuDownload {
    # Release and SHA-512 pinned from the upstream Windows build publisher.
    # https://qemu.weilnetz.de/w64/2026/qemu-w64-setup-20260811.sha512
    @{
        Version = '11.1.0 (2026-08-11)'
        Url = 'https://qemu.weilnetz.de/w64/2026/qemu-w64-setup-20260811.exe'
        Sha512 = '5bcf9eed634e8575a37b74f445af41a2fe4106da512d0c30c368301d4c105037fdfab40a5287367a28a957624cddebbc8c07e16c88ab6634f554cdf3d16bf543'
    }
}

function Get-InstalledQemuImg {
    param([string]$ConfiguredPath)
    if ($ConfiguredPath) {
        if (Test-Path -LiteralPath $ConfiguredPath -PathType Leaf) { return (Resolve-Path -LiteralPath $ConfiguredPath).Path }
        return ''
    }
    $candidates = @()
    $qemu = Get-Command qemu-img.exe -ErrorAction SilentlyContinue
    if ($qemu) { $candidates += $qemu.Source }
    foreach ($key in @('HKLM:\SOFTWARE\QEMU', 'HKLM:\SOFTWARE\qemu64', 'HKLM:\SOFTWARE\WOW6432Node\QEMU')) {
        $item = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if ($item -and $item.PSObject.Properties['Install_Dir']) { $candidates += Join-Path $item.Install_Dir 'qemu-img.exe' }
    }
    foreach ($directory in @($env:ProgramW6432, $env:ProgramFiles)) {
        if ($directory) { $candidates += Join-Path $directory 'qemu/qemu-img.exe' }
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return (Resolve-Path -LiteralPath $candidate).Path }
    }
    return ''
}

function Confirm-QemuDownload {
    param($Package, [string]$ConfiguredPath)
    Write-Host 'qemu-img.exe is required to convert the cloud images into VMware disks.'
    if ($ConfiguredPath) { Write-Host "The configured file was not found: $ConfiguredPath" }
    Write-Host "Download QEMU $($Package.Version) for Windows (about 200 MB) from:"
    Write-Host "  $($Package.Url)"
    Write-Host 'Its SHA-512 will be verified before the QEMU setup wizard opens.'
    Write-Host 'Windows will ask for administrator approval. Keep Tools and Libraries selected in setup.'
    # This is intentionally independent of -Yes, which only confirms the lab.
    (Read-Host 'Download and open QEMU setup? [y/N]') -match '^(y|yes)$'
}

function Invoke-QemuSetup {
    param([string]$Installer)
    try {
        $process = Start-Process -FilePath $Installer -Verb RunAs -Wait -PassThru
    } catch {
        throw "QEMU setup could not start or administrator approval was canceled. Install QEMU manually or retry. $($_.Exception.Message)"
    }
    try {
        if ($process.ExitCode -ne 0) { throw "QEMU setup was canceled or failed (exit $($process.ExitCode))." }
    } finally { $process.Dispose() }
}

function New-QemuStagingDirectory {
    param([string]$Path)
    Protect-LabDirectory $Path
    # A standard Windows user may approve UAC with a different admin account.
    # That account needs read/execute access to the verified setup file.
    $acl = Get-Acl -LiteralPath $Path
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($administrators, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Install-MissingQemu {
    param([string]$ConfiguredPath, [switch]$Preview)
    $existing = Get-InstalledQemuImg $ConfiguredPath
    if ($existing) { return $existing }
    if ($Preview) { throw 'qemu-img.exe is missing. A normal install will offer to download QEMU with confirmation; dry-run downloads and installs nothing.' }
    $package = Get-QemuDownload
    if (-not (Confirm-QemuDownload $package $ConfiguredPath)) {
        throw 'QEMU download declined. Install it manually and set qemu_img, or rerun the installer when ready.'
    }
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('scenarioforge-qemu-' + [Guid]::NewGuid())
    try {
        New-QemuStagingDirectory $temporary
        $installer = Join-Path $temporary 'qemu-setup.exe'
        Write-Host 'Downloading QEMU...'
        Invoke-WebRequest -Uri $package.Url -OutFile $installer -TimeoutSec 600 -MaximumRetryCount 2 -RetryIntervalSec 2
        if ((Get-FileHash -LiteralPath $installer -Algorithm SHA512).Hash -ne $package.Sha512) {
            throw 'QEMU download checksum mismatch. The downloaded installer was not run. Retry or install QEMU manually.'
        }
        Write-Host 'Download verified. Complete QEMU setup to continue the lab installation.'
        Invoke-QemuSetup $installer
        $installed = Get-InstalledQemuImg
        if (-not $installed) {
            throw 'QEMU setup finished, but qemu-img.exe was not found. Enable the Tools component or set qemu_img to its installed path, then retry.'
        }
        return $installed
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
    }
}

function Find-ImageTools {
    param($Config, [switch]$Preview)
    if (-not $Config.python_exe) {
        $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($launcher) {
            $Config.python_exe = (Invoke-HostCommand $launcher.Source @('-3', '-c', 'import sys; print(sys.executable)')).Out.Trim()
        } else {
            $python = Get-Command python.exe -ErrorAction SilentlyContinue
            if ($python -and $python.Source -notmatch 'WindowsApps') { $Config.python_exe = $python.Source }
        }
    }
    if (-not $Config.python_exe -or -not (Test-Path -LiteralPath $Config.python_exe -PathType Leaf)) {
        throw 'Install Windows Python 3.11+ or set python_exe to its python.exe path.'
    }
    $Config.python_exe = (Resolve-Path -LiteralPath $Config.python_exe).Path
    $Config.qemu_img = Install-MissingQemu $Config.qemu_img -Preview:$Preview
    if ($Config.flag_generators -or $Config.vulnhub) {
        if (-not $Config.git_exe) {
            $git = Get-Command git.exe -ErrorAction SilentlyContinue
            if ($git) { $Config.git_exe = $git.Source }
        }
        if (-not $Config.git_exe -or -not (Test-Path -LiteralPath $Config.git_exe -PathType Leaf)) {
            throw 'Optional catalogs require Git for Windows. Install it or set git_exe.'
        }
        $Config.git_exe = (Resolve-Path -LiteralPath $Config.git_exe).Path
    }
    $builder = Join-Path $PSScriptRoot 'prepare-images.py'
    $arguments = @($builder, '--check', '--qemu-img', $Config.qemu_img)
    if ($Config.flag_generators -or $Config.vulnhub) { $arguments += @('--git', $Config.git_exe) }
    Invoke-HostCommand $Config.python_exe $arguments -TimeoutSeconds 60 | Out-Null
}

function New-LabPassword {
    [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
}

function Read-LabCredentials {
    param([string]$Directory)
    $saved = Import-Clixml -LiteralPath (Join-Path $Directory 'credentials.xml')
    $values = @{}
    foreach ($key in @('core', 'app', 'participant', 'web_admin')) {
        $values[$key] = [Net.NetworkCredential]::new('', $saved[$key]).Password
    }
    return $values
}

function Remove-Lab {
    param($State, [string]$StateFile, [switch]$Preview, [switch]$Confirmed, [switch]$AllowRunning)
    $running = @(Get-RunningVMs $State)
    $paths = @()
    foreach ($role in @('core', 'app', 'participant')) {
        $path = $State.VMs[$role].Path
        $directory = Split-Path $path -Parent
        if (-not (Test-Path -LiteralPath $directory)) { continue }
        if (-not (Test-OwnedVM $State $role)) { throw "Preserving unverified VM directory: $directory. Installer state retained." }
        # Reparse points anywhere inside a VM directory must not redirect deletion.
        foreach ($entry in Get-ChildItem -LiteralPath $directory -Recurse -Force) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing cleanup through link: $($entry.FullName)" }
        }
        $paths += $path
        Write-Host "Remove owned VM: $directory"
    }
    Write-Host "Preserve pre-existing management and NAT networks: $($State.Config.management_vmnet) and vmnet8."
    Remove-OwnedHitlNetwork $State $StateFile -Preview -Force:$AllowRunning -Keep:$KeepHitlNetwork
    if ($Preview) { Write-Host 'Preview only. No files, VMs, or host networks are changed.'; return }
    if (@($paths | Where-Object { $running -contains $_ }).Count -and -not $AllowRunning) { throw 'VMs are running. Shut them down, or use cleanup -Force to permit graceful shutdown before removal.' }
    if (-not $Confirmed -and (Read-Host 'Type CLEANUP to permanently remove these lab VMs') -cne 'CLEANUP') { throw 'Cleanup canceled.' }
    foreach ($path in $paths) {
        if ($running -contains $path) {
            Invoke-HostCommand $State.Vmrun @('-T', 'ws', 'stop', $path, 'soft') -TimeoutSeconds 60 | Out-Null
            if (@(Get-RunningVMs $State) -contains $path) { throw 'VM is still running; cleanup stopped. Shut it down in Workstation and retry.' }
        }
        Remove-Item -LiteralPath (Split-Path $path -Parent) -Recurse -Force
    }
    Remove-OwnedHitlNetwork $State $StateFile -Force:$AllowRunning -Keep:$KeepHitlNetwork
    foreach ($path in $State.Files.Keys) {
        if ((Test-Path -LiteralPath $path) -and (Get-FileHash -LiteralPath $path).Hash -eq $State.Files[$path]) {
            Remove-Item -LiteralPath $path -Force
        } elseif (Test-Path -LiteralPath $path) { Write-Warning "Preserving modified file: $path" }
    }
    foreach ($name in @('credentials.xml', 'build-request.json', 'state.json')) {
        $path = Join-Path (Split-Path $StateFile -Parent) $name
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    $archive = Join-Path $State.LabDir 'scenarioforge-optional-content.tar.gz'
    if ((Test-Path -LiteralPath $archive) -and $State.ArchiveHash -and (Get-FileHash -LiteralPath $archive).Hash -eq $State.ArchiveHash) { Remove-Item -LiteralPath $archive }
    Write-Host 'Cleanup complete. Host networks, modified files, and downloaded image cache were preserved.'
}

function Invoke-Installer {
    if ($KeepHitlNetwork -and $Command -ne 'cleanup') { throw '-KeepHitlNetwork is only valid with cleanup.' }
    if ($Command -eq 'help') {
        Write-Host @'
ScenarioForge VMware Workstation for Windows (PowerShell 7.4+)
  ./install-scenarioforge-lab.ps1 install [-ConfigFile lab.json] [-DryRun] [-Yes]
  ./install-scenarioforge-lab.ps1 status [-Watch]
  ./install-scenarioforge-lab.ps1 resume [-NoWait]
  ./install-scenarioforge-lab.ps1 credentials
  ./install-scenarioforge-lab.ps1 cleanup [-DryRun] [-Force] [-Yes]
Overrides: -LabDir, -StateDir, -VmwareDir, -PythonExe, -QemuImg, -NoDesktopShortcut
Desktop shortcuts default to enabled. Missing QEMU can be downloaded with confirmation.
Use -ParticipantOS kali for a Kali XFCE participant with standard tools (2 GB RAM, 40 GB disk).
HITL networking is created automatically when needed; use -NoManageHitlNetwork to require an existing vmnet.
Cleanup removes owned HITL networks; -Force allows changed settings, -KeepHitlNetwork preserves the network.
Image preparation uses Windows Python and qemu-img.exe.
See the adjacent README for prerequisites and isolated network configuration.
'@
        return
    }
    if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') { throw 'Run this installer in PowerShell 7.4+ on x64 Windows.' }
    $stateFile = Join-Path $StateDir 'state.json'
    Assert-NoReparsePoint $StateDir
    if ($Command -ne 'install') {
        $state = Read-LabState $stateFile
        if ($Command -eq 'cleanup') { Remove-Lab $state $stateFile -Preview:$DryRun -Confirmed:$Yes -AllowRunning:$Force; return }
        if ($DryRun) { throw '-DryRun is supported for install and cleanup.' }
        $credentials = Read-LabCredentials $StateDir
        if ($Command -eq 'credentials') { $credentials.GetEnumerator() | Sort-Object Key | Format-Table Name, Value; return }
        if ($Command -eq 'resume') {
            if ($NoWait) { $state.Config.no_wait = $true }
            Create-OwnedHitlNetwork $state $stateFile
            Assert-HostNetworks $state
            Complete-LabSetup $state $credentials $stateFile
            Install-LabShortcuts $state $stateFile $PSScriptRoot
            return
        }
        do {
            $running = @(Get-RunningVMs $state)
            $allReady = $true
            foreach ($role in @('core', 'app', 'participant')) {
                $progress = Get-GuestProgress $state $credentials $role
                Write-Host "$role : $(if ($running -contains $state.VMs[$role].Path) { 'running' } else { 'stopped/suspended' }); $progress"
                $allReady = $allReady -and $progress -eq 'ready'
            }
            Write-Host "Participant temporary NAT attached: $($state.UplinkAttached)"
            if ($state.UplinkAttached) { Write-Host 'Run resume to finish bootstrap and participant isolation.' }
            if (-not $Watch -or $allReady) { break }
            Start-Sleep -Seconds 10
        } while ($true)
        return
    }
    $config = Read-InstallerConfig $ConfigFile $ParticipantOS
    foreach ($pair in @(@('LabDir', 'lab_dir'), @('VmwareDir', 'vmware_dir'), @('PythonExe', 'python_exe'), @('QemuImg', 'qemu_img'))) {
        $value = Get-Variable -Name $pair[0] -ValueOnly
        if ($value) { $config[$pair[1]] = $value }
    }
    if ($NoDesktopShortcut) { $config.desktop_shortcut = $false }
    if ($NoWait) { $config.no_wait = $true }
    if ($NoManageHitlNetwork) { $config.manage_hitl_network = $false }
    Assert-InstallerConfig $config
    $config.lab_dir = [IO.Path]::GetFullPath($config.lab_dir)
    if ($config.image_cache -notmatch '^[A-Za-z]:[\\/].+') { throw 'image_cache must be an absolute Windows directory.' }
    $config.image_cache = [IO.Path]::GetFullPath($config.image_cache)
    Assert-NoReparsePoint $config.image_cache
    if ($config.ssh_public_key) { $config.ssh_public_key = (Resolve-Path -LiteralPath $config.ssh_public_key).Path }
    Assert-NoReparsePoint $config.lab_dir
    if ((Test-Path -LiteralPath $stateFile) -or (Test-Path -LiteralPath $config.lab_dir)) { throw 'Lab/state already exists. Use status, resume, or cleanup; existing files will not be overwritten.' }
    if ((Test-Path -LiteralPath $StateDir) -and @(Get-ChildItem -LiteralPath $StateDir -Force).Count) { throw 'StateDir must be new or empty; existing files will not be overwritten.' }
    if ($StateDir -notmatch '^[A-Za-z]:[\\/].+' -or $StateDir.Substring(2) -match '[:"<>|?*]') { throw 'StateDir must be an absolute local Windows directory.' }
    $vmwareDirectory = Find-Workstation $config.vmware_dir
    $state = @{
        Owner = 'scenarioforge-vmware-windows-v1'; Schema = 1; InstallId = [Guid]::NewGuid().ToString()
        LabDir = $config.lab_dir; Vmrun = Join-Path $vmwareDirectory 'vmrun.exe'; Vmware = Join-Path $vmwareDirectory 'vmware.exe'
        Config = $config.Clone(); VMs = @{}; Files = @{}; Complete = $false; UplinkAttached = $true; ImagesPrepared = $false
        OptionalPending = $config.flag_generators -or $config.vulnhub; ArchiveHash = ''
    }
    foreach ($role in @('core', 'app', 'participant')) {
        $name = "scenarioforge-$role"
        $state.VMs[$role] = @{ Path = Join-Path $config.lab_dir "$name/$name.vmx"; User = $(switch ($role) { core { 'corevm' } app { 'scenarioforge' } participant { 'participant' } }) }
    }
    foreach ($key in @('core_password', 'app_password', 'participant_password', 'web_admin_password')) { $state.Config.Remove($key) }
    Plan-HitlNetwork $state
    $config.hitl_vmnet = $state.Config.hitl_vmnet
    Assert-HostNetworks $state
    $totalMemory = $config.core_memory_mb + $config.app_memory_mb + $config.participant_memory_mb
    $hostMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB
    if ($hostMemory -lt $totalMemory + 2048) { throw 'Not enough host RAM for the configured VMs plus Windows. Reduce the configured guest memory or use a larger host.' }
    Find-ImageTools $config -Preview:$DryRun
    $state.Config = $config.Clone()
    foreach ($key in @('core_password', 'app_password', 'participant_password', 'web_admin_password')) { $state.Config.Remove($key) }
    Write-Host "Create CORE, APP and participant VMs in $($config.lab_dir) ($totalMemory MB guest RAM)."
    Write-Host "Networks: $($config.management_vmnet) management; $($config.hitl_vmnet) isolated HITL; vmnet8 NAT. Desktop shortcuts: $($config.desktop_shortcut)."
    if ($DryRun) { Write-Host 'Validation complete; no files or VMs changed.'; return }
    if (-not $Yes -and (Read-Host 'Create and start this lab? [y/N]') -notmatch '^(y|yes)$') { throw 'Installation canceled.' }
    Protect-LabDirectory $StateDir
    Protect-LabDirectory $config.lab_dir
    $secrets = @{}
    foreach ($role in @('core', 'app', 'participant', 'web_admin')) {
        if (-not $config["${role}_password"]) { $config["${role}_password"] = New-LabPassword }
        $secrets[$role] = ConvertTo-SecureString $config["${role}_password"] -AsPlainText -Force
    }
    # Export-Clixml encrypts SecureString values with DPAPI for this Windows user.
    $secrets | Export-Clixml -LiteralPath (Join-Path $StateDir 'credentials.xml')
    Save-LabState $state $stateFile
    Create-OwnedHitlNetwork $state $stateFile
    Assert-HostNetworks $state
    $request = $config.Clone()
    $request.install_id = $state.InstallId
    $requestFile = Join-Path $StateDir 'build-request.json'
    try {
        $request | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $requestFile -Encoding utf8NoBOM
        $builder = Join-Path $PSScriptRoot 'prepare-images.py'
        & $config.python_exe $builder $requestFile
        if ($LASTEXITCODE -ne 0) { throw 'Image preparation failed. Partial lab and encrypted credentials were kept for diagnosis; use cleanup before reinstalling.' }
    } finally {
        if (Test-Path -LiteralPath $requestFile) { Remove-Item -LiteralPath $requestFile -Force }
    }
    $archive = Join-Path $config.lab_dir 'scenarioforge-optional-content.tar.gz'
    if (Test-Path -LiteralPath $archive) { $state.ArchiveHash = (Get-FileHash -LiteralPath $archive).Hash }
    $state.ImagesPrepared = $true
    Save-LabState $state $stateFile
    Install-LabShortcuts $state $stateFile $PSScriptRoot
    Complete-LabSetup $state (Read-LabCredentials $StateDir) $stateFile
    Write-Host 'Lab setup finished; participant NAT removed. Use the desktop shortcuts to open ScenarioForge or the participant VM.'
    Write-Host 'Run the credentials command to display guest and web administrator passwords.'
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-Installer } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
