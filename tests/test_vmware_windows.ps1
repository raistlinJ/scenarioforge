# Native Windows CI smoke/regression tests; no VMware, WSL, SSH, or guest credentials.
# Also executable with PowerShell 7.4+ on macOS/Linux.
#requires -Version 7.4
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
$source = Join-Path $root 'scripts/provision/vmware-workstation-windows'
. (Join-Path $source 'install-scenarioforge-lab.ps1') -Command help
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "ASSERTION: $Message" } }
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action } catch { Assert ($_.Exception.Message -match $Pattern) "Expected $Pattern; got $_"; return }
    throw "Expected failure: $Pattern"
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('scenarioforge-windows-test-' + [Guid]::NewGuid())
if ($IsMacOS) { $temp = Join-Path '/private/tmp' (Split-Path $temp -Leaf) }
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    # Parse all shipped scripts before mocking any commands.
    foreach ($file in Get-ChildItem -LiteralPath $source -Include *.ps1,*.psm1 -Recurse) {
        $tokens = $null; $errors = $null
        [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
        Assert ($errors.Count -eq 0) "PowerShell syntax: $($file.Name): $errors"
    }
    $config = Read-InstallerConfig (Join-Path $source 'scenarioforge-lab.json.example')
    Assert $config.desktop_shortcut 'Desktop shortcuts default on'
    Assert (-not $config.ContainsKey('wsl_distribution')) 'No Linux host dependency in config'
    Assert (-not $config.flag_generators -and -not $config.vulnhub) 'Public install needs no private repository access'
    Assert-InstallerConfig $config
    $config.hitl_vmnet = $config.management_vmnet
    Assert-Throws { Assert-InstallerConfig $config } 'must differ'
    $config = Read-InstallerConfig ''
    $config.lab_dir = 'C:\VMs\ScenarioForge'
    $config.desktop_shortcut = 'false'
    Assert-Throws { Assert-InstallerConfig $config } 'JSON boolean'
    $configFile = Join-Path $temp 'input.json'
    @{ mystery = 'value' } | ConvertTo-Json | Set-Content $configFile
    Assert-Throws { Read-InstallerConfig $configFile } 'Unknown configuration'
    $literal = 'spaces " quotes & $dollars; $(code) `ticks'
    @{ app_password = $literal } | ConvertTo-Json | Set-Content $configFile
    Assert ((Read-InstallerConfig $configFile).app_password -ceq $literal) 'Config preserves literal passwords'

    # OS selection changes only the participant defaults and honors explicit resources.
    @{ participant_os = 'kali' } | ConvertTo-Json | Set-Content $configFile
    $kali = Read-InstallerConfig $configFile
    Assert ($kali.participant_os -eq 'kali') 'Kali JSON option'
    Assert ($kali.participant_memory_mb -eq 2048) 'Kali has 2 GB RAM'
    Assert ($kali.participant_disk_gb -eq 40) 'Kali has 40 GB disk'
    Assert ($kali.core_disk_gb -eq 80) 'CORE defaults preserved'
    $debian = Read-InstallerConfig $configFile 'debian'
    Assert ($debian.participant_disk_gb -eq 20) 'CLI overrides JSON OS'
    @{ participant_os = 'kali'; participant_memory_mb = 3072; participant_disk_gb = 60 } | ConvertTo-Json | Set-Content $configFile
    $kali = Read-InstallerConfig $configFile
    Assert ($kali.participant_memory_mb -eq 3072 -and $kali.participant_disk_gb -eq 60) 'Explicit resource overrides preserved'
    @{ participant_os = 'invalid' } | ConvertTo-Json | Set-Content $configFile
    Assert-Throws { Read-InstallerConfig $configFile } 'participant_os must'
    $oldOS = $env:SF_PARTICIPANT_OS
    try {
        $env:SF_PARTICIPANT_OS = 'kali'
        Assert ((Read-InstallerConfig '').participant_disk_gb -eq 40) 'Environment OS selection'
        Assert ((Read-InstallerConfig '' 'debian').participant_os -eq 'debian') 'CLI overrides environment'
    } finally { $env:SF_PARTICIPANT_OS = $oldOS }

    # Exercise the real native process argument handling, including embedded quotes.
    $probe = Join-Path $temp 'argument probe.ps1'
    'param([string]$Value); [Console]::Write($Value)' | Set-Content $probe
    $pwsh = (Get-Process -Id $PID).Path
    $result = Invoke-HostCommand $pwsh @('-NoProfile', '-File', $probe, $literal)
    Assert ($result.Out -ceq $literal) 'Native arguments stay literal'
    $slow = Join-Path $temp 'slow.ps1'
    'Start-Sleep -Seconds 30' | Set-Content $slow
    Assert-Throws { Invoke-HostCommand $pwsh @('-NoProfile', '-File', $slow) -TimeoutSeconds 1 } 'timed out'
    $retryable = Invoke-HostCommand $pwsh @('-NoProfile', '-File', $slow) -TimeoutSeconds 1 -AllowFailure
    Assert ($retryable.Code -eq 124) 'Transient guest timeouts can be retried'

    # Tool preflight passes literal Windows paths to native Python, never Bash/WSL.
    $toolsDir = Join-Path $temp 'native tools with spaces'
    New-Item -ItemType Directory -Path $toolsDir | Out-Null
    $native = Read-InstallerConfig ''
    foreach ($pair in @(@('python_exe', 'python.exe'), @('qemu_img', 'qemu-img.exe'), @('git_exe', 'git.exe'))) {
        $native[$pair[0]] = Join-Path $toolsDir $pair[1]
        '' | Set-Content -LiteralPath $native[$pair[0]]
    }
    function Invoke-HostCommand { param($File, $Arguments, $TimeoutSeconds)
        $script:NativeCommand = @($File, $Arguments)
        @{Code = 0; Out = ''; Error = ''}
    }
    Find-ImageTools $native
    Assert ($script:NativeCommand[0] -eq $native.python_exe) 'Selected native Python invoked'
    Assert ($script:NativeCommand[1][0] -match 'prepare-images.py$') 'Native builder selected'
    Assert ($script:NativeCommand[1][-1] -eq $native.qemu_img) 'QEMU path preserved as one argument'
    Assert ($script:NativeCommand[1] -notcontains '--git') 'Public install needs no Git'
    $native.flag_generators = $true
    Find-ImageTools $native
    Assert ($script:NativeCommand[1][-2] -eq '--git' -and $script:NativeCommand[1][-1] -eq $native.git_exe) 'Optional catalogs use Windows Git'
    $native.python_exe = Join-Path $temp 'missing-python.exe'
    Assert-Throws { Find-ImageTools $native } 'Install Windows Python'


    # Missing-QEMU approval/download tests use actual hashing and temp-file cleanup.
    $package = Get-QemuDownload
    Assert ($package.Sha512 -match '^[a-f0-9]{128}$') 'Pinned SHA-512 supplied'
    Assert ($package.Url -match '^https://qemu\.weilnetz\.de/w64/2026/qemu-w64-setup-20260811\.exe$') 'Pinned upstream installer URL'
    $script:QemuPayload = 'simulated QEMU installer'
    $script:QemuDigest = [Convert]::ToHexString([Security.Cryptography.SHA512]::HashData([Text.Encoding]::UTF8.GetBytes($script:QemuPayload)))
    $script:QemuInstalled = ''
    $script:QemuAnswer = 'n'
    $script:QemuAsked = 0; $script:QemuDownloads = 0; $script:QemuSetups = 0; $script:QemuFolders = 0
    $script:QemuFailure = ''; $script:QemuTemp = ''
    $Yes = $true # Lab auto-confirmation must never bypass the dependency prompt.
    function Get-InstalledQemuImg { param($ConfiguredPath) $script:QemuInstalled }
    function Get-QemuDownload { @{Version = 'fixture'; Url = 'https://example.invalid/qemu.exe'; Sha512 = $script:QemuDigest} }
    function Read-Host { param($Prompt) $script:QemuAsked++; $script:QemuAnswer }
    function New-QemuStagingDirectory { param($Path)
        $script:QemuFolders++
        New-Item -ItemType Directory -Path $Path | Out-Null
        $script:QemuTemp = $Path
    }
    function Invoke-WebRequest { param($Uri, $OutFile, $TimeoutSec, $MaximumRetryCount, $RetryIntervalSec)
        $script:QemuDownloads++
        if ($script:QemuFailure -eq 'download') { throw 'simulated network failure' }
        $content = if ($script:QemuFailure -eq 'checksum') { 'corrupted download' } else { $script:QemuPayload }
        [IO.File]::WriteAllText($OutFile, $content, [Text.UTF8Encoding]::new($false))
    }
    function Invoke-QemuSetup { param($Installer)
        $script:QemuSetups++
        Assert ((Get-FileHash -LiteralPath $Installer -Algorithm SHA512).Hash -eq $script:QemuDigest) 'Setup file verified before execution'
        if ($script:QemuFailure -eq 'setup') { throw 'simulated setup cancellation' }
        if ($script:QemuFailure -ne 'missing-tool') { $script:QemuInstalled = Join-Path $toolsDir 'qemu-img.exe' }
    }
    Assert-Throws { Install-MissingQemu -Preview } 'dry-run downloads and installs nothing'
    Assert ($script:QemuAsked -eq 0 -and $script:QemuFolders -eq 0) 'Dry-run does not prompt or write'
    foreach ($answer in @('', 'n', 'no')) {
        $script:QemuAnswer = $answer
        Assert-Throws { Install-MissingQemu } 'QEMU download declined'
    }
    Assert ($script:QemuAsked -eq 3 -and $script:QemuDownloads -eq 0 -and $script:QemuFolders -eq 0) 'No download without explicit consent, even with -Yes'
    $script:QemuAnswer = 'yes'
    foreach ($failure in @('download', 'checksum', 'setup', 'missing-tool')) {
        $script:QemuFailure = $failure
        $script:QemuSetups = 0
        $pattern = switch ($failure) { download { 'network failure' } checksum { 'checksum mismatch' } setup { 'setup cancellation' } default { 'qemu-img.exe was not found' } }
        Assert-Throws { Install-MissingQemu } $pattern
        Assert (-not (Test-Path -LiteralPath $script:QemuTemp)) 'Failed download/setup staging removed'
        if ($failure -in @('download', 'checksum')) { Assert ($script:QemuSetups -eq 0) 'Unverified package never executed' }
    }
    $script:QemuFailure = ''
    $path = Install-MissingQemu
    Assert ($path -eq (Join-Path $toolsDir 'qemu-img.exe')) 'Installed QEMU rediscovered'
    Assert (-not (Test-Path -LiteralPath $script:QemuTemp)) 'Successful setup staging removed'
    $prompts = $script:QemuAsked; $downloads = $script:QemuDownloads
    $path = Install-MissingQemu
    Assert ($script:QemuAsked -eq $prompts -and $script:QemuDownloads -eq $downloads) 'Existing installation reused without download or prompt'
    $Yes = $false

    $stateFile = Join-Path $temp 'state.json'
    $state = @{ Owner = 'scenarioforge-vmware-windows-v1'; Schema = 1; InstallId = 'test-owner'; LabDir = $temp
        Vmrun = 'fake-vmrun'; Vmware = 'fake-vmware'; VMs = @{}; Files = @{}; Config = @{hitl_vmnet = 'vmnet2'}
        UplinkAttached = $false; Complete = $false; ImagesPrepared = $false }
    foreach ($role in @('core', 'app', 'participant')) {
        $dir = Join-Path $temp "scenarioforge-$role"
        New-Item -ItemType Directory -Path $dir | Out-Null
        $vmx = Join-Path $dir "scenarioforge-$role.vmx"
        @('scenarioforge.install.owner = "test-owner"', 'ethernet0.connectionType = "custom"', 'ethernet0.vnet = "vmnet2"', 'ethernet1.present = "TRUE"', 'ethernet1.connectionType = "nat"') | Set-Content $vmx
        $state.VMs[$role] = @{Path = $vmx; User = $role}
    }
    Save-LabState $state $stateFile
    Assert-Throws { Complete-LabSetup $state @{} $stateFile } 'Image preparation did not complete'
    $loaded = Read-LabState $stateFile
    Assert (Test-OwnedVM $loaded core) 'Owned VM recognized'
    $loaded.VMs.core.Path = Join-Path $temp 'unrelated.vmx'
    Save-LabState $loaded $stateFile
    Assert-Throws { Read-LabState $stateFile } 'Invalid saved core VM path'
    Save-LabState $state $stateFile

    # Mock only host interactions, keeping the launcher and isolation logic real.
    $module = Get-Module ScenarioForge.VMware
    & $module {
        $script:Running = @(); $script:Started = @(); $script:Opened = @(); $script:Consent = $false; $script:Asked = @()
        function script:Get-RunningVMs { param($State) $script:Running }
        function script:Confirm-VMStart { param($Roles) $script:Asked += ,$Roles; $script:Consent }
        function script:Start-LabVM { param($State, $Role) if ($script:Running -notcontains $State.VMs[$Role].Path) { $script:Started += $Role; $script:Running += $State.VMs[$Role].Path } }
        function script:Get-AppUrl { param($State) 'https://192.0.2.10/' }
        function script:Start-Process { param($FilePath) $script:Opened += $FilePath }
        function script:Open-VMConsole { param($Vmware, $Path) $script:Opened += $Path }
    }
    Open-LabDestination $state browser
    & $module { if ($script:Started.Count -or $script:Opened.Count) { throw 'Cancellation had side effects' } }
    & $module { $script:Consent = $true }
    Open-LabDestination $state browser
    & $module {
        if (($script:Started -join ',') -ne 'core,app') { throw 'Incorrect VM start order or dependency' }
        if (($script:Opened -join ',') -ne 'https://192.0.2.10/') { throw 'Browser destination not opened' }
        $script:Started = @(); $script:Asked = @()
    }
    Open-LabDestination $state browser
    & $module { if ($script:Started.Count -or $script:Asked.Count) { throw 'Already-running VMs restarted/prompted' } }
    $state.UplinkAttached = $true
    Assert-Throws { Open-LabDestination $state participant } 'temporary NAT'
    $state.UplinkAttached = $false
    & $module { $script:Running = @(); $script:Started = @(); $script:Opened = @(); $script:Consent = $false }
    Open-LabDestination $state participant
    & $module { if ($script:Started.Count -or $script:Opened.Count) { throw 'Participant cancellation had side effects' }; $script:Consent = $true }
    Open-LabDestination $state participant
    & $module {
        if (($script:Started -join ',') -ne 'core,participant') { throw 'Participant dependency mismatch' }
        if ($script:Opened.Count -ne 1 -or $script:Opened[0] -notmatch 'scenarioforge-participant.vmx$') { throw 'Participant console not opened' }
    }
    $state.UplinkAttached = $true

    # Only remove ethernet1 after shutdown; keep HITL and persist recovery state.
    & $module {
        function script:Invoke-HostCommand { param($File, $Arguments, $TimeoutSeconds, [switch]$AllowFailure)
            if ($Arguments[2] -eq 'stop') { $script:Running = @($script:Running | Where-Object { $_ -ne $Arguments[3] }) }
            @{Code = 0; Out = ''; Error = ''}
        }
    }
    Remove-ParticipantUplink $state $stateFile
    Assert (-not $state.UplinkAttached) 'Participant isolation persisted'
    $vmx = Get-Content -LiteralPath $state.VMs.participant.Path -Raw
    Assert ($vmx -notmatch 'ethernet1\.') 'Temporary NAT removed'
    Assert ($vmx -match 'ethernet0.vnet = "vmnet2"') 'HITL retained'
    Assert (-not (Read-LabState $stateFile).UplinkAttached) 'Recovery state stored'

    # Test host-network validation using representative vmrun output.
    function Invoke-HostCommand { param($File, $Arguments) @{Out = $script:Networks} }
    function Get-NetAdapter { param([switch]$IncludeHidden) @() }
    $state.Config.management_vmnet = 'vmnet1'
    $script:Networks = "INDEX NAME TYPE DHCP SUBNET MASK`n1 vmnet1 hostOnly false 172.31.250.0 255.255.255.0`n2 vmnet2 hostOnly false 10.254.200.0 255.255.255.0`n8 vmnet8 nat true 192.168.20.0 255.255.255.0"
    Assert-HostNetworks $state
    $script:Networks = $script:Networks.Replace('vmnet2 hostOnly false', 'vmnet2 nat true')
    Assert-Throws { Assert-HostNetworks $state } 'Configure vmnet2'

    # A cleanup preview must leave every VM and state file untouched.
    function Get-RunningVMs { param($State) @() }
    Remove-Lab $state $stateFile -Preview
    Assert (Test-Path -LiteralPath $stateFile) 'Preview preserved state'
    Assert (Test-Path -LiteralPath $state.VMs.core.Path) 'Preview preserved VM'
    'scenarioforge.install.owner = "someone-else"' | Set-Content -LiteralPath $state.VMs.core.Path
    Assert-Throws { Remove-Lab $state $stateFile -Confirmed -AllowRunning } 'Preserving unverified'
    Assert (Test-Path -LiteralPath $stateFile) 'Refused cleanup preserves recovery state'
    Write-Host 'Windows installer regression tests passed.'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}
