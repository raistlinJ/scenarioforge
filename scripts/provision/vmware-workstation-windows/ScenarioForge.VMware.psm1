#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-HostCommand {
    param([string]$File, [string[]]$Arguments, [int]$TimeoutSeconds = 30, [switch]$AllowFailure)
    $info = [Diagnostics.ProcessStartInfo]::new($File)
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw "Could not start $File" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill() # Only this automation client, never its VM descendants.
            if ($AllowFailure) { return @{ Code = 124; Out = ''; Error = 'VMware command timed out; retrying.' } }
            throw "$(Split-Path $File -Leaf) timed out after $TimeoutSeconds seconds."
        }
        $result = @{ Code = $process.ExitCode; Out = $stdout.GetAwaiter().GetResult(); Error = $stderr.GetAwaiter().GetResult() }
        if ($result.Code -ne 0 -and -not $AllowFailure) {
            # Arguments can contain guest passwords; never include them in errors.
            throw "$(Split-Path $File -Leaf) failed (exit $($result.Code)): $($result.Error) $($result.Out)"
        }
        return $result
    } finally { $process.Dispose() }
}

function Get-RunningVMs {
    param($State)
    $result = Invoke-HostCommand $State.Vmrun @('-T', 'ws', 'list')
    $lines = @($result.Out -split '\r?\n' | Where-Object { $_.Trim() })
    if ($lines.Count -eq 0 -or $lines[0] -notmatch '^Total running VMs:\s*\d+') { throw 'Could not read VMware power status.' }
    @($lines | Select-Object -Skip 1 | ForEach-Object { [IO.Path]::GetFullPath($_.Trim()) })
}

function Start-LabVM {
    param($State, [string]$Role, [int]$TimeoutSeconds = 120)
    $path = $State.VMs[$Role].Path
    if (@(Get-RunningVMs $State) -contains $path) { return }
    Write-Host "Starting/resuming $Role VM..."
    $info = [Diagnostics.ProcessStartInfo]::new($State.Vmrun)
    $info.UseShellExecute = $false
    # Inherit the console; do not wait for output pipes inherited by vmware.exe.
    foreach ($arg in @('-T', 'ws', 'start', $path, 'gui')) { $info.ArgumentList.Add($arg) }
    $process = [Diagnostics.Process]::Start($info)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    try {
        do {
            if (@(Get-RunningVMs $State) -contains $path) { return }
            if ($process.HasExited -and $process.ExitCode -ne 0) { throw "Could not start $Role VM. Check its Workstation window." }
            Start-Sleep -Seconds 2
        } while ([DateTime]::UtcNow -lt $deadline)
        throw "Could not confirm $Role VM started. Check Workstation for a pending question or startup error, then retry."
    } finally {
        if (-not $process.HasExited) { $process.Kill() }
        $process.Dispose()
    }
}

function Get-AppUrl {
    param($State, [int]$TimeoutSeconds = 120)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $result = Invoke-HostCommand $State.Vmrun @('-T', 'ws', 'getGuestIPAddress', $State.VMs.app.Path) -AllowFailure
        $address = $null
        if ($result.Code -eq 0 -and [Net.IPAddress]::TryParse($result.Out.Trim(), [ref]$address) -and
            -not [Net.IPAddress]::IsLoopback($address) -and $address.ToString() -notin @('0.0.0.0', '::')) {
            $hostAddress = $address.ToString()
            if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $hostAddress = "[$hostAddress]" }
            return "https://$hostAddress/"
        }
        Start-Sleep -Seconds 3
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'The APP VM is running but its network address is not ready. Wait for it to boot and retry the shortcut.'
}

function Confirm-VMStart {
    param([string[]]$Roles)
    Add-Type -AssemblyName System.Windows.Forms
    $message = "These VMs are stopped or suspended:`n`n$($Roles -join "`n")`n`nStart/resume them and continue?"
    [Windows.Forms.MessageBox]::Show($message, 'ScenarioForge', 'YesNo', 'Question', 'Button2') -eq 'Yes'
}

function Open-LabDestination {
    param($State, [ValidateSet('browser', 'participant')][string]$Mode)
    $required = @('core', $(if ($Mode -eq 'browser') { 'app' } else { 'participant' }))
    foreach ($role in $required) {
        if (-not (Test-Path -LiteralPath $State.VMs[$role].Path -PathType Leaf)) { throw "$role VM is missing. Run installer status." }
    }
    if ($Mode -eq 'participant' -and $State.UplinkAttached) {
        throw 'Participant setup is incomplete and its temporary NAT adapter is still attached. Run the installer resume command to finish isolation.'
    }
    $running = @(Get-RunningVMs $State)
    $stopped = @($required | Where-Object { $running -notcontains $State.VMs[$_].Path })
    if ($stopped.Count -gt 0 -and -not (Confirm-VMStart $stopped)) { return }
    foreach ($role in $stopped) { Start-LabVM $State $role }
    if ($Mode -eq 'browser') { Start-Process (Get-AppUrl $State) | Out-Null }
    else { Open-VMConsole $State.Vmware $State.VMs.participant.Path }
}

function Open-VMConsole {
    param([string]$Vmware, [string]$Path)
    $info = [Diagnostics.ProcessStartInfo]::new($Vmware)
    $info.ArgumentList.Add($Path)
    [Diagnostics.Process]::Start($info).Dispose()
}

function Assert-NoReparsePoint {
    param([string]$Path)
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing a link/junction in lab path: $current"
            }
        }
        $current = Split-Path $current -Parent
    }
}

function Protect-LabDirectory {
    param([string]$Path)
    Assert-NoReparsePoint $Path
    if ([IO.Path]::GetFullPath($Path) -eq [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))) { throw 'Cannot use a drive root for lab/state storage.' }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in @($sid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Save-LabState {
    param($State, [string]$StateFile)
    $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$StateFile.new" -Encoding utf8NoBOM
    Move-Item -LiteralPath "$StateFile.new" -Destination $StateFile -Force
}

function Read-LabState {
    param([string]$StateFile)
    Assert-NoReparsePoint $StateFile
    $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json -AsHashtable
    if ($state.Owner -ne 'scenarioforge-vmware-windows-v1' -or $state.Schema -ne 1) { throw 'Unrecognized installer state.' }
    Assert-NoReparsePoint $state.LabDir
    foreach ($role in @('core', 'app', 'participant')) {
        $name = "scenarioforge-$role"
        $expected = Join-Path $state.LabDir "$name/$name.vmx"
        if ([IO.Path]::GetFullPath($state.VMs[$role].Path) -ne [IO.Path]::GetFullPath($expected)) { throw "Invalid saved $role VM path." }
        Assert-NoReparsePoint $expected
    }
    $allowedFiles = @('ScenarioForge.VMware.psm1', 'desktop-launcher.ps1') | ForEach-Object { Join-Path (Split-Path $StateFile -Parent) $_ }
    $desktop = [Environment]::GetFolderPath('DesktopDirectory')
    if ($desktop) { $allowedFiles += @('ScenarioForge.lnk', 'ScenarioForge Participant VM.lnk') | ForEach-Object { Join-Path $desktop $_ } }
    foreach ($path in $state.Files.Keys) {
        if ($path -notin $allowedFiles) { throw "Unexpected tracked file in installer state: $path" }
        Assert-NoReparsePoint $path
    }
    return $state
}

function Test-OwnedVM {
    param($State, [string]$Role)
    $path = $State.VMs[$Role].Path
    Assert-NoReparsePoint $path
    if (-not (Test-Path -LiteralPath $path)) {
        $marker = Join-Path (Split-Path $path -Parent) '.scenarioforge-owner'
        Assert-NoReparsePoint $marker
        return (Test-Path -LiteralPath $marker) -and (Get-Content -LiteralPath $marker -Raw).Trim() -ceq $State.InstallId
    }
    (Test-Path -LiteralPath $path -PathType Leaf) -and
        ((Get-Content -LiteralPath $path) -contains ('scenarioforge.install.owner = "' + $State.InstallId + '"'))
}

function Invoke-GuestCommand {
    param($State, $Credentials, [string]$Role, [string[]]$Arguments, [switch]$AllowFailure)
    $vm = $State.VMs[$Role]
    Invoke-HostCommand $State.Vmrun (@('-T', 'ws', '-gu', $vm.User, '-gp', $Credentials[$Role], $Arguments[0], $vm.Path) + @($Arguments | Select-Object -Skip 1)) -AllowFailure:$AllowFailure
}

function Get-GuestProgress {
    param($State, $Credentials, [string]$Role)
    if (-not (Test-Path -LiteralPath $State.VMs[$Role].Path)) { return 'VM not created' }
    $result = Invoke-GuestCommand $State $Credentials $Role @('fileExistsInGuest', "/var/lib/scenarioforge/$Role-ready") -AllowFailure
    if ($result.Code -eq 0) { return 'ready' }
    $temp = [IO.Path]::GetTempFileName()
    try {
        $result = Invoke-GuestCommand $State $Credentials $Role @('copyFileFromGuestToHost', '/var/lib/scenarioforge/bootstrap-status', $temp) -AllowFailure
        if ($result.Code -eq 0) { return (Get-Content -LiteralPath $temp -Raw).Trim() }
    } finally { Remove-Item -LiteralPath $temp -Force }
    return 'waiting for VMware Tools / bootstrap (see guest console)'
}

function Remove-ParticipantUplink {
    param($State, [string]$StateFile)
    if (-not $State.UplinkAttached) { return }
    if (-not (Test-OwnedVM $State participant)) { throw 'Participant VM ownership could not be verified.' }
    $path = $State.VMs.participant.Path
    if (@(Get-RunningVMs $State) -contains $path) {
        Invoke-HostCommand $State.Vmrun @('-T', 'ws', 'stop', $path, 'soft') -TimeoutSeconds 60 | Out-Null
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        while (@(Get-RunningVMs $State) -contains $path) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Participant did not shut down. Shut it down in Workstation, then run resume.' }
            Start-Sleep -Seconds 2
        }
    }
    # Editing the owned, powered-off VMX also works with older vmrun releases.
    $lines = @(Get-Content -LiteralPath $path | Where-Object { $_ -notmatch '^ethernet1\.' })
    if ($lines -notcontains 'ethernet0.connectionType = "custom"' -or
        $lines -notcontains ('ethernet0.vnet = "' + $State.Config.hitl_vmnet + '"')) { throw 'Unexpected participant network layout.' }
    $lines | Set-Content -LiteralPath $path -Encoding utf8NoBOM
    $State.UplinkAttached = $false
    Save-LabState $State $StateFile
    Start-LabVM $State participant
}

function Complete-LabSetup {
    param($State, $Credentials, [string]$StateFile)
    if (-not $State.ImagesPrepared) { throw 'Image preparation did not complete. Use cleanup before reinstalling the partial lab.' }
    foreach ($role in @('core', 'app', 'participant')) {
        if (-not (Test-Path -LiteralPath $State.VMs[$role].Path) -or -not (Test-OwnedVM $State $role)) { throw "$role VM is missing or belongs to a different installation. Use cleanup before reinstalling." }
        Start-LabVM $State $role
    }
    $deadline = [DateTime]::UtcNow.AddMinutes($State.Config.wait_minutes)
    if ($State.OptionalPending) {
        $archive = Join-Path $State.LabDir 'scenarioforge-optional-content.tar.gz'
        do {
            $result = Invoke-GuestCommand $State $Credentials app @('copyFileFromHostToGuest', $archive, '/tmp/scenarioforge-optional-content.tar.gz.part') -AllowFailure
            if ($result.Code -eq 0) { break }
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Optional-content transfer timed out; run resume to retry.' }
            Start-Sleep -Seconds 10
        } while ($true)
        # The shared APP bootstrap verifies the archive SHA256 before extracting.
        Invoke-GuestCommand $State $Credentials app @('runProgramInGuest', '/bin/mv', '/tmp/scenarioforge-optional-content.tar.gz.part', '/tmp/scenarioforge-optional-content.tar.gz') | Out-Null
        $State.OptionalPending = $false
        Save-LabState $State $StateFile
    }
    do {
        $ready = @{}
        foreach ($role in @('participant', 'core', 'app')) {
            $phase = Get-GuestProgress $State $Credentials $role
            if ($phase -like 'failed*') { throw "$role bootstrap failed: $phase. Check the guest console before retrying resume." }
            $ready[$role] = $phase -eq 'ready'
            Write-Host "$role : $phase"
        }
        if ($ready.participant -and $State.UplinkAttached) { Remove-ParticipantUplink $State $StateFile }
        if ($ready.participant -and ($State.Config.no_wait -or ($ready.core -and $ready.app))) {
            $State.Complete = $ready.core -and $ready.app
            Save-LabState $State $StateFile
            return
        }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Guest setup timed out. Check the VM consoles and run resume. Participant NAT remains attached until its bootstrap completes.' }
        Start-Sleep -Seconds 15
    } while ($true)
}

function Install-LabShortcuts {
    param($State, [string]$StateFile, [string]$SourceDir)
    if (-not $State.Config.desktop_shortcut) { return }
    $stateDir = Split-Path $StateFile -Parent
    # Preserve locally edited helpers and shortcuts, including their ownership hashes.
    foreach ($name in @('ScenarioForge.VMware.psm1', 'desktop-launcher.ps1')) {
        $path = Join-Path $stateDir $name
        if (Test-Path -LiteralPath $path) {
            if (-not $State.Files.ContainsKey($path) -or (Get-FileHash -LiteralPath $path).Hash -ne $State.Files[$path]) {
                Write-Warning "Preserving modified/untracked launcher: $path"
                return
            }
        }
    }
    foreach ($name in @('ScenarioForge.VMware.psm1', 'desktop-launcher.ps1')) {
        $path = Join-Path $stateDir $name
        Copy-Item -LiteralPath (Join-Path $SourceDir $name) -Destination $path -Force
        $State.Files[$path] = (Get-FileHash -LiteralPath $path).Hash
    }
    $shell = New-Object -ComObject WScript.Shell
    foreach ($mode in @('browser', 'participant')) {
        $name = if ($mode -eq 'browser') { 'ScenarioForge.lnk' } else { 'ScenarioForge Participant VM.lnk' }
        $path = Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) $name
        if ((Test-Path -LiteralPath $path) -and (-not $State.Files.ContainsKey($path) -or
            (Get-FileHash -LiteralPath $path).Hash -ne $State.Files[$path])) { Write-Warning "Preserving existing shortcut: $path"; continue }
        $link = $shell.CreateShortcut($path)
        $link.TargetPath = Join-Path $PSHOME 'pwsh.exe'
        $launcher = Join-Path $stateDir 'desktop-launcher.ps1'
        $link.Arguments = "-NoProfile -File `"$launcher`" -StateFile `"$StateFile`" -Mode $mode"
        $link.WorkingDirectory = $stateDir
        $link.IconLocation = "$($State.Vmware),0"
        $link.Save()
        $State.Files[$path] = (Get-FileHash -LiteralPath $path).Hash
    }
    Save-LabState $State $StateFile
}

Export-ModuleMember -Function *
