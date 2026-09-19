#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/provision/vmware-workstation-windows/install-scenarioforge-lab.ps1') -Command help
function Assert($Value, $Message) { if (-not $Value) { throw $Message } }
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('sf-reinstall-test-' + [Guid]::NewGuid())
New-Item -ItemType Directory $temporary | Out-Null
try {
    foreach ($target in @('core', 'app', 'participant', 'all')) {
        foreach ($mode in @('run', 'preview', 'bad-cache', 'build-failure', 'unowned', 'still-running', 'graceful', 'shutdown-timeout', 'late-shutdown', 'soft-pending', 'stop-failed', 'ownership-changed', 'status-failed', 'force-run', 'force-preview', 'force-bad-cache')) {
            & {
                $case = Join-Path $temporary "$target-$mode"
                $refresh = $mode.StartsWith('force-')
                $mode = $mode -replace '^force-', ''
                New-Item -ItemType Directory $case | Out-Null
                $state = @{ LabDir = $case; InstallId = 'owner'; Complete = $true; UplinkAttached = $false
                    Config = @{ flag_generators = $false; vulnhub = $false }; VMs = @{}; Vmrun = 'vmrun' }
                $credentials = @{ core = 'core'; app = 'app'; participant = 'participant'; web_admin = 'admin' }
                foreach ($role in @('core', 'app', 'participant')) {
                    $directory = Join-Path $case "scenarioforge-$role"
                    New-Item -ItemType Directory $directory | Out-Null
                    $path = Join-Path $directory "scenarioforge-$role.vmx"
                    'original' | Set-Content $path
                    $state.VMs[$role] = @{ Path = $path }
                }
                $script:events = @()
                $script:stopped = @()
                $script:shutdownAttempted = $false
                $script:ownershipChanged = $false
                $rebuild = $mode -in @('run', 'graceful', 'shutdown-timeout', 'late-shutdown', 'soft-pending')
                $selected = @(if ($target -eq 'all') { 'core'; 'app'; 'participant' } else { $target })
                function Test-OwnedVM { param($State, $Role) return $mode -ne 'unowned' -and -not $script:ownershipChanged }
                function Protect-LabDirectory { param($Path) New-Item -ItemType Directory $Path | Out-Null }
                function Ensure-WorkstationStarted { param($State) $script:events += 'open' }
                function Invoke-ReinstallBuild {
                    param($Config, $RequestFile, [switch]$CheckCache, [switch]$PromptMissing, [switch]$ForceDownload, [switch]$Preview)
                    if ($CheckCache) {
                        Assert ($ForceDownload -eq $refresh) 'Force refresh reaches image preflight'
                        Assert ($Preview -eq ($mode -eq 'preview')) 'Preview must never download'
                        Assert ($PromptMissing -eq ($mode -ne 'preview')) 'Only real reinstall may prompt for missing images'
                        $script:events += 'cache'
                        if ($mode -eq 'bad-cache') { throw 'Missing cached image' }
                        return
                    }
                    Assert (-not $ForceDownload -and -not $Preview) 'Build consumes verified cache without downloading again'
                    $script:events += 'build'
                    if ($mode -eq 'build-failure') { throw 'Build failed' }
                    foreach ($role in $Config.reinstall_roles) {
                        $directory = Join-Path $Config.lab_dir "scenarioforge-$role"
                        New-Item -ItemType Directory $directory | Out-Null
                        'replacement' | Set-Content (Join-Path $directory "scenarioforge-$role.vmx")
                    }
                }
                function Save-LabState { param($State, $Path) $script:events += 'save' }
                function Get-RunningVMs {
                    param($State)
                    if ($mode -eq 'status-failed' -and $script:shutdownAttempted) { throw 'Cannot read power status' }
                    if ($mode -in @('graceful', 'shutdown-timeout', 'late-shutdown', 'soft-pending', 'still-running', 'stop-failed', 'ownership-changed', 'status-failed')) {
                        return @($State.VMs.Values | ForEach-Object { $_.Path } | Where-Object { $_ -notin $script:stopped })
                    }
                    return @()
                }
                function Start-Sleep {
                    param($Seconds)
                    # Advance the caller's deadline without waiting two minutes.
                    Set-Variable -Name deadline -Value ([DateTime]::UtcNow.AddSeconds(-1)) -Scope 1
                }
                function Invoke-HostCommand {
                    param($File, $Arguments, $TimeoutSeconds)
                    Assert ($Arguments[2] -eq 'stop') 'Only stop commands expected'
                    $path = $Arguments[3]
                    $kind = $Arguments[4]
                    $role = @($state.VMs.Keys | Where-Object { $state.VMs[$_].Path -eq $path })[0]
                    Assert ($role -in $selected) 'Never stop unselected VMs'
                    Assert ($TimeoutSeconds -eq 120) 'Shutdown commands must be bounded'
                    $script:events += "stop:${kind}:$role"
                    if ($kind -eq 'soft') {
                        $script:shutdownAttempted = $true
                        if ($mode -eq 'ownership-changed') { $script:ownershipChanged = $true }
                        if ($mode -in @('graceful', 'late-shutdown')) { $script:stopped += $path }
                        if ($mode -notin @('graceful', 'soft-pending')) { throw 'Graceful shutdown timed out' }
                    } else {
                        Assert ($kind -eq 'hard') 'Fallback must use hard stop'
                        if ($mode -eq 'stop-failed') { throw 'Hard stop failed' }
                        if ($mode -ne 'still-running') { $script:stopped += $path }
                    }
                }
                function Complete-LabSetup {
                    param($State, $Credentials, $StateFile)
                    $script:events += 'complete'
                    $expected = if ($target -eq 'all') { @('core', 'app', 'participant') } else { @($target) }
                    Assert (($State.ReinstallRoles -join ',') -eq ($expected -join ',')) 'Scope must persist for resume'
                    Assert ($State.UplinkAttached -eq ('participant' -in $expected)) 'Only participant reinstall restores NAT'
                }
                $failed = $false
                try { Reinstall-LabVMs $state $credentials (Join-Path $case 'state.json') $target -Preview:($mode -eq 'preview') -Confirmed -RefreshImages:$refresh }
                catch { $failed = $true }
                Assert ($failed -eq (-not $rebuild -and $mode -ne 'preview')) "Unexpected result: $target $mode"
                foreach ($role in @('core', 'app', 'participant')) {
                    $expected = if ($rebuild -and ($target -eq $role -or $target -eq 'all')) { 'replacement' } else { 'original' }
                    Assert ((Get-Content $state.VMs[$role].Path) -eq $expected) "Preserve scope: $target $mode $role"
                }
                if (-not $rebuild) { Assert ('save' -notin $script:events -and 'complete' -notin $script:events) 'Failed preflight must not change state' }
                $stops = @($script:events | Where-Object { $_ -like 'stop:*' })
                $expectedStops = @()
                if ($mode -in @('graceful', 'shutdown-timeout', 'late-shutdown', 'soft-pending')) {
                    foreach ($role in $selected) {
                        $expectedStops += "stop:soft:$role"
                        if ($mode -in @('shutdown-timeout', 'soft-pending')) { $expectedStops += "stop:hard:$role" }
                    }
                    $firstSave = [Array]::IndexOf($script:events, 'save')
                    foreach ($stop in $expectedStops) { Assert ([Array]::IndexOf($script:events, $stop) -lt $firstSave) 'All guests stop before replacement' }
                } elseif ($mode -in @('stop-failed', 'still-running', 'ownership-changed', 'status-failed')) {
                    $expectedStops += "stop:soft:$($selected[0])"
                    if ($mode -in @('stop-failed', 'still-running')) { $expectedStops += "stop:hard:$($selected[0])" }
                }
                Assert (($stops -join ',') -eq ($expectedStops -join ',')) "Unexpected shutdown sequence: $target $mode"
                if ($mode -eq 'preview') { Assert (($script:events -join ',') -eq 'cache') 'Preview only checks cache' }
            }
        }
    }
    # Exercise the real completion function with hypervisor calls mocked inside
    # its module. It must never start/poll a VM outside a pending reinstall.
    & (Get-Module ScenarioForge.VMware) {
        param($Directory)
        $saved = @{}
        foreach ($name in @('Start-LabVM', 'Test-OwnedVM', 'Get-GuestProgress', 'Remove-ParticipantUplink', 'Save-LabState')) {
            $saved[$name] = (Get-Item "Function:$name").ScriptBlock
        }
        try {
            function script:Start-LabVM { param($State, $Role) $script:reinstallEvents += "start:$Role" }
            function script:Test-OwnedVM { param($State, $Role) return $true }
            function script:Get-GuestProgress { param($State, $Credentials, $Role) $script:reinstallEvents += "poll:$Role"; return 'ready' }
            function script:Remove-ParticipantUplink { param($State, $StateFile) $script:reinstallEvents += 'detach'; $State.UplinkAttached = $false }
            function script:Save-LabState { param($State, $StateFile) }
            foreach ($role in @('core', 'app', 'participant')) {
                $script:reinstallEvents = @()
                $path = Join-Path $Directory "$role.vmx"
                '' | Set-Content $path
                $state = @{ ImagesPrepared = $true; ReinstallRoles = @($role); ReinstallWasComplete = $true
                    Complete = $false; UplinkAttached = $true; OptionalPending = $false
                    Config = @{ wait_minutes = 1; no_wait = $false }; VMs = @{} }
                $state.VMs[$role] = @{Path = $path}
                Complete-LabSetup $state @{} 'unused'
                $expected = @("start:$role", "poll:$role")
                if ($role -eq 'participant') { $expected += 'detach' }
                if (($script:reinstallEvents -join ',') -ne ($expected -join ',')) { throw "Unexpected completion scope: $script:reinstallEvents" }
                if (-not $state.Complete -or $state.ContainsKey('ReinstallRoles')) { throw 'Completion must clear pending reinstall scope' }
            }
        } finally {
            foreach ($name in $saved.Keys) { Set-Item "Function:script:$name" $saved[$name] }
        }
    } $temporary
    Write-Host 'Windows reinstall regressions passed.'
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force }
