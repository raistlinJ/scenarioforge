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
        foreach ($mode in @('run', 'preview', 'bad-cache', 'build-failure', 'unowned', 'still-running', 'force-run', 'force-preview', 'force-bad-cache')) {
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
                function Test-OwnedVM { param($State, $Role) return $mode -ne 'unowned' }
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
                    if ($mode -eq 'still-running') { return @($State.VMs.Values | ForEach-Object { $_.Path }) }
                    return @()
                }
                function Invoke-HostCommand { param($File, $Arguments, $TimeoutSeconds) $script:events += 'stop' }
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
                Assert ($failed -eq ($mode -notin @('run', 'preview'))) "Unexpected result: $target $mode"
                foreach ($role in @('core', 'app', 'participant')) {
                    $expected = if ($mode -eq 'run' -and ($target -eq $role -or $target -eq 'all')) { 'replacement' } else { 'original' }
                    Assert ((Get-Content $state.VMs[$role].Path) -eq $expected) "Preserve scope: $target $mode $role"
                }
                if ($mode -ne 'run') { Assert ('save' -notin $script:events -and 'complete' -notin $script:events) 'Failed preflight must not change state' }
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
