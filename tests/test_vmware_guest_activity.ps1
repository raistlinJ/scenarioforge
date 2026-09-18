#requires -Version 7.4
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'scripts/provision/vmware-workstation-windows/ScenarioForge.VMware.psm1') -Force -DisableNameChecking
$temp = Join-Path ([IO.Path]::GetTempPath()) ('sf-activity-' + [guid]::NewGuid())
New-Item -ItemType Directory $temp | Out-Null
try {
    & (Get-Module ScenarioForge.VMware) {
        param($Directory)
        function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
        $saved = @{}
        foreach ($name in @('Start-LabVM', 'Test-OwnedVM', 'Get-GuestProgress', 'Remove-ParticipantUplink', 'Save-LabState', 'Invoke-HostCommand')) {
            $saved[$name] = (Get-Item "Function:$name").ScriptBlock
        }
        try {
            function script:Start-LabVM { param($State, $Role) }
            function script:Test-OwnedVM { param($State, $Role) return $true }
            function script:Get-GuestProgress {
                param($State, $Credentials, $Role)
                if ($script:mode -eq 'failed') { return 'failed: package install' }
                if ($script:poll -ge 4) { return 'ready' }
                return 'installing packages'
            }
            function script:Remove-ParticipantUplink { param($State, $StateFile) $State.UplinkAttached = $false }
            function script:Save-LabState { param($State, $StateFile) }
            function script:Start-Sleep { param($Seconds) $script:poll++ }
            function script:Write-Host { param([string]$Object) $script:messages += $Object }
            function script:Invoke-HostCommand {
                param($File, $Arguments, $TimeoutSeconds, [switch]$AllowFailure)
                Assert ($TimeoutSeconds -eq 5 -and $AllowFailure) 'Activity polling must be bounded and tolerate missing Tools/logs'
                Assert ($Arguments[6] -eq 'copyFileFromGuestToHost') 'Activity must only read guest files'
                $path = $Arguments[8]
                $target = $Arguments[9]
                $script:temporaryFiles += $target
                # Simulate an unsuccessful copy leaving partial data behind.
                'must not display partial output' | Set-Content $target
                if ($script:poll -eq 0) { return @{Code = 124} }
                if ($script:poll -lt 3) {
                    if ($path -ne '/var/log/cloud-init-output.log') { return @{Code = 1} }
                    @('older output', 'Unpacking chromium-common ...') | Set-Content $target
                } else {
                    @('older output', 'Setting up chromium ...') | Set-Content $target
                }
                return @{Code = 0}
            }
            foreach ($script:mode in @('regular', 'no_wait', 'reinstall', 'failed', 'timeout')) {
                $script:poll = 0
                $script:messages = @()
                $script:temporaryFiles = @()
                $state = @{ ImagesPrepared = $true; Complete = $false; UplinkAttached = $true; OptionalPending = $false
                    Config = @{ wait_minutes = 1; no_wait = $script:mode -eq 'no_wait' }; Vmrun = 'unused'; VMs = @{} }
                foreach ($role in @('core', 'app', 'participant')) {
                    $path = Join-Path $Directory "$role.vmx"
                    '' | Set-Content $path
                    $state.VMs[$role] = @{Path = $path; User = $role}
                }
                if ($script:mode -eq 'reinstall') {
                    $state.ReinstallRoles = @('participant')
                    $state.ReinstallWasComplete = $true
                }
                if ($script:mode -eq 'timeout') { $state.Config.wait_minutes = 0 }
                $failure = ''
                try { Complete-LabSetup $state @{ core = 'secret'; app = 'secret'; participant = 'secret' } 'unused' }
                catch { $failure = $_.Exception.Message }
                if ($script:mode -eq 'failed') {
                    Assert ($failure -match 'bootstrap failed') "Failure remains visible: $failure"
                } elseif ($script:mode -eq 'timeout') {
                    Assert ($failure -match 'timed out') "Timeout remains enforced: $failure"
                } else {
                    Assert (-not $failure) "Unexpected failure: $failure"
                    Assert $state.Complete 'Ready markers must still determine completion'
                    $roles = if ($script:mode -eq 'reinstall') { @('participant') } else { @('core', 'app', 'participant') }
                    foreach ($role in $roles) {
                        Assert (@($script:messages | Where-Object { $_ -eq "$role guest: Unpacking chromium-common ..." }).Count -eq 1) 'Print each changed package sample once per guest'
                        Assert (@($script:messages | Where-Object { $_ -eq "$role guest: Setting up chromium ..." }).Count -eq 1) 'Print subsequent package activity'
                    }
                    if ($script:mode -eq 'reinstall') {
                        Assert (-not ($script:messages -match '^(core|app)')) 'Only selected reinstall guests are polled'
                    }
                    Assert ($script:messages -match 'elapsed') 'Elapsed time is visible'
                }
                Assert (-not ($script:messages -match 'older output|partial output|secret')) 'Only the last successful log line is displayed'
                foreach ($file in $script:temporaryFiles) { Assert (-not (Test-Path $file)) 'Temporary log copies are cleaned up' }
            }
        } finally {
            foreach ($name in $saved.Keys) { Set-Item "Function:script:$name" $saved[$name] }
            Remove-Item Function:script:Start-Sleep, Function:script:Write-Host
        }
    } $temp
    Write-Host 'Windows guest activity tests passed.'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
