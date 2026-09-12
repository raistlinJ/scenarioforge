#requires -Version 5.1
# Loaded before the installer's PowerShell 7 modules. Keep this file compatible with 5.1.

function Find-InstallerPowerShell {
    $candidates = @()
    foreach ($command in @(Get-Command pwsh.exe -CommandType Application -All -ErrorAction SilentlyContinue)) {
        $candidates += $command.Source
    }
    foreach ($directory in @($env:ProgramW6432, $env:ProgramFiles)) {
        if ($directory) { $candidates += Join-Path $directory 'PowerShell\7\pwsh.exe' }
    }
    if ($env:LOCALAPPDATA) { $candidates += Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\pwsh.exe' }
    foreach ($candidate in @($candidates | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        try {
            $versionText = & $candidate -NoLogo -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
            if ($LASTEXITCODE -eq 0 -and ([version]([string]$versionText)) -ge [version]'7.4') { return $candidate }
        } catch { continue }
    }
    return $null
}

function New-InstallerEncodedCommand {
    param([string]$ScriptPath, [System.Collections.IDictionary]$Parameters, [switch]$Preview)
    # Serialize data instead of reconstructing a shell command from user arguments.
    $forward = @{}
    foreach ($key in $Parameters.Keys) {
        $value = $Parameters[$key]
        if ($value -is [Management.Automation.SwitchParameter]) { $value = [bool]$value }
        $forward[$key] = $value
    }
    $payload = [Management.Automation.PSSerializer]::Serialize(@{
        ScriptPath = $ScriptPath; Parameters = $forward; Directory = (Get-Location).Path; Preview = [bool]$Preview
    })
    $data = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    $command = @'
$ErrorActionPreference = 'Stop'
try {
    $data = [Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('__PAYLOAD__')))
    if ($PSVersionTable.PSVersion -lt [version]'7.4') { throw 'PowerShell 7.4 or newer is still required.' }
    if ($env:OS -eq 'Windows_NT' -and (Get-ExecutionPolicy) -notin @('Bypass', 'Unrestricted')) {
        foreach ($scope in @('MachinePolicy', 'UserPolicy')) {
            if ((Get-ExecutionPolicy -Scope $scope) -notin @('Undefined', 'Bypass', 'Unrestricted')) {
                throw 'Script execution is managed by Group Policy. Contact your administrator to approve this installer.'
            }
        }
        if ($data.Preview) { throw 'PowerShell 7 needs script execution consent. Run install-scenarioforge-lab.cmd, or configure this session before retrying -DryRun.' }
        $answer = Read-Host 'Allow the reviewed ScenarioForge scripts to run in this PowerShell process only? No saved execution policy will change [y/N]'
        if (([string]$answer).Trim() -notmatch '^(?i:y|yes)$') { throw 'Script execution declined; setup stopped. Enter Y or Yes at the execution prompt to continue.' }
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        if ((Get-ExecutionPolicy) -ne 'Bypass') { throw 'Execution policy remains blocked; contact your administrator.' }
    }
    Set-Location -LiteralPath $data.Directory
    $forward = $data.Parameters
    $global:LASTEXITCODE = 0
    & $data.ScriptPath @forward
    if (-not $?) {
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        exit 1
    }
    exit 0
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
'@
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command.Replace('__PAYLOAD__', $data)))
}

function Invoke-PowerShellBootstrap {
    param([string]$ScriptPath, [System.Collections.IDictionary]$Parameters, [switch]$Preview)
    if ($env:OS -ne 'Windows_NT') { throw 'Install PowerShell 7.4 or newer before running this installer.' }
    if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -and $env:PROCESSOR_ARCHITEW6432 -ne 'AMD64') {
        throw 'The ScenarioForge installer requires x64 Windows.'
    }
    $pwsh = Find-InstallerPowerShell
    if (-not $pwsh) {
        $instructions = 'Install PowerShell 7.4+ from https://learn.microsoft.com/powershell/scripting/install/install-powershell-on-windows and rerun this command.'
        if ($Preview) { throw "PowerShell 7.4+ is missing. Dry run will not install or upgrade it. $instructions" }
        $winget = Get-Command winget.exe -CommandType Application -ErrorAction SilentlyContinue
        if (-not $winget) { throw "PowerShell 7.4+ and WinGet were not found. $instructions" }
        Write-Host "This shell is PowerShell $($PSVersionTable.PSVersion); the installer needs 7.4 or newer."
        $answer = Read-Host 'Install or upgrade Microsoft PowerShell using WinGet, then continue? This will take a few minutes. Windows may request administrator approval [y/N]'
        if (([string]$answer).Trim() -notmatch '^(?i:y|yes)$') { throw 'PowerShell installation declined; setup stopped.' }
        & $winget.Source install --id Microsoft.PowerShell --exact --source winget --installer-type wix
        if ($LASTEXITCODE -ne 0) { throw "PowerShell installation failed or was canceled (exit $LASTEXITCODE). $instructions" }
        $pwsh = Find-InstallerPowerShell
        if (-not $pwsh) { throw "Setup finished, but PowerShell 7.4+ was not found. $instructions" }
    }
    Write-Host "Continuing in $pwsh"
    $encoded = New-InstallerEncodedCommand -ScriptPath $ScriptPath -Parameters $Parameters -Preview:$Preview
    # Keep the child attached to the console so Read-Host can receive consent.
    # Neither this call nor Invoke-PowerShellBootstrap may capture/pipeline output.
    & $pwsh -NoLogo -NoProfile -EncodedCommand $encoded
    $global:LASTEXITCODE = $LASTEXITCODE
}
