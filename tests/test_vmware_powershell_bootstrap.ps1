#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/provision/vmware-workstation-windows'
. (Join-Path $source 'powershell-bootstrap.ps1')
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "ASSERTION: $Message" } }
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action } catch { Assert ($_.Exception.Message -match $Pattern) "Expected $Pattern; got $_"; return }
    throw "Expected failure: $Pattern"
}
$runtime = $env:SF_TEST_PWSH
if (-not $runtime) { $runtime = (Get-Command pwsh -CommandType Application -ErrorAction Stop).Source }
$temp = Join-Path ([IO.Path]::GetTempPath()) ('sf-bootstrap-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $temp | Out-Null
$oldOS = $env:OS
$oldArchitecture = $env:PROCESSOR_ARCHITECTURE
try {
    # Parsing with Windows PowerShell 5.1 catches syntax that would block bootstrap.
    foreach ($name in @('install-scenarioforge-lab.ps1', 'powershell-bootstrap.ps1')) {
        $tokens = $null; $errors = $null
        [Management.Automation.Language.Parser]::ParseFile((Join-Path $source $name), [ref]$tokens, [ref]$errors) | Out-Null
        Assert ($errors.Count -eq 0) "5.1-compatible entry point: $errors"
    }
    # Real cross-process serialization: literal metacharacters, Unicode, explicit
    # false switches, relative config paths, and the child's exit status survive.
    $probe = Join-Path $temp "argument ' probe.ps1"
    @'
param([string]$ConfigFile, [string]$StateDir, [switch]$Yes, [switch]$Watch)
if ($Yes -or -not $Watch) { exit 21 }
if (-not (Test-Path -LiteralPath $ConfigFile)) { exit 22 }
[IO.File]::WriteAllText($StateDir, (Get-Content -LiteralPath $ConfigFile -Raw))
exit 23
'@ | Set-Content -LiteralPath $probe
    $literal = 'spaces " quotes & $dollars; $(code) `ticks ' + [char]0x03bb
    $config = Join-Path $temp 'lab.json'
    [IO.File]::WriteAllText($config, $literal)
    $output = Join-Path $temp 'output.txt'
    Push-Location $temp
    try {
        $encoded = New-InstallerEncodedCommand $probe @{
            ConfigFile = '.\lab.json'; StateDir = $output
            Yes = [Management.Automation.SwitchParameter]::new($false)
            Watch = [Management.Automation.SwitchParameter]::new($true)
        }
        & $runtime -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded
        Assert ($LASTEXITCODE -eq 23) 'Child exit code preserved'
        Assert ([IO.File]::ReadAllText($output) -ceq $literal) 'Literal values and working directory preserved'
    } finally { Pop-Location }

    # Exercise execution-policy decisions in isolated children with mocked policy
    # commands: never change the test machine's saved policy or prompt a human.
    $policyProbe = Join-Path $temp 'policy-probe.ps1'
    'exit 0' | Set-Content $policyProbe
    foreach ($case in @(
        @{ Policy = 'Restricted'; Managed = 'Undefined'; Answer = ''; Preview = $false; Exit = 1 },
        @{ Policy = 'Restricted'; Managed = 'Undefined'; Answer = 'yes'; Preview = $false; Exit = 0 },
        @{ Policy = 'Restricted'; Managed = 'Undefined'; Answer = ' Y '; Preview = $false; Exit = 0 },
        @{ Policy = 'Restricted'; Managed = 'Undefined'; Answer = 'unexpected'; Preview = $true; Exit = 1 },
        @{ Policy = 'AllSigned'; Managed = 'AllSigned'; Answer = 'unexpected'; Preview = $false; Exit = 1 },
        @{ Policy = 'Bypass'; Managed = 'Undefined'; Answer = 'unexpected'; Preview = $true; Exit = 0 }
    )) {
        $encoded = New-InstallerEncodedCommand $policyProbe @{} -Preview:$case.Preview
        $body = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
        $prefix = @'
$env:OS = 'Windows_NT'
$global:testPolicy = '__POLICY__'
function Get-ExecutionPolicy { param($Scope); if ($Scope) { return '__MANAGED__' }; return $global:testPolicy }
function Read-Host { if ('__ANSWER__' -eq 'unexpected') { exit 91 }; return '__ANSWER__' }
function Set-ExecutionPolicy {
    param($Scope, $ExecutionPolicy, [switch]$Force)
    if ($Scope -ne 'Process' -or $ExecutionPolicy -ne 'Bypass') { exit 92 }
    $global:testPolicy = $ExecutionPolicy
}
'@
        $prefix = $prefix.Replace('__POLICY__', $case.Policy).Replace('__MANAGED__', $case.Managed).Replace('__ANSWER__', $case.Answer)
        $command = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($prefix + "`n" + $body))
        # Windows PowerShell turns native stderr into ErrorRecords, so capture it
        # with Continue while checking the actual exit status explicitly.
        $ErrorActionPreference = 'Continue'
        $result = & $runtime -NoProfile -EncodedCommand $command 2>&1
        $ErrorActionPreference = 'Stop'
        Assert ($LASTEXITCODE -eq $case.Exit) "Policy decision $($case.Policy), managed $($case.Managed), preview $($case.Preview): $result"
    }

    $env:OS = 'Windows_NT'; $env:PROCESSOR_ARCHITECTURE = 'AMD64'
    & {
        $oldRuntime = Join-Path $temp 'old-runtime.ps1'
        $newRuntime = Join-Path $temp 'new-runtime.ps1'
        "'7.3.0'; `$global:LASTEXITCODE = 0" | Set-Content $oldRuntime
        "'7.4.0'; `$global:LASTEXITCODE = 0" | Set-Content $newRuntime
        function Get-Command { return @(@{ Source = $oldRuntime }, @{ Source = $newRuntime }) }
        Assert ((Find-InstallerPowerShell) -eq $newRuntime) 'Discovery skips old runtimes and accepts minimum supported version'
    }
    & {
        function Find-InstallerPowerShell { return $null }
        function Read-Host { throw 'Unexpected prompt' }
        function Get-Command { throw 'Unexpected install lookup' }
        Assert-Throws { Invoke-PowerShellBootstrap $probe @{} -Preview } 'Dry run will not install'
    }
    & {
        function Find-InstallerPowerShell { return $null }
        function Get-Command { return $null }
        function Read-Host { throw 'Unexpected prompt' }
        Assert-Throws { Invoke-PowerShellBootstrap $probe @{} } 'WinGet were not found'
    }
    & {
        function Find-InstallerPowerShell { return $null }
        function Get-Command { return @{ Source = 'must-not-run.exe' } }
        function Read-Host { return '' }
        Assert-Throws { Invoke-PowerShellBootstrap $probe @{ Yes = $true } } 'installation declined'
    }
    & {
        $failedSetup = Join-Path $temp 'failed-setup.ps1'
        '$global:LASTEXITCODE = 42' | Set-Content $failedSetup
        function Find-InstallerPowerShell { return $null }
        function Get-Command { return @{ Source = $failedSetup } }
        function Read-Host { return 'yes' }
        Assert-Throws { Invoke-PowerShellBootstrap $probe @{} } 'failed or was canceled \(exit 42\)'
    }
    & {
        $setup = Join-Path $temp 'setup.ps1'
        @'
if (($args -join ' ') -ne 'install --id Microsoft.PowerShell --exact --source winget --installer-type wix') { throw 'Unexpected WinGet arguments' }
$global:LASTEXITCODE = 0
'@ | Set-Content $setup
        $script:discoveryCalls = 0
        function Find-InstallerPowerShell {
            $script:discoveryCalls++
            if ($script:discoveryCalls -gt 1) { return $runtime }
            return $null
        }
        function Get-Command { return @{ Source = $setup } }
        function Read-Host {
            param($Prompt)
            Assert ($Prompt -match 'take a few minutes') 'Upgrade prompt explains installation time'
            return ' y '
        }
        function New-InstallerEncodedCommand { [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('exit 0')) }
        Invoke-PowerShellBootstrap $probe @{}
        Assert ($LASTEXITCODE -eq 0) 'Accepted installation continues'
        Assert ($script:discoveryCalls -eq 2) 'Runtime rediscovered after install without restarting terminal'
    }
    & {
        function Find-InstallerPowerShell { return $runtime }
        function Read-Host { throw 'Unexpected installation prompt' }
        # A supported runtime must be reused even during a dry run.
        $simple = Join-Path $temp 'exit.ps1'
        'exit 17' | Set-Content $simple
        # Policy checks are covered separately; this tests discovery/relaunch routing.
        function New-InstallerEncodedCommand { [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('exit 17')) }
        Invoke-PowerShellBootstrap $simple @{} -Preview
        Assert ($LASTEXITCODE -eq 17) 'Existing runtime reused and exit propagated'
    }
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        # Real 5.1 entry -> installed 7 -> installer help, with no VM actions.
        & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $source 'install-scenarioforge-lab.ps1') help
        Assert ($LASTEXITCODE -eq 0) 'Real Windows PowerShell entry point relaunches successfully'
    }
    Write-Host 'PowerShell bootstrap tests passed.'
} finally {
    $env:OS = $oldOS; $env:PROCESSOR_ARCHITECTURE = $oldArchitecture
    Remove-Item -LiteralPath $temp -Recurse -Force
}
