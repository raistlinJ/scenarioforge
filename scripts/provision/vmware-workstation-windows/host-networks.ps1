#requires -Version 7.4
# Native Workstation HITL management. Dot-source for planning; run for UAC operations.
param(
    [ValidateSet('Create', 'Remove')][string]$Action,
    [string]$VMnet,
    [string]$ManagementVMnet = 'vmnet1',
    [string]$VmwareDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-HostNetworkRows {
    param($State)
    $result = Invoke-HostCommand $State.Vmrun @('-T', 'ws', 'listHostNetworks')
    if ($result.Out -notmatch '(?m)^Total host networks:\s*\d+') { throw 'Could not inspect Workstation host networks.' }
    $rows = @{}
    foreach ($line in $result.Out -split '\r?\n') {
        if ($line -match '^\s*\d+\s+(vmnet\d+)\s+(\S+)\s+(true|false)\s+(\S+)\s+(\S+)\s*$') {
            $rows[$Matches[1]] = @{ Type = $Matches[2]; DHCP = $Matches[3]; Subnet = $Matches[4]; Mask = $Matches[5] }
        }
    }
    return $rows
}

function Get-VMnetRegistryNames {
    $names = @()
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32, [Microsoft.Win32.RegistryView]::Registry64)) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $key = $base.OpenSubKey('SOFTWARE\VMware, Inc.\VMnetLib\VMnetConfig')
            if ($key) { try { $names += $key.GetSubKeyNames() } finally { $key.Dispose() } }
        } finally { $base.Dispose() }
    }
    return @($names | Select-Object -Unique)
}

function Get-VMnetHostAdapters {
    param([string]$Name)
    $pattern = '\b' + [regex]::Escape($Name) + '\b'
    @(Get-NetAdapter -IncludeHidden | Where-Object {
        $_.Name -match $pattern -or $_.InterfaceDescription -match $pattern
    })
}

function Test-IsolatedHitl {
    param($Rows, [string]$Name)
    if (-not $Rows.ContainsKey($Name)) { return $false }
    $row = $Rows[$Name]
    return ($row.Type -eq 'hostOnly' -and $row.DHCP -eq 'false' -and
        $row.Subnet -eq '10.254.200.0' -and $row.Mask -eq '255.255.255.0' -and
        @(Get-VMnetHostAdapters $Name | Where-Object { $_.Status -ne 'Disabled' }).Count -eq 0)
}

function Assert-VMnetNotInUse {
    param($State, [string]$Name)
    foreach ($path in @(Get-RunningVMs $State)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Cannot inspect running VM: $path" }
        if ((Get-Content -LiteralPath $path -Raw) -match ('(?m)^\s*ethernet\d+\.vnet\s*=\s*"' + [regex]::Escape($Name) + '"')) {
            throw "Another running VM references $Name; stop or reconfigure it before changing this network."
        }
    }
}

function Find-Vnetlib {
    param([string]$Directory)
    foreach ($name in @('vnetlib64.exe', 'vnetlib.exe')) {
        $path = Join-Path $Directory $name
        if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    }
    throw 'Workstation vnetlib64.exe/vnetlib.exe is required for automatic HITL networking.'
}

function Plan-HitlNetwork {
    param($State)
    $rows = Get-HostNetworkRows $State
    $requested = $State.Config.hitl_vmnet
    if (Test-IsolatedHitl $rows $requested) { return }
    if (-not $State.Config.manage_hitl_network) { throw "Configure $requested as an isolated HITL network or enable manage_hitl_network." }
    Find-Vnetlib (Split-Path $State.Vmrun -Parent) | Out-Null
    $used = @($rows.Keys) + @(Get-VMnetRegistryNames)
    $candidates = @($requested) + @(2..19 | Where-Object { $_ -ne 8 } | ForEach-Object { "vmnet$_" })
    foreach ($name in $candidates | Select-Object -Unique) {
        if ($name -eq $State.Config.management_vmnet -or $name -in $used -or
            $name -notmatch '^vmnet([2-7]|9|1[0-9])$') { continue }
        if (@(Get-VMnetHostAdapters $name).Count) { continue }
        try { Assert-VMnetNotInUse $State $name } catch { continue }
        $State.Config.hitl_vmnet = $name
        $State.HitlNetworkPlan = $true
        Write-Host "Create dedicated $name for HITL (DHCP/NAT/host access disabled); Windows will request elevation."
        return
    }
    throw 'No unused Workstation vmnet2..19 is available for HITL.'
}

function Invoke-ElevatedNetworkAction {
    param($State, [ValidateSet('Create', 'Remove')][string]$Operation)
    $helper = Join-Path $PSScriptRoot 'host-networks.ps1'
    $quote = { param($Value) "'" + $Value.Replace("'", "''") + "'" }
    $command = "& $(& $quote $helper) -Action $Operation -VMnet $(& $quote $State.Config.hitl_vmnet) -ManagementVMnet $(& $quote $State.Config.management_vmnet) -VmwareDirectory $(& $quote (Split-Path $State.Vmrun -Parent))"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $process = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -Verb RunAs -PassThru -Wait -ArgumentList @('-NoProfile', '-EncodedCommand', $encoded)
    if ($process.ExitCode -ne 0) { throw "HITL $Operation failed or was canceled. Installer state was retained for cleanup/retry." }
}

function Create-OwnedHitlNetwork {
    param($State, [string]$StateFile)
    if (-not $State.ContainsKey('HitlNetworkPlan') -or -not $State.HitlNetworkPlan) { return }
    $name = $State.Config.hitl_vmnet
    if ((Get-HostNetworkRows $State).ContainsKey($name) -or $name -in @(Get-VMnetRegistryNames)) {
        throw "$name became configured; refusing to overwrite it."
    }
    Assert-VMnetNotInUse $State $name
    $State.CreatedHitlNetwork = @{ Name = $name; Subnet = '10.254.200.0'; Mask = '255.255.255.0'; Status = 'creating' }
    Save-LabState $State $StateFile
    Invoke-ElevatedNetworkAction $State Create
    if (-not (Test-IsolatedHitl (Get-HostNetworkRows $State) $name)) { throw 'HITL isolation verification failed; state retained.' }
    $State.CreatedHitlNetwork.Status = 'created'
    $State.HitlNetworkPlan = $false
    Save-LabState $State $StateFile
}

function Remove-OwnedHitlNetwork {
    param($State, [string]$StateFile, [switch]$Force, [switch]$Preview, [switch]$Keep)
    if (-not $State.ContainsKey('CreatedHitlNetwork') -or -not $State.CreatedHitlNetwork) {
        Write-Host 'Preserving pre-existing host networks; this lab created no vmnet.'
        return
    }
    $name = $State.CreatedHitlNetwork.Name
    if ($name -ne $State.Config.hitl_vmnet -or $name -eq $State.Config.management_vmnet -or
        $name -notmatch '^vmnet([2-7]|9|1[0-9])$') { throw 'Invalid tracked HITL network; cleanup stopped.' }
    if ($Keep) { Write-Host "Preserving $name by explicit request."; return }
    Write-Host "Remove installer-created HITL network $name."
    if ($Preview) { return }
    Assert-VMnetNotInUse $State $name
    $rows = Get-HostNetworkRows $State
    $registryNames = @(Get-VMnetRegistryNames)
    if (-not $rows.ContainsKey($name) -and $name -notin $registryNames -and
        @(Get-VMnetHostAdapters $name).Count -eq 0) {
        $State.CreatedHitlNetwork = $null
        Save-LabState $State $StateFile
        return
    }
    if (-not $Force -and -not (Test-IsolatedHitl $rows $name)) {
        throw "$name changed or is partially configured; use cleanup -Force to remove it, or -KeepHitlNetwork to preserve it."
    }
    Invoke-ElevatedNetworkAction $State Remove
    if ((Get-HostNetworkRows $State).ContainsKey($name) -or $name -in @(Get-VMnetRegistryNames) -or
        @(Get-VMnetHostAdapters $name).Count) { throw "$name still exists; installer state retained." }
    $State.CreatedHitlNetwork = $null
    Save-LabState $State $StateFile
}

function Invoke-NativeNetworkAction {
    param([string]$Operation, [string]$Name, [string]$Management, [string]$Directory)
    if ($Name -notmatch '^vmnet([2-7]|9|1[0-9])$' -or $Name -eq $Management) { throw 'Refusing reserved/management vmnet.' }
    $state = @{ Vmrun = Join-Path $Directory 'vmrun.exe' }
    Assert-VMnetNotInUse $state $Name
    $vnetlib = Find-Vnetlib $Directory
    function Invoke-Vnet([string[]]$Arguments) {
        # vnetlib uses both 0 and 1 for successful operations. Verify actual
        # network/adapter state instead of applying normal process exit semantics.
        $result = Invoke-HostCommand $vnetlib (@('--') + $Arguments) -AllowFailure -TimeoutSeconds 120
        if ($result.Code -notin @(0, 1)) { throw "vnetlib failed (exit $($result.Code))." }
    }
    if ($Operation -eq 'Create') {
        if ((Get-HostNetworkRows $state).ContainsKey($Name) -or $Name -in @(Get-VMnetRegistryNames) -or
            @(Get-VMnetHostAdapters $Name).Count) { throw "$Name already exists; no changes made." }
        Invoke-Vnet @('add', 'adapter', $Name)
        Invoke-Vnet @('set', 'vnet', $Name, 'addr', '10.254.200.0')
        Invoke-Vnet @('set', 'vnet', $Name, 'mask', '255.255.255.0')
        Invoke-Vnet @('remove', 'dhcp', $Name)
        Invoke-Vnet @('remove', 'nat', $Name)
        Invoke-Vnet @('update', 'adapter', $Name)
        Invoke-Vnet @('disable', 'adapter', $Name)
        foreach ($adapter in @(Get-VMnetHostAdapters $Name | Where-Object { $_.Status -ne 'Disabled' })) {
            $adapter | Disable-NetAdapter -Confirm:$false
        }
        if (-not (Test-IsolatedHitl (Get-HostNetworkRows $state) $Name)) { throw 'Could not create isolated HITL vmnet.' }
    } else {
        Invoke-Vnet @('remove', 'dhcp', $Name)
        Invoke-Vnet @('remove', 'nat', $Name)
        Invoke-Vnet @('remove', 'adapter', $Name)
        if (@(Get-VMnetHostAdapters $Name).Count) { throw 'VMware did not remove the host adapter; network state retained.' }
        # Workstation can retain a disabled vmnet's database key after removing
        # its adapter. Remove only the explicitly selected custom network.
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32, [Microsoft.Win32.RegistryView]::Registry64)) {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            try {
                $key = $base.OpenSubKey('SOFTWARE\VMware, Inc.\VMnetLib\VMnetConfig', $true)
                if ($key) { try { $key.DeleteSubKeyTree($Name, $false) } finally { $key.Dispose() } }
            } finally { $base.Dispose() }
        }
        if ((Get-HostNetworkRows $state).ContainsKey($Name)) { throw 'VMware still reports the removed network; state retained.' }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        if (-not $IsWindows -or -not $Action) { throw 'Use the Windows installer to invoke network management.' }
        Import-Module (Join-Path $PSScriptRoot 'ScenarioForge.VMware.psm1') -Force -DisableNameChecking
        Invoke-NativeNetworkAction $Action $VMnet $ManagementVMnet $VmwareDirectory
    } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
