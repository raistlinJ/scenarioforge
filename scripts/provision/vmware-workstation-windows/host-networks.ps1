#requires -Version 7.4
# Native Workstation HITL management. Dot-source for planning; run for UAC operations.
param(
    [ValidateSet('Create', 'Remove')][string]$Action,
    [string]$VMnet,
    [string]$ManagementVMnet = 'vmnet1',
    [string]$VmwareDirectory,
    [ValidateSet('HITL', 'Management')][string]$NetworkRole = 'HITL'
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

function Test-VMnetRegistryConfigured {
    param($Key)
    # Workstation pre-creates slots containing only DisplayName (e.g. VMnet2).
    # Any other value or child key is configuration we must preserve, including
    # unknown settings and disabled networks. Never remove placeholders here.
    return (@($Key.GetSubKeyNames()).Count -gt 0 -or
        @($Key.GetValueNames() | Where-Object { $_ -ine 'DisplayName' }).Count -gt 0)
}

function Get-VMnetRegistryNames {
    $names = @()
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32, [Microsoft.Win32.RegistryView]::Registry64)) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $key = $base.OpenSubKey('SOFTWARE\VMware, Inc.\VMnetLib\VMnetConfig')
            if ($key) {
                try {
                    foreach ($name in $key.GetSubKeyNames()) {
                        $network = $key.OpenSubKey($name)
                        if (-not $network) { throw "VMware registry entry $name changed during inspection; retry setup." }
                        try {
                            if (Test-VMnetRegistryConfigured $network) { $names += $name }
                        } finally { $network.Dispose() }
                    }
                } finally { $key.Dispose() }
            }
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
    $registryNames = @(Get-VMnetRegistryNames)
    $rejections = [Collections.Generic.List[string]]::new()
    $candidates = @($requested) + @(2..19 | Where-Object { $_ -ne 8 } | ForEach-Object { "vmnet$_" })
    foreach ($name in $candidates | Select-Object -Unique) {
        if ($name -notmatch '^vmnet([2-7]|9|1[0-9])$') { continue }
        if ($name -eq $State.Config.management_vmnet) {
            $rejections.Add("${name}: reserved for management")
            continue
        }
        if ($rows.ContainsKey($name)) {
            $rejections.Add("${name}: already configured in Workstation")
            continue
        }
        if ($name -in $registryNames) {
            $rejections.Add("${name}: VMware registry configuration exists")
            continue
        }
        if (@(Get-VMnetHostAdapters $name).Count) {
            $rejections.Add("${name}: a host adapter exists (including hidden or disabled adapters)")
            continue
        }
        try { Assert-VMnetNotInUse $State $name } catch {
            $rejections.Add("${name}: $($_.Exception.Message)")
            continue
        }
        $State.Config.hitl_vmnet = $name
        $State.HitlNetworkPlan = $true
        Write-Host "Create dedicated $name for HITL (DHCP/NAT/host access disabled); Windows will request elevation."
        return
    }
    throw ("No unused Workstation vmnet2..19 is available for HITL. Rejection details:`n" +
        ($rejections -join "`n") + "`nNo networks were changed. Inspect these entries in Workstation's Virtual Network Editor. " +
        'An existing dedicated HITL network can be selected with hitl_vmnet once it meets the isolation settings in the README.')
}

function Test-ManagementNetwork {
    param($Rows, [string]$Name)
    if (-not $Rows.ContainsKey($Name)) { return $false }
    $row = $Rows[$Name]
    return ($row.Type -eq 'hostOnly' -and $row.DHCP -eq 'false' -and
        $row.Subnet -eq '172.31.250.0' -and $row.Mask -eq '255.255.255.0')
}

function Plan-ManagementNetwork {
    param($State, [switch]$Preview)
    $rows = Get-HostNetworkRows $State
    $requested = $State.Config.management_vmnet
    if (Test-ManagementNetwork $rows $requested) { return }
    $manual = "In Workstation, open Edit > Virtual Network Editor > Change Settings. Select $requested, choose Host-only, set subnet 172.31.250.0 and mask 255.255.255.0, and uncheck 'Use local DHCP service'. Apply and rerun setup. Alternatively, configure a dedicated network this way and set management_vmnet in your JSON to its name."
    if ($Preview) { throw "Management network $requested needs configuration. A normal install can offer to create a separate host-only network. $manual" }
    $answer = Read-Host "$requested does not have the required management settings. Create a separate host-only network (172.31.250.0/24, DHCP off, host adapter enabled), preserving ${requested}? Windows will request administrator approval [y/N]"
    if (([string]$answer).Trim() -notmatch '^(?i:y|yes)$') { throw "Management network creation declined. $manual" }
    Find-Vnetlib (Split-Path $State.Vmrun -Parent) | Out-Null
    $registryNames = @(Get-VMnetRegistryNames)
    $rejections = [Collections.Generic.List[string]]::new()
    foreach ($number in 2..19) {
        $name = "vmnet$number"
        if ($number -eq 8 -or $name -eq $requested -or $name -eq $State.Config.hitl_vmnet) { continue }
        if ($rows.ContainsKey($name) -or $name -in $registryNames -or @(Get-VMnetHostAdapters $name).Count) {
            $rejections.Add("${name}: existing network configuration or host adapter")
            continue
        }
        try { Assert-VMnetNotInUse $State $name } catch { $rejections.Add("${name}: $($_.Exception.Message)"); continue }
        $State.Config.management_vmnet = $name
        $State.ManagementNetworkPlan = $true
        Write-Host "Create dedicated $name for management (host-only 172.31.250.0/24, DHCP off, host adapter enabled); preserve $requested."
        return
    }
    throw ("No unused network is available for management.`n" + ($rejections -join "`n") + "`n$manual")
}

function Create-OwnedManagementNetwork {
    param($State, [string]$StateFile)
    if (-not $State.ContainsKey('ManagementNetworkPlan') -or -not $State.ManagementNetworkPlan) { return }
    $name = $State.Config.management_vmnet
    if ($name -eq $State.Config.hitl_vmnet -or $name -notmatch '^vmnet([2-7]|9|1[0-9])$') { throw 'Invalid planned management network.' }
    if ((Get-HostNetworkRows $State).ContainsKey($name) -or $name -in @(Get-VMnetRegistryNames) -or
        @(Get-VMnetHostAdapters $name).Count) { throw "$name became configured; refusing to overwrite it." }
    Assert-VMnetNotInUse $State $name
    $State.CreatedManagementNetwork = @{ Name = $name; Subnet = '172.31.250.0'; Mask = '255.255.255.0'; Status = 'creating' }
    Save-LabState $State $StateFile
    Invoke-ElevatedNetworkAction $State Create -Management
    if (-not (Test-ManagementNetwork (Get-HostNetworkRows $State) $name)) { throw 'Management network verification failed; state retained.' }
    $State.CreatedManagementNetwork.Status = 'created'
    $State.ManagementNetworkPlan = $false
    Save-LabState $State $StateFile
}

function Remove-OwnedManagementNetwork {
    param($State, [string]$StateFile, [switch]$Force, [switch]$Preview)
    if (-not $State.ContainsKey('CreatedManagementNetwork') -or -not $State.CreatedManagementNetwork) { return }
    $name = $State.CreatedManagementNetwork.Name
    if ($name -ne $State.Config.management_vmnet -or $name -eq $State.Config.hitl_vmnet -or
        $name -notmatch '^vmnet([2-7]|9|1[0-9])$') { throw 'Invalid tracked management network; cleanup stopped.' }
    Write-Host "Remove installer-created management network $name."
    if ($Preview) { return }
    Assert-VMnetNotInUse $State $name
    $rows = Get-HostNetworkRows $State
    $exists = $rows.ContainsKey($name) -or $name -in @(Get-VMnetRegistryNames) -or @(Get-VMnetHostAdapters $name).Count
    if ($exists) {
        if (-not $Force -and -not (Test-ManagementNetwork $rows $name)) { throw "$name changed or is partially configured; use cleanup -Force to remove it." }
        Invoke-ElevatedNetworkAction $State Remove -Management
        if ((Get-HostNetworkRows $State).ContainsKey($name) -or $name -in @(Get-VMnetRegistryNames) -or
            @(Get-VMnetHostAdapters $name).Count) { throw "$name still exists; installer state retained." }
    }
    $State.CreatedManagementNetwork = $null
    Save-LabState $State $StateFile
}

function Invoke-ElevatedNetworkAction {
    param($State, [ValidateSet('Create', 'Remove')][string]$Operation, [switch]$Management)
    $helper = Join-Path $PSScriptRoot 'host-networks.ps1'
    $quote = { param($Value) "'" + $Value.Replace("'", "''") + "'" }
    $name = $State.Config.hitl_vmnet
    $protected = $State.Config.management_vmnet
    $role = 'HITL'
    if ($Management) { $name = $State.Config.management_vmnet; $protected = $State.Config.hitl_vmnet; $role = 'Management' }
    $command = "& $(& $quote $helper) -Action $Operation -VMnet $(& $quote $name) -ManagementVMnet $(& $quote $protected) -NetworkRole $role -VmwareDirectory $(& $quote (Split-Path $State.Vmrun -Parent))"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $process = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -Verb RunAs -PassThru -Wait -ArgumentList @('-NoProfile', '-EncodedCommand', $encoded)
    if ($process.ExitCode -ne 0) { throw "$role $Operation failed or was canceled. Installer state was retained for cleanup/retry." }
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
    param([string]$Operation, [string]$Name, [string]$Management, [string]$Directory,
        [ValidateSet('HITL', 'Management')][string]$Role = 'HITL')
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
        $subnet = if ($Role -eq 'Management') { '172.31.250.0' } else { '10.254.200.0' }
        Invoke-Vnet @('set', 'vnet', $Name, 'addr', $subnet)
        Invoke-Vnet @('set', 'vnet', $Name, 'mask', '255.255.255.0')
        Invoke-Vnet @('remove', 'dhcp', $Name)
        Invoke-Vnet @('remove', 'nat', $Name)
        Invoke-Vnet @('update', 'adapter', $Name)
        if ($Role -eq 'HITL') {
            Invoke-Vnet @('disable', 'adapter', $Name)
            foreach ($adapter in @(Get-VMnetHostAdapters $Name | Where-Object { $_.Status -ne 'Disabled' })) {
                $adapter | Disable-NetAdapter -Confirm:$false
            }
            if (-not (Test-IsolatedHitl (Get-HostNetworkRows $state) $Name)) { throw 'Could not create isolated HITL vmnet.' }
        } else {
            Invoke-Vnet @('enable', 'adapter', $Name)
            if (-not (Test-ManagementNetwork (Get-HostNetworkRows $state) $Name)) { throw 'Could not create host-only management vmnet.' }
        }
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
        Invoke-NativeNetworkAction $Action $VMnet $ManagementVMnet $VmwareDirectory $NetworkRole
    } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
