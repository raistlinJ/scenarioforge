#requires -Version 7.4
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/provision/vmware-workstation-windows/install-scenarioforge-lab.ps1') -Command help
function Assert($Value, $Message) { if (-not $Value) { throw $Message } }
function Assert-Throws([scriptblock]$Block, $Pattern) {
    try { & $Block } catch { Assert ($_.Exception.Message -match $Pattern) "Unexpected failure: $_"; return }
    throw "Expected failure: $Pattern"
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('sf-network-test-' + [Guid]::NewGuid())
New-Item -ItemType Directory $temp | Out-Null
try {
    # Real registry-key interface, including the display-name-only slots reported
    # on Windows. Unknown values and child keys must continue blocking reuse.
    foreach ($case in @(
        @{ Values = @('DisplayName'); Children = @(); Configured = $false },
        @{ Values = @(); Children = @(); Configured = $false },
        @{ Values = @('displayname'); Children = @(); Configured = $false },
        @{ Values = @('DisplayName', 'UnknownSetting'); Children = @(); Configured = $true },
        @{ Values = @('DisplayName', ''); Children = @(); Configured = $true },
        @{ Values = @('DisplayName'); Children = @('Adapter'); Configured = $true },
        @{ Values = @('DisplayName'); Children = @('NAT'); Configured = $true }
    )) {
        $key = [pscustomobject]@{ Values = $case.Values; Children = $case.Children }
        $key | Add-Member ScriptMethod GetValueNames { $this.Values }
        $key | Add-Member ScriptMethod GetSubKeyNames { $this.Children }
        Assert ((Test-VMnetRegistryConfigured $key) -eq $case.Configured) 'Registry placeholder classification'
    }
    $stateFile = Join-Path $temp 'state.json'
    $script:rows = @{
        vmnet1 = @{ Type='hostOnly'; DHCP='false'; Subnet='172.31.250.0'; Mask='255.255.255.0' }
        vmnet2 = @{ Type='hostOnly'; DHCP='true'; Subnet='192.168.99.0'; Mask='255.255.255.0' }
        vmnet8 = @{ Type='nat'; DHCP='true'; Subnet='192.168.20.0'; Mask='255.255.255.0' }
    }
    $script:registryNames = @('vmnet1','vmnet2','vmnet8')
    $script:operations = @()
    $script:failCreate = $false
    function Get-HostNetworkRows { param($State) return $script:rows }
    function Get-VMnetRegistryNames { return $script:registryNames }
    function Get-VMnetHostAdapters { param($Name) @() }
    function Assert-VMnetNotInUse { param($State, $Name) }
    function Find-Vnetlib { param($Directory) 'vnetlib64.exe' }
    function Invoke-ElevatedNetworkAction {
        param($State, $Operation, [switch]$Management)
        $name = if ($Management) { $State.Config.management_vmnet } else { $State.Config.hitl_vmnet }
        $ownedKey = if ($Management) { 'CreatedManagementNetwork' } else { 'CreatedHitlNetwork' }
        $script:operations += $Operation
        if ($Operation -eq 'Create') {
            $saved = Get-Content $stateFile -Raw | ConvertFrom-Json -AsHashtable
            Assert ($saved[$ownedKey].Status -eq 'creating') 'Ownership must be saved before mutation'
            if ($script:failCreate) { throw 'simulated UAC failure' }
            $subnet = if ($Management) { '172.31.250.0' } else { '10.254.200.0' }
            $script:rows[$name] = @{ Type='hostOnly'; DHCP='false'; Subnet=$subnet; Mask='255.255.255.0' }
            $script:registryNames += $name
        } else {
            $script:rows.Remove($name)
            $script:registryNames = @($script:registryNames | Where-Object { $_ -ne $name })
        }
    }
    $state = @{ Vmrun = (Join-Path $temp 'vmrun.exe'); Config = @{ hitl_vmnet='vmnet2'; management_vmnet='vmnet1'; manage_hitl_network=$true } }
    Plan-HitlNetwork $state
    Assert ($state.Config.hitl_vmnet -eq 'vmnet3') 'Occupied vmnet2 must be preserved'
    Assert (-not $state.ContainsKey('CreatedHitlNetwork')) 'Plan is read-only'
    Create-OwnedHitlNetwork $state $stateFile
    Assert ($state.CreatedHitlNetwork.Status -eq 'created') 'Successful creation is recorded'
    Assert (Test-IsolatedHitl $script:rows 'vmnet3') 'New network is isolated'
    $script:rows.vmnet3.DHCP = 'true'
    Assert-Throws { Remove-OwnedHitlNetwork $state $stateFile } 'changed'
    Remove-OwnedHitlNetwork $state $stateFile -Preview -Force
    Assert ($script:operations.Count -eq 1) 'Preview cannot remove networks'
    Remove-OwnedHitlNetwork $state $stateFile -Force
    Assert (-not $script:rows.ContainsKey('vmnet3')) 'Force removes changed owned network'
    Assert ($script:rows.ContainsKey('vmnet2')) 'Unrelated network preserved'
    Assert ($null -eq $state.CreatedHitlNetwork) 'Ownership cleared only after verification'
    Remove-OwnedHitlNetwork $state $stateFile -Force
    Assert ($script:operations.Count -eq 2) 'Repeated cleanup is idempotent'

    $state.Config.hitl_vmnet = 'vmnet3'
    Plan-HitlNetwork $state
    $script:failCreate = $true
    Assert-Throws { Create-OwnedHitlNetwork $state $stateFile } 'UAC failure'
    Assert ((Get-Content $stateFile -Raw | ConvertFrom-Json).CreatedHitlNetwork.Status -eq 'creating') 'Failure retains cleanup state'

    $state.CreatedHitlNetwork = @{ Name='vmnet8' }
    $state.Config.hitl_vmnet = 'vmnet8'
    Assert-Throws { Remove-OwnedHitlNetwork $state $stateFile -Force } 'Invalid tracked'

    $state.Config.hitl_vmnet = 'vmnet2'
    $state.Config.manage_hitl_network = $false
    Assert-Throws { Plan-HitlNetwork $state } 'enable manage_hitl_network'
    $state.Config.manage_hitl_network = $true
    $state.HitlNetworkPlan = $false
    & {
        function Assert-VMnetNotInUse { throw 'Could not read VMware power status.' }
        Assert-Throws { Plan-HitlNetwork $state } 'vmnet3: Could not read VMware power status'
        Assert (-not $state.ContainsKey('HitlNetworkPlan') -or -not $state.HitlNetworkPlan) 'Failed planning cannot schedule creation'
    }
    & {
        function Get-VMnetRegistryNames { @(2..19 | ForEach-Object { "vmnet$_" }) }
        Assert-Throws { Plan-HitlNetwork $state } 'vmnet3: VMware registry configuration exists'
    }
    & {
        function Get-VMnetHostAdapters { param($Name) @{ Status = 'Disabled' } }
        Assert-Throws { Plan-HitlNetwork $state } 'vmnet3: a host adapter exists'
    }
    $managementState = @{ Vmrun = $state.Vmrun; Config = @{ management_vmnet='vmnet1'; hitl_vmnet='vmnet3' } }
    & {
        function Read-Host { throw 'Unexpected prompt' }
        Plan-ManagementNetwork $managementState
        Assert (-not $managementState.ContainsKey('ManagementNetworkPlan')) 'Valid existing management network reused'
    }
    $script:rows.vmnet1.DHCP = 'true'
    & {
        function Read-Host { throw 'Unexpected prompt' }
        Assert-Throws { Plan-ManagementNetwork $managementState -Preview } 'Virtual Network Editor.*Host-only.*172.31.250.0'
    }
    & {
        function Read-Host { return '' }
        Assert-Throws { Plan-ManagementNetwork $managementState } 'creation declined.*Virtual Network Editor'
        Assert ($managementState.Config.management_vmnet -eq 'vmnet1') 'Declining preserves configured network name'
    }
    & {
        function Read-Host { return ' yes ' }
        Plan-ManagementNetwork $managementState
    }
    Assert ($managementState.Config.management_vmnet -eq 'vmnet4') 'New management network excludes existing and planned HITL networks'
    Assert (-not $managementState.ContainsKey('CreatedManagementNetwork')) 'Management planning does not create network'
    $script:failCreate = $true
    Assert-Throws { Create-OwnedManagementNetwork $managementState $stateFile } 'UAC failure'
    Assert ((Get-Content $stateFile -Raw | ConvertFrom-Json).CreatedManagementNetwork.Status -eq 'creating') 'Failed management creation retains ownership'
    $script:failCreate = $false
    Create-OwnedManagementNetwork $managementState $stateFile
    Assert ($managementState.CreatedManagementNetwork.Status -eq 'created') 'Management creation verified and recorded'
    Assert (-not $managementState.ManagementNetworkPlan) 'Management plan cleared after creation'
    Assert ($script:rows.vmnet1.DHCP -eq 'true') 'Original management network preserved'
    $script:rows.vmnet4.DHCP = 'true'
    Assert-Throws { Remove-OwnedManagementNetwork $managementState $stateFile } 'changed'
    $before = $script:operations.Count
    Remove-OwnedManagementNetwork $managementState $stateFile -Preview -Force
    Assert ($script:operations.Count -eq $before) 'Management cleanup preview cannot mutate'
    Remove-OwnedManagementNetwork $managementState $stateFile -Force
    Assert (-not $script:rows.ContainsKey('vmnet4')) 'Owned management network removed'
    Assert ($script:rows.ContainsKey('vmnet1')) 'Pre-existing management network retained'
    Assert ($null -eq $managementState.CreatedManagementNetwork) 'Management ownership cleared after removal'
    Remove-OwnedManagementNetwork $managementState $stateFile
    Assert ($script:operations.Count -eq ($before + 1)) 'Management cleanup is idempotent'
    & {
        # Verify native management creation uses the management subnet and keeps
        # the host adapter enabled, unlike the isolated HITL network.
        $script:nativeCommands = @()
        $script:managementReady = $false
        function Get-HostNetworkRows {
            param($State)
            if ($script:managementReady) { return @{ vmnet4 = @{ Type='hostOnly'; DHCP='false'; Subnet='172.31.250.0'; Mask='255.255.255.0' } } }
            return @{}
        }
        function Get-VMnetRegistryNames { @() }
        function Invoke-HostCommand {
            param($File, $Arguments, [switch]$AllowFailure, $TimeoutSeconds)
            $command = $Arguments -join ' '
            $script:nativeCommands += $command
            if ($command -eq '-- enable adapter vmnet4') { $script:managementReady = $true }
            return @{ Code = 1 }
        }
        Invoke-NativeNetworkAction Create vmnet4 vmnet3 $temp Management
        Assert ($script:nativeCommands -contains '-- set vnet vmnet4 addr 172.31.250.0') 'Native management subnet'
        Assert ($script:nativeCommands -contains '-- remove dhcp vmnet4') 'Native management disables DHCP'
        Assert ($script:nativeCommands -contains '-- remove nat vmnet4') 'Native management disables NAT'
        Assert ($script:nativeCommands -contains '-- enable adapter vmnet4') 'Native management enables host adapter'
        Assert ($script:nativeCommands -notcontains '-- disable adapter vmnet4') 'Management host adapter remains enabled'
    }
    Write-Host 'Managed Workstation networking tests passed.'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
