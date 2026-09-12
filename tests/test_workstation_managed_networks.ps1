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
        param($State, $Operation)
        $name = $State.Config.hitl_vmnet
        $script:operations += $Operation
        if ($Operation -eq 'Create') {
            $saved = Get-Content $stateFile -Raw | ConvertFrom-Json -AsHashtable
            Assert ($saved.CreatedHitlNetwork.Status -eq 'creating') 'Ownership must be saved before mutation'
            if ($script:failCreate) { throw 'simulated UAC failure' }
            $script:rows[$name] = @{ Type='hostOnly'; DHCP='false'; Subnet='10.254.200.0'; Mask='255.255.255.0' }
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
    Write-Host 'Managed Workstation networking tests passed.'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
