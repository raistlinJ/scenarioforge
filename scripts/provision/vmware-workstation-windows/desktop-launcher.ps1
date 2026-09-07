#requires -Version 7.4
param([Parameter(Mandatory)][string]$StateFile, [ValidateSet('browser', 'participant')][string]$Mode = 'browser')
$ErrorActionPreference = 'Stop'
try {
    Import-Module (Join-Path $PSScriptRoot 'ScenarioForge.VMware.psm1') -Force -DisableNameChecking
    Open-LabDestination (Read-LabState $StateFile) $Mode
} catch {
    Add-Type -AssemblyName System.Windows.Forms
    [Windows.Forms.MessageBox]::Show($_.Exception.Message, 'ScenarioForge', 'OK', 'Error') | Out-Null
    exit 1
}
