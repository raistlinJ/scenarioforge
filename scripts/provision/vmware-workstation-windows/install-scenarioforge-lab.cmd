@echo off
setlocal
echo ScenarioForge setup will run the PowerShell scripts from this repository.
echo Allow script execution for this run only? No saved execution policy will change.
choice /C YN /N /T 30 /D N /M "Continue [y/N]? "
if errorlevel 2 exit /b 1
if errorlevel 1 goto run
exit /b 1
:run
powershell.exe -NoLogo -NoProfile -Command "foreach ($scope in @('MachinePolicy','UserPolicy')) { if ((Get-ExecutionPolicy -Scope $scope) -notin @('Undefined','Bypass','Unrestricted')) { Write-Host 'Script execution is managed by Group Policy. Contact your administrator to approve this installer.'; exit 1 } }"
if errorlevel 1 exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-scenarioforge-lab.ps1" %*
exit /b %errorlevel%
