<#
  SCCM uninstall program for commatrix (run as SYSTEM). Removes the startup task
  and the Program Files payload; leaves %ProgramData%\commatrix (config + data)
  unless -Purge is given.
#>
param([switch]$Purge)
$ErrorActionPreference = "SilentlyContinue"

$Root = Join-Path $env:ProgramFiles "commatrix"
$Data = Join-Path $env:ProgramData "commatrix"
$cmd  = Join-Path $Root "commatrix.cmd"

if (Test-Path $cmd) { & $cmd uninstall-windows }
schtasks /delete /tn "commatrix-collector" /f | Out-Null
if (Test-Path $Root) { Remove-Item -Recurse -Force $Root }
if ($Purge -and (Test-Path $Data)) { Remove-Item -Recurse -Force $Data }
exit 0
