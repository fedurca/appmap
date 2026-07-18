<#
  SCCM detection script. SCCM treats any stdout as "installed". We report
  installed when the startup task exists and the payload launcher is present.
#>
$taskOk = $false
schtasks /query /tn "commatrix-collector" 1>$null 2>$null
if ($LASTEXITCODE -eq 0) { $taskOk = $true }
$cmd = Join-Path $env:ProgramFiles "commatrix\commatrix.cmd"
if ($taskOk -and (Test-Path $cmd)) {
    Write-Output "commatrix installed"
}
exit 0
