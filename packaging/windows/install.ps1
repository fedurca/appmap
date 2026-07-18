<#
  SCCM install program for commatrix (run as SYSTEM by the SCCM client).
  Copies the self-contained payload (embedded Python + commatrix) to Program
  Files, secures the data dir, and registers the SYSTEM startup task.
  Exit codes: 0 = success, 1 = failure.
#>
$ErrorActionPreference = "Stop"
$log = "$env:ProgramData\commatrix\install.log"

try {
    $Root = Join-Path $env:ProgramFiles "commatrix"
    $Data = Join-Path $env:ProgramData "commatrix"
    New-Item -ItemType Directory -Force -Path $Root, $Data | Out-Null

    # Payload sits next to this script (python\, lib\commatrix\, commatrix.cmd).
    Copy-Item -Recurse -Force (Join-Path $PSScriptRoot "payload\*") $Root

    # Harden the data directory ACL (SYSTEM + Administrators only).
    icacls $Data /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

    $cmd  = Join-Path $Root "commatrix.cmd"
    $conf = Join-Path $Data "commatrix.conf"
    $taskCmd = "`"$cmd`" collect --config `"$conf`""

    # install-windows writes a default config (if missing), sets the ACL and
    # registers the SYSTEM startup task pointing at the bundled launcher.
    & $cmd install-windows --config "$conf" --task-command "$taskCmd" 2>&1 | Tee-Object -FilePath $log -Append
    if ($LASTEXITCODE -ne 0) { throw "install-windows returned $LASTEXITCODE" }
    exit 0
} catch {
    "$(Get-Date -Format o) install failed: $_" | Out-File -FilePath $log -Append
    exit 1
}
