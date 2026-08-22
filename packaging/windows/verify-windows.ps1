<#
  Verify the Windows behaviour this branch changed, and print a pass/fail line
  for each item so the result is a record rather than a recollection.

  Run in an ELEVATED PowerShell on the target host, from a checkout of this
  branch:

      powershell -ExecutionPolicy Bypass -File packaging\windows\verify-windows.ps1

  It makes real changes (it runs elevate-windows), so use a test host or a VM
  snapshot. -DryRun checks everything that can be checked without changing the
  machine; -Revoke puts things back afterwards.

  What is covered, and why each item needs a real Windows host:

    SEC-023  the scheduled task is registered from S4U XML, so no password is
             handed to schtasks. Only the registration itself can prove the
             task actually starts under 'commatrix' with no stored secret.
    SEC-025  after the rebind the service account must be able to write its
             own database. This regressed to Access Denied before, and the
             documented operator fix for that is to put the task back on
             SYSTEM -- which undoes the whole point.
    SEC-022  attribution must still work WITHOUT SeDebugPrivilege.
    CODE-031 os.times() on Windows does not report children_*; the CPU
             governor has to measure something non-zero anyway.
    CODE-027 the DNS monitor must not re-ingest the same event log records.
#>
param(
    [switch]$DryRun,
    [switch]$Revoke,
    [string]$Python = "python"
)
$ErrorActionPreference = "Continue"
$script:Failures = 0

function Check($name, [scriptblock]$test, $detail = "") {
    try {
        $ok = & $test
    } catch {
        $ok = $false
        $detail = "$detail exception: $($_.Exception.Message)"
    }
    if ($ok) {
        Write-Host ("  PASS  {0}" -f $name) -ForegroundColor Green
    } else {
        Write-Host ("  FAIL  {0} {1}" -f $name, $detail) -ForegroundColor Red
        $script:Failures++
    }
}

function Info($msg) { Write-Host "        $msg" -ForegroundColor DarkGray }

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must run elevated (it registers a scheduled task)." -ForegroundColor Red
    exit 2
}

$dataDir = Join-Path $env:ProgramData "commatrix"
$db = Join-Path $dataDir "commatrix.db"
$taskName = "commatrix-collector"

if ($Revoke) {
    Write-Host "== revoking =="
    & $Python -m commatrix elevate-windows --revoke
    exit $LASTEXITCODE
}

Write-Host "== 0. dry run (changes nothing) =="
$dry = & $Python -m commatrix elevate-windows --dry-run 2>&1 | Out-String
Check "elevate-windows --dry-run succeeds" { $LASTEXITCODE -eq 0 } $dry
Check "dry run does not promise SeDebugPrivilege" {
    $dry -notmatch "granted SeDebugPrivilege"
}
if ($DryRun) {
    Write-Host ""
    Write-Host ("Dry run only. Failures: {0}" -f $script:Failures)
    exit ([int]($script:Failures -gt 0))
}

Write-Host ""
Write-Host "== 1. SEC-023: apply, and prove no password reached a command line =="
$apply = & $Python -m commatrix elevate-windows 2>&1 | Out-String
Check "elevate-windows succeeds" { $LASTEXITCODE -eq 0 } $apply
Check "S4U was used, not the /rp fallback" {
    $apply -notmatch "falling back to 'schtasks /rp'"
} "the output asked for the /rp fallback, so S4U registration failed"
Check "password was not set through 'net user'" {
    $apply -notmatch "falling back to 'net user'"
} "PowerShell was unavailable, so the secret went through argv"

$xml = & schtasks /query /tn $taskName /xml ONE 2>&1 | Out-String
Check "task registered with LogonType S4U" { $xml -match "<LogonType>S4U</LogonType>" } $xml
Check "task runs as the service account" { $xml -match "<UserId>commatrix</UserId>" }
Check "task runs at LeastPrivilege" { $xml -match "<RunLevel>LeastPrivilege</RunLevel>" }

Write-Host ""
Write-Host "== 2. SEC-025: the service account can write its own database =="
$acl = & icacls $dataDir 2>&1 | Out-String
Check "data directory grants 'commatrix'" { $acl -match "commatrix" } $acl
if (Test-Path $db) {
    $dbAcl = & icacls $db 2>&1 | Out-String
    Check "database file grants 'commatrix'" { $dbAcl -match "commatrix" } $dbAcl
} else {
    Info "no database yet; it is created on the first collect below"
}

Write-Host ""
Write-Host "== 3. run one collect as the service account =="
Info "starting the task and waiting for it to finish"
& schtasks /run /tn $taskName | Out-Null
Start-Sleep -Seconds 20
$status = & schtasks /query /tn $taskName /fo LIST /v 2>&1 | Out-String
$lastResult = ([regex]::Match($status, "Last Result:\s+(\S+)")).Groups[1].Value
Check "last run result is 0 (not Access Denied)" {
    $lastResult -eq "0" -or $lastResult -eq "0x0"
} "Last Result=$lastResult -- 0x5/5 means SEC-025 regressed"
Check "the database exists and is non-empty" {
    (Test-Path $db) -and ((Get-Item $db).Length -gt 0)
}

Write-Host ""
Write-Host "== 4. SEC-022 + CODE-031: attribution and CPU accounting, no SeDebug =="
$out = & $Python -m commatrix collect --allow-manual --iterations 2 --database $db 2>&1 | Out-String
Check "collect runs without SeDebugPrivilege" { $LASTEXITCODE -eq 0 } $out
$report = & $Python -m commatrix report -f json --database $db 2>&1 | Out-String
Check "at least one edge is attributed to a process" {
    $report -match '"process_comm":\s*"[^"]+"'
} "no edge carries a process name -- attribution is not working"
Check "the CPU governor measured non-zero cost (CODE-031)" {
    $out -notmatch "cpu 0\.000s"
} "every poll reported zero CPU, so the governor is inert again"

Write-Host ""
Write-Host "== 5. CODE-027: the DNS monitor does not re-ingest the same records =="
$before = & $Python -m commatrix dns --database $db -f jsonl 2>&1 | Measure-Object -Line
& $Python -m commatrix collect --allow-manual --iterations 3 --database $db 2>&1 | Out-Null
$after = & $Python -m commatrix dns --database $db -f jsonl 2>&1 | Measure-Object -Line
Info ("dns rows before=$($before.Lines) after=$($after.Lines)")
Check "DNS rows did not explode across polls" {
    ($after.Lines - $before.Lines) -lt 500
} "rows grew by $($after.Lines - $before.Lines) in three polls -- the bookmark is not holding"

Write-Host ""
if ($script:Failures -eq 0) {
    Write-Host "All Windows checks passed." -ForegroundColor Green
} else {
    Write-Host ("{0} check(s) FAILED." -f $script:Failures) -ForegroundColor Red
}
Write-Host "Undo with: powershell -File packaging\windows\verify-windows.ps1 -Revoke"
exit ([int]($script:Failures -gt 0))
