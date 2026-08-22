<#
  Build the commatrix MSI (WiX v5). Assembles the self-contained payload
  (commatrix + launcher via build_package.py), fetches the Windows embeddable
  Python into the payload, then compiles the MSI. Intended for CI on
  windows-latest; requires the .NET SDK (for the wix dotnet tool).

    packaging\windows\build_msi.ps1 -Version 1.2.3 -PythonVersion 3.12.7
#>
param(
    [string]$Version = "0.0.0",
    [string]$PythonVersion = "3.12.7",
    # Pin WiX 5.x — WiX 7+ requires accepting the OSMF EULA in interactive installs.
    [string]$WixVersion = "5.0.2",
    # SEC-033 escape hatch. Only for a local experiment; never in CI.
    [switch]$AllowUnverifiedPython
)
$ErrorActionPreference = "Stop"
$Here = $PSScriptRoot
$Repo = (Resolve-Path (Join-Path $Here "..\..")).Path
$Out  = Join-Path $Repo "dist"
$Payload = Join-Path $Out "commatrix-win\payload"

New-Item -ItemType Directory -Force -Path $Out | Out-Null

# 1) Assemble payload skeleton (lib/commatrix + commatrix.cmd + scripts).
python (Join-Path $Here "build_package.py") --out (Join-Path $Out "commatrix-win")
if ($LASTEXITCODE -ne 0) { throw "build_package.py failed with exit $LASTEXITCODE" }

# 2) Add the Windows embeddable Python into payload\python.
#
# SEC-033: this interpreter is shipped inside the MSI and runs as the
# collector, so whatever bytes land here are executed on every managed Windows
# host. Downloading them over TLS proves who served them, not what they are:
# a compromised mirror, a cached proxy or a redirected CI runner all produce a
# perfectly valid TLS session around the wrong file. Nothing is unpacked until
# the Sigstore signature below has been verified.
$zip = "python-$PythonVersion-embed-amd64.zip"
$url = "https://www.python.org/ftp/python/$PythonVersion/$zip"
$tmp = Join-Path $env:TEMP $zip
Invoke-WebRequest -Uri $url -OutFile $tmp

# SEC-033, part 1: verify the Sigstore bundle python.org publishes next to the
# artifact. This proves the bytes were signed by the release manager for this
# version series, which is a stronger statement than any checksum we could
# record here -- and unlike a per-patch-release hash it does not go stale.
# python.org only publishes MD5 next to the file, and MD5 has practical
# chosen-prefix collisions, so it is not usable as a supply-chain control.
$bundle = "$tmp.sigstore"
Invoke-WebRequest -Uri "$url.sigstore" -OutFile $bundle

$series = ($PythonVersion -split '\.')[0..1] -join '.'
$trustFile = Join-Path $Here "python-embed-trust.json"
$trust = (Get-Content -Raw $trustFile | ConvertFrom-Json).series.$series
if ($null -eq $trust) {
    throw "No Sigstore trust anchor for CPython $series in $trustFile (SEC-033). " +
          "Add it from https://www.python.org/download/sigstore/"
}

python -m pip install --quiet --disable-pip-version-check sigstore
if ($LASTEXITCODE -ne 0) { throw "could not install the sigstore verifier (SEC-033)" }

python -m sigstore verify identity `
    --bundle $bundle `
    --cert-identity $trust.cert_identity `
    --cert-oidc-issuer $trust.cert_oidc_issuer `
    $tmp
if ($LASTEXITCODE -ne 0) {
    Remove-Item -Force $tmp, $bundle -ErrorAction SilentlyContinue
    throw "Sigstore verification FAILED for $zip (expected signer " +
          "$($trust.cert_identity) via $($trust.cert_oidc_issuer)) - SEC-033"
}
Write-Host "Sigstore: $zip signed by $($trust.cert_identity)."

# SEC-033, part 2: if a SHA256 has been recorded for this exact file, it must
# also match. Signature plus a recorded digest means a rebuild is reproducible
# and a swapped-but-validly-signed artifact is still caught.
$manifest = Join-Path $Here "python-embed-sha256.txt"
$expected = $null
if (Test-Path $manifest) {
    foreach ($line in Get-Content $manifest) {
        $t = $line.Trim()
        if ($t -eq "" -or $t.StartsWith("#")) { continue }
        $parts = $t -split "\s+"
        if ($parts.Length -eq 2 -and $parts[1] -eq $zip) { $expected = $parts[0].ToLower() }
    }
}

$actual = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
if ($null -eq $expected) {
    # Not fatal: the signature above already established provenance. Print the
    # digest so it can be recorded for reproducibility.
    Write-Host "No SHA256 recorded for $zip yet. Add this line to ${manifest}:"
    Write-Host "  $actual  $zip"
} elseif ($actual -ne $expected) {
    Remove-Item -Force $tmp, $bundle -ErrorAction SilentlyContinue
    throw "SHA256 mismatch for ${zip}: expected $expected, got $actual (SEC-033)"
} else {
    Write-Host "Verified $zip against the recorded SHA256."
}

$pyDir = Join-Path $Payload "python"
if (Test-Path $pyDir) { Remove-Item -Recurse -Force $pyDir }
Expand-Archive -Path $tmp -DestinationPath $pyDir -Force
if (-not (Test-Path (Join-Path $pyDir "python.exe"))) {
    throw "embeddable Python missing python.exe under $pyDir"
}

# 3) Compile the MSI with a pinned WiX toolset (no OSMF gate).
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
dotnet tool uninstall --global wix 2>&1 | Out-Null
$ErrorActionPreference = $prevEap
dotnet tool install --global wix --version $WixVersion
if ($LASTEXITCODE -ne 0) { throw "dotnet tool install wix@$WixVersion failed" }

# Ensure the global tools folder is on PATH for this session.
$dotnetTools = Join-Path $env:USERPROFILE ".dotnet\tools"
if (Test-Path $dotnetTools) {
    $env:PATH = "$dotnetTools;$env:PATH"
}

$msi = Join-Path $Out "commatrix-$Version-x64.msi"
if (Test-Path $msi) { Remove-Item -Force $msi }

& wix build (Join-Path $Here "commatrix.wxs") `
    -d "Version=$Version" -d "PayloadDir=$Payload" -o $msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed with exit $LASTEXITCODE" }
if (-not (Test-Path $msi)) { throw "MSI was not produced at $msi" }

Write-Output "built $msi"
Get-Item $msi | Format-List FullName, Length
