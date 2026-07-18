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
    [string]$WixVersion = "5.0.2"
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
$zip = "python-$PythonVersion-embed-amd64.zip"
$url = "https://www.python.org/ftp/python/$PythonVersion/$zip"
$tmp = Join-Path $env:TEMP $zip
Invoke-WebRequest -Uri $url -OutFile $tmp
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
