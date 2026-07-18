<#
  Build the commatrix MSI (WiX v4). Assembles the self-contained payload
  (commatrix + launcher via build_package.py), fetches the Windows embeddable
  Python into the payload, then compiles the MSI. Intended for CI on
  windows-latest; requires the .NET SDK (for the wix dotnet tool).

    packaging\windows\build_msi.ps1 -Version 1.2.3 -PythonVersion 3.12.7
#>
param(
    [string]$Version = "0.0.0",
    [string]$PythonVersion = "3.12.7"
)
$ErrorActionPreference = "Stop"
$Here = $PSScriptRoot
$Repo = (Resolve-Path (Join-Path $Here "..\..")).Path
$Out  = Join-Path $Repo "dist"
$Payload = Join-Path $Out "commatrix-win\payload"

# 1) Assemble payload skeleton (lib/commatrix + commatrix.cmd + scripts).
python (Join-Path $Here "build_package.py") --out (Join-Path $Out "commatrix-win")

# 2) Add the Windows embeddable Python into payload\python.
$zip = "python-$PythonVersion-embed-amd64.zip"
$url = "https://www.python.org/ftp/python/$PythonVersion/$zip"
$tmp = Join-Path $env:TEMP $zip
Invoke-WebRequest -Uri $url -OutFile $tmp
Expand-Archive -Path $tmp -DestinationPath (Join-Path $Payload "python") -Force

# 3) Compile the MSI.
dotnet tool install --global wix | Out-Null
$msi = Join-Path $Out "commatrix-$Version-x64.msi"
wix build (Join-Path $Here "commatrix.wxs") `
    -d "Version=$Version" -d "PayloadDir=$Payload" -o $msi
Write-Output "built $msi"
