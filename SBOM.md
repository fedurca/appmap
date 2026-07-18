# Software Bill of Materials (SBOM)

This document describes the components that make up commatrix and each
distributable artifact. A machine-readable SBOM (CycloneDX + SPDX) is also
generated in CI (Syft) and attached to each GitHub Release; see
[Machine-readable SBOM](#machine-readable-sbom).

- Project: **commatrix**
- License: **GPL-3.0-or-later** (see [`LICENSE`](LICENSE))
- Source: https://github.com/fedurca/appmap

## Runtime dependencies

**None (third-party).** commatrix is intentionally *standard-library only* -
[`pyproject.toml`](pyproject.toml) declares `dependencies = []`. At runtime it
uses only the Python standard library (`sqlite3`, `socket`, `ctypes`, `winreg`,
`json`, `struct`, `subprocess`, `ipaddress`, `html`, `xml.etree`, `threading`, ...).

| Component | Version | License | Role |
|---|---|---|---|
| commatrix | (this repo, see tag) | GPL-3.0-or-later | the tool |
| CPython standard library | >= 3.9 | PSF License | runtime |

At runtime commatrix may *invoke* OS-provided tools (not bundled): Linux
`systemctl`, `conntrack` (optional), `icacls`/`w32tm`/`wevtutil`/`schtasks`
(Windows). These are part of the OS, not shipped by commatrix.

## Bundled components per artifact

Some artifacts embed a Python runtime so no system Python is required. The
embedded interpreter is CPython under the PSF License.

| Artifact | Bundles | Licenses of bundled parts |
|---|---|---|
| Python wheel / sdist | commatrix only | GPL-3.0-or-later |
| Docker image (`ghcr.io/fedurca/commatrix`) | commatrix + `python:3.12-slim` base (Debian) | GPL-3.0-or-later; CPython PSF; Debian base packages (mostly GPL/LGPL/MIT/BSD - see the image's own SBOM) |
| AppImage | commatrix + embedded CPython | GPL-3.0-or-later; PSF |
| Snap (classic) | commatrix + CPython (core22) | GPL-3.0-or-later; PSF; Ubuntu core22 base |
| Flatpak | commatrix + `org.freedesktop.Platform` runtime | GPL-3.0-or-later; freedesktop runtime licenses |
| Windows MSI | commatrix + Windows embeddable CPython | GPL-3.0-or-later; PSF |

The Docker base image contents change with upstream; the authoritative
component list for the image is the CycloneDX SBOM generated in CI for that
specific image digest.

## Build-time only (not in any runtime artifact)

| Tool | License | Used for |
|---|---|---|
| setuptools / build | MIT | wheel/sdist |
| WiX Toolset v4 | MS-RL | Windows MSI |
| appimagetool / python-appimage | MIT | AppImage |
| snapcraft | GPL-3.0 | Snap |
| flatpak-builder | LGPL-2.1 | Flatpak |
| Syft (anchore/sbom-action) | Apache-2.0 | machine SBOM |

## License obligations

commatrix is GPL-3.0-or-later. Distributed binaries (MSI, AppImage, Snap,
Flatpak, Docker) must be accompanied by, or offer, the corresponding source -
which is the public repository at the tagged release. The bundled CPython is
under the PSF License (permissive, compatible). No proprietary third-party code
is included.

## Machine-readable SBOM

CI generates CycloneDX JSON (and SPDX) with Syft:

- per commit in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (uploaded
  as the `sbom` artifact);
- per release in [`.github/workflows/release.yml`](.github/workflows/release.yml),
  attached to the GitHub Release, including an image SBOM for the published
  Docker digest.

To generate locally:

```bash
syft dir:. -o cyclonedx-json=commatrix.cdx.json
syft ghcr.io/fedurca/commatrix:latest -o spdx-json=commatrix-image.spdx.json
```
