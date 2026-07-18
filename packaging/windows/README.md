# commatrix - Windows SCCM package

Build a self-contained deployment package (embedded Python + commatrix, no pip,
no system Python required) and import it into SCCM as a Script Installer.

```bash
python packaging/windows/build_package.py --out dist/commatrix-win
# then extract the official "Windows embeddable" Python zip into
# dist/commatrix-win/payload/python (must contain python.exe), and zip the folder.
```

SCCM application (Script Installer, "Install for system"):

- Install: `powershell -ExecutionPolicy Bypass -File install.ps1`
- Uninstall: `powershell -ExecutionPolicy Bypass -File uninstall.ps1`
- Detection: `powershell -ExecutionPolicy Bypass -File detect.ps1`

SCCM runs the program as SYSTEM, which is exactly the privilege the collector
needs. `install.ps1` copies the payload to `%ProgramFiles%\commatrix`, hardens
`%ProgramData%\commatrix` (ACL: SYSTEM + Administrators), and registers the
`commatrix-collector` SYSTEM startup task.

See the Czech usage/deployment guide in [`docs/pouziti-cs.md`](../../docs/pouziti-cs.md).
