# commatrix documentation

## English

- [How it works and what it does](how-it-works.md) - architecture, capture
  backends, attribution, DNS/DoH/SNI, storage, reports, security.
- Project overview: [`../README.md`](../README.md)
- Bill of materials: [`../SBOM.md`](../SBOM.md)

## Čeština

- [Jak commatrix funguje](jak-funguje-cs.md) - architektura a co vše dělá.
- [Použití a nasazení (návod pro firmu)](pouziti-cs.md) - Linux, Windows/SCCM,
  konfigurace, reporty, Ansible, řešení problémů.

## Deployment

- Linux: [`../install.sh`](../install.sh), [`../packaging/install-service.sh`](../packaging/install-service.sh)
- Windows: `commatrix install-windows`, SCCM package
  [`../packaging/windows/`](../packaging/windows)
- Fleet (Ansible): [`../ansible/README.md`](../ansible/README.md)
- Packaging/CI (MSI, Docker, Snap, Flatpak, AppImage): [`../packaging/`](../packaging),
  [`../.github/workflows/`](../.github/workflows)
