# Commatrix

> English: [`README.en.md`](README.en.md).

Stdlib-only nástroj pro **Linux i Windows**. Mapuje síťovou komunikaci (conntrack / IP Helper), přiřazuje toky k procesům a skládá komunikační matici a katalog aplikací.

Od **2.0.0** běží **pouze jako root / Administrator (SYSTEM)** se všemi právy. Least-privilege profily, dedicated účet `commatrix` a `elevate-*` jsou pryč.

## Instalace

```bash
sudo ./install.sh
```

Windows (jako Administrator):

```powershell
python -m commatrix install-windows
```

Docker (live capture):

```bash
docker run --rm --privileged --network host --pid host \
  -v /var/lib/commatrix:/var/lib/commatrix \
  ghcr.io/fedurca/commatrix:latest collect --allow-manual \
  --database /var/lib/commatrix/commatrix.db
```

## Použití

```bash
sudo commatrix collect --config /etc/commatrix/commatrix.conf
commatrix export -o /var/lib/commatrix/snapshots/$(hostname).json
commatrix aggregate --central central.db --snapshot-dir snapshots/
commatrix report -f html --database central.db
```

Jednorázově mimo systemd: `sudo commatrix collect --allow-manual --once`.

`serve` stále vyžaduje token (`--token-file` / `COMMATRIX_TOKEN`).

## Nasazení

| Metoda | Poznámka |
|---|---|
| `./install.sh` | systemd unit `User=root` |
| `install-windows` | scheduled task jako SYSTEM |
| Ansible | [`ansible/`](ansible/README.md) |
| Docker / GHCR | `--privileged` + host network pro capture |

Release artefakty: https://github.com/fedurca/appmap/releases/latest

## Dokumentace

- [`docs/jak-funguje-cs.md`](docs/jak-funguje-cs.md) / [`docs/how-it-works.md`](docs/how-it-works.md)
- [`docs/pouziti-cs.md`](docs/pouziti-cs.md)

## Licence

GPL-3.0-or-later. Viz [LICENSE](LICENSE).
