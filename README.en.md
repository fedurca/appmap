# Commatrix

> Czech: [`README.md`](README.md).

Stdlib-only Linux + Windows tool: map network communication (conntrack / IP Helper), attribute flows to processes, build a communication matrix and application catalog.

From **2.0.0** it **only runs as root / Administrator (SYSTEM)** with full privileges. Least-privilege profiles, the dedicated `commatrix` account, and `elevate-*` are gone.

## Install

```bash
sudo ./install.sh
```

Windows (as Administrator):

```powershell
python -m commatrix install-windows
```

## Usage

```bash
sudo commatrix collect --config /etc/commatrix/commatrix.conf
commatrix report -f html --database /var/lib/commatrix/commatrix.db
```

One-shot outside systemd: `sudo commatrix collect --allow-manual --once`.

`serve` still requires a token (`--token-file` / `COMMATRIX_TOKEN`).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
