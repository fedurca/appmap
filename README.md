# Commatrix

> Primární README (čeština). English: [`README.en.md`](README.en.md).

Commatrix je **čistě stdlib** Python nástroj pro **Linux i Windows**, který
mapuje síťovou komunikaci přes vestavěné API operačního systému — bez odposlechu
paketů (`tcpdump`/libpcap). Na hostitelích sbírá toky, přiřazuje je k
**aplikacím/procesům**, volitelně obohacuje o **Zabbix host parametry** a skládá
**komunikační matici**, **katalog aplikací** a dokumentační exporty. Snapshoty
z Linuxu a Windows sdílejí stejné schema a sloučí se do jednoho fleet reportu.

## Tři způsoby běhu

Commatrix lze provozovat ve třech úrovních práv (zvolte jednu na hostitele):

1. **Pod uživatelem** — bez elevace. Topologie a omezená atribuce; vhodné pro
   lab a lehké inventáře.
2. **Uživatel se zvýšenými právy** — `elevate-linux` / `elevate-windows` dá
   dedicated účtu `commatrix` cílené capability/ACL **bez** běhu jako
   root/Administrator, bez sudoers, setuid i členství v Administrators.
   Podrobnosti: [`docs/elevace-cs.md`](docs/elevace-cs.md)
   ([EN](docs/elevation-en.md)).
3. **Pod administrátorem / rootem** — `install.sh --as-root` nebo Windows SYSTEM
   přes `install-windows`. Plný capture včetně spolehlivého SNI, kde OS Admin
   vyžaduje.

### Co režim 2 ve skutečnosti znamená

Dřívější znění tohoto README slibovalo u režimu 2 „**bez** otevření cesty
k získání rootu". **To neplatilo** a bylo to opraveno. Naměřeno na živém jádře
(`setpriv`, cizí UID):

| capabilities | `listdir(/proc/PID/fd)` | `readlink(fd/N)` | `readlink(exe)` |
| --- | --- | --- | --- |
| žádné | ✗ | ✗ | ✗ |
| `CAP_DAC_READ_SEARCH` | ✓ | ✗ | ✗ |
| `CAP_SYS_PTRACE` | ✗ | — | ✓ |
| **obě** | ✓ | ✓ | ✓ |

Atribuce procesů napříč uživateli potřebuje **obě** capability — ani jedna sama
nestačí. A ta dvojice je čtecím ekvivalentem rootu nad každým procesem
i souborem na hostiteli.

Proto má `elevate-linux` dva profily:

```bash
sudo commatrix elevate-linux --profile topology
sudo commatrix elevate-linux --profile attribution   # výchozí
```

- **`topology`** — jen `CAP_NET_ADMIN` + `CAP_NET_RAW`. Toky i služby se sbírají
  normálně, ale sloupce proces/unit/balíček zůstanou u cizích procesů prázdné.
  Žádné zbytkové riziko.
- **`attribution`** (výchozí) — přidá `CAP_DAC_READ_SEARCH` + `CAP_SYS_PTRACE`.
  Drop-in to omezuje dvěma nezávislými mechanismy:
  `SystemCallFilter=~@debug ptrace process_vm_readv process_vm_writev` odebírá
  eskalační primitivum (čtení `/proc` používá jen `openat`/`getdents`/
  `readlinkat`, kdežto `PTRACE_ATTACH` potřebuje syscall `ptrace`), a
  `ProtectHome=tmpfs` + `InaccessiblePaths=` schovají citlivé cesty přes mount
  namespace, který `CAP_DAC_READ_SEARCH` obejít nedokáže.

  **Zbytkové riziko zůstává:** kompromitace collectoru znamená čtení všeho, co
  je mimo `InaccessiblePaths`. `apply_elevate` na to při každém spuštění
  upozorní.

Na Windows se `SeDebugPrivilege` **neuděluje** — atribuce používá
`PROCESS_QUERY_LIMITED_INFORMATION` + `QueryFullProcessImageNameW`, což na cizí
procesy funguje i bez něj. Pro protected (PPL) procesy je k dispozici opt-in:

```bash
python -m commatrix elevate-windows --allow-sedebug
```

```bash
# Linux: po ./install.sh (service účet)
sudo commatrix elevate-linux

# Windows: po install-windows (jednou jako Administrator)
python -m commatrix elevate-windows
```

Revokace (obnoví předchozí stav; při uninstall běží automaticky):

```bash
# Linux
sudo commatrix elevate-linux --revoke

# Windows (jako Administrator)
python -m commatrix elevate-windows --revoke
```

## Výstupy k nasazení (balíčky)

Hotové artefakty z CI/CD (wheel, AppImage, MSI, Snap, Flatpak, SBOM, `SHA256SUMS`)
jsou u **GitHub Releases**:

- **Nejnovější verze:** https://github.com/fedurca/appmap/releases/latest
- Všechny verze: https://github.com/fedurca/appmap/releases

Docker image: `ghcr.io/fedurca/commatrix:latest` (a tag `ghcr.io/fedurca/commatrix:<verze>`).

Release vznikne po pushi tagu `vX.Y.Z` / `X.Y.Z`, po publikaci release ve webovém UI,
nebo ručně: Actions → Release → Run workflow. Workflow přiloží MSI, AppImage, wheel,
Snap/Flatpak (best-effort) a SBOM k danému tagu.
Dokud artefakty nejsou, stáhněte zdroj z `main` a použijte `./install.sh` /
`install-windows`.

## Model capture

**Linux:** jádro už spoje sleduje. Čtení `/proc/net/nf_conntrack` (nebo
event-driven netlink) dává src/dst, port, protokol a (s accountingem) bajty.
Bez conntracku: **`sock_diag`** (jako `ss -i`), pak `/proc/net/{tcp,udp}`
(jen topologie).

**Windows:** IP Helper (`GetExtendedTcpTable`) + TCP ESTATS (best-effort bajty).
DNS-Client události, DoH posture z registru, volitelné SNI přes raw socket —
viz [Windows Server](#windows-server).

Na obou platformách se efemerní klientské porty skládají do stabilních *service
edges* s `first_seen` / `last_seen` / `max_gap`.

### Požadované Linux sysctly

```bash
sysctl -w net.netfilter.nf_conntrack_acct=1
sysctl -w net.netfilter.nf_conntrack_timestamp=1
```

(systemd unit / elevate to řeší za běhu a při stopu obnoví.)

## Požadavky

| | Linux | Windows |
|---|---|---|
| Runtime | Python 3.9+ (jen stdlib) | Python 3.9+ (stdlib; `ctypes` / `winreg`) |
| Zdroj dat | `nf_conntrack` / sock_diag / `/proc` | IP Helper + TCP ESTATS |
| Plný capture | root, nebo `elevate-linux` (caps) | Administrator / SYSTEM, nebo `elevate-windows` |
| Bez elevace | topologie (omezená atribuce) | omezená connection table |
| Volitelně | Zabbix agent | SCCM / Ansible WinRM |

## Možnosti nasazení

| Metoda | Platforma | Co dostanete | Limity |
|---|---|---|---|
| **`./install.sh`** → systemd | Linux | Collector, config, limity CPU/RAM, volitelně Zabbix | Plný capture: `--as-root` nebo `elevate-linux` |
| **`commatrix elevate-linux`** | Linux | Ambient caps + polkit DNS na účet `commatrix` | Setup jednou jako root; `--profile topology` bez zbytkového rizika — [elevace](docs/elevace-cs.md) |
| **`packaging/install-service.sh`** | Linux | Systémová instalace + ovládání přes `commatrix-ctl` | Stejný privilege model; delegace jen pro unit |
| **`pip install .` / ze zdroje** | Linux, Windows | CLI | Bez auto-startu, dokud nepřidáte unit/task |
| **`install-windows`** | Windows | Scheduled task jako SYSTEM | Admin k instalaci; SNI potřebuje Admin |
| **`elevate-windows`** | Windows | Dedicated user + Event Log Readers | Setup jednou Admin; SeDebug jen s `--allow-sedebug`; SNI zůstává u režimu 3 — [elevace](docs/elevace-cs.md) |
| **MSI / SCCM** | Windows | Installer / fleet push | Stejné limity runtime |
| **Ansible** | Linux + Windows | Deploy, pull DB, aggregate HTML | SSH / WinRM |
| **Docker / GHCR** | Linux kontejnery | CLI + report | Live capture: privileged + host network |
| **AppImage / Snap / Flatpak** | Linux | Balíčky | Flatpak jen report/aggregate; Snap classic |
| **One-shot `collect` / `report`** | Linux, Windows | Ad-hoc matice | Mezi běhy chybí toky |

## Instalace

### Doporučeno: installer (systemd + limity)

```bash
sudo ./install.sh                 # systémově; nainstaluje a spustí službu
sudo ./install.sh --no-start
./install.sh --user               # lab (user session)
sudo ./install.sh --uninstall     # odebere (config/data nechá); revoke elevate
sudo commatrix elevate-linux      # režim 2 (profil attribution)
```

### Ovládání služby jako běžný uživatel

```bash
sudo ./packaging/install-service.sh
commatrix-ctl status | start | stop | restart | logs
```

### Windows

```powershell
python -m commatrix install-windows
python -m commatrix elevate-windows   # volitelně režim 2
```

Fleet: [`ansible/`](ansible/README.md), Windows playbook
[`ansible/deploy_windows.yml`](ansible/deploy_windows.yml).

## Breaking changes oproti 344112e

Po bezpečnostní revizi se změnily výchozí hodnoty. Kdo běží podle starého
quick-startu, po upgradu narazí:

| Co | Dřív | Teď |
| --- | --- | --- |
| `commatrix serve` bez `--token` | nastartoval | **odmítne nastartovat** |
| `commatrix serve --host` | `0.0.0.0` | `127.0.0.1` |
| `commatrix-server.service` | funkční `ExecStart` bez tokenu | vyžaduje `EnvironmentFile=/etc/commatrix/server.env` |
| `commatrix-export.service` | `User=root` | `User=commatrix` |
| Docker | dokumentováno `--privileged` | `--cap-drop ALL` + tři konkrétní capability |
| Windows `elevate-windows` | uděloval `SeDebugPrivilege` | neuděluje; opt-in `--allow-sedebug` |
| Docker image | běžel jako root | `USER 65532` |

Token pro server se generuje takto:

```bash
install -d -m 0750 -o commatrix -g commatrix /etc/commatrix
printf 'COMMATRIX_TOKEN=%s\n' "$(openssl rand -hex 32)" > /etc/commatrix/server.env
chown root:commatrix /etc/commatrix/server.env
chmod 0640 /etc/commatrix/server.env
```

Token nikdy nedávejte na příkazovou řádku — je čitelný přes `ps` a `/proc`.
Podporované zdroje v pořadí priority: `--token-file`, `COMMATRIX_TOKEN`,
`--token` (poslední varuje).

## Bezpečnostní poznámky

- **Report je aktivní obsah.** HTML dashboard vkládá jména peerů, která pochází
  z reverzního DNS, z SNI parseru a z endpointu `/ingest` — tedy z dat, která
  ovládá protistrana. Všechny výstupní cesty escapují podle cílové syntaxy
  (HTML entity pro mermaid, vlastní escaping pro DOT, apostrofový prefix pro CSV).
- **Report je citlivý dokument.** Obsahuje kompletní mapu vnitřní sítě. Databáze
  vzniká s právy `0640` a adresář `0750`.
- **`--host` filtruje všechny výstupy.** Per-host report neobsahuje nálezy ani
  topologii jiných hostů.
- **`/ingest` je autoritativní zápis.** Bez tokenu by kdokoli v dosahu portu
  mohl podvrhnout záznamy toků pro libovolný host.

## Bezpečnost vůči hostiteli

- **CPU** ≤ ~10 % celkového výkonu (governor + systemd `CPUQuota` / Job Object)
- **Disk** ≤ ~10 % volného místa + `retention_days`
- **Paměť** strop `MemoryMax` / Job Object
- Nejnižší priorita plánovače

## Použití (stručně)

```bash
# sběr
sudo commatrix collect --config /etc/commatrix/commatrix.conf
commatrix collect --once --allow-manual --database /tmp/commatrix.db

# centralizace
commatrix export -o /var/lib/commatrix/snapshots/$(hostname).json
commatrix aggregate --central central.db --snapshot-dir snapshots/

# report
commatrix report -f html --database central.db
commatrix report -f mermaid --database central.db
```

Další: `history`, `dns`, `doh`, `time`, `diff` — viz
[`docs/pouziti-cs.md`](docs/pouziti-cs.md).

## Windows Server

Stejný princip (jen stdlib). Mapování Linux → Windows: IP Helper, ESTATS,
DNS-Client/`wevtutil`, DoH z registru, SNI přes `SIO_RCVALL` (Admin), Job Object
místo CPUQuota, `install-windows` / `elevate-windows` místo systemd.

## Architektura

```mermaid
flowchart LR
  subgraph vm [Kazdy host]
    ct["conntrack / IP Helper"] --> collector
    proc["procesy / služby"] --> collector
    collector --> localdb[("lokalni SQLite")]
  end
  localdb --> central["aggregate / Ansible pull"]
  central --> report["Matice + katalog + diagramy"]
```

## Omezení

- Polling conntrack může minout krátké toky → preferujte event mode (caps/root).
- Byte county jsou best-effort.
- SNI na Windows po `elevate-windows` **není** garantované (potřebuje Admin/SYSTEM).

## Dokumentace

- Jak to funguje: [`docs/jak-funguje-cs.md`](docs/jak-funguje-cs.md),
  [`docs/how-it-works.md`](docs/how-it-works.md)
- **Elevace práv:** [`docs/elevace-cs.md`](docs/elevace-cs.md),
  [`docs/elevation-en.md`](docs/elevation-en.md)
- Nasazení a použití: [`docs/pouziti-cs.md`](docs/pouziti-cs.md)
- SBOM: [`SBOM.md`](SBOM.md)
- Packaging / CI: [`packaging/`](packaging), [`.github/workflows/`](.github/workflows)

## Licence

GPL-3.0-or-later. Viz [LICENSE](LICENSE).
