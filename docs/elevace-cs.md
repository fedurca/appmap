# Elevace práv (Linux a Windows)

Rozšířený popis příkazů `elevate-linux` a `elevate-windows`. Cíl: **maximum
informací bez běhu jako root/Administrator** a **bez otevření cesty k získání
rootu** (žádné sudoers, setuid, CAP_SETUID/CAP_SYS_ADMIN, členství v
Administrators, SeImpersonatePrivilege).

Související: [README](../README.md) · [English](elevation-en.md)

---

## Tři režimy běhu

| Režim | Linux | Windows | Co získáte |
|---|---|---|---|
| **1. Pod uživatelem** | běžný uživatel / unit bez extra caps | běžný uživatel | topologie, omezená atribuce |
| **2. Elevace** | `elevate-linux` na účet `commatrix` | `elevate-windows` na účet `commatrix` | téměř plný capture bez root/Admin |
| **3. Administrátor / root** | `install.sh --as-root` | `install-windows` (SYSTEM) | maximum včetně jistoty SNI |

Elevace se vztahuje na **dedicated service účet** (nologin), ne na váš
interaktivní login. Samotný příkaz elevate musí jednorázově spustit root/Admin.

---

## Linux: `elevate-linux`

```bash
sudo commatrix elevate-linux              # grant
sudo commatrix elevate-linux --dry-run    # náhled
sudo commatrix elevate-linux --revoke     # vrácení
```

### Co se nastaví

1. **Systemd drop-in**  
   `/etc/systemd/system/commatrix-collector.service.d/60-elevate.conf`

   - `User=commatrix` / `Group=commatrix`
   - AmbientCapabilities / CapabilityBoundingSet:
     - `CAP_DAC_READ_SEARCH` — čtení conntrack a `/proc/<pid>/fd` jiných uživatelů
     - `CAP_NET_ADMIN` — sysctly nf_conntrack, event netlink
     - `CAP_NET_RAW` — SNI přes AF_PACKET
     - `CAP_SYS_PTRACE` — netns / kontejnery přes `/proc/<pid>/net`
   - `NoNewPrivileges=true`

2. **Polkit**  
   `/etc/polkit-1/rules.d/50-commatrix-resolved.rules`  
   úzký grant pro uživatele `commatrix` na akce `org.freedesktop.resolve1.*`
   (DNS monitor bez euid 0).

3. **Stav**  
   `/var/lib/commatrix/elevate-state.json` — předchozí drop-in/polkit pro revoke.
   `install.sh --uninstall` revoke volá automaticky.

### Feature → právo

| Funkce | Potřebuje | Po elevate-linux |
|---|---|---|
| Topologie | — | ano |
| Byte accounting (conntrack) | CAP_NET_ADMIN (+ acct sysctl) | ano |
| Cizí procesy | CAP_DAC_READ_SEARCH | ano |
| Event-driven conntrack | CAP_NET_ADMIN | ano |
| DNS query log | polkit / root | ano (polkit) |
| SNI (AF_PACKET) | CAP_NET_RAW | ano |
| Netns / kontejnery | CAP_SYS_PTRACE | ano |

### Co elevate-linux záměrně nedělá

- sudoers / passwordless sudo
- setuid na Python
- `CAP_SETUID`, `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`
- interaktivní shell pro účet `commatrix` (nologin)

---

## Windows: `elevate-windows`

```powershell
# jako Administrator, po install-windows
python -m commatrix elevate-windows
python -m commatrix elevate-windows --dry-run
python -m commatrix elevate-windows --revoke
```

### Co se nastaví

1. Lokální účet **`commatrix`** (ne Administrators); při bindu tasku se
   heslo rotuje (neukládá se do state souboru).
2. Skupina **Event Log Readers** + enable kanálu
   `Microsoft-Windows-DNS-Client/Operational`.
3. **SeDebugPrivilege** jen pro tento účet (cross-process atribuce) — pokud je
   k dispozici `ntrights`; jinak varování a ruční Local Security Policy.
4. ACL na `%ProgramData%\commatrix`: SYSTEM + `commatrix`.
5. Scheduled task přepsán z SYSTEM na `commatrix` s `/rl limited`.
6. Stav: `%ProgramData%\commatrix\elevate-state.json`.  
   `uninstall-windows` revoke volá automaticky.

### Feature → právo

| Funkce | Potřebuje | Po elevate-windows |
|---|---|---|
| Topologie (IP Helper) | — | ano |
| Byte counts (ESTATS) | — (best-effort) | ano |
| Cizí procesy (image path) | SeDebugPrivilege | ano (pokud grant uspěje) |
| DNS log | Event Log Readers + kanál | ano |
| DoH posture (čtení) | — | ano |
| SNI (`SIO_RCVALL`) | Administrator / SYSTEM | **ne** — zůstává u režimu 3 |

### Co elevate-windows záměrně nedělá

- členství v **Administrators**
- `SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege`
- slib SNI bez Admin/SYSTEM

---

## Revoke a odinstalace

| Akce | Linux | Windows |
|---|---|---|
| Ruční revoke | `elevate-linux --revoke` | `elevate-windows --revoke` |
| Při uninstall | `install.sh --uninstall` | `uninstall-windows` |

Revoke obnoví předchozí drop-in/polkit (Linux) nebo SYSTEM task (Windows) ze
state souboru a state smaže.

---

## Bezpečnostní poznámka

Ambient capabilities / SeDebugPrivilege na **service účet bez loginu** jsou
výrazně bezpečnější než běh jako root/SYSTEM, ale stále umožňují číst citlivá
síťová a procesní data. Nasazení musí schválit provozovatel (SOC). Elevace
**není** obcházení firemních privilegovaných přístupů — je to least-privilege
profil pro sběr.
