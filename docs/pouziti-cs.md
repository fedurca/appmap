# Commatrix – uživatelská a nasazovací dokumentace

Interní dokumentace k nástroji **commatrix** pro mapování síťové komunikace,
katalog aplikací a bezpečnostní přehledy na serverech (Linux i Windows).

---

## 1. Co to je a jak to funguje

Commatrix je odlehčený agent, který na každém stroji zjišťuje **kdo s kým a jak
komunikuje po síti**, přiřazuje spojení k procesům/službám a ukládá to do lokální
SQLite databáze. Z databází lze vygenerovat **komunikační matici**, **topologii**,
**katalog aplikací** a **bezpečnostní přehledy**. Databáze se dají centrálně
posbírat (Ansible) a sloučit do jednoho reportu za celou flotilu.

### Principy (proč je to bezpečné nasadit)

- **Pouze standardní knihovna** – žádné pip/třetí-strana závislosti. Na Windows
  jen `ctypes`/`winreg`/`socket`/vestavěné nástroje, žádný pywin32.
- **Bez odposlechu paketů** (žádný libpcap/tcpdump). Používá vestavěné funkce
  jádra: Linux `nf_conntrack`/netlink/`/proc`, Windows IP Helper API / ETW.
- **Nikdy nepoškodí hosta** – tvrdé limity CPU (≤10 % celkového výkonu), disku
  (≤10 % volného místa) i paměti; běží s nejnižší prioritou.
- **Graceful degradace** – když něco není dostupné, funkce se vypne a zaloguje,
  nespadne.
- **Restriktivní práva** – databáze a snapshoty nejsou čitelné běžnými uživateli
  (Linux `0640`, Windows ACL na SYSTEM + Administrators).
- **Append-only historie** pro forenzní analýzu (IR) + statistiky pokrytí.

### Zdroje dat podle platformy (automatická volba)

- **Linux:** `nf_conntrack` (procfs / netlink události) → `conntrack-tools` →
  `sock_diag` (per-socket byty bez instalace) → `/proc/net/tcp` (jen topologie).
- **Windows:** IP Helper API (spojení + PID) → TCP ESTATS (byty) → jen topologie.

---

## 2. Podporované platformy

- **Linux:** RHEL 8+/9+, Ubuntu 20.04+, Debian, Fedora. Python 3.9+.
- **Windows:** Windows Server 2019/2022+. Python 3.9+ (nebo zabalený v SCCM
  balíčku).

---

## 3. Nasazení na Linuxu

### 3.1 Jednorázově jako systémová služba + ovládání uživatelem

```bash
sudo ./packaging/install-service.sh            # nainstaluje službu (root) a deleguje ovládání
```

Nainstaluje systemd službu a povolí danému uživateli (výchozí `$SUDO_USER`) ji
ovládat bez hesla přes `commatrix-ctl`:

```bash
commatrix-ctl status | start | stop | restart | logs | follow
```

Volby: `--user JMENO` (řídící uživatel), `--as-root` (běh pod rootem – nutné pro
DNS log a plnou atribuci), jinak běží pod neprivilegovaným účtem `commatrix`
s capabilitami `CAP_NET_ADMIN`/`CAP_DAC_READ_SEARCH`.

### 3.2 Přímá instalace služby

```bash
sudo ./install.sh                 # systémová služba (systemd)
sudo ./install.sh --as-root       # běh pod rootem (DNS log, plná atribuce)
sudo ./install.sh --uninstall     # odebrat
```

### 3.3 Privilegia (co která úroveň umí)

| Úroveň | Topologie | Byte county | Procesy jiných uživatelů | DNS log |
|---|---|---|---|---|
| neprivilegovaně | ano | ano (sock_diag, TCP) | ne | ne |
| capabilities | ano | ano | ano | ne |
| root | ano | ano | ano | ano |

---

## 4. Nasazení na Windows

### 4.1 Ruční instalace na jednom stroji (jako Administrator)

Předpoklad: nainstalovaný Python 3.9+ a balíček commatrix (`pip install .`).

```powershell
python -m commatrix install-windows
```

Zaregistruje **startup úlohu pod SYSTEM** (obdoba systemd unitu), vytvoří a
zabezpečí `%ProgramData%\commatrix\` (ACL: SYSTEM + Administrators) a spustí
sběr. Odebrání:

```powershell
python -m commatrix uninstall-windows
```

### 4.2 Nasazení přes SCCM (doporučeno pro flotilu)

Commatrix je „stdlib-only“, takže se dá zabalit **plně samostatně** i s vloženým
Pythonem – na cílových serverech nemusí být Python ani pip.

**Krok 1 – sestavit balíček** (na build stroji):

```bash
python packaging/windows/build_package.py --out dist/commatrix-win
```

**Krok 2 – přidat vložený Python:** stáhnout oficiální *Windows embeddable
package* zip pro danou verzi Pythonu a rozbalit do
`dist/commatrix-win/payload/python\` (musí obsahovat `python.exe`). Poté složku
zazipovat.

**Krok 3 – import do SCCM** jako aplikace typu *Script Installer* s režimem
**„Install for system“** (SCCM spouští program pod SYSTEM, což je přesně potřebné
oprávnění):

- Install program: `powershell -ExecutionPolicy Bypass -File install.ps1`
- Uninstall program: `powershell -ExecutionPolicy Bypass -File uninstall.ps1`
- Detection: `powershell -ExecutionPolicy Bypass -File detect.ps1` (SCCM považuje
  jakýkoli výstup na stdout za „nainstalováno“)

**Co balíček udělá na klientovi:** rozbalí payload do `%ProgramFiles%\commatrix`,
zabezpečí `%ProgramData%\commatrix` (ACL), zaregistruje startup úlohu
`commatrix-collector` mířící na `commatrix.cmd` (spouští vložený Python s
`PYTHONPATH`).

### 4.3 Co bylo pro SCCM doplněno (a co případně ještě doladit)

Doplněno v projektu:

- příkaz **`uninstall-windows`** (odebrání startup úlohy),
- volba **`install-windows --task-command`** (úloha míří na zabalený launcher,
  takže není potřeba systémový Python ani pip),
- balicí skript **`packaging/windows/build_package.py`** + **`install.ps1`** /
  **`uninstall.ps1`** / **`detect.ps1`** / **`commatrix.cmd`**.

K dořešení podle prostředí firmy:

- doplnit do balíčku konkrétní **embeddable Python** (licenčně OK, jen ho
  přibalit) – build skript na to upozorní,
- volitelně vytvořit **MSI** (WiX) místo Script Installeru, pokud to vyžadují
  vaše SCCM konvence (detection přes MSI product code),
- rozhodnout **režim běhu** (root/SYSTEM je nutný pro DNS log; jinak topologie +
  byty i bez něj) a nastavit **retenci/limity** v configu (viz níže),
- reálné **integrační ověření na Windows Serveru** (build stroj v tomto repu byl
  Linux; Windows-specifické cesty jsou pokryté unit testy parserů).

---

## 5. Konfigurace

Konfigurační soubor (INI): Linux `/etc/commatrix/commatrix.conf`, Windows
`%ProgramData%\commatrix\commatrix.conf`. Všechny hodnoty mají rozumné výchozí
nastavení; přepisujte jen co potřebujete. Nejdůležitější sekce:

```ini
[collector]
poll_interval = 5                 ; interval sběru (s)
source = auto                     ; auto|procfs|conntrack-events|socket-diag|sockets
require_root = false              ; true = běh jen jako root/Administrator

[network]
internal_cidrs = 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

[resources]
cpu_budget_percent = 10           ; strop CPU
disk_budget_percent = 10          ; strop velikosti DB vůči volnému místu
retention_days = 30               ; jak dlouho držet hrany/události

[capture]
mode = auto                       ; auto|events|poll (event-driven zachytí i krátké toky)
netns = auto                      ; auto|host-only|all (kontejnery, jen jako root)

[dns]
enabled = true                    ; log DNS dotazů (Linux resolved / Windows DNS-Client)
enrich_flows = true               ; doplnit doménu k IP (sloupec Domain)

[sni]
enabled = false                   ; opt-in odchyt SNI z TLS ClientHello (root/CAP_NET_RAW)

[time]
; ntp_check_server = pool.ntp.org ; volitelný aktivní SNTP test přesnosti hodin
```

---

## 6. Reporty a přehledy

Databáze je `…/commatrix.db`. Report se generuje průběžně při zastavení služby
(HTML vedle DB), nebo kdykoli ručně:

```bash
commatrix report -f html      -o /tmp/report.html --database <cesta k DB>   # dashboard
commatrix report -f markdown  --database <DB>    # komunikační matice
commatrix report -f security  --database <DB>    # bezpečnostní přehledy
commatrix report -f mermaid   --database <DB>    # diagram topologie
commatrix history --database <DB>                # append-only IR log
commatrix dns     --database <DB>                # log DNS dotazů
commatrix doh                                    ; posture DoH (vypnuto/vynuceno?)
commatrix time                                   ; přesnost hodin / NTP
```

HTML report nahoře obsahuje **Host posture** (DoH, čas, kvalita sběru), statistiky
(první spuštění, počet běhů, celková doba běhu, **procento bílých míst**),
rozklikávací **komunikační flow** (seskupené po procesech a adresách) a
bezpečnostní sekce (externí expozice, cleartext, **šifrované DNS**, chybějící
byte county). Externí IP jsou proklik na VirusTotal.

---

## 7. DNS, DoH a SNI (viditelnost DNS)

- **DNS log:** Linux přes systemd-resolved monitor, Windows přes DNS-Client
  kanál. Vyžaduje root/Administrator.
- **DoH posture:** `commatrix doh` zkontroluje, zda je DNS-over-HTTPS v
  prohlížečích/systému vypnuté a vynucené (jinak aplikace obchází systémový DNS).
- **Detekce DoH endpointů:** spojení na známé DoH/DoT resolvery se označí a
  vypíšou v bezpečnostní sekci (obsah je šifrovaný, ale fakt komunikace je signál).
- **SNI capture (volitelné):** z TLS ClientHello získá cílový hostname i při
  šifrovaném DNS. ECH (Encrypted Client Hello) SNI skryje (`<ech>`).

---

## 8. Centrální sběr přes Ansible (Linux + Windows)

Ve složce `ansible/`:

```bash
cp ansible/inventory.example.ini ansible/inventory.ini   # upravit hosty

# Nasazení
ansible-playbook -i ansible/inventory.ini ansible/deploy.yml           # Linux
ansible-playbook -i ansible/inventory.ini ansible/deploy_windows.yml   # Windows (WinRM)

# Sběr lokálních DB + sloučení + analytický přehled
ansible-playbook -i ansible/inventory.ini ansible/pull_and_report.yml
# -> ansible/commatrix-data/commatrix-report.html
```

Windows i Linux používají **stejný formát snapshotů**, takže se slévají do jednoho
reportu za celou flotilu.

---

## 9. Řešení problémů

- **„Bytes = 0“ v matici:** běží fallback bez accountingu. Linux: `sock_diag`
  dodá byty i bez instalace; pro conntrack county zapnout modul + accounting.
  Windows: TCP ESTATS (best-effort). Kvalitu ukazuje sekce *Capture quality*.
- **Prázdné procesy u cizích spojení:** běžíte neprivilegovaně; atribuce cizích
  procesů vyžaduje root/Administrator (nebo capabilities).
- **Prázdný DNS log:** vyžaduje root/Administrator a systemd-resolved (Linux) /
  DNS-Client kanál (Windows); aplikace s vlastním DoH se stejně neuvidí.
- **Report hlásí „readonly database“:** čtěte přes uživatele s právem na DB, nebo
  přes `sudo`; report/export/history otvírají DB read-only.
- **Coverage gap vysoký:** sběr velkou část času neběžel – zkontrolujte službu/úlohu.

---

## 10. Bezpečnost a soukromí

- Databáze = kompletní mapa síťové komunikace + jména procesů + (volitelně) DNS
  dotazy. Je zabezpečená právy (0640 / ACL); přístup k reportům omezte.
- Sběr běží s tvrdými limity a nejnižší prioritou, aby neovlivnil provoz.
- Na stroji se při běhu zapínají jen nezbytné volby (Linux `nf_conntrack`
  accounting) a **při ukončení se vrací do původního stavu** (i po pádu díky
  perzistovanému stavu).

---

Kontakt / správa: doplňte interní kontakt týmu.
