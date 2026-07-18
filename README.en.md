# Commatrix

> English README. Czech (primary): [`README.md`](README.md).

Commatrix is a **standard-library-only** Python tool for **Linux and Windows**
that maps network communication using host-native APIs instead of packet
capture (`tcpdump`/libpcap). It collects flow data on many hosts, attributes
each flow to the **application/process** that produced it, optionally enriches
it with **Zabbix host parameters**, and aggregates everything into a
**communication matrix** and an **application catalog** with ready-to-use
documentation exports. Linux and Windows snapshots share the same schema and
merge into one fleet report.

## Three ways to run

Commatrix can be operated in three privilege modes (pick one per host):

1. **As a normal user** — no elevation. Topology and limited attribution;
   enough for labs and light inventories.
2. **Elevated service user** — `elevate-linux` / `elevate-windows` grant the
   dedicated `commatrix` account the maximum capabilities/ACLs **without**
   running as root/Administrator and **without** opening a path to obtain root
   (no sudoers, setuid, or Administrators membership). See
   [`docs/elevation-en.md`](docs/elevation-en.md)
   ([Česky](docs/elevace-cs.md)).
3. **As Administrator / root** — `install.sh --as-root` or Windows SYSTEM via
   `install-windows`. Full capture including reliable SNI where the OS requires
   Admin.

```bash
# Linux: after ./install.sh (service user)
sudo commatrix elevate-linux

# Windows: after install-windows (Administrator once)
python -m commatrix elevate-windows
```

## Capture model

**Linux:** the kernel already tracks connections. Reading
`/proc/net/nf_conntrack` (or the event-driven netlink listener) gives source,
destination, port, protocol and (with accounting enabled) byte/packet counters
without any capture library. When conntrack is absent, Commatrix uses
**`sock_diag`** (same source as `ss -i`) for per-socket TCP counts, then falls
back to `/proc/net/{tcp,udp}` (topology only).

**Windows:** IP Helper (`GetExtendedTcpTable`) owns the connection table and
PID attribution; TCP ESTATS provides best-effort byte counts. DNS-Client events,
registry DoH posture, and optional raw-socket SNI mirror the Linux feature set
(see [Windows Server](#windows-server)).

On both platforms Commatrix folds ephemeral client ports into stable *service
edges* and maintains, per edge:

- source, destination, service port, protocol, direction
- cumulative bytes / packets (best-effort estimate from snapshot deltas)
- `first_seen`, `last_seen`
- `max_gap` — the **longest idle interval between two communications**

### Required Linux kernel settings

Byte/packet accounting and flow timestamps are off on many distros. Enable them
(the systemd unit does this automatically):

```bash
sysctl -w net.netfilter.nf_conntrack_acct=1
sysctl -w net.netfilter.nf_conntrack_timestamp=1
```

Reading `/proc/net/nf_conntrack` and `/proc/<pid>/fd` for other users requires
**root** (or matching capabilities).

## Requirements

| | Linux | Windows |
|---|---|---|
| Runtime | Python 3.9+ (stdlib only) | Python 3.9+ (stdlib only; `ctypes` / `winreg`) |
| Capture source | `nf_conntrack` / sock_diag / `/proc` | IP Helper + TCP ESTATS |
| Full capture privileges | root or `CAP_NET_ADMIN` (+ `CAP_NET_RAW` for SNI) | Administrator / SYSTEM scheduled task |
| Unprivileged | topology (limited process attribution) | limited connection table |
| Optional | Zabbix agent (`zabbix_get` / `zabbix_sender`) | SCCM / Ansible WinRM for fleet deploy |

## Deployment options

| Method | Platform | What you get | Limits |
|---|---|---|---|
| **`./install.sh`** → systemd unit | Linux | Collector service, config, resource caps, optional Zabbix UserParameter | Full capture needs root/`--as-root` or `elevate-linux`; unprivileged = topology-oriented |
| **`commatrix elevate-linux`** | Linux | Ambient caps + polkit DNS on service user `commatrix` | Setup needs root once; no sudoers/setuid; see [elevation docs](docs/elevation-en.md) |
| **`packaging/install-service.sh`** | Linux | System install + user control via scoped sudoers/`commatrix-ctl` | Same privilege model as `install.sh`; control delegation is for the unit only |
| **`pip install .` / run from source** | Linux, Windows | CLI (`collect`, `report`, `aggregate`, …) | No auto-start unless you add a unit/task yourself |
| **`python -m commatrix install-windows`** | Windows | Scheduled task as SYSTEM, data under ProgramData | Needs Administrator to install; byte counts are best-effort ESTATS; SNI needs Admin + `[sni] enabled` |
| **`commatrix elevate-windows`** | Windows | Dedicated user + Event Log / SeDebug; task off SYSTEM | Setup needs Admin once; SNI still needs Admin/SYSTEM; see [elevation docs](docs/elevation-en.md) |
| **MSI** (`packaging/windows/`, CI release) | Windows | Installer for SCCM / manual deploy | Same runtime limits as `install-windows`; build needs WiX + Python on the build host |
| **SCCM Script Installer** (`packaging/windows/sccm/`) | Windows | Fleet push via ConfigMgr | Depends on SCCM reachability and how Python/runtime is bundled |
| **Ansible** (`ansible/deploy.yml`, `deploy_windows.yml`, `pull_and_report.yml`) | Linux + Windows | Deploy collector, pull DBs, aggregate HTML | SSH (Linux) / WinRM (Windows); central node must reach inventory |
| **Docker / GHCR** (`Dockerfile`, CI) | Linux containers | Reproducible CLI + report tooling | Live host capture needs **privileged + host network** (or matching caps); otherwise use mounted DBs for report/aggregate only |
| **AppImage** (CI release) | Linux | Single-file binary, no package install | Still needs root/caps for privileged collect; not a substitute for systemd on fleets |
| **Snap** (`snapcraft.yaml`, classic) | Linux | Distro-agnostic package | Classic confinement; strict confinement cannot usefully see host `/proc`/conntrack |
| **Flatpak** (`packaging/flatpak/`) | Linux desktop | Sandboxed CLI for **report / aggregate** | **Not for live capture** — sandbox blocks conntrack/proc/netns; use on exported DBs/JSON |
| **One-shot `collect` / `report`** | Linux, Windows | Ad-hoc matrix without a service | Misses flows between runs; use a timer/task for continuous coverage |

**Privilege summary:** unprivileged collect still builds a useful topology.
Exact byte accounting, DNS monitor, SNI, container/netns walk, and toggling
conntrack sysctls need elevated rights (Linux capabilities/root, or Windows
Administrator/SYSTEM).

## Install

### Recommended: the installer (systemd + resource limits)

```bash
sudo ./install.sh                 # system-wide; installs & starts the systemd service
sudo ./install.sh --no-start      # install without starting
./install.sh --user               # per-user install (labs/testing; capture still needs root)
sudo ./install.sh --uninstall     # remove (keeps config/data)
```

The installer copies the package, writes `/etc/commatrix/commatrix.conf`, enables
the required conntrack sysctls, installs the systemd unit **with a CPU quota of
10% of total compute** (`10% x nproc`) and a memory ceiling, installs the Zabbix
`UserParameter` file if an agent is present, and enables the service. Override
budgets with `--cpu-percent N` / `--disk-percent N`.

### One-shot: install as root, control as a user

If you want the collector installed once as a **system** service (root) but be
able to start/stop/inspect it as your normal user **without a root password**:

```bash
sudo ./packaging/install-service.sh            # controlling user defaults to $SUDO_USER
sudo ./packaging/install-service.sh --user alice
sudo ./packaging/install-service.sh --uninstall
```

It runs the system installer, then delegates control of **only** the
`commatrix-collector.service` unit to that user via a scoped `sudoers` drop-in
(and a polkit rule when polkit is present), and installs a `commatrix-ctl`
wrapper:

```bash
commatrix-ctl status
commatrix-ctl start | stop | restart
commatrix-ctl logs | follow
```

### Manual / pip

```bash
pip install .        # provides the `commatrix` command; also runnable as `python3 -m commatrix`
```

### Fleet deployment (Ansible)

`ansible/` ships playbooks to deploy the collector fleet-wide and then pull each
host's local database, merge them on a control node and generate one analytical
overview (`deploy.yml`, `collect.yml`, `report.yml`, `pull_and_report.yml`). See
[`ansible/README.md`](ansible/README.md).

## Resource safety (never hurt the host)

Commatrix is designed to be invisible to real workloads:

- **CPU:** an in-process governor measures how much CPU each poll consumed and
  sleeps so the collector never averages more than **10% of total compute**
  (all cores). It also backs off further under high load average. The systemd
  unit additionally enforces `CPUQuota`, `Nice=19`, `CPUSchedulingPolicy=idle`
  and `IOSchedulingClass=idle` as a hard ceiling.
- **Disk:** the database never exceeds **10% of free disk space** (least-recently
  active edges are pruned, plus a `retention_days` window). Writes pause entirely
  if free space falls below a hard floor (default 5%).
- **Memory:** advisory `memory_max_mb` in the config, enforced by the unit's
  `MemoryMax`.

All limits are configurable in the `[resources]` section of the config.

## Test Zabbix agent installer (lab only)

To spin up a Zabbix agent for exercising the integration on a lab machine:

```bash
sudo ./packaging/install-zabbix-agent-test.sh \
    --hostname lab-pc --server 127.0.0.1 --with-commatrix-userparams
```

This installs the distro `zabbix-agent`, points it at the given server, sets the
hostname, and (optionally) installs the commatrix UserParameters. It is **not**
hardened for production.

### Lab sudo helper (passwordless root for collection)

For lab machines (RHEL 8+, Ubuntu 20.04+), install passwordless sudo once
interactively, then run collection without prompts. No packages or network access
are required by these scripts.

```bash
cd /path/to/appmap

# 1) One-time: installs /etc/sudoers.d/commatrix-lab (prompts for YOUR password once)
chmod +x packaging/install-lab-sudoers.sh packaging/lab-commatrix-helper.sh
./packaging/install-lab-sudoers.sh

# 2) Enable conntrack accounting / detect capture backend (no password after step 1)
sudo ./packaging/lab-commatrix-helper.sh setup-conntrack

# 3) Collect (writes DB + HTML report; sysctls restored automatically after run)
sudo ./packaging/lab-commatrix-helper.sh collect-once --database /tmp/commatrix.db
sudo ./packaging/lab-commatrix-helper.sh collect --database /tmp/commatrix.db --iterations 120

# Environment changes (sysctls) are logged to ./commatrix-lab-env.log in the repo root.

# Remove passwordless sudo when done
./packaging/install-lab-sudoers.sh --remove
```

After collection, open `/tmp/commatrix-report.html` for the dashboard with graphs.

## Usage

### 1. Collect on each VM (daemon)

```bash
sudo commatrix collect --config /etc/commatrix/commatrix.conf
# one-shot for testing:
sudo commatrix collect --once --database /tmp/commatrix.db
```

### 2. Centralise across VMs

Two supported transports (pick one, both ship):

**File pull (default):** each host exports a snapshot; a central node merges.

```bash
# on each host (systemd timer does this):
commatrix export -o /var/lib/commatrix/snapshots/$(hostname).json
# on the central node, after rsync/scp of the snapshots:
commatrix aggregate --central /var/lib/commatrix/central.db \
    --snapshot-dir /var/lib/commatrix/snapshots
```

**Push to a central server:**

```bash
# central node:
commatrix serve --database /var/lib/commatrix/central.db --port 8899 --token SECRET
# each host:
commatrix push --server http://central:8899 --token SECRET
```

### 3. Report / document

```bash
commatrix report -f markdown  --database central.db   # communication matrix
commatrix report -f html      --database central.db   # HTML dashboard + graphs
commatrix report -f csv       --database central.db
commatrix report -f mermaid   --database central.db   # topology diagram
commatrix report -f dot       --database central.db | dot -Tpng -o topology.png
commatrix report -f sheets    --database central.db   # per-application docs
commatrix report -f catalog   --database central.db   # machine-readable JSON
commatrix report -f security  --database central.db   # exposure highlights
```

### 4. Drift detection

```bash
commatrix diff baseline.json current.json    # added/removed communications
```

## Zabbix integration

- **Host parameters:** Commatrix reads `zabbix_agentd.conf` for the canonical
  `Hostname`/`HostMetadata`, and queries the local agent via `zabbix_get` for
  system facts (falling back to procfs/`platform` when unavailable). See
  `commatrix hostparams`.
- **UserParameters:** `packaging/zabbix_userparameter.conf` exposes summary
  metrics (edge counts, external exposure, freshness) so Zabbix can pull health.
- **Transport:** an optional `zabbix_sender` exporter is available for pushing
  summary items to a trapper.

## Application catalog

Beyond raw flows, Commatrix enriches the catalog with:

- process/service/unit/package/container attribution per port,
- logical application naming and layer-7 protocol inference via
  `commatrix/signatures/*.json` (editable),
- internal vs external peer classification and optional reverse DNS,
- inter-VM linking (peer IPs matched back to known hosts),
- drift detection (baseline vs current),
- security highlights (external inbound exposure, cleartext protocols),
- documentation outputs (matrix, topology diagram, per-app service sheets, CMDB-ready JSON).

## Windows Server

commatrix runs on Windows Server too, keeping every principle (standard library
only - `ctypes`/`winreg`/`socket`/`subprocess` to built-in tools; no pywin32, no
libpcap). A platform layer (`commatrix/platform/`) routes OS-specific capture
while the core (store, report, aggregate, catalog, DoH/SNI logic) is shared, so
the snapshot/report contract is identical and Linux + Windows merge into one
report.

Linux -> Windows mapping:

- connections + owning PID: IP Helper API `GetExtendedTcpTable` (ctypes) instead
  of `/proc/net/tcp` + inode walk;
- byte accounting: TCP ESTATS (best-effort) instead of sock_diag/nf_conntrack;
- DNS logging: DNS-Client event channel (`wevtutil`, ETW real-time is a
  follow-up) instead of the systemd-resolved monitor;
- DoH posture: registry policies (`winreg`) instead of policy files;
- SNI capture: raw socket `SIO_RCVALL` (opt-in, Administrator) instead of
  AF_PACKET - same TLS ClientHello parser;
- time posture: `w32tm /query /status` instead of `timedatectl`/chrony;
- resource safety: Job Object CPU/memory caps + `IDLE_PRIORITY_CLASS` instead of
  CPUQuota/nice; disk budget via `shutil.disk_usage`;
- data-at-rest ACL via `icacls`; runs as a SYSTEM startup task
  (`commatrix install-windows`) instead of a systemd unit.

Install on a host (Administrator): `python -m commatrix install-windows`.
Optionally least-privilege the task with `python -m commatrix elevate-windows`
(see [`docs/elevation-en.md`](docs/elevation-en.md)). Deploy a fleet with
[`ansible/deploy_windows.yml`](ansible/deploy_windows.yml).

## Architecture

```mermaid
flowchart LR
  subgraph vm [Each VM]
    ct["/proc/net/nf_conntrack"] --> collector
    procfs["/proc/net/tcp*, /proc/PID/*"] --> collector
    zbx["Zabbix agent params"] --> collector
    collector --> localdb[("local SQLite")]
    localdb --> exporter["JSON snapshot / zabbix_sender"]
  end
  exporter --> central["Central aggregator (http.server or file pull)"]
  central --> centraldb[("central SQLite")]
  centraldb --> report["Matrix + Catalog + Diagrams"]
```

## Limitations

- Snapshot polling of `nf_conntrack` can miss flows created *and* destroyed
  between polls. Set `[capture] mode = auto` (default) to use the **event-driven
  netlink conntrack listener** when running as root (pure stdlib, no
  `conntrack-tools`): DESTROY events carry final counters so short flows are
  captured. Falls back to polling otherwise.
- Byte counts are a best-effort cumulative estimate, not exact accounting, and
  require `nf_conntrack_acct=1`.
- Runs **unprivileged by default**: topology is always captured, but toggling
  the `nf_conntrack` sysctls and attributing *other users'* processes need
  `CAP_NET_ADMIN` / `CAP_DAC_READ_SEARCH` (default unit or `elevate-linux`) or
  root (`install.sh --as-root`, or `require_root`/`--require-root`).

## Incident-response history

Every collect run also writes an **append-only event log** (`flow_events`):
one row when an edge is first seen (`new`) and one when it becomes active again
after being idle (`reactivated`, threshold `event_min_gap_seconds`). This gives
a forensic timeline of "when did host X first talk to Y":

```bash
commatrix history --database /var/lib/commatrix/commatrix.db            # markdown
commatrix history -f jsonl --since-seconds 3600 --kind new              # for SIEM
```

The database and exported snapshots are created `0640` (dir `0750`) so the
network map is not world-readable.

## DNS query logging and DoH posture

When `systemd-resolved` is the active resolver (systemd ≥ 247), commatrix can
log DNS queries via its monitor interface (the same source as `resolvectl
monitor`) — pure stdlib, no packages. It records an append-only DNS log and, by
default, annotates flows with the **domain** each peer IP was resolved from (a
`Domain`/`peer_domain` column alongside the raw IP):

```bash
commatrix dns --database /var/lib/commatrix/commatrix.db          # query log
commatrix dns -f jsonl --qname example.com                        # for SIEM
```

DNS logging needs privileges (resolved subscription); prefer
`commatrix elevate-linux` (polkit for the service user) or
`install.sh --as-root`. It only sees queries via the system resolver — apps
doing their own **DoH/DoT bypass it**.

Check whether DoH is disabled/enforced on the host (so DNS stays visible):

```bash
commatrix doh            # markdown posture report (exit 2 if DoH enabled anywhere)
```

`doh` inspects Chrome/Chromium/Edge managed policies (`DnsOverHttpsMode`),
Firefox enterprise policy (`DNSOverHTTPS`), and systemd-resolved `DNSOverTLS`,
and the posture is also stored in host parameters and surfaced in the HTML
report. "Enforced off" means a locked/managed policy users cannot override.

Beyond posture, commatrix flags flows to **known DoH/DoT resolver endpoints**
(Cloudflare/Google/Quad9/NextDNS/... in `signatures/doh_endpoints.json`) as
`l7=doh:<provider>`/`dot:<provider>` and lists them under "Encrypted DNS to
external resolver" in the security highlights - a DNS blind-spot signal even
when the query content is invisible.

Optionally, enable **SNI capture** (`[sni] enabled = true`, needs root /
CAP_NET_RAW) to recover destination hostnames from the TLS ClientHello even when
DNS is encrypted; the domain enriches the flow's `Domain` column. Encrypted
Client Hello (ECH) hides the SNI (reported as `<ech>`).

## Namespaces, containers and capture quality

With `[capture] netns = auto` (default) and root, commatrix also reads container
and other network namespaces via `/proc/<pid>/net/*`, tagging flows with
`container_id`, `pod` (Kubernetes pod UID from the cgroup) and `netns`. Each
host's report shows a **Capture quality** posture line (`exact` /
`per-socket-tcp` / `topology-only`) so a SOC knows where byte counts are
trustworthy.

## Documentation

- How it works / what it does: [`docs/how-it-works.md`](docs/how-it-works.md)
  (EN), [`docs/jak-funguje-cs.md`](docs/jak-funguje-cs.md) (CS)
- Privilege elevation (Linux + Windows): [`docs/elevation-en.md`](docs/elevation-en.md)
  (EN), [`docs/elevace-cs.md`](docs/elevace-cs.md) (CS)
- Usage & deployment (CS): [`docs/pouziti-cs.md`](docs/pouziti-cs.md)
- Bill of materials: [`SBOM.md`](SBOM.md)
- Packaging & CI (MSI, Docker, Snap, Flatpak, AppImage):
  [`packaging/`](packaging), [`.github/workflows/`](.github/workflows)
- Czech README (primary): [`README.md`](README.md)

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
