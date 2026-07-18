# Privilege elevation (Linux and Windows)

Extended description of `elevate-linux` and `elevate-windows`. Goal: **maximum
capture without running as root/Administrator**, and **without opening a path to
obtain root** (no sudoers, setuid, CAP_SETUID/CAP_SYS_ADMIN, Administrators
membership, or SeImpersonatePrivilege).

Related: [README (EN)](../README.en.md) · [Česky](elevace-cs.md)

---

## Three run modes

| Mode | Linux | Windows | What you get |
|---|---|---|---|
| **1. As user** | normal user / unit without extra caps | normal user | topology, limited attribution |
| **2. Elevated** | `elevate-linux` on account `commatrix` | `elevate-windows` on account `commatrix` | near-full capture without root/Admin |
| **3. Administrator / root** | `install.sh --as-root` | `install-windows` (SYSTEM) | maximum, including reliable SNI |

Elevation applies to a **dedicated service account** (nologin), not your
interactive login. Running the elevate command itself still requires root/Admin
once for setup.

---

## Linux: `elevate-linux`

```bash
sudo commatrix elevate-linux              # grant
sudo commatrix elevate-linux --dry-run    # preview
sudo commatrix elevate-linux --revoke     # restore
```

### What it configures

1. **Systemd drop-in**  
   `/etc/systemd/system/commatrix-collector.service.d/60-elevate.conf`

   - `User=commatrix` / `Group=commatrix`
   - AmbientCapabilities / CapabilityBoundingSet:
     - `CAP_DAC_READ_SEARCH` — conntrack and other users' `/proc/<pid>/fd`
     - `CAP_NET_ADMIN` — nf_conntrack sysctls, event netlink
     - `CAP_NET_RAW` — SNI via AF_PACKET
     - `CAP_SYS_PTRACE` — netns / containers via `/proc/<pid>/net`
   - `NoNewPrivileges=true`

2. **Polkit**  
   `/etc/polkit-1/rules.d/50-commatrix-resolved.rules`  
   narrow grant for user `commatrix` on `org.freedesktop.resolve1.*`
   (DNS monitor without euid 0).

3. **State**  
   `/var/lib/commatrix/elevate-state.json` — previous drop-in/polkit for revoke.
   `install.sh --uninstall` calls revoke automatically.

### Feature → privilege

| Feature | Needs | After elevate-linux |
|---|---|---|
| Topology | — | yes |
| Byte accounting (conntrack) | CAP_NET_ADMIN (+ acct sysctl) | yes |
| Other users' processes | CAP_DAC_READ_SEARCH | yes |
| Event-driven conntrack | CAP_NET_ADMIN | yes |
| DNS query log | polkit / root | yes (polkit) |
| SNI (AF_PACKET) | CAP_NET_RAW | yes |
| Netns / containers | CAP_SYS_PTRACE | yes |

### What elevate-linux deliberately does not do

- sudoers / passwordless sudo
- setuid on Python
- `CAP_SETUID`, `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`
- interactive shell for `commatrix` (nologin)

---

## Windows: `elevate-windows`

```powershell
# as Administrator, after install-windows
python -m commatrix elevate-windows
python -m commatrix elevate-windows --dry-run
python -m commatrix elevate-windows --revoke
```

### What it configures

1. Local account **`commatrix`** (not Administrators); password is rotated for
   task binding (never stored in the state file).
2. **Event Log Readers** group + enable
   `Microsoft-Windows-DNS-Client/Operational`.
3. **SeDebugPrivilege** for this account only (cross-process attribution) when
   `ntrights` is available; otherwise a warning and manual Local Security Policy.
4. ACL on `%ProgramData%\commatrix`: SYSTEM + `commatrix`.
5. Scheduled task rebound from SYSTEM to `commatrix` with `/rl limited`.
6. State: `%ProgramData%\commatrix\elevate-state.json`.  
   `uninstall-windows` calls revoke automatically.

### Feature → privilege

| Feature | Needs | After elevate-windows |
|---|---|---|
| Topology (IP Helper) | — | yes |
| Byte counts (ESTATS) | — (best-effort) | yes |
| Other processes (image path) | SeDebugPrivilege | yes (if grant succeeds) |
| DNS log | Event Log Readers + channel | yes |
| DoH posture (read) | — | yes |
| SNI (`SIO_RCVALL`) | Administrator / SYSTEM | **no** — remains mode 3 |

### What elevate-windows deliberately does not do

- **Administrators** membership
- `SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege`
- promising SNI without Admin/SYSTEM

---

## Revoke and uninstall

| Action | Linux | Windows |
|---|---|---|
| Manual revoke | `elevate-linux --revoke` | `elevate-windows --revoke` |
| On uninstall | `install.sh --uninstall` | `uninstall-windows` |

Revoke restores the previous drop-in/polkit (Linux) or SYSTEM task (Windows)
from the state file and deletes the state.

---

## Security note

Ambient capabilities / SeDebugPrivilege on a **non-login service account** are
safer than running as root/SYSTEM, but still allow reading sensitive network and
process data. Operators (SOC) must approve the deployment. Elevation is
**least-privilege collection**, not a bypass of corporate privileged access.
