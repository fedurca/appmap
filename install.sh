#!/usr/bin/env bash
#
# Commatrix installer.
#
# Installs the commatrix collector as a systemd service with strict resource
# limits (<=10% of total compute, DB <=10% of free disk). Standard-library
# only, so "installing" is just copying the package and wiring up systemd.
#
# Modes:
#   sudo ./install.sh                 # system-wide (root), systemd system unit
#   ./install.sh --user               # per-user, systemd --user unit (for labs)
#   ./install.sh --uninstall [--user] # remove
#
# Options:
#   --user            install into $HOME (no root needed; capture still needs root)
#   --uninstall       remove a previous installation
#   --no-start        install but do not enable/start the service
#   --cpu-percent N   CPU budget as % of TOTAL compute (default 10)
#   --disk-percent N  disk budget as % of free space (default 10)
#   --help
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

USER_MODE=0
UNINSTALL=0
NO_START=0
CPU_PERCENT=10
DISK_PERCENT=10

log()  { printf '\033[1;32m[commatrix]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[commatrix]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[commatrix]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --user) USER_MODE=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --no-start) NO_START=1 ;;
    --cpu-percent) CPU_PERCENT="${2:?}"; shift ;;
    --disk-percent) DISK_PERCENT="${2:?}"; shift ;;
    -h|--help)
      sed -n '2,25p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

# --- resolve python ------------------------------------------------------
PYTHON="$(command -v python3 || true)"
[ -n "$PYTHON" ] || die "python3 not found (Python 3.9+ required)"
"$PYTHON" - <<'PY' || die "Python 3.9+ required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 9) else 1)
PY

# --- compute layout ------------------------------------------------------
if [ "$USER_MODE" -eq 1 ]; then
  LIBROOT="$HOME/.local/lib/commatrix"
  BINDIR="$HOME/.local/bin"
  CONFDIR="$HOME/.config/commatrix"
  UNITDIR="$HOME/.config/systemd/user"
  STATEDIR="$HOME/.local/state/commatrix"
  SYSTEMCTL=(systemctl --user)
else
  [ "$(id -u)" -eq 0 ] || die "system install requires root (use sudo, or pass --user)"
  LIBROOT="/usr/lib/commatrix"
  BINDIR="/usr/bin"
  CONFDIR="/etc/commatrix"
  UNITDIR="/etc/systemd/system"
  STATEDIR="/var/lib/commatrix"
  SYSTEMCTL=(systemctl)
fi

DB_PATH="$STATEDIR/commatrix.db"
SNAP_DIR="$STATEDIR/snapshots"
WRAPPER="$BINDIR/commatrix"
CONF="$CONFDIR/commatrix.conf"

have_systemd() { command -v systemctl >/dev/null 2>&1; }

# --- uninstall -----------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
  log "uninstalling (mode: $([ "$USER_MODE" -eq 1 ] && echo user || echo system))"
  if have_systemd; then
    "${SYSTEMCTL[@]}" disable --now commatrix-collector.service 2>/dev/null || true
  fi
  rm -f "$UNITDIR/commatrix-collector.service"
  rm -rf "$UNITDIR/commatrix-collector.service.d"
  rm -f "$WRAPPER"
  rm -rf "$LIBROOT"
  [ "$USER_MODE" -eq 0 ] && rm -f /etc/sysctl.d/99-commatrix-conntrack.conf || true
  have_systemd && "${SYSTEMCTL[@]}" daemon-reload 2>/dev/null || true
  warn "left config ($CONFDIR) and data ($STATEDIR) in place; remove manually if desired"
  log "uninstalled."
  exit 0
fi

# --- install package -----------------------------------------------------
log "installing commatrix package -> $LIBROOT"
mkdir -p "$LIBROOT" "$BINDIR" "$CONFDIR" "$STATEDIR" "$SNAP_DIR"
rm -rf "$LIBROOT/commatrix"
cp -r "$SCRIPT_DIR/commatrix" "$LIBROOT/commatrix"
# Drop compiled caches.
find "$LIBROOT/commatrix" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

log "installing wrapper -> $WRAPPER"
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
exec env PYTHONPATH="$LIBROOT\${PYTHONPATH:+:\$PYTHONPATH}" "$PYTHON" -m commatrix "\$@"
EOF
chmod +x "$WRAPPER"

# --- config --------------------------------------------------------------
if [ ! -f "$CONF" ]; then
  log "installing config -> $CONF"
  cp "$SCRIPT_DIR/packaging/commatrix.conf.example" "$CONF"
  # Point at the mode-appropriate paths and budgets.
  "$PYTHON" - "$CONF" "$DB_PATH" "$SNAP_DIR" "$CPU_PERCENT" "$DISK_PERCENT" <<'PY'
import re, sys
conf, db, snap, cpu, disk = sys.argv[1:6]
text = open(conf).read()
text = re.sub(r'(?m)^database\s*=.*$', f'database = {db}', text)
text = re.sub(r'(?m)^snapshot_dir\s*=.*$', f'snapshot_dir = {snap}', text)
text = re.sub(r'(?m)^cpu_budget_percent\s*=.*$', f'cpu_budget_percent = {cpu}', text)
text = re.sub(r'(?m)^disk_budget_percent\s*=.*$', f'disk_budget_percent = {disk}', text)
open(conf, 'w').write(text)
PY
else
  warn "config already exists at $CONF (left unchanged)"
fi

# --- sysctls (system mode only) -----------------------------------------
if [ "$USER_MODE" -eq 0 ]; then
  log "enabling nf_conntrack accounting + timestamps (sysctl)"
  cat > /etc/sysctl.d/99-commatrix-conntrack.conf <<'EOF'
# Required by commatrix for byte/packet accounting and flow timestamps.
net.netfilter.nf_conntrack_acct = 1
net.netfilter.nf_conntrack_timestamp = 1
EOF
  sysctl -p /etc/sysctl.d/99-commatrix-conntrack.conf >/dev/null 2>&1 || \
    warn "could not apply sysctls now (nf_conntrack module may load later)"
fi

# --- systemd unit + resource drop-in ------------------------------------
CORES="$(nproc 2>/dev/null || echo 1)"
TOTAL_QUOTA=$(( CPU_PERCENT * CORES ))   # 10% of total compute across all cores
MEM_MB="$("$PYTHON" - "$CONF" <<'PY'
import configparser, sys
c = configparser.ConfigParser(); c.read(sys.argv[1])
print(c.get('resources', 'memory_max_mb', fallback='128'))
PY
)"

install_unit() {
  local src="$SCRIPT_DIR/systemd/commatrix-collector.service"
  local dst="$UNITDIR/commatrix-collector.service"
  log "installing systemd unit -> $dst"
  mkdir -p "$UNITDIR"
  # Rewrite ExecStart to use the installed wrapper and config.
  sed \
    -e "s#^ExecStart=.*#ExecStart=$WRAPPER collect --config $CONF#" \
    "$src" > "$dst"

  if [ "$USER_MODE" -eq 1 ]; then
    # User services can't set sysctls, run as root, or use system protections.
    sed -i \
      -e '/^ExecStartPre=/d' \
      -e '/^User=/d' \
      -e '/^ProtectHome=/d' \
      -e '/^ProtectControlGroups=/d' \
      -e '/^ProtectKernelTunables=/d' \
      -e '/^StateDirectory=/d' \
      -e '/^RuntimeDirectory=/d' \
      -e '/^\[Install\]/,$d' \
      "$dst"
    printf '\n[Install]\nWantedBy=default.target\n' >> "$dst"
  fi

  # Resource drop-in: 10% of TOTAL compute + memory ceiling.
  mkdir -p "$dst.d"
  cat > "$dst.d/resources.conf" <<EOF
[Service]
# ${CPU_PERCENT}% of total compute across ${CORES} core(s).
CPUQuota=${TOTAL_QUOTA}%
MemoryMax=${MEM_MB}M
MemoryHigh=$(( MEM_MB * 3 / 4 ))M
EOF
  log "resource limits: CPUQuota=${TOTAL_QUOTA}% (=${CPU_PERCENT}% of ${CORES} cores), MemoryMax=${MEM_MB}M"
}

# --- zabbix userparameters (system mode, if agent present) --------------
if [ "$USER_MODE" -eq 0 ]; then
  for zdir in /etc/zabbix/zabbix_agentd.d /etc/zabbix/zabbix_agent2.d; do
    if [ -d "$zdir" ]; then
      log "installing Zabbix UserParameters -> $zdir/commatrix.conf"
      sed "s#/usr/bin/commatrix#$WRAPPER#g" \
        "$SCRIPT_DIR/packaging/zabbix_userparameter.conf" > "$zdir/commatrix.conf"
    fi
  done
fi

# --- enable & start ------------------------------------------------------
if have_systemd; then
  install_unit
  "${SYSTEMCTL[@]}" daemon-reload 2>/dev/null || warn "daemon-reload failed (no systemd session bus?)"
  if [ "$NO_START" -eq 0 ]; then
    log "enabling and starting commatrix-collector.service"
    if "${SYSTEMCTL[@]}" enable --now commatrix-collector.service 2>/dev/null; then
      "${SYSTEMCTL[@]}" --no-pager status commatrix-collector.service 2>/dev/null | head -n 8 || true
    else
      warn "could not enable/start service (no systemd session bus?); start manually later"
    fi
  else
    log "installed (not started; --no-start)"
  fi
else
  warn "systemd not detected; run the collector manually: $WRAPPER collect --config $CONF"
fi

log "done. Try:  $WRAPPER report -f markdown  (after some collection)"
