#!/usr/bin/env bash
#
# Install commatrix as a systemd service running as root with full privileges.
#
#   sudo ./install.sh
#   sudo ./install.sh --no-start
#   sudo ./install.sh --uninstall
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UNINSTALL=0
NO_START=0
CPU_PERCENT=10
DISK_PERCENT=10

log()  { printf '\033[1;32m[commatrix]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[commatrix]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[commatrix]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --uninstall) UNINSTALL=1 ;;
    --no-start) NO_START=1 ;;
    --cpu-percent) CPU_PERCENT="${2:?}"; shift ;;
    --disk-percent) DISK_PERCENT="${2:?}"; shift ;;
    --user|--as-root)
      warn "ignored obsolete option $1 (always installs as root)" ;;
    -h|--help)
      sed -n '2,10p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "install requires root (sudo ./install.sh)"

PYTHON="$(command -v python3 || true)"
[ -n "$PYTHON" ] || die "python3 not found (Python 3.9+ required)"

LIBROOT="/usr/lib/commatrix"
BINDIR="/usr/bin"
CONFDIR="/etc/commatrix"
UNITDIR="/etc/systemd/system"
STATEDIR="/var/lib/commatrix"
DB_PATH="$STATEDIR/commatrix.db"
SNAP_DIR="$STATEDIR/snapshots"
WRAPPER="$BINDIR/commatrix"
CONF="$CONFDIR/commatrix.conf"

have_systemd() { command -v systemctl >/dev/null 2>&1; }

if [ "$UNINSTALL" -eq 1 ]; then
  log "uninstalling"
  if have_systemd; then
    systemctl disable --now commatrix-collector.service 2>/dev/null || true
    systemctl disable --now commatrix-server.service 2>/dev/null || true
  fi
  rm -f "$UNITDIR/commatrix-collector.service"
  rm -rf "$UNITDIR/commatrix-collector.service.d"
  rm -f "$WRAPPER"
  rm -rf "$LIBROOT"
  have_systemd && systemctl daemon-reload 2>/dev/null || true
  warn "left config ($CONFDIR) and data ($STATEDIR) in place"
  log "uninstalled."
  exit 0
fi

log "installing package -> $LIBROOT"
mkdir -p "$LIBROOT" "$BINDIR" "$CONFDIR" "$STATEDIR" "$SNAP_DIR"
rm -rf "$LIBROOT/commatrix"
cp -r "$SCRIPT_DIR/commatrix" "$LIBROOT/commatrix"
find "$LIBROOT/commatrix" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
exec env PYTHONPATH="$LIBROOT\${PYTHONPATH:+:\$PYTHONPATH}" "$PYTHON" -m commatrix "\$@"
EOF
chmod +x "$WRAPPER"

if [ ! -f "$CONF" ]; then
  log "installing config -> $CONF"
  cp "$SCRIPT_DIR/packaging/commatrix.conf.example" "$CONF"
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

if have_systemd; then
  dst="$UNITDIR/commatrix-collector.service"
  log "installing systemd unit -> $dst"
  sed \
    -e "s#^ExecStart=.*#ExecStart=$WRAPPER collect --config $CONF#" \
    -e "s#^ExecStopPost=.*#ExecStopPost=$WRAPPER restore-sysctls --config $CONF#" \
    "$SCRIPT_DIR/systemd/commatrix-collector.service" > "$dst"
  systemctl daemon-reload 2>/dev/null || warn "daemon-reload failed"
  if [ "$NO_START" -eq 0 ]; then
    log "enabling and starting commatrix-collector.service"
    systemctl enable --now commatrix-collector.service 2>/dev/null \
      || warn "could not enable/start service"
  else
    log "installed (not started; --no-start)"
  fi
else
  warn "systemd not detected; run: $WRAPPER collect --config $CONF --allow-manual"
fi

log "done. Collector runs as root with full privileges."
