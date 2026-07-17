#!/usr/bin/env bash
#
# Commatrix service helper.
#
# One-time, run-as-root installer that:
#   1. installs the commatrix collector as a SYSTEM systemd service (root), and
#   2. delegates control of *only that unit* to a normal user, so they can
#      start/stop/restart/inspect it without a root password every time.
#
# Delegation is set up two ways for portability:
#   * a tightly-scoped sudoers drop-in (works everywhere), and
#   * a polkit rule when polkit is present (lets plain `systemctl` work too).
# A convenience wrapper `commatrix-ctl` is installed for the user.
#
# Usage:
#   sudo ./packaging/install-service.sh [--user NAME] [--no-start]
#                                       [--cpu-percent N] [--disk-percent N]
#   sudo ./packaging/install-service.sh --uninstall [--user NAME]
#   ./packaging/install-service.sh --help
#
# If run without root it re-executes itself under sudo. The controlling user
# defaults to $SUDO_USER (the human who invoked sudo); override with --user.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

UNIT="commatrix-collector.service"
SUDOERS_FILE="/etc/sudoers.d/commatrix-control"
POLKIT_FILE="/etc/polkit-1/rules.d/49-commatrix.rules"
CTL="/usr/local/bin/commatrix-ctl"

TARGET_USER=""
UNINSTALL=0
PASS_ARGS=()

log()  { printf '\033[1;32m[commatrix]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[commatrix]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[commatrix]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --user) TARGET_USER="${2:?--user needs a name}"; shift ;;
    --uninstall) UNINSTALL=1 ;;
    --no-start|--cpu-percent|--disk-percent)
      PASS_ARGS+=("$1")
      case "$1" in --cpu-percent|--disk-percent) PASS_ARGS+=("${2:?}"); shift ;; esac
      ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

# --- ensure root (re-exec under sudo, preserving the invoking user) ---------
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "must run as root and sudo is not available"
  log "elevating with sudo..."
  exec sudo -E bash "$0" ${TARGET_USER:+--user "$TARGET_USER"} \
       $([ "$UNINSTALL" -eq 1 ] && echo --uninstall) \
       ${PASS_ARGS[@]+"${PASS_ARGS[@]}"}
fi

# --- resolve the controlling user ------------------------------------------
if [ -z "$TARGET_USER" ]; then
  TARGET_USER="${SUDO_USER:-}"
fi
[ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ] || \
  die "cannot determine a non-root controlling user; pass --user NAME"
id "$TARGET_USER" >/dev/null 2>&1 || die "user '$TARGET_USER' does not exist"

command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) is required"

# --- uninstall --------------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
  log "removing user control delegation"
  rm -f "$SUDOERS_FILE" "$POLKIT_FILE" "$CTL"
  log "uninstalling the service"
  bash "$REPO_DIR/install.sh" --uninstall || warn "install.sh --uninstall reported an error"
  log "done. (config/data left in place by install.sh)"
  exit 0
fi

# --- 1) install the system service -----------------------------------------
log "installing commatrix system service (root)"
bash "$REPO_DIR/install.sh" ${PASS_ARGS[@]+"${PASS_ARGS[@]}"}

# --- 2a) sudoers drop-in: scoped control without a password -----------------
log "granting '$TARGET_USER' password-less control of $UNIT (sudoers)"
SYSTEMCTL_BIN="$(command -v systemctl)"
JOURNALCTL_BIN="$(command -v journalctl || echo /usr/bin/journalctl)"
tmp_sudoers="$(mktemp)"
cat > "$tmp_sudoers" <<EOF
# Installed by commatrix install-service.sh — lets $TARGET_USER control only
# the commatrix collector unit without a password. Safe to remove.
Cmnd_Alias COMMATRIX_CTL = \\
    $SYSTEMCTL_BIN start $UNIT, \\
    $SYSTEMCTL_BIN stop $UNIT, \\
    $SYSTEMCTL_BIN restart $UNIT, \\
    $SYSTEMCTL_BIN reload $UNIT, \\
    $SYSTEMCTL_BIN try-restart $UNIT, \\
    $SYSTEMCTL_BIN enable $UNIT, \\
    $SYSTEMCTL_BIN disable $UNIT, \\
    $SYSTEMCTL_BIN enable --now $UNIT, \\
    $SYSTEMCTL_BIN disable --now $UNIT, \\
    $JOURNALCTL_BIN -u $UNIT *
$TARGET_USER ALL=(root) NOPASSWD: COMMATRIX_CTL
EOF
chmod 0440 "$tmp_sudoers"
# Validate before installing so we never leave a broken sudoers file.
if visudo -cf "$tmp_sudoers" >/dev/null 2>&1; then
  install -m 0440 "$tmp_sudoers" "$SUDOERS_FILE"
  log "installed $SUDOERS_FILE"
else
  rm -f "$tmp_sudoers"
  die "generated sudoers file failed validation; aborting (no changes made)"
fi
rm -f "$tmp_sudoers"

# --- 2b) polkit rule (optional; lets plain `systemctl` work) ----------------
if [ -d /etc/polkit-1/rules.d ]; then
  log "installing polkit rule for '$TARGET_USER' -> $POLKIT_FILE"
  cat > "$POLKIT_FILE" <<EOF
// Installed by commatrix install-service.sh.
// Allow $TARGET_USER to manage ONLY the commatrix collector unit via systemctl.
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.systemd1.manage-units") &&
        (action.lookup("unit") == "$UNIT") &&
        (subject.user == "$TARGET_USER")) {
        return polkit.Result.YES;
    }
});
EOF
  chmod 0644 "$POLKIT_FILE"
else
  warn "polkit not detected; skipping polkit rule (sudoers + commatrix-ctl still work)"
fi

# --- 3) convenience wrapper: commatrix-ctl ----------------------------------
log "installing control wrapper -> $CTL"
cat > "$CTL" <<EOF
#!/usr/bin/env bash
# Control the commatrix collector service without needing root each time.
# Installed by commatrix install-service.sh.
set -euo pipefail
UNIT="$UNIT"
usage() { echo "usage: commatrix-ctl {start|stop|restart|status|enable|disable|logs|follow}"; exit 1; }
cmd="\${1:-}"; shift || true
case "\$cmd" in
  start|stop|restart|enable|disable)  exec sudo -n systemctl "\$cmd" "\$UNIT" ;;
  status)                             exec systemctl --no-pager status "\$UNIT" ;;
  logs)                               exec sudo -n journalctl -u "\$UNIT" --no-pager "\$@" ;;
  follow)                             exec sudo -n journalctl -u "\$UNIT" -f ;;
  *) usage ;;
esac
EOF
chmod 0755 "$CTL"

cat <<EOF

$(log "done.")
The commatrix collector is installed as a SYSTEM service (root) and '$TARGET_USER'
can now control it WITHOUT a root password:

  commatrix-ctl status      # show state
  commatrix-ctl start        # start collecting
  commatrix-ctl stop         # stop (restores nf_conntrack sysctls)
  commatrix-ctl restart
  commatrix-ctl logs         # recent logs
  commatrix-ctl follow       # live logs

Plain 'systemctl start/stop $UNIT' also works for '$TARGET_USER' when polkit is present.
Remove everything with:  sudo $0 --uninstall
EOF
