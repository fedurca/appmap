#!/usr/bin/env bash
#
# TEST Zabbix agent installer -- for lab / test machines only.
#
# Installs and configures a Zabbix agent pointed at a local (or given) server so
# that commatrix's Zabbix integration can be exercised. NOT hardened for
# production use.
#
# Usage:
#   sudo ./install-zabbix-agent-test.sh [--hostname NAME] [--server IP]
#                                       [--with-commatrix-userparams]
#
set -euo pipefail

HOSTNAME_VALUE="$(hostname)"
SERVER="127.0.0.1"
WITH_UP=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '\033[1;32m[zabbix-test]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[zabbix-test]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[zabbix-test]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --hostname) HOSTNAME_VALUE="${2:?}"; shift ;;
    --server) SERVER="${2:?}"; shift ;;
    --with-commatrix-userparams) WITH_UP=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "must run as root (sudo)"

# --- install the agent via the available package manager ----------------
install_agent() {
  if command -v apt-get >/dev/null 2>&1; then
    log "installing zabbix-agent via apt-get"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y zabbix-agent >/dev/null 2>&1 && return 0
  elif command -v dnf >/dev/null 2>&1; then
    log "installing zabbix-agent via dnf"
    dnf install -y zabbix-agent >/dev/null 2>&1 && return 0
  elif command -v yum >/dev/null 2>&1; then
    log "installing zabbix-agent via yum"
    yum install -y zabbix-agent >/dev/null 2>&1 && return 0
  elif command -v zypper >/dev/null 2>&1; then
    log "installing zabbix-agent via zypper"
    zypper --non-interactive install zabbix-agent >/dev/null 2>&1 && return 0
  elif command -v apk >/dev/null 2>&1; then
    log "installing zabbix-agent via apk"
    apk add --no-cache zabbix-agentd >/dev/null 2>&1 && return 0
  fi
  return 1
}

if command -v zabbix_agentd >/dev/null 2>&1 || command -v zabbix_agent2 >/dev/null 2>&1; then
  log "a Zabbix agent is already installed"
elif ! install_agent; then
  warn "could not install a Zabbix agent from distro repositories."
  warn "On a real lab machine add the Zabbix repo first (https://www.zabbix.com/download)."
  die  "aborting: no agent available"
fi

# --- write a minimal test config ----------------------------------------
CONF_DIR=""
CONF_FILE=""
INCLUDE_DIR=""
if [ -f /etc/zabbix/zabbix_agentd.conf ]; then
  CONF_FILE=/etc/zabbix/zabbix_agentd.conf
  INCLUDE_DIR=/etc/zabbix/zabbix_agentd.d
elif [ -f /etc/zabbix/zabbix_agent2.conf ]; then
  CONF_FILE=/etc/zabbix/zabbix_agent2.conf
  INCLUDE_DIR=/etc/zabbix/zabbix_agent2.d
else
  die "installed agent but no config file found under /etc/zabbix"
fi
CONF_DIR="$(dirname "$CONF_FILE")"
mkdir -p "$INCLUDE_DIR"

log "writing test config to $CONF_FILE (Hostname=$HOSTNAME_VALUE, Server=$SERVER)"
# Preserve the original once.
[ -f "$CONF_FILE.commatrix.bak" ] || cp "$CONF_FILE" "$CONF_FILE.commatrix.bak"

set_kv() { # key value file
  local key="$1" val="$2" file="$3"
  if grep -Eq "^\s*${key}=" "$file"; then
    sed -i -E "s#^\s*${key}=.*#${key}=${val}#" "$file"
  elif grep -Eq "^\s*#\s*${key}=" "$file"; then
    sed -i -E "0,/^\s*#\s*${key}=.*/s##${key}=${val}#" "$file"
  else
    printf '%s=%s\n' "$key" "$val" >> "$file"
  fi
}

set_kv Hostname "$HOSTNAME_VALUE" "$CONF_FILE"
set_kv Server "$SERVER" "$CONF_FILE"
set_kv ServerActive "$SERVER" "$CONF_FILE"
if ! grep -Eq "^\s*Include=.*$(basename "$INCLUDE_DIR")" "$CONF_FILE"; then
  printf 'Include=%s/*.conf\n' "$INCLUDE_DIR" >> "$CONF_FILE"
fi

# --- optional: commatrix userparameters ---------------------------------
if [ "$WITH_UP" -eq 1 ] && [ -f "$SCRIPT_DIR/zabbix_userparameter.conf" ]; then
  log "installing commatrix UserParameters into $INCLUDE_DIR"
  cp "$SCRIPT_DIR/zabbix_userparameter.conf" "$INCLUDE_DIR/commatrix.conf"
fi

# --- start / enable ------------------------------------------------------
SERVICE=zabbix-agent
systemctl list-unit-files 2>/dev/null | grep -q '^zabbix-agent2' && SERVICE=zabbix-agent2
if command -v systemctl >/dev/null 2>&1; then
  log "enabling and starting $SERVICE"
  systemctl enable --now "$SERVICE" 2>/dev/null || warn "could not start $SERVICE via systemd"
  systemctl restart "$SERVICE" 2>/dev/null || true
fi

# --- smoke test ----------------------------------------------------------
if command -v zabbix_get >/dev/null 2>&1; then
  sleep 1
  log "smoke test: zabbix_get agent.ping ->"
  zabbix_get -s 127.0.0.1 -k agent.ping || warn "agent.ping failed (agent may still be starting)"
else
  warn "zabbix_get not installed; skipping smoke test (install zabbix-get to test queries)"
fi

log "done. Test host parameters with: commatrix hostparams"
