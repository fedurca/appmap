#!/usr/bin/env bash
# lab-commatrix-helper.sh — root-only helpers for commatrix lab workflow.
#
# Called via sudo from install-lab-sudoers.sh (passwordless for the lab user).
# Does not install packages or require network access.
#
# collect / collect-once save sysctl state, apply lab settings for the run,
# then restore previous values on exit. All changes are logged to
# ${APPMAP_ROOT}/commatrix-lab-env.log.
#
# Commands:
#   setup-conntrack  — load nf_conntrack modules and enable accounting sysctls
#                      (does not restore; use collect* for save/restore)
#   collect          — run commatrix collect as root (passes remaining args)
#   collect-once     — single poll (passes remaining args)

set -euo pipefail

# Rewritten by install-lab-sudoers.sh in the installed root-owned copy. Empty
# means "run from the checkout" (developer use, not via sudo).
COMMATRIX_SRC=""
APPMAP_ROOT="${COMMATRIX_SRC:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"

# State and logs live under /var/lib, never next to the code: the code
# directory must stay root-owned and non-writable (see require_root_owned).
STATE_DIR="/var/lib/commatrix"
ENV_LOG="${STATE_DIR}/commatrix-lab-env.log"
ENV_STATE="${STATE_DIR}/.commatrix-lab-env.state"
mkdir -p "$STATE_DIR" 2>/dev/null || true

SYSCTL_KEYS=(
    net.netfilter.nf_conntrack_acct
    net.netfilter.nf_conntrack_timestamp
)

log_env() {
    printf '[%s] %s\n' "$(date -Iseconds)" "$*" >> "$ENV_LOG"
}

read_sysctl_value() {
    local key="$1"
    local val
    if val="$(sysctl -n "$key" 2>/dev/null)"; then
        printf '%s' "$val"
        return 0
    fi
    printf '__missing__'
}

save_environment() {
    local label="${1:-collect}"
    local key val
    : > "$ENV_STATE"
    log_env "=== session start (pid=$$, user=${SUDO_USER:-root}, ${label}) ==="
    for key in "${SYSCTL_KEYS[@]}"; do
        val="$(read_sysctl_value "$key")"
        printf '%s=%s\n' "$key" "$val" >> "$ENV_STATE"
        log_env "saved ${key}=${val}"
    done
}

load_modules() {
    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_conntrack_ipv4 2>/dev/null || true
    modprobe nf_conntrack_ipv6 2>/dev/null || true
    log_env "loaded nf_conntrack kernel modules (if available)"
}

apply_sysctls() {
    local key old new
    for key in "${SYSCTL_KEYS[@]}"; do
        old="$(read_sysctl_value "$key")"
        new="1"
        if [ "$old" = "$new" ]; then
            log_env "unchanged ${key}=${old}"
            continue
        fi
        if sysctl -w "${key}=${new}" >/dev/null 2>&1; then
            log_env "changed ${key}: ${old} -> ${new}"
        else
            log_env "WARN failed to set ${key}=${new} (was ${old})"
        fi
    done
}

restore_environment() {
    local key val old current
    if [ ! -f "$ENV_STATE" ]; then
        return 0
    fi
    log_env "--- restoring environment ---"
    while IFS='=' read -r key val; do
        [ -n "$key" ] || continue
        current="$(read_sysctl_value "$key")"
        if [ "$val" = "__missing__" ]; then
            log_env "skip restore ${key} (was not present before run; now ${current})"
            continue
        fi
        if [ "$current" = "$val" ]; then
            log_env "already ${key}=${val}"
            continue
        fi
        if sysctl -w "${key}=${val}" >/dev/null 2>&1; then
            log_env "restored ${key}: ${current} -> ${val}"
        else
            log_env "WARN failed to restore ${key}=${val} (currently ${current})"
        fi
    done < "$ENV_STATE"
    rm -f "$ENV_STATE"
    log_env "=== session end (pid=$$) ==="
}

detect_backend() {
    if [ -r /proc/net/nf_conntrack ]; then
        echo "procfs"
    elif command -v conntrack >/dev/null 2>&1; then
        echo "conntrack-list"
    elif [ -r /proc/net/tcp ]; then
        echo "sockets"
    else
        echo "none"
    fi
}

cmd_setup_conntrack() {
    log_env "=== setup-conntrack (no automatic restore) ==="
    load_modules
    apply_sysctls
    local backend
    backend="$(detect_backend)"
    case "$backend" in
        procfs)
            echo "setup-conntrack: OK (backend=procfs, /proc/net/nf_conntrack)"
            log_env "setup OK backend=procfs"
            ;;
        conntrack-list)
            echo "setup-conntrack: OK (backend=conntrack-list; procfs absent, using distro conntrack)"
            log_env "setup OK backend=conntrack-list"
            ;;
        sockets)
            echo "setup-conntrack: OK (backend=sockets; using /proc/net/{tcp,udp} fallback, no byte counts)"
            log_env "setup OK backend=sockets"
            ;;
        *)
            echo "setup-conntrack: failed — cannot read /proc/net/tcp" >&2
            log_env "setup FAILED backend=none"
            return 1
            ;;
    esac
}

# Root-owned, fixed locations. Never taken from the caller: this script runs
# as root via a passwordless sudo grant, and `commatrix collect --config <ini>`
# would honour an attacker-supplied INI whose zabbix_get key is executed as
# root, while --database is an arbitrary root-owned file write.
LAB_CONF="/etc/commatrix/commatrix.conf"
LAB_DB="/var/lib/commatrix/commatrix.db"

require_root_owned() {
    # sudo does not check who owns the code it runs. If this script, or the
    # tree we add to PYTHONPATH, is writable by a non-root user, then the
    # sudoers grant is unconditional root for that user regardless of how
    # carefully the arguments below are handled.
    local path="$1" label="$2" owner perms
    owner="$(stat -c '%u' "$path")"
    perms="$(stat -c '%a' "$path")"
    if [ "$owner" -ne 0 ]; then
        echo "refusing to run: ${label} (${path}) is not owned by root" >&2
        echo "install it to a root-owned path first (see install-lab-sudoers.sh)" >&2
        exit 3
    fi
    if [ $(( 8#$perms & 8#0022 )) -ne 0 ]; then
        echo "refusing to run: ${label} (${path}) is group- or world-writable" >&2
        exit 3
    fi
}

run_collect() {
    local once="$1"

    require_root_owned "${BASH_SOURCE[0]}" "helper script"
    require_root_owned "${APPMAP_ROOT}" "commatrix source tree"

    save_environment "collect once=${once}"
    trap 'restore_environment' EXIT INT TERM

    load_modules
    apply_sysctls
    local backend
    backend="$(detect_backend)"
    log_env "collect starting backend=${backend} once=${once}"

    export PYTHONPATH="${APPMAP_ROOT}:${PYTHONPATH:-}"
    if [ "$once" -eq 1 ]; then
        python3 -m commatrix collect --once --config "$LAB_CONF" --database "$LAB_DB"
    else
        python3 -m commatrix collect --config "$LAB_CONF" --database "$LAB_DB"
    fi
}

usage() {
    echo "Usage: $0 {setup-conntrack|collect|collect-once}" >&2
    echo "Takes no further arguments; config and database are fixed to" >&2
    echo "  ${LAB_CONF} / ${LAB_DB}" >&2
    exit 2
}

# No argument passthrough: the sudoers grant is an exact-match allowlist and
# anything beyond the subcommand is rejected here as well.
[ "$#" -eq 1 ] || usage

case "$1" in
    setup-conntrack) cmd_setup_conntrack ;;
    collect)         run_collect 0 ;;
    collect-once)    run_collect 1 ;;
    *)               usage ;;
esac
