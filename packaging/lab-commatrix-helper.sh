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

APPMAP_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_LOG="${APPMAP_ROOT}/commatrix-lab-env.log"
ENV_STATE="${APPMAP_ROOT}/.commatrix-lab-env.state"

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

run_collect() {
    local once=0
    if [ "${1:-}" = "--once-internal" ]; then
        once=1
        shift
    fi

    save_environment "collect once=${once} args=$*"
    trap 'restore_environment' EXIT INT TERM

    load_modules
    apply_sysctls
    local backend
    backend="$(detect_backend)"
    log_env "collect starting backend=${backend} once=${once} args=$*"

    export PYTHONPATH="${APPMAP_ROOT}:${PYTHONPATH:-}"
    if [ "$once" -eq 1 ]; then
        python3 -m commatrix collect --once "$@"
    else
        python3 -m commatrix collect "$@"
    fi
}

cmd_collect() {
    run_collect "$@"
}

cmd_collect_once() {
    run_collect --once-internal "$@"
}

usage() {
    echo "Usage: $0 {setup-conntrack|collect|collect-once} [args...]" >&2
    exit 2
}

case "${1:-}" in
    setup-conntrack) shift; cmd_setup_conntrack "$@" ;;
    collect)         shift; cmd_collect "$@" ;;
    collect-once)    shift; cmd_collect_once "$@" ;;
    *)               usage ;;
esac
