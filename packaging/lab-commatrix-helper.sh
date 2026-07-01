#!/usr/bin/env bash
# lab-commatrix-helper.sh — root-only helpers for commatrix lab workflow.
#
# Called via sudo from install-lab-sudoers.sh (passwordless for the lab user).
# Does not install packages or require network access.
#
# Commands:
#   setup-conntrack  — load nf_conntrack module and enable accounting sysctls
#   collect          — run commatrix collect as root (passes remaining args)
#   collect-once     — single poll (passes remaining args)

set -euo pipefail

APPMAP_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

cmd_setup_conntrack() {
    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_conntrack_ipv4 2>/dev/null || true
    modprobe nf_conntrack_ipv6 2>/dev/null || true
    sysctl -w net.netfilter.nf_conntrack_acct=1
    sysctl -w net.netfilter.nf_conntrack_timestamp=1

    if [ -r /proc/net/nf_conntrack ]; then
        echo "setup-conntrack: OK (backend=procfs, /proc/net/nf_conntrack)"
        return 0
    fi
    if command -v conntrack >/dev/null 2>&1; then
        echo "setup-conntrack: OK (backend=conntrack-list; procfs absent, using distro conntrack)"
        return 0
    fi
    if [ -r /proc/net/tcp ]; then
        echo "setup-conntrack: OK (backend=sockets; using /proc/net/{tcp,udp} fallback, no byte counts)"
        return 0
    fi
    echo "setup-conntrack: failed — cannot read /proc/net/tcp" >&2
    return 1
}

cmd_collect() {
    export PYTHONPATH="${APPMAP_ROOT}:${PYTHONPATH:-}"
    exec python3 -m commatrix collect "$@"
}

cmd_collect_once() {
    export PYTHONPATH="${APPMAP_ROOT}:${PYTHONPATH:-}"
    exec python3 -m commatrix collect --once "$@"
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
