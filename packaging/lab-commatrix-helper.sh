#!/usr/bin/env bash
# lab-commatrix-helper.sh — root-only helpers for commatrix lab workflow.
#
# Called via sudo from install-lab-sudoers.sh (passwordless for the lab user).
#
# Commands:
#   setup-conntrack  — enable nf_conntrack byte/timestamp accounting sysctls
#   collect          — run commatrix collect as root (passes remaining args)
#   collect-once     — single poll (passes remaining args after --once)

set -euo pipefail

APPMAP_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

cmd_setup_conntrack() {
    modprobe nf_conntrack 2>/dev/null || true
    sysctl -w net.netfilter.nf_conntrack_acct=1
    sysctl -w net.netfilter.nf_conntrack_timestamp=1
    if [ -r /proc/net/nf_conntrack ]; then
        echo "setup-conntrack: OK (/proc/net/nf_conntrack readable)"
        return 0
    fi
    if ! command -v conntrack >/dev/null 2>&1; then
        echo "setup-conntrack: installing conntrack-tools (procfs unavailable on this kernel)"
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y conntrack
    fi
    if command -v conntrack >/dev/null 2>&1; then
        echo "setup-conntrack: OK (using conntrack -L; /proc/net/nf_conntrack absent)"
        return 0
    fi
    echo "setup-conntrack: failed — neither procfs nor conntrack-tools available" >&2
    return 1
}

APPMAP_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

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
