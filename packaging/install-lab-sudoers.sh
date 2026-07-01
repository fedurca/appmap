#!/usr/bin/env bash
# install-lab-sudoers.sh — passwordless sudo for commatrix lab scripts.
#
# Installs /etc/sudoers.d/commatrix-lab so lab-commatrix-helper.sh can manage
# nf_conntrack sysctls and run the collector without a password prompt.
#
# Usage:
#   ./install-lab-sudoers.sh          # install for current user
#   ./install-lab-sudoers.sh --remove # remove commatrix-lab sudoers drop-in

set -euo pipefail

SUDOERS_FILE="/etc/sudoers.d/commatrix-lab"
LAB_USER="${SUDO_USER:-${USER}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HELPER="${SCRIPT_DIR}/lab-commatrix-helper.sh"

remove() {
    if [ -f "$SUDOERS_FILE" ]; then
        sudo rm -f "$SUDOERS_FILE"
        echo "Removed ${SUDOERS_FILE}"
    else
        echo "Nothing to remove (${SUDOERS_FILE} not present)"
    fi
}

if [ "${1:-}" = "--remove" ]; then
    remove
    exit 0
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "Run as your normal user (not root); the script will call sudo once." >&2
    exit 1
fi

if [ ! -f "$HELPER" ]; then
    echo "ERROR: lab-commatrix-helper.sh not found at ${HELPER}" >&2
    exit 1
fi
chmod +x "$HELPER"

echo "=== install-lab-sudoers.sh ==="
echo "User: ${LAB_USER}"
echo "Target: ${SUDOERS_FILE}"
echo "Helper: ${HELPER}"
echo

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" << EOF
# commatrix lab — nf_conntrack + collector helpers (generated $(date -Iseconds))
${LAB_USER} ALL=(root) NOPASSWD: ${HELPER}
EOF

sudo cp "$TMP" "$SUDOERS_FILE"
sudo chmod 440 "$SUDOERS_FILE"

if sudo visudo -c -f "$SUDOERS_FILE"; then
    echo
    echo "OK: passwordless sudo installed for ${HELPER}"
    echo "Test: sudo ${HELPER} setup-conntrack"
else
    echo "ERROR: visudo rejected ${SUDOERS_FILE} — removing." >&2
    sudo rm -f "$SUDOERS_FILE"
    exit 1
fi
