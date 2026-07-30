#!/usr/bin/env bash
# install-lab-sudoers.sh — passwordless sudo for commatrix lab scripts.
#
# Installs /etc/sudoers.d/commatrix-lab so lab-commatrix-helper.sh can manage
# nf_conntrack sysctls and run the collector without a password prompt.
#
# Does not install packages or touch the network. Run once interactively as your
# normal user (you will be prompted for your sudo password exactly once).
#
# Usage:
#   ./packaging/install-lab-sudoers.sh          # install for current user
#   ./packaging/install-lab-sudoers.sh --remove # remove commatrix-lab drop-in
#
# After install, test (no password prompt expected):
#   sudo /path/to/appmap/packaging/lab-commatrix-helper.sh setup-conntrack

set -euo pipefail

SUDOERS_FILE="/etc/sudoers.d/commatrix-lab"
LAB_USER="${SUDO_USER:-${USER}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$(cd -- "${SCRIPT_DIR}" && pwd)/lab-commatrix-helper.sh"
INSTALLED_HELPER="/usr/local/lib/commatrix/lab-commatrix-helper.sh"

remove() {
    if [ -f "$SUDOERS_FILE" ]; then
        sudo rm -f "$SUDOERS_FILE"
        echo "Removed ${SUDOERS_FILE}"
    else
        echo "Nothing to remove (${SUDOERS_FILE} not present)"
    fi
    if [ -f "$INSTALLED_HELPER" ]; then
        sudo rm -f "$INSTALLED_HELPER"
        echo "Removed ${INSTALLED_HELPER}"
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

echo "=== commatrix install-lab-sudoers.sh ==="
echo "User:   ${LAB_USER}"
echo "Target: ${SUDOERS_FILE}"
echo "Helper: ${HELPER}"
echo "Target helper: ${INSTALLED_HELPER}"
echo
echo "You will be asked for your sudo password once to install the drop-in."
echo

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# The sudoers grant must point at a root-owned copy. Granting NOPASSWD on a
# script inside the user's own checkout is unconditional root: sudo does not
# check who owns the code it executes, so the grantee can simply rewrite it.
SRC_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
if [ "$(stat -c '%u' "$SRC_ROOT")" -ne 0 ] || [ $(( 8#$(stat -c '%a' "$SRC_ROOT") & 8#0022 )) -ne 0 ]; then
    echo >&2
    echo "ERROR: ${SRC_ROOT} is not root-owned and non-writable by others." >&2
    echo "A passwordless sudo grant that imports Python from a user-writable" >&2
    echo "tree is unconditional root. Move the checkout somewhere root-owned" >&2
    echo "(e.g. /opt/appmap, root:root 0755) or 'sudo pip install .' instead." >&2
    exit 1
fi

echo "Installing a root-owned copy to ${INSTALLED_HELPER}"
sudo install -d -o root -g root -m 0755 "$(dirname "$INSTALLED_HELPER")"
sudo install -o root -g root -m 0755 "$HELPER" "$INSTALLED_HELPER"
sudo sed -i "s|^COMMATRIX_SRC=\"\"|COMMATRIX_SRC=\"${SRC_ROOT}\"|" "$INSTALLED_HELPER"

cat > "$TMP" << EOF
# commatrix lab — nf_conntrack + collector helpers (generated $(date -Iseconds))
# Exact-match allowlist: no wildcards, so no argument passthrough. The helper
# itself refuses to run if it or the source tree is writable by a non-root user.
Cmnd_Alias COMMATRIX_LAB = \\
    ${INSTALLED_HELPER} setup-conntrack, \\
    ${INSTALLED_HELPER} collect, \\
    ${INSTALLED_HELPER} collect-once
${LAB_USER} ALL=(root) NOPASSWD: COMMATRIX_LAB
EOF

sudo cp "$TMP" "$SUDOERS_FILE"
sudo chmod 440 "$SUDOERS_FILE"

if sudo visudo -c -f "$SUDOERS_FILE"; then
    echo
    echo "OK: passwordless sudo installed."
    echo
    echo "Next steps (run from the appmap checkout):"
    echo "  sudo ${HELPER} setup-conntrack"
    echo "  sudo ${HELPER} collect-once --database /tmp/commatrix.db"
    echo "  sudo ${HELPER} collect --database /tmp/commatrix.db --iterations 120"
    echo
    APPMAP_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
    echo "HTML report is written automatically to /tmp/commatrix-report.html"
    echo "Environment log: ${APPMAP_ROOT}/commatrix-lab-env.log"
else
    echo "ERROR: visudo rejected ${SUDOERS_FILE} — removing." >&2
    sudo rm -f "$SUDOERS_FILE"
    exit 1
fi
