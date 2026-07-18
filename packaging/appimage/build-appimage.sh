#!/usr/bin/env bash
#
# Build a portable AppImage bundling CPython + commatrix (standard-library only).
# Runs as the invoking user; privileged capture needs sudo. Intended for CI
# (ubuntu, FUSE available) but runnable locally with python-appimage installed.
#
#   packaging/appimage/build-appimage.sh [VERSION]
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VERSION="${1:-$(python3 "$REPO/packaging/version.py" get)}"
PYVER="${PYVER:-3.12}"

cd "$REPO"

# 1) Build the wheel so python-appimage can install 'commatrix' from it.
python3 -m pip install --upgrade build python-appimage >/dev/null
python3 -m build --wheel >/dev/null

# 2) Generate a simple icon if none is committed (valid 64x64 PNG via stdlib).
if [ ! -f "$HERE/commatrix.png" ]; then
  python3 - "$HERE/commatrix.png" <<'PY'
import struct, zlib, sys
w = h = 64
raw = bytearray()
for y in range(h):
    raw.append(0)  # filter type 0
    for x in range(w):
        raw += bytes((37, 99, 235))  # solid brand blue
def chunk(tag, data):
    c = tag + data
    return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
png = b"\x89PNG\r\n\x1a\n"
png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
png += chunk(b"IEND", b"")
open(sys.argv[1], "wb").write(png)
PY
fi

# 3) Build the AppImage (installs the local wheel via find-links).
export PIP_FIND_LINKS="$REPO/dist"
python3 -m python_appimage build app -p "$PYVER" "$HERE"

# python-appimage emits <name>-<pyver>-<arch>.AppImage; normalize the name.
built="$(ls -t ./*.AppImage | head -1)"
out="commatrix-${VERSION}-x86_64.AppImage"
mv "$built" "$out"
echo "built $out"
