#!/usr/bin/env python3
"""Assemble a self-contained SCCM deployment package for Windows.

Builds an output folder with:

    <out>/install.ps1  uninstall.ps1  detect.ps1
    <out>/payload/commatrix.cmd
    <out>/payload/lib/commatrix/...        (the package; stdlib-only)
    <out>/payload/python/python.exe ...    (embedded Python - add manually)

Because commatrix is standard-library only, an embedded Python (the official
"Windows embeddable package" zip) makes the package fully self-contained: no
Python/pip needs to exist on the target servers. Download the embeddable zip for
your Python version and extract it into <out>/payload/python (this script prints
a reminder). Zip <out> and import it into SCCM as a Script Installer application:

    Install program:   powershell -ExecutionPolicy Bypass -File install.ps1
    Uninstall program: powershell -ExecutionPolicy Bypass -File uninstall.ps1
    Detection:         powershell -ExecutionPolicy Bypass -File detect.ps1
    Run mode:          Install for system (SCCM runs it as SYSTEM)

Usage:  python packaging/windows/build_package.py [--out dist/commatrix-win]
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))


def build(out: str) -> None:
    payload = os.path.join(out, "payload")
    lib = os.path.join(payload, "lib")
    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(lib)

    # Package (drop compiled caches).
    shutil.copytree(
        os.path.join(REPO, "commatrix"),
        os.path.join(lib, "commatrix"),
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    # Launcher + SCCM scripts.
    shutil.copy2(os.path.join(HERE, "commatrix.cmd"), os.path.join(payload, "commatrix.cmd"))
    for name in ("install.ps1", "uninstall.ps1", "detect.ps1"):
        shutil.copy2(os.path.join(HERE, name), os.path.join(out, name))

    os.makedirs(os.path.join(payload, "python"), exist_ok=True)
    print(f"Package skeleton written to: {out}")
    print("NEXT: extract the Windows embeddable Python zip into "
          f"{os.path.join(payload, 'python')} (must contain python.exe),")
    print("then zip the folder and import it into SCCM as a Script Installer app.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=os.path.join(REPO, "dist", "commatrix-win"))
    args = ap.parse_args(argv)
    build(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
