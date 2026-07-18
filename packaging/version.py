#!/usr/bin/env python3
"""Single source of truth for the commatrix version (standard library only).

The version lives in two places - ``pyproject.toml`` and ``commatrix/__init__.py``
- and CI keeps them in sync from the git tag. Usage:

    python packaging/version.py get                 # print current version
    python packaging/version.py set 1.2.3           # write 1.2.3 to both files
    python packaging/version.py from-git            # derive + write from the tag

``from-git`` uses the ``vX.Y.Z`` tag (from ``GITHUB_REF`` or ``git describe``);
off a tag it produces a dev version ``0.0.0+<shortsha>`` so untagged builds are
clearly marked and never collide with a release.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PYPROJECT = os.path.join(REPO, "pyproject.toml")
INIT = os.path.join(REPO, "commatrix", "__init__.py")

_INIT_RE = re.compile(r'^(__version__\s*=\s*)"[^"]*"', re.MULTILINE)
_PYPROJECT_RE = re.compile(r'^(version\s*=\s*)"[^"]*"', re.MULTILINE)
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+")


def get() -> str:
    with open(INIT, encoding="utf-8") as fh:
        m = re.search(r'__version__\s*=\s*"([^"]*)"', fh.read())
    return m.group(1) if m else "0.0.0"


def _sub_file(path: str, pattern: re.Pattern, version: str) -> None:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    new = pattern.sub(lambda mm: f'{mm.group(1)}"{version}"', text, count=1)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new)


def set_version(version: str) -> None:
    version = version.lstrip("v").strip()
    if not version:
        raise SystemExit("empty version")
    _sub_file(INIT, _INIT_RE, version)
    _sub_file(PYPROJECT, _PYPROJECT_RE, version)


def _from_git() -> str:
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/"):
        tag = ref[len("refs/tags/"):]
        if _SEMVER_RE.match(tag.lstrip("v")):
            return tag.lstrip("v")
    try:
        desc = subprocess.run(["git", "describe", "--tags", "--always", "--dirty"],
                              capture_output=True, text=True, cwd=REPO, check=False)
        out = desc.stdout.strip()
        if out.startswith("v") and _SEMVER_RE.match(out.lstrip("v")):
            # Exact tag: vX.Y.Z ; otherwise fall through to a dev version.
            if re.fullmatch(r"v\d+\.\d+\.\d+", out):
                return out.lstrip("v")
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, cwd=REPO, check=False).stdout.strip()
    except OSError:
        sha = ""
    return f"0.0.0+{sha or 'unknown'}"


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv or argv[0] == "get":
        print(get())
        return 0
    if argv[0] == "set" and len(argv) == 2:
        set_version(argv[1])
        print(get())
        return 0
    if argv[0] == "from-git":
        set_version(_from_git())
        print(get())
        return 0
    sys.stderr.write("usage: version.py [get|set X.Y.Z|from-git]\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
