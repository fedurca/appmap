#!/usr/bin/env python3
"""Resolve and enforce supply-chain pins (SEC-033, SEC-040, SEC-044).

Three things in this repository are fetched by tag or by name at build time,
which means the bytes that end up in a release are whatever the upstream
happened to be serving at that moment:

  SEC-040  GitHub Actions referenced by mutable tags (``actions/checkout@v4``)
  SEC-044  the container base image referenced by a tag (``python:3.12-slim``)
  SEC-033  the Windows embeddable Python zip downloaded with no verification

This script resolves each of them to an immutable identifier and writes the
pins back into the repository. It uses only the standard library.

    python packaging/pin_supply_chain.py --write     # resolve and pin
    python packaging/pin_supply_chain.py --check     # fail if anything is unpinned

``--check`` needs no network and is what CI runs; ``--write`` needs to reach
api.github.com, the container registry and python.org.

Why a script instead of hardcoded values: a pin is only worth having if it is
the *real* digest. Writing a plausible-looking placeholder would break every
build and teach everyone to bypass the check, which is worse than no pin at
all. Run ``--write`` once, review the diff, commit it; Dependabot
(.github/dependabot.yml) keeps the pins current afterwards.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW_DIR = os.path.join(REPO_ROOT, ".github", "workflows")
DOCKERFILE = os.path.join(REPO_ROOT, "Dockerfile")
PY_EMBED_MANIFEST = os.path.join(
    REPO_ROOT, "packaging", "windows", "python-embed-sha256.txt"
)

USER_AGENT = "commatrix-pin-supply-chain"
TIMEOUT = 30

# uses: owner/repo[/path]@ref   (ref may already be a 40-hex SHA)
_USES_RE = re.compile(
    r"^(?P<indent>\s*(?:-\s*)?uses:\s*)"
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)"
    r"@(?P<ref>[^\s#]+)"
    r"(?P<rest>.*)$"
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_FROM_RE = re.compile(
    r"^FROM\s+(?P<image>[^\s@:]+(?::[^\s@]+)?)(?:@(?P<digest>sha256:[0-9a-f]{64}))?"
    r"(?P<rest>.*)$"
)

# Actions published by GitHub itself and by well-known vendors still need
# pinning; there is no allowlist. Local (./path) and docker:// uses are skipped.
_SKIP_PREFIXES = ("./", "../", "docker://")


def _get(url: str, headers=None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read()


# -- SEC-040: GitHub Actions ------------------------------------------------
def resolve_action_sha(action: str, ref: str) -> str:
    """Return the commit SHA a tag or branch of *action* points at."""

    owner_repo = "/".join(action.split("/")[:2])
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://api.github.com/repos/{owner_repo}/commits/{ref}"
    data = json.loads(_get(url, headers))
    sha = data.get("sha")
    if not sha or not _SHA_RE.match(sha):
        raise RuntimeError(f"no commit sha for {action}@{ref}")
    return sha


def iter_workflow_files():
    if not os.path.isdir(WORKFLOW_DIR):
        return
    for name in sorted(os.listdir(WORKFLOW_DIR)):
        if name.endswith((".yml", ".yaml")):
            yield os.path.join(WORKFLOW_DIR, name)


def check_actions() -> list:
    problems = []
    for path in iter_workflow_files():
        for lineno, line in enumerate(open(path, encoding="utf-8"), 1):
            m = _USES_RE.match(line.rstrip("\n"))
            if not m:
                continue
            action, ref = m.group("action"), m.group("ref")
            if action.startswith(_SKIP_PREFIXES):
                continue
            if not _SHA_RE.match(ref):
                problems.append(
                    f"{os.path.relpath(path, REPO_ROOT)}:{lineno}: "
                    f"{action}@{ref} is a mutable ref (SEC-040)"
                )
    return problems


def write_actions() -> list:
    changed = []
    cache = {}
    for path in iter_workflow_files():
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
        out = []
        touched = False
        for line in lines:
            m = _USES_RE.match(line.rstrip("\n"))
            if not m:
                out.append(line)
                continue
            action, ref, rest = m.group("action"), m.group("ref"), m.group("rest")
            if action.startswith(_SKIP_PREFIXES) or _SHA_RE.match(ref):
                out.append(line)
                continue
            key = (action, ref)
            if key not in cache:
                cache[key] = resolve_action_sha(action, ref)
            sha = cache[key]
            comment = rest.strip()
            if comment.startswith("#"):
                comment = ""
            out.append(f"{m.group('indent')}{action}@{sha}  # {ref}\n")
            touched = True
        if touched:
            with open(path, "w", encoding="utf-8") as fh:
                fh.writelines(out)
            changed.append(os.path.relpath(path, REPO_ROOT))
    return changed


# -- SEC-044: container base image digest -----------------------------------
def resolve_image_digest(image: str) -> str:
    """Resolve a Docker Hub image reference to its manifest digest."""

    name, _, tag = image.partition(":")
    tag = tag or "latest"
    if "/" not in name:
        name = f"library/{name}"
    token_url = (
        "https://auth.docker.io/token?service=registry.docker.io"
        f"&scope=repository:{name}:pull"
    )
    token = json.loads(_get(token_url))["token"]
    req = urllib.request.Request(
        f"https://registry-1.docker.io/v2/{name}/manifests/{tag}",
        headers={
            "User-Agent": USER_AGENT,
            "Authorization": f"Bearer {token}",
            "Accept": ", ".join([
                "application/vnd.oci.image.index.v1+json",
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            ]),
        },
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        digest = resp.headers.get("Docker-Content-Digest")
        body = resp.read()
    if not digest:
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
    return digest


def check_dockerfile() -> list:
    problems = []
    if not os.path.exists(DOCKERFILE):
        return problems
    for lineno, line in enumerate(open(DOCKERFILE, encoding="utf-8"), 1):
        m = _FROM_RE.match(line.strip())
        if not m:
            continue
        if not m.group("digest"):
            problems.append(
                f"Dockerfile:{lineno}: base image {m.group('image')} is not "
                "pinned to a digest (SEC-044)"
            )
    return problems


def write_dockerfile() -> list:
    if not os.path.exists(DOCKERFILE):
        return []
    with open(DOCKERFILE, encoding="utf-8") as fh:
        lines = fh.readlines()
    out, touched = [], False
    for line in lines:
        m = _FROM_RE.match(line.strip())
        if not m or m.group("digest"):
            out.append(line)
            continue
        image = m.group("image")
        digest = resolve_image_digest(image)
        out.append(f"FROM {image}@{digest}{m.group('rest')}\n")
        touched = True
    if touched:
        with open(DOCKERFILE, "w", encoding="utf-8") as fh:
            fh.writelines(out)
        return ["Dockerfile"]
    return []


# -- SEC-033: Windows embeddable Python -------------------------------------
def default_python_version() -> str:
    script = os.path.join(REPO_ROOT, "packaging", "windows", "build_msi.ps1")
    try:
        text = open(script, encoding="utf-8").read()
    except OSError:
        return "3.12.7"
    m = re.search(r'\$PythonVersion\s*=\s*"([0-9.]+)"', text)
    return m.group(1) if m else "3.12.7"


def read_manifest() -> dict:
    entries = {}
    if not os.path.exists(PY_EMBED_MANIFEST):
        return entries
    for line in open(PY_EMBED_MANIFEST, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2:
            entries[parts[1]] = parts[0]
    return entries


def check_python_embed(version: str) -> list:
    filename = f"python-{version}-embed-amd64.zip"
    entries = read_manifest()
    if filename not in entries:
        return [
            f"packaging/windows/python-embed-sha256.txt: no SHA256 recorded for "
            f"{filename}; the MSI build would install an unverified interpreter "
            "(SEC-033)"
        ]
    return []


def write_python_embed(version: str) -> list:
    filename = f"python-{version}-embed-amd64.zip"
    entries = read_manifest()
    if filename in entries:
        return []
    url = f"https://www.python.org/ftp/python/{version}/{filename}"
    digest = hashlib.sha256(_get(url)).hexdigest()
    os.makedirs(os.path.dirname(PY_EMBED_MANIFEST), exist_ok=True)
    header = (
        "# SHA256 of the Windows embeddable Python archives the MSI build\n"
        "# embeds (SEC-033). Format: <sha256>  <filename>\n"
        "# Regenerate with: python packaging/pin_supply_chain.py --write\n"
    )
    existing = ""
    if os.path.exists(PY_EMBED_MANIFEST):
        existing = open(PY_EMBED_MANIFEST, encoding="utf-8").read()
    else:
        existing = header
    with open(PY_EMBED_MANIFEST, "w", encoding="utf-8") as fh:
        fh.write(existing.rstrip("\n") + "\n")
        fh.write(f"{digest}  {filename}\n")
    return ["packaging/windows/python-embed-sha256.txt"]


# -- driver -----------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true",
                       help="report unpinned dependencies and exit non-zero (offline)")
    group.add_argument("--write", action="store_true",
                       help="resolve pins upstream and rewrite the files (needs network)")
    ap.add_argument("--python-version", default=None,
                    help="embeddable Python version to pin (default: from build_msi.ps1)")
    args = ap.parse_args(argv)

    py_version = args.python_version or default_python_version()

    if args.check:
        problems = check_actions() + check_dockerfile() + check_python_embed(py_version)
        for p in problems:
            print(f"UNPINNED: {p}")
        if problems:
            print(
                f"\n{len(problems)} unpinned dependency/dependencies. "
                "Run: python packaging/pin_supply_chain.py --write",
                file=sys.stderr,
            )
            return 1
        print("All supply-chain dependencies are pinned.")
        return 0

    changed = []
    errors = []
    for label, fn in (
        ("GitHub Actions", write_actions),
        ("container base image", write_dockerfile),
        ("embeddable Python", lambda: write_python_embed(py_version)),
    ):
        try:
            changed.extend(fn())
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, OSError) as exc:
            errors.append(f"{label}: {exc}")

    for path in changed:
        print(f"pinned: {path}")
    for err in errors:
        print(f"FAILED: {err}", file=sys.stderr)
    if not changed and not errors:
        print("Nothing to pin.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
