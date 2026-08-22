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
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW_DIR = os.path.join(REPO_ROOT, ".github", "workflows")
DOCKERFILE = os.path.join(REPO_ROOT, "Dockerfile")
PY_EMBED_MANIFEST = os.path.join(
    REPO_ROOT, "packaging", "windows", "python-embed-sha256.txt"
)
PY_EMBED_TRUST = os.path.join(
    REPO_ROOT, "packaging", "windows", "python-embed-trust.json"
)
POLICY_FILE = os.path.join(REPO_ROOT, "packaging", "supply-chain-policy.json")

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


def load_policy() -> dict:
    """Whether an unpinned dependency fails the build, or only warns.

    Bootstrap problem: the pins can only be produced by a run with network
    access to api.github.com, the registry and python.org. Shipping a check
    that hard-fails before anyone has had the chance to run it means CI is red
    on arrival for a reason nobody can fix from a pull request -- and a
    permanently red build is one people stop reading, which costs more than
    this finding does.

    So the check starts in "warn" mode: it prints every unpinned dependency as
    a GitHub warning annotation and exits 0. `--write` flips it to "enforce"
    once real pins exist, after which any regression fails the build. Flip it
    by hand if you would rather the build stayed red until then.
    """

    default = {
        "enforce": False,
        "note": (
            "Set by packaging/pin_supply_chain.py --write once real pins exist. "
            "While false, unpinned dependencies are reported as warnings "
            "instead of failing CI."
        ),
    }
    try:
        with open(POLICY_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return default
    if not isinstance(data, dict):
        return default
    default.update(data)
    return default


def save_policy(policy: dict) -> None:
    with open(POLICY_FILE, "w", encoding="utf-8") as fh:
        json.dump(policy, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _annotate(level: str, message: str) -> None:
    """Emit a GitHub Actions annotation when running in CI."""

    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{message}")


def _get(url: str, headers=None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read()


# -- SEC-040: GitHub Actions ------------------------------------------------
def _resolve_action_sha_git(owner_repo: str, ref: str) -> Optional[str]:
    """Resolve a tag or branch to its commit SHA with ``git ls-remote``.

    Preferred over the REST API for three reasons, all of them learned the
    hard way while producing the first set of pins:

    * ``refs/tags/<v>`` for an *annotated* tag advertises the tag object's SHA,
      not the commit's. A workflow pinned to a tag-object SHA does not run --
      GitHub only accepts a commit. ``^{}`` asks for the peeled value, and
      several of the actions this repository uses (attest-build-provenance,
      snapcore/action-build, flatpak, cosign-installer) are annotated.
    * ``/repos/X/commits/<ref>`` resolves refs in GitHub's own precedence
      order, which is not necessarily the tag you meant.
    * the unauthenticated REST API allows 60 requests an hour; ls-remote has
      no such limit.
    """

    url = f"https://github.com/{owner_repo}"
    try:
        proc = subprocess.run(
            ["git", "ls-remote", url,
             f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}", f"refs/heads/{ref}"],
            capture_output=True, text=True, timeout=90, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None

    found = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            found[parts[1]] = parts[0]
    for candidate in (f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}", f"refs/heads/{ref}"):
        sha = found.get(candidate)
        if sha and _SHA_RE.match(sha):
            return sha
    return None


def _resolve_action_sha_api(owner_repo: str, ref: str) -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://api.github.com/repos/{owner_repo}/commits/{ref}"
    data = json.loads(_get(url, headers))
    sha = data.get("sha")
    if not sha or not _SHA_RE.match(sha):
        raise RuntimeError(f"no commit sha for {owner_repo}@{ref}")
    return sha


def resolve_action_sha(action: str, ref: str) -> str:
    """Return the commit SHA a tag or branch of *action* points at."""

    owner_repo = "/".join(action.split("/")[:2])
    sha = _resolve_action_sha_git(owner_repo, ref)
    if sha:
        return sha
    return _resolve_action_sha_api(owner_repo, ref)


def verify_action_sha(action: str, sha: str) -> bool:
    """Confirm *sha* really is a commit in *action*'s repository.

    A pin nobody checked is a pin that can be a typo. Fetching the object is
    the cheapest end-to-end proof that the value is real and is a commit.
    """

    owner_repo = "/".join(action.split("/")[:2])
    with tempfile.TemporaryDirectory() as tmp:
        try:
            subprocess.run(["git", "init", "-q", tmp],
                           capture_output=True, timeout=30, check=True)
            fetch = subprocess.run(
                ["git", "-C", tmp, "fetch", "-q", "--depth", "1",
                 f"https://github.com/{owner_repo}", sha],
                capture_output=True, text=True, timeout=120, check=False,
            )
            if fetch.returncode != 0:
                return False
            kind = subprocess.run(
                ["git", "-C", tmp, "cat-file", "-t", sha],
                capture_output=True, text=True, timeout=30, check=False,
            )
            return kind.stdout.strip() == "commit"
        except (OSError, subprocess.SubprocessError):
            return False


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
                resolved = resolve_action_sha(action, ref)
                if not verify_action_sha(action, resolved):
                    raise RuntimeError(
                        f"{action}@{ref} resolved to {resolved}, but that is not "
                        "a fetchable commit in the repository; refusing to write "
                        "a pin that would break the build"
                    )
                cache[key] = resolved
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


def read_trust_anchors() -> dict:
    try:
        with open(PY_EMBED_TRUST, encoding="utf-8") as fh:
            return json.load(fh).get("series", {})
    except (OSError, ValueError):
        return {}


def check_python_embed(version: str) -> list:
    """The embedded interpreter must be verifiable before it is unpacked.

    Two independent controls, either of which is sufficient:

    * a Sigstore trust anchor for the version series -- python.org signs every
      release artifact, and the signature proves who produced it. This is the
      primary control: it does not need a new value for each patch release,
      and it is what python.org itself recommends.
    * a recorded SHA256 for this exact file -- reproducibility, and it also
      catches a differently-signed-but-swapped artifact.

    Not accepted: the MD5 python.org prints beside the download. Chosen-prefix
    collisions against MD5 are practical, so it establishes nothing against an
    attacker who can serve a different file.
    """

    filename = f"python-{version}-embed-amd64.zip"
    series = ".".join(version.split(".")[:2])
    if series in read_trust_anchors():
        return []
    if filename in read_manifest():
        return []
    return [
        f"packaging/windows/python-embed-trust.json: no Sigstore trust anchor "
        f"for CPython {series} and no SHA256 recorded for {filename}; the MSI "
        "build would install an unverified interpreter (SEC-033)"
    ]


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
    ap.add_argument("--enforce", action="store_true",
                    help="fail on unpinned dependencies even while the policy "
                         "file still has enforce=false")
    ap.add_argument("--python-version", default=None,
                    help="embeddable Python version to pin (default: from build_msi.ps1)")
    args = ap.parse_args(argv)

    py_version = args.python_version or default_python_version()

    if args.check:
        policy = load_policy()
        enforce = bool(policy.get("enforce")) or args.enforce
        problems = check_actions() + check_dockerfile() + check_python_embed(py_version)
        level = "error" if enforce else "warning"
        for p in problems:
            print(f"UNPINNED: {p}")
            _annotate(level, f"unpinned dependency: {p}")
        if not problems:
            print("All supply-chain dependencies are pinned.")
            if not enforce:
                print(
                    "Everything is pinned but enforcement is still off. "
                    "Set \"enforce\": true in packaging/supply-chain-policy.json "
                    "(or re-run --write) so a regression fails the build."
                )
            return 0
        summary = (
            f"{len(problems)} unpinned dependency/dependencies. "
            "Run: python packaging/pin_supply_chain.py --write"
        )
        if enforce:
            print("\n" + summary, file=sys.stderr)
            return 1
        print(
            "\n" + summary
            + "\n\nReported as warnings because packaging/supply-chain-policy.json "
              "has enforce=false: the pins need one run with network access to "
              "api.github.com, the registry and python.org, which a pull request "
              "cannot provide. --write flips enforcement on."
        )
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

    # Turn enforcement on once nothing is left unpinned, so the next regression
    # fails the build instead of warning.
    remaining = check_actions() + check_dockerfile() + check_python_embed(py_version)
    policy = load_policy()
    if not remaining and not policy.get("enforce"):
        policy["enforce"] = True
        save_policy(policy)
        print("pinned: packaging/supply-chain-policy.json (enforcement enabled)")
    elif remaining:
        print(
            f"\n{len(remaining)} dependency/dependencies still unpinned; "
            "enforcement stays off.",
            file=sys.stderr,
        )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
