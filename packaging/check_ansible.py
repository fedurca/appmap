#!/usr/bin/env python3
"""Parse and lint the Ansible playbooks this project ships.

`ansible/collect.yml` referenced `ansible.windows.win_fetch` -- a module that
does not exist and never has -- so the Windows snapshot play could not even be
parsed, let alone run. Nothing caught it because nothing ever asked Ansible to
look at these files: they are deployment glue, not Python, and the test suite
did not reach them.

    python packaging/check_ansible.py           # syntax-check every playbook
    python packaging/check_ansible.py --lint    # also run ansible-lint

`--syntax-check` is the part that matters: it resolves every module reference
against the installed collections, which is what turns a typo'd or imaginary
module into a build failure instead of a 3am surprise. It needs the
collections in ansible/requirements.yml to be installed.
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANSIBLE_DIR = os.path.join(REPO, "ansible")


def playbooks():
    """Every playbook, excluding files that are not playbooks."""

    skip = {"requirements.yml"}
    out = []
    for path in sorted(glob.glob(os.path.join(ANSIBLE_DIR, "*.yml"))):
        if os.path.basename(path) in skip:
            continue
        out.append(path)
    return out


def syntax_check(problems, skipped):
    exe = shutil.which("ansible-playbook")
    if not exe:
        skipped.append("ansible-playbook not installed; syntax check skipped")
        return
    for path in playbooks():
        name = os.path.relpath(path, REPO)
        proc = subprocess.run(
            [exe, "--syntax-check", "-i", "localhost,", path],
            capture_output=True, text=True, check=False, cwd=REPO,
        )
        output = proc.stdout + proc.stderr
        if proc.returncode != 0 or "ERROR" in output:
            detail = " | ".join(
                line.strip() for line in output.splitlines()
                if "ERROR" in line or "Origin:" in line
            )
            problems.append(f"{name}: {detail or output.strip()[:400]}")
        else:
            print(f"  ok   {name}")


def lint(problems, skipped):
    exe = shutil.which("ansible-lint")
    if not exe:
        skipped.append("ansible-lint not installed; lint skipped")
        return
    proc = subprocess.run(
        [exe, "ansible/"], capture_output=True, text=True, check=False, cwd=REPO,
    )
    if proc.returncode != 0:
        problems.append("ansible-lint:\n" + (proc.stdout + proc.stderr).strip())
    else:
        print("  ok   ansible-lint")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lint", action="store_true", help="also run ansible-lint")
    args = ap.parse_args(argv)

    problems, skipped = [], []
    print("playbooks:")
    syntax_check(problems, skipped)
    if args.lint:
        lint(problems, skipped)

    for note in skipped:
        print(f"  SKIP {note}")
    for problem in problems:
        print(f"  FAIL {problem}")
    if problems:
        print(f"\n{len(problems)} playbook problem(s).", file=sys.stderr)
        return 1
    print("\nAll playbooks parse.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
