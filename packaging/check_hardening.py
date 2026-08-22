#!/usr/bin/env python3
"""Verify the sudoers drop-ins and systemd units this project installs.

The security review listed `visudo -cf` on the generated sudoers files and
`systemd-analyze security` on the units as "verify on a real machine". Doing
that once by hand answers the question for one commit and for nobody
afterwards, so both checks live here and run in CI instead:

* every sudoers template is rendered with realistic values (including a
  username containing a dot, which is the shape that historically breaks
  sudoers parsing) and validated with ``visudo -cf``;
* every unit -- and the ``elevate-linux`` drop-in merged onto the collector
  unit, for each capability profile -- is scored with
  ``systemd-analyze security --offline=true`` and must stay at or below a
  recorded exposure budget.

The budget is a ratchet, not a target: a change that makes a unit measurably
more exposed fails the build and has to either be justified by raising the
number deliberately or not made.

Both tools ship with sudo and systemd. Where they are missing (a slim CI
image, macOS) the corresponding check is skipped, loudly.

    python packaging/check_hardening.py            # check
    python packaging/check_hardening.py --report   # full systemd-analyze output
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSTEMD_DIR = os.path.join(REPO, "systemd")

# Maximum systemd-analyze exposure score per unit. Lower is better; the tool
# scores 0-10. Measured with systemd 255.
EXPOSURE_BUDGET = {
    "commatrix-collector.service": 5.0,
    "commatrix-export.service": 2.0,
    "commatrix-server.service": 4.0,
    # The collector unit with the elevate-linux drop-in applied.
    "merged-attribution.service": 5.0,
    "merged-topology.service": 5.0,
}

_SCORE_RE = re.compile(r"Overall exposure level for \S+:\s+([0-9.]+)")


def _sudoers_samples():
    """The sudoers files install-service.sh and install-lab-sudoers.sh write.

    Kept in sync with the heredocs in those scripts. A username with a dot is
    included on purpose: sudoers treats some punctuation specially and a
    firstname.lastname account is the common case that finds it.
    """

    systemctl, journalctl = "/usr/bin/systemctl", "/usr/bin/journalctl"
    unit = "commatrix-collector.service"
    helper = "/usr/local/sbin/lab-commatrix-helper.sh"
    samples = {}
    for user in ("commatrixadm", "roman.maier"):
        samples[f"commatrix-control ({user})"] = (
            "Cmnd_Alias COMMATRIX_CTL = \\\n"
            + ", \\\n".join(
                f"    {systemctl} {verb} {unit}"
                for verb in ("start", "stop", "restart", "reload", "try-restart",
                             "enable", "disable", "enable --now", "disable --now")
            )
            + ", \\\n"
            + f"    {journalctl} --no-pager -u {unit} -n 200, \\\n"
            + f"    {journalctl} --no-pager -u {unit} -f\n"
            + f"{user} ALL=(root) NOPASSWD: COMMATRIX_CTL\n"
        )
        samples[f"commatrix-lab ({user})"] = (
            "Cmnd_Alias COMMATRIX_LAB = \\\n"
            f"    {helper} setup-conntrack, \\\n"
            f"    {helper} collect, \\\n"
            f"    {helper} collect-once\n"
            f"{user} ALL=(root) NOPASSWD: COMMATRIX_LAB\n"
        )
    return samples


def check_sudoers(problems, skipped):
    if not shutil.which("visudo"):
        skipped.append("visudo not installed; sudoers validation skipped")
        return
    for name, content in _sudoers_samples().items():
        with tempfile.NamedTemporaryFile("w", suffix=".sudoers", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            os.chmod(path, 0o440)
            proc = subprocess.run(
                ["visudo", "-cf", path], capture_output=True, text=True, check=False
            )
            if proc.returncode != 0:
                problems.append(
                    f"sudoers {name} fails visudo: "
                    f"{(proc.stdout + proc.stderr).strip()}"
                )
            else:
                print(f"  ok   sudoers {name}")
        finally:
            os.unlink(path)


def _merged_units(tmpdir):
    """Write the collector unit with each elevate-linux drop-in applied."""

    sys.path.insert(0, REPO)
    try:
        from commatrix.elevate_linux import CAP_PROFILES, render_dropin
    finally:
        sys.path.pop(0)

    base = open(os.path.join(SYSTEMD_DIR, "commatrix-collector.service"),
                encoding="utf-8").read()
    out = []
    for profile in sorted(CAP_PROFILES):
        dropin = render_dropin(profile)
        body = dropin.split("[Service]", 1)[1]
        merged = base.replace("[Install]", body + "\n[Install]")
        path = os.path.join(tmpdir, f"merged-{profile}.service")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(merged)
        out.append(path)
    return out


def check_units(problems, skipped, report=False):
    if not shutil.which("systemd-analyze"):
        skipped.append("systemd-analyze not installed; unit review skipped")
        return
    probe = subprocess.run(
        ["systemd-analyze", "security", "--help"],
        capture_output=True, text=True, check=False,
    )
    if "--offline" not in (probe.stdout + probe.stderr):
        skipped.append(
            "systemd-analyze is too old for --offline (needs v247+); "
            "unit review skipped"
        )
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        units = sorted(
            os.path.join(SYSTEMD_DIR, n)
            for n in os.listdir(SYSTEMD_DIR)
            if n.endswith(".service")
        ) + _merged_units(tmpdir)

        for unit in units:
            name = os.path.basename(unit)
            proc = subprocess.run(
                ["systemd-analyze", "security", "--offline=true", unit],
                capture_output=True, text=True, check=False,
            )
            output = proc.stdout + proc.stderr
            if report:
                print(output)
            match = _SCORE_RE.search(output)
            if not match:
                problems.append(f"{name}: could not parse an exposure score")
                continue
            score = float(match.group(1))
            budget = EXPOSURE_BUDGET.get(name)
            if budget is None:
                problems.append(
                    f"{name}: no exposure budget recorded; add one to "
                    "EXPOSURE_BUDGET in packaging/check_hardening.py"
                )
            elif score > budget:
                problems.append(
                    f"{name}: exposure {score} exceeds the recorded budget "
                    f"{budget}. Either restore the hardening or raise the "
                    "budget deliberately, with a reason."
                )
            else:
                print(f"  ok   {name}: exposure {score} (budget {budget})")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", action="store_true",
                    help="print the full systemd-analyze output for each unit")
    args = ap.parse_args(argv)

    problems, skipped = [], []
    print("sudoers:")
    check_sudoers(problems, skipped)
    print("systemd units:")
    check_units(problems, skipped, report=args.report)

    for note in skipped:
        print(f"  SKIP {note}")
    for problem in problems:
        print(f"  FAIL {problem}")
    if problems:
        print(f"\n{len(problems)} hardening check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll hardening checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
