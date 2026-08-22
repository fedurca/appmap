#!/usr/bin/env python3
"""Measure how much socket->process attribution the current privileges buy.

`elevate-linux --profile topology` drops CAP_DAC_READ_SEARCH, and the review
asked how much attribution that costs. The answer is not a constant: it
depends on how many of the sockets on the box belong to processes owned by
other users, which is a property of the host, not of the tool. So measure it
rather than quote a number.

Run it under each profile on the host you care about:

    sudo -u commatrix python packaging/measure_attribution.py    # topology-ish
    sudo python packaging/measure_attribution.py                 # full

It reports, for every socket the kernel shows us, whether we could map it to a
PID and read that PID's executable -- and breaks the misses down by cause.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from commatrix.processes import get_process_info  # noqa: E402
from commatrix.sockets import build_inode_to_pid, read_all_sockets  # noqa: E402


def _own_uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else -1


def _has_cap(name: str) -> bool:
    """Best-effort read of an effective capability from /proc/self/status."""

    bits = {"CAP_DAC_READ_SEARCH": 2, "CAP_NET_ADMIN": 12, "CAP_SYS_PTRACE": 19,
            "CAP_NET_RAW": 13}
    bit = bits.get(name)
    if bit is None:
        return False
    try:
        with open("/proc/self/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    return bool(int(line.split(":", 1)[1].strip(), 16) & (1 << bit))
    except (OSError, ValueError):
        pass
    return False


def measure(proc_root: str = "/proc") -> dict:
    sockets = read_all_sockets(proc_root)
    inode_to_pid = build_inode_to_pid(proc_root)

    total = len(sockets)
    with_pid = 0
    with_exe = 0
    foreign_uid_total = 0
    foreign_uid_attributed = 0
    me = _own_uid()

    for sock in sockets:
        pid = inode_to_pid.get(sock.inode)
        foreign = sock.uid is not None and sock.uid != me
        if foreign:
            foreign_uid_total += 1
        if pid is None:
            continue
        with_pid += 1
        if foreign:
            foreign_uid_attributed += 1
        info = get_process_info(pid, proc_root=proc_root, resolve_package=False)
        if info is not None and info.exe:
            with_exe += 1

    def pct(n, d):
        return round(100.0 * n / d, 1) if d else None

    return {
        "euid": me,
        "is_root": me == 0,
        "cap_dac_read_search": _has_cap("CAP_DAC_READ_SEARCH"),
        "cap_net_admin": _has_cap("CAP_NET_ADMIN"),
        "sockets_total": total,
        "sockets_with_pid": with_pid,
        "sockets_with_pid_pct": pct(with_pid, total),
        "sockets_with_exe": with_exe,
        "sockets_with_exe_pct": pct(with_exe, total),
        "sockets_owned_by_other_uid": foreign_uid_total,
        "sockets_owned_by_other_uid_attributed": foreign_uid_attributed,
        "sockets_owned_by_other_uid_attributed_pct": pct(
            foreign_uid_attributed, foreign_uid_total
        ),
    }


def main() -> int:
    result = measure()
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["sockets_total"] == 0:
        print("\nNo sockets visible; nothing to measure.", file=sys.stderr)
        return 0
    print(
        "\nAttribution coverage: {}% of sockets mapped to a PID, {}% also to an "
        "executable.".format(
            result["sockets_with_pid_pct"], result["sockets_with_exe_pct"]
        )
    )
    if result["sockets_owned_by_other_uid"]:
        print(
            "Sockets owned by another user: {} of them, {}% attributed. This is "
            "the number CAP_DAC_READ_SEARCH moves.".format(
                result["sockets_owned_by_other_uid"],
                result["sockets_owned_by_other_uid_attributed_pct"],
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
