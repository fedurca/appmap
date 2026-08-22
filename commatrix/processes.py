"""Process, service, package and container inventory from procfs.

Given a set of pids (typically obtained via :mod:`commatrix.sockets`), collect
identifying metadata: command name, full command line, executable path, the
owning systemd unit and container id (parsed from the cgroup), and the owning
distribution package (best effort via ``dpkg``/``rpm``).
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional

log = logging.getLogger("commatrix.processes")

# CODE-011: package resolution shells out to dpkg-query/rpm. Each call can
# block for up to _PACKAGE_TIMEOUT seconds, and they used to run serially with
# no cap, so a burst of previously unseen binaries (a deploy, a cron fan-out,
# a container image swap) could stall a single poll for minutes. The lookups
# are now budgeted per poll: unresolved binaries are simply left unresolved and
# picked up by a later poll, which drains the backlog without ever blocking the
# collector for long.
_PACKAGE_TIMEOUT = 5.0
_PACKAGE_MAX_LOOKUPS_PER_POLL = 16
_PACKAGE_BUDGET_SECONDS = 2.0
_PACKAGE_CACHE_MAX = 4096

# exe path -> resolved package (or None when the resolver ran and found none).
_PACKAGE_CACHE: "OrderedDict[str, Optional[str]]" = OrderedDict()

_SYSTEMD_UNIT_RE = re.compile(r"/([\w@.\-\\]+\.(?:service|scope|socket|mount|slice))")
_DOCKER_RE = re.compile(r"docker[-/]([0-9a-f]{12,64})")
_CRIO_RE = re.compile(r"crio-([0-9a-f]{12,64})")
_LIBPOD_RE = re.compile(r"libpod-([0-9a-f]{12,64})")
# Kubernetes pod UID in the kubepods cgroup path (dashes or underscores per the
# cgroup driver): .../pod<uuid>/...
_KUBE_POD_RE = re.compile(r"pod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}|[0-9a-fA-F]{32})")


@dataclass
class ProcessInfo:
    pid: int
    comm: str = ""
    cmdline: str = ""
    exe: str = ""
    unit: Optional[str] = None
    container_id: Optional[str] = None
    container_runtime: Optional[str] = None
    pod: Optional[str] = None
    package: Optional[str] = None
    uid: Optional[int] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "pid": self.pid,
            "comm": self.comm,
            "cmdline": self.cmdline,
            "exe": self.exe,
            "unit": self.unit,
            "container_id": self.container_id,
            "container_runtime": self.container_runtime,
            "pod": self.pod,
            "package": self.package,
            "uid": self.uid,
        }


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _read_cmdline(path: str) -> str:
    data = _read_text(path)
    if not data:
        return ""
    # cmdline args are NUL separated.
    return " ".join(part for part in data.split("\x00") if part).strip()


def _read_exe(pid: int, proc_root: str) -> str:
    try:
        return os.readlink(os.path.join(proc_root, str(pid), "exe"))
    except OSError:
        return ""


def _parse_cgroup(text: str) -> (Optional[str], Optional[str], Optional[str], Optional[str]):  # type: ignore[valid-type]
    """Return (systemd_unit, container_id, container_runtime, pod_uid) from cgroup text."""

    unit: Optional[str] = None
    container_id: Optional[str] = None
    runtime: Optional[str] = None
    pod: Optional[str] = None

    for line in text.splitlines():
        # Format: hierarchy-ID:controller-list:cgroup-path
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        path = parts[2]

        m = _DOCKER_RE.search(path)
        if m:
            container_id, runtime = m.group(1), "docker"
        elif _CRIO_RE.search(path):
            container_id, runtime = _CRIO_RE.search(path).group(1), "crio"  # type: ignore[union-attr]
        elif _LIBPOD_RE.search(path):
            container_id, runtime = _LIBPOD_RE.search(path).group(1), "podman"  # type: ignore[union-attr]

        pm = _KUBE_POD_RE.search(path)
        if pm:
            pod = pm.group(1).replace("_", "-")

        for m2 in _SYSTEMD_UNIT_RE.finditer(path):
            candidate = m2.group(1)
            # Prefer the most specific (last) service/scope, ignore slices.
            if candidate.endswith(".slice"):
                continue
            unit = candidate

    return unit, container_id, runtime, pod


def _read_uid(pid: int, proc_root: str) -> Optional[int]:
    status = _read_text(os.path.join(proc_root, str(pid), "status"))
    if not status:
        return None
    for line in status.splitlines():
        if line.startswith("Uid:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


class PackageBudget:
    """Per-poll budget for the subprocess-backed package resolver (CODE-011)."""

    def __init__(
        self,
        max_lookups: int = _PACKAGE_MAX_LOOKUPS_PER_POLL,
        max_seconds: float = _PACKAGE_BUDGET_SECONDS,
        clock=time.monotonic,
    ) -> None:
        self.max_lookups = max_lookups
        self.max_seconds = max_seconds
        self._clock = clock
        self._started = clock()
        self.lookups = 0
        self.skipped = 0

    def allows(self) -> bool:
        if self.max_lookups >= 0 and self.lookups >= self.max_lookups:
            return False
        if self.max_seconds >= 0 and (self._clock() - self._started) >= self.max_seconds:
            return False
        return True

    def spend(self) -> None:
        self.lookups += 1

    def skip(self) -> None:
        self.skipped += 1


def _cache_package(exe: str, value: Optional[str]) -> Optional[str]:
    _PACKAGE_CACHE[exe] = value
    _PACKAGE_CACHE.move_to_end(exe)
    while len(_PACKAGE_CACHE) > _PACKAGE_CACHE_MAX:
        _PACKAGE_CACHE.popitem(last=False)
    return value


def _resolve_package_uncached(exe: str) -> Optional[str]:
    if shutil.which("dpkg-query"):
        try:
            out = subprocess.run(
                ["dpkg-query", "-S", exe],
                capture_output=True,
                text=True,
                timeout=_PACKAGE_TIMEOUT,
                check=False,
            )
            if out.returncode == 0 and out.stdout:
                return out.stdout.split(":", 1)[0].strip() or None
        except (OSError, subprocess.SubprocessError):
            pass
    elif shutil.which("rpm"):
        try:
            out = subprocess.run(
                ["rpm", "-qf", exe],
                capture_output=True,
                text=True,
                timeout=_PACKAGE_TIMEOUT,
                check=False,
            )
            if out.returncode == 0 and out.stdout and "not owned" not in out.stdout:
                return out.stdout.strip().splitlines()[0] or None
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def _package_for_path(exe: str, budget: Optional[PackageBudget] = None) -> Optional[str]:
    """Best-effort resolution of the distro package owning *exe*.

    A cache hit never costs budget. A miss is only resolved while *budget*
    still allows a subprocess call; otherwise the answer is left unresolved
    (and uncached) so a later poll can try again.
    """

    if not exe or not os.path.isabs(exe):
        return None
    # Strip " (deleted)" suffix that readlink adds for replaced binaries.
    exe = exe.split(" (deleted)")[0]

    if exe in _PACKAGE_CACHE:
        _PACKAGE_CACHE.move_to_end(exe)
        return _PACKAGE_CACHE[exe]

    if budget is not None:
        if not budget.allows():
            budget.skip()
            return None
        budget.spend()

    return _cache_package(exe, _resolve_package_uncached(exe))


def clear_package_cache() -> None:
    """Drop the resolved-package cache (used by tests and by --refresh)."""

    _PACKAGE_CACHE.clear()


def get_process_info(
    pid: int,
    proc_root: str = "/proc",
    resolve_package: bool = True,
    package_budget: Optional[PackageBudget] = None,
) -> Optional[ProcessInfo]:
    """Collect metadata for a single pid, or ``None`` if it disappeared."""

    base = os.path.join(proc_root, str(pid))
    if not os.path.isdir(base):
        return None

    comm = (_read_text(os.path.join(base, "comm")) or "").strip()
    cmdline = _read_cmdline(os.path.join(base, "cmdline"))
    exe = _read_exe(pid, proc_root)
    cgroup_text = _read_text(os.path.join(base, "cgroup")) or ""
    unit, container_id, runtime, pod = _parse_cgroup(cgroup_text)
    uid = _read_uid(pid, proc_root)

    package = _package_for_path(exe, package_budget) if resolve_package else None

    return ProcessInfo(
        pid=pid,
        comm=comm,
        cmdline=cmdline,
        exe=exe,
        unit=unit,
        container_id=container_id,
        container_runtime=runtime,
        pod=pod,
        package=package,
        uid=uid,
    )


def collect_processes(
    pids: List[int],
    proc_root: str = "/proc",
    resolve_package: bool = True,
    package_budget: Optional[PackageBudget] = None,
) -> Dict[int, ProcessInfo]:
    """Collect :class:`ProcessInfo` for each pid in *pids*."""

    if resolve_package and package_budget is None:
        package_budget = PackageBudget()

    result: Dict[int, ProcessInfo] = {}
    for pid in set(pids):
        info = get_process_info(
            pid,
            proc_root=proc_root,
            resolve_package=resolve_package,
            package_budget=package_budget,
        )
        if info is not None:
            result[pid] = info
    if package_budget is not None and package_budget.skipped:
        log.debug(
            "package resolution budget exhausted: %d resolved, %d deferred to a later poll",
            package_budget.lookups,
            package_budget.skipped,
        )
    return result
