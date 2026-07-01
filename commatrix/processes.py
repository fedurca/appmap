"""Process, service, package and container inventory from procfs.

Given a set of pids (typically obtained via :mod:`commatrix.sockets`), collect
identifying metadata: command name, full command line, executable path, the
owning systemd unit and container id (parsed from the cgroup), and the owning
distribution package (best effort via ``dpkg``/``rpm``).
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_SYSTEMD_UNIT_RE = re.compile(r"/([\w@.\-\\]+\.(?:service|scope|socket|mount|slice))")
_DOCKER_RE = re.compile(r"docker[-/]([0-9a-f]{12,64})")
_CRIO_RE = re.compile(r"crio-([0-9a-f]{12,64})")
_LIBPOD_RE = re.compile(r"libpod-([0-9a-f]{12,64})")


@dataclass
class ProcessInfo:
    pid: int
    comm: str = ""
    cmdline: str = ""
    exe: str = ""
    unit: Optional[str] = None
    container_id: Optional[str] = None
    container_runtime: Optional[str] = None
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


def _parse_cgroup(text: str) -> (Optional[str], Optional[str], Optional[str]):  # type: ignore[valid-type]
    """Return (systemd_unit, container_id, container_runtime) from cgroup text."""

    unit: Optional[str] = None
    container_id: Optional[str] = None
    runtime: Optional[str] = None

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

        for m2 in _SYSTEMD_UNIT_RE.finditer(path):
            candidate = m2.group(1)
            # Prefer the most specific (last) service/scope, ignore slices.
            if candidate.endswith(".slice"):
                continue
            unit = candidate

    return unit, container_id, runtime


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


@functools.lru_cache(maxsize=4096)
def _package_for_path(exe: str) -> Optional[str]:
    """Best-effort resolution of the distro package owning *exe*."""

    if not exe or not os.path.isabs(exe):
        return None
    # Strip " (deleted)" suffix that readlink adds for replaced binaries.
    exe = exe.split(" (deleted)")[0]

    if shutil.which("dpkg-query"):
        try:
            out = subprocess.run(
                ["dpkg-query", "-S", exe],
                capture_output=True,
                text=True,
                timeout=5,
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
                timeout=5,
                check=False,
            )
            if out.returncode == 0 and out.stdout and "not owned" not in out.stdout:
                return out.stdout.strip().splitlines()[0] or None
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def get_process_info(
    pid: int, proc_root: str = "/proc", resolve_package: bool = True
) -> Optional[ProcessInfo]:
    """Collect metadata for a single pid, or ``None`` if it disappeared."""

    base = os.path.join(proc_root, str(pid))
    if not os.path.isdir(base):
        return None

    comm = (_read_text(os.path.join(base, "comm")) or "").strip()
    cmdline = _read_cmdline(os.path.join(base, "cmdline"))
    exe = _read_exe(pid, proc_root)
    cgroup_text = _read_text(os.path.join(base, "cgroup")) or ""
    unit, container_id, runtime = _parse_cgroup(cgroup_text)
    uid = _read_uid(pid, proc_root)

    package = _package_for_path(exe) if resolve_package else None

    return ProcessInfo(
        pid=pid,
        comm=comm,
        cmdline=cmdline,
        exe=exe,
        unit=unit,
        container_id=container_id,
        container_runtime=runtime,
        package=package,
        uid=uid,
    )


def collect_processes(
    pids: List[int], proc_root: str = "/proc", resolve_package: bool = True
) -> Dict[int, ProcessInfo]:
    """Collect :class:`ProcessInfo` for each pid in *pids*."""

    result: Dict[int, ProcessInfo] = {}
    for pid in set(pids):
        info = get_process_info(pid, proc_root=proc_root, resolve_package=resolve_package)
        if info is not None:
            result[pid] = info
    return result
