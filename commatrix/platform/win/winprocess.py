"""Map PIDs to process metadata on Windows (ctypes, no pywin32).

Fills the shared :class:`commatrix.processes.ProcessInfo` so the rest of the
pipeline (attribution, catalog, report) is unchanged. Executable path comes from
``QueryFullProcessImageNameW``; service attribution is best-effort via ``sc``.
"""

from __future__ import annotations

import logging
import ntpath
import subprocess
from typing import Dict, List, Optional

from ...processes import ProcessInfo

log = logging.getLogger("commatrix.win.winprocess")

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _image_path(pid: int) -> Optional[str]:
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32
        handle = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None
        try:
            size = wintypes.DWORD(32768)
            buf = ctypes.create_unicode_buffer(size.value)
            if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                return buf.value
        finally:
            k32.CloseHandle(handle)
    except Exception as exc:  # noqa: BLE001
        log.debug("image path for pid %s failed: %s", pid, exc)
    return None


def _service_map() -> Dict[int, str]:
    """Best-effort PID -> service name map via 'tasklist /svc'."""

    mapping: Dict[int, str] = {}
    try:
        proc = subprocess.run(["tasklist", "/svc", "/fo", "csv", "/nh"],
                              capture_output=True, text=True, timeout=15, check=False)
        if proc.returncode != 0:
            return mapping
        import csv
        import io
        for row in csv.reader(io.StringIO(proc.stdout)):
            if len(row) >= 3 and row[1].isdigit():
                svc = row[2].strip()
                if svc and svc != "N/A":
                    mapping[int(row[1])] = svc.split(",")[0].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return mapping


def get_process_info(pid: int, service_map: Optional[Dict[int, str]] = None) -> Optional[ProcessInfo]:
    if pid <= 0:
        return None
    exe = _image_path(pid) or ""
    comm = ntpath.basename(exe) if exe else ""
    unit = (service_map or {}).get(pid)
    return ProcessInfo(pid=pid, comm=comm, cmdline="", exe=exe, unit=unit)


def collect_processes(pids: List[int]) -> Dict[int, ProcessInfo]:
    svc = _service_map()
    result: Dict[int, ProcessInfo] = {}
    for pid in set(pids):
        info = get_process_info(pid, svc)
        if info is not None:
            result[pid] = info
    return result
