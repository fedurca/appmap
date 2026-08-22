"""Map PIDs to process metadata on Windows (ctypes, no pywin32).

Fills the shared :class:`commatrix.processes.ProcessInfo` so the rest of the
pipeline (attribution, catalog, report) is unchanged. Executable path comes from
``QueryFullProcessImageNameW``; service attribution is best-effort via ``sc``.
"""

from __future__ import annotations

import logging
import ntpath
import subprocess
import time
from typing import Dict, List, Optional

from ...processes import ProcessInfo

log = logging.getLogger("commatrix.win.winprocess")

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# CODE-028: 'tasklist /svc' enumerates every process on the box and used to run
# once per poll purely to attribute the handful of pids that actually own a
# socket. On a busy server that is a multi-hundred-millisecond fork+enumerate
# every few seconds for data that changes when services start or stop, not when
# connections do. Cache it briefly.
_SERVICE_MAP_TTL = 60.0
_service_map_cache: Optional[Dict[int, str]] = None
_service_map_stamp = 0.0


def _declare(k32) -> None:
    """Declare argtypes/restype for the kernel32 calls used here (SEC-029).

    Without them ctypes assumes every argument and return value is a C int.
    On 64-bit Windows a HANDLE is 64 bits wide, so the handle returned by
    OpenProcess is truncated: the calls that follow either fail with an
    invalid handle or, worse, act on whatever object now matches the truncated
    value, and CloseHandle then closes it.
    """

    import ctypes
    from ctypes import wintypes

    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    k32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]


def _image_path(pid: int) -> Optional[str]:
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32
        _declare(k32)
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


def _service_map(max_age: float = _SERVICE_MAP_TTL) -> Dict[int, str]:
    """Best-effort PID -> service name map via 'tasklist /svc'.

    Cached for *max_age* seconds (CODE-028); pass 0 to force a refresh.
    """

    global _service_map_cache, _service_map_stamp
    now = time.monotonic()
    if (
        _service_map_cache is not None
        and max_age > 0
        and (now - _service_map_stamp) < max_age
    ):
        return _service_map_cache

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
        # Keep serving the previous map rather than losing all service
        # attribution because one enumeration failed.
        if _service_map_cache is not None:
            return _service_map_cache
    _service_map_cache = mapping
    _service_map_stamp = now
    return mapping


def clear_service_map_cache() -> None:
    """Drop the cached tasklist result (tests, and an explicit refresh)."""

    global _service_map_cache, _service_map_stamp
    _service_map_cache = None
    _service_map_stamp = 0.0


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
