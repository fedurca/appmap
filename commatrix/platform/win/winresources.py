"""Windows resource safety: idle priority + Job Object CPU/memory caps.

Analogue of Linux ``nice`` + systemd ``CPUQuota``/``MemoryMax``. The in-process
CPU governor (portable) still self-throttles; the Job Object is the hard ceiling.
All ctypes, best-effort (any failure is non-fatal).
"""

from __future__ import annotations

import logging
from typing import Optional

log = logging.getLogger("commatrix.win.winresources")

_IDLE_PRIORITY_CLASS = 0x00000040
# JOBOBJECT_CPU_RATE_CONTROL_INFORMATION flags
_JOB_CPU_RATE_CONTROL_ENABLE = 0x1
_JOB_CPU_RATE_CONTROL_HARD_CAP = 0x4
# JOBOBJECT_EXTENDED_LIMIT_INFORMATION / basic limit flags
_JOB_LIMIT_PROCESS_MEMORY = 0x00000100


def set_idle_priority() -> bool:
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        return bool(k32.SetPriorityClass(k32.GetCurrentProcess(), _IDLE_PRIORITY_CLASS))
    except Exception as exc:  # noqa: BLE001
        log.debug("SetPriorityClass failed: %s", exc)
        return False


def _check(k32, ok, what: str, warnings: list) -> bool:
    """Record a failed Win32 BOOL call with its GetLastError code (CODE-029)."""

    if ok:
        return True
    try:
        err = k32.GetLastError()
    except Exception:  # noqa: BLE001
        err = None
    msg = f"{what} failed (GetLastError={err})"
    warnings.append(msg)
    log.warning("job object: %s", msg)
    return False


def apply_job_limits(
    cpu_percent: float = 10.0, memory_mb: int = 128, warnings: "Optional[list]" = None
) -> bool:
    """Assign this process to a Job Object with CPU rate + memory limits.

    CODE-029: every one of these is a Win32 BOOL and every one of them used to
    be ignored, so the function returned True -- "hard ceiling in place" -- even
    when the job object had no limits on it and the process was never assigned
    to it. Returns True only when the process really is inside a job that
    carries both limits; failures are logged and appended to *warnings*.
    """

    if warnings is None:
        warnings = []
    hjob = None
    k32 = None
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32

        # SEC-029: declare argtypes/restype so ctypes does not silently
        # truncate 64-bit HANDLEs to int on Win64.
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.GetCurrentProcess.argtypes = []
        k32.SetInformationJobObject.restype = wintypes.BOOL
        k32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
        ]
        k32.AssignProcessToJobObject.restype = wintypes.BOOL
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]

        hjob = k32.CreateJobObjectW(None, None)
        if not hjob:
            _check(k32, False, "CreateJobObjectW", warnings)
            return False

        # --- CPU rate control (hard cap, in 1/100 of a percent) ---
        class CPU_RATE(ctypes.Structure):
            _fields_ = [("ControlFlags", wintypes.DWORD), ("CpuRate", wintypes.DWORD)]

        JobObjectCpuRateControlInformation = 15
        cpu = CPU_RATE()
        cpu.ControlFlags = _JOB_CPU_RATE_CONTROL_ENABLE | _JOB_CPU_RATE_CONTROL_HARD_CAP
        # CpuRate is in 1/100 of a percent and must be in [1, 10000].
        cpu.CpuRate = max(1, min(10000, int(cpu_percent * 100)))
        cpu_ok = _check(
            k32,
            k32.SetInformationJobObject(
                hjob, JobObjectCpuRateControlInformation,
                ctypes.byref(cpu), ctypes.sizeof(cpu),
            ),
            "SetInformationJobObject(CpuRateControl)",
            warnings,
        )

        # --- memory limit via extended limit info ---
        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in
                        ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                         "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class BASIC_LIMIT(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class EXTENDED_LIMIT(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BASIC_LIMIT),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        JobObjectExtendedLimitInformation = 9
        ext = EXTENDED_LIMIT()
        ext.BasicLimitInformation.LimitFlags = _JOB_LIMIT_PROCESS_MEMORY
        ext.ProcessMemoryLimit = int(memory_mb) * 1024 * 1024
        mem_ok = _check(
            k32,
            k32.SetInformationJobObject(
                hjob, JobObjectExtendedLimitInformation,
                ctypes.byref(ext), ctypes.sizeof(ext),
            ),
            "SetInformationJobObject(ExtendedLimit)",
            warnings,
        )

        assigned = _check(
            k32,
            k32.AssignProcessToJobObject(hjob, k32.GetCurrentProcess()),
            "AssignProcessToJobObject",
            warnings,
        )
        if not assigned:
            # Nothing is capped; do not leave a stray job object behind.
            try:
                k32.CloseHandle(hjob)
            except Exception:  # noqa: BLE001
                pass
            return False
        # The handle is deliberately leaked for the lifetime of the process:
        # closing the last handle to a job object destroys it and releases the
        # limits we just applied.
        return bool(cpu_ok and mem_ok)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"job object setup raised: {exc}")
        log.debug("Job Object limits failed: %s", exc)
        if hjob and k32 is not None:
            try:
                k32.CloseHandle(hjob)
            except Exception:  # noqa: BLE001
                pass
        return False
