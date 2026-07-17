"""Windows resource safety: idle priority + Job Object CPU/memory caps.

Analogue of Linux ``nice`` + systemd ``CPUQuota``/``MemoryMax``. The in-process
CPU governor (portable) still self-throttles; the Job Object is the hard ceiling.
All ctypes, best-effort (any failure is non-fatal).
"""

from __future__ import annotations

import logging

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


def apply_job_limits(cpu_percent: float = 10.0, memory_mb: int = 128) -> bool:
    """Assign this process to a Job Object with CPU rate + memory limits."""

    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32
        hjob = k32.CreateJobObjectW(None, None)
        if not hjob:
            return False

        # --- CPU rate control (hard cap, in 1/100 of a percent) ---
        class CPU_RATE(ctypes.Structure):
            _fields_ = [("ControlFlags", wintypes.DWORD), ("CpuRate", wintypes.DWORD)]

        JobObjectCpuRateControlInformation = 15
        cpu = CPU_RATE()
        cpu.ControlFlags = _JOB_CPU_RATE_CONTROL_ENABLE | _JOB_CPU_RATE_CONTROL_HARD_CAP
        cpu.CpuRate = max(1, int(cpu_percent * 100))  # e.g. 10% -> 1000
        k32.SetInformationJobObject(hjob, JobObjectCpuRateControlInformation,
                                    ctypes.byref(cpu), ctypes.sizeof(cpu))

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
        k32.SetInformationJobObject(hjob, JobObjectExtendedLimitInformation,
                                    ctypes.byref(ext), ctypes.sizeof(ext))

        k32.AssignProcessToJobObject(hjob, k32.GetCurrentProcess())
        return True
    except Exception as exc:  # noqa: BLE001
        log.debug("Job Object limits failed: %s", exc)
        return False
