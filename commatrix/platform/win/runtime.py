"""Windows runtime: privilege/service detection and service installation.

Preserves the Linux "systemd + root" model: the collector is meant to run as a
service (Task Scheduler at startup, SYSTEM) with administrative privileges. No
pywin32 - a scheduled task is registered via schtasks (stdlib subprocess), which
is the robust, dependency-free equivalent of the systemd unit.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

log = logging.getLogger("commatrix.win.runtime")

TASK_NAME = "commatrix-collector"


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - non-Windows or restricted
        return False


def _session_id() -> int:
    try:
        import ctypes
        sid = ctypes.c_ulong()
        pid = ctypes.windll.kernel32.GetCurrentProcessId()
        if ctypes.windll.kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
            return int(sid.value)
    except Exception:  # noqa: BLE001
        pass
    return -1


def running_as_service() -> bool:
    """True when running under the SCM / a startup task as SYSTEM (session 0)."""

    user = os.environ.get("USERNAME", "").upper()
    if user == "SYSTEM" or user.endswith("$"):
        return True
    return _session_id() == 0


def install_service(config_path: str, python_exe: str = None, run_as_root: bool = True,
                    command: str = None) -> bool:
    """Register a startup scheduled task running the collector as SYSTEM.

    Equivalent to installing+enabling the systemd unit. Requires admin.

    ``command`` overrides the task action - used by the SCCM package to point at
    a bundled-Python launcher (a .cmd that sets PYTHONPATH), so no system-wide
    Python or pip install is required on the target.
    """

    python_exe = python_exe or sys.executable
    cmd = command or f'"{python_exe}" -m commatrix collect --config "{config_path}"'
    args = [
        "schtasks", "/create", "/tn", TASK_NAME,
        "/tr", cmd, "/sc", "onstart", "/rl", "highest", "/f",
    ]
    if run_as_root:
        args += ["/ru", "SYSTEM"]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
        if proc.returncode != 0:
            log.error("schtasks create failed: %s", proc.stderr.strip())
            return False
        subprocess.run(["schtasks", "/run", "/tn", TASK_NAME],
                       capture_output=True, text=True, timeout=30, check=False)
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        log.error("schtasks unavailable: %s", exc)
        return False


def uninstall_service() -> bool:
    try:
        subprocess.run(["schtasks", "/end", "/tn", TASK_NAME],
                       capture_output=True, text=True, timeout=30, check=False)
        proc = subprocess.run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
                              capture_output=True, text=True, timeout=30, check=False)
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
