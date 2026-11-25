"""Platform abstraction: OS-specific capture, attribution, posture and service.

The shared core (store, report, aggregate, catalog, config, flows, dohdetect,
SNI/ClientHello parsing, SNTP, history/coverage stats) is platform-independent.
Everything that must touch the kernel differently on Linux vs Windows is routed
through this layer so the same tool - and the same snapshot/report contract -
works on both. Windows uses only the standard library (ctypes / winreg / socket
SIO_RCVALL / subprocess to built-in tools); no pywin32.
"""

from __future__ import annotations

import os
import sys

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

# CODE-023: the single source of truth for on-disk permissions of anything
# holding capture data (database, WAL/SHM sidecars, snapshots, state files,
# their parent directories). store.py and aggregate.py each
# used to carry their own literal, and store.DB_FILE_MODE was declared but
# never actually applied. Import these instead of writing 0o640 again.
DATA_FILE_MODE = 0o640
DATA_DIR_MODE = 0o750


def is_privileged() -> bool:
    """True if running as root (Linux) or Administrator (Windows)."""

    if IS_WINDOWS:
        from .win import runtime
        return runtime.is_admin()
    return hasattr(os, "geteuid") and os.geteuid() == 0


def running_as_service() -> bool:
    """True if launched by the platform's service manager.

    Linux: started by systemd (INVOCATION_ID). Windows: running as a service /
    scheduled task under SYSTEM.
    """

    if IS_WINDOWS:
        from .win import runtime
        return runtime.running_as_service()
    return bool(os.environ.get("INVOCATION_ID"))


def secure_permissions(path: str, is_dir: bool = False) -> None:
    """Restrict a file/dir so the network map is not world-readable.

    Linux: chmod 0640/0750. Windows: NTFS ACL limited to SYSTEM+Administrators.
    """

    if IS_WINDOWS:
        try:
            from .win import perms
            perms.restrict(path, is_dir)
        except Exception:  # noqa: BLE001 - best-effort hardening
            pass
        return
    try:
        os.chmod(path, DATA_DIR_MODE if is_dir else DATA_FILE_MODE)
    except OSError:
        pass


def lower_priority() -> None:
    """Run at the lowest scheduling priority so real workloads always win."""

    if IS_WINDOWS:
        try:
            from .win import winresources
            winresources.set_idle_priority()
        except Exception:  # noqa: BLE001
            pass
        return
    try:
        os.nice(19)
    except (OSError, AttributeError):
        pass
