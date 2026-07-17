"""Restrict data-at-rest permissions on Windows via NTFS ACLs (icacls).

Analogue of the Linux chmod 0640/0750: the network map must not be readable by
ordinary users. Grants full control to SYSTEM and Administrators only and
removes inherited ACEs.
"""

from __future__ import annotations

import logging
import subprocess

log = logging.getLogger("commatrix.win.perms")


def restrict(path: str, is_dir: bool = False) -> bool:
    """Limit *path* to SYSTEM + Administrators. Returns True on success."""

    try:
        proc = subprocess.run(
            ["icacls", path, "/inheritance:r",
             "/grant:r", "SYSTEM:(OI)(CI)F" if is_dir else "SYSTEM:F",
             "/grant:r", "Administrators:(OI)(CI)F" if is_dir else "Administrators:F"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if proc.returncode != 0:
            log.debug("icacls on %s failed: %s", path, proc.stderr.strip())
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("icacls unavailable for %s: %s", path, exc)
        return False
