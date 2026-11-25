"""Restrict data-at-rest permissions on Windows via NTFS ACLs (icacls).

Grants full control to SYSTEM and Administrators and removes inherited ACEs.
The collector runs as SYSTEM.
"""

from __future__ import annotations

import logging
import os
import subprocess
from typing import List, Optional

log = logging.getLogger("commatrix.win.perms")

_ICACLS_TIMEOUT = 15


def current_account() -> Optional[str]:
    user = os.environ.get("USERNAME") or ""
    if not user:
        return None
    domain = os.environ.get("USERDOMAIN") or ""
    return f"{domain}\\{user}" if domain else user


def _principals(extra: Optional[List[str]] = None) -> List[str]:
    out: List[str] = ["SYSTEM", "Administrators"]
    for candidate in [current_account()] + list(extra or []):
        if candidate and candidate not in out:
            out.append(candidate)
    return out


def _grant_args(principals: List[str], is_dir: bool) -> List[str]:
    suffix = ":(OI)(CI)F" if is_dir else ":F"
    args: List[str] = []
    for name in principals:
        args.extend(["/grant:r", f"{name}{suffix}"])
    return args


def restrict(
    path: str, is_dir: bool = False, extra_principals: Optional[List[str]] = None
) -> bool:
    principals = _principals(extra_principals)
    try:
        reset = subprocess.run(
            ["icacls", path, "/inheritance:r"] + _grant_args(principals[:2], is_dir),
            capture_output=True, text=True, timeout=_ICACLS_TIMEOUT, check=False,
        )
        if reset.returncode != 0:
            log.debug("icacls on %s failed: %s", path, (reset.stderr or "").strip())
            return False
        ok = True
        for name in principals[2:]:
            proc = subprocess.run(
                ["icacls", path] + _grant_args([name], is_dir),
                capture_output=True, text=True, timeout=_ICACLS_TIMEOUT, check=False,
            )
            if proc.returncode != 0:
                log.debug(
                    "icacls could not grant %s on %s: %s",
                    name, path, (proc.stderr or "").strip(),
                )
                ok = False
        return ok
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("icacls unavailable for %s: %s", path, exc)
        return False
