"""Restrict data-at-rest permissions on Windows via NTFS ACLs (icacls).

Analogue of the Linux chmod 0640/0750: the network map must not be readable by
ordinary users.  Grants full control to SYSTEM, Administrators and the account
the collector actually runs as, and removes inherited ACEs.

SEC-025: the previous version granted SYSTEM + Administrators and nothing else,
with ``/inheritance:r`` wiping whatever ``elevate-windows`` had granted on the
parent directory.  After elevation the scheduled task runs as the unprivileged
``commatrix`` account, which was then denied access to its own database -- and
the documented way out of "Access Denied" is for an operator to put the task
back on SYSTEM.  A hardening step that reliably produces a privilege regression
is worse than no hardening step, so the running account is now part of the ACL.
"""

from __future__ import annotations

import logging
import os
import subprocess
from typing import List, Optional

log = logging.getLogger("commatrix.win.perms")

# Kept in sync with elevate.SERVICE_USER (imported lazily to avoid a cycle).
_SERVICE_USER_FALLBACK = "commatrix"

_ICACLS_TIMEOUT = 15


def current_account() -> Optional[str]:
    """The account this process runs as, in a form icacls understands.

    Returns ``DOMAIN\\USER`` when both are known, otherwise the bare user name.
    None when the environment tells us nothing (icacls then just gets the
    built-in principals).
    """

    user = os.environ.get("USERNAME") or ""
    if not user:
        return None
    domain = os.environ.get("USERDOMAIN") or ""
    return f"{domain}\\{user}" if domain else user


def service_account() -> str:
    try:
        from .elevate import SERVICE_USER
        return SERVICE_USER
    except Exception:  # noqa: BLE001 - keep working if elevate is unavailable
        return _SERVICE_USER_FALLBACK


def _principals(extra: Optional[List[str]] = None) -> List[str]:
    """Accounts that must retain full control of the data at rest."""

    out: List[str] = ["SYSTEM", "Administrators"]
    for candidate in [current_account(), service_account()] + list(extra or []):
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
    """Limit *path* to SYSTEM, Administrators and the collector's own account.

    Returns True when every principal was granted.  A principal that does not
    exist (typically the service account before ``elevate-windows`` has run)
    makes icacls fail for that entry only, so grants are applied one at a time
    and a missing optional account is a warning, not a failure.
    """

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
                # The service account may legitimately not exist yet.
                log.debug(
                    "icacls could not grant %s on %s: %s",
                    name, path, (proc.stderr or "").strip(),
                )
                ok = False
        return ok
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("icacls unavailable for %s: %s", path, exc)
        return False
