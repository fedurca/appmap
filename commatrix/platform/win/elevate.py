"""Least-privilege elevation for the Windows collector service account.

Creates/reuses a dedicated local user (no Administrators membership), grants
Event Log Readers + SeDebugPrivilege for process attribution and DNS visibility,
rebinds the scheduled task away from SYSTEM, and persists state for revoke.

Deliberately does NOT grant Administrators, SeImpersonatePrivilege, or
SeAssignPrimaryTokenPrivilege. SNI (SIO_RCVALL) still needs Admin/SYSTEM and is
not promised by elevate-windows.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import string
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("commatrix.win.elevate")

SERVICE_USER = "commatrix"
TASK_NAME = "commatrix-collector"
DNS_CHANNEL = "Microsoft-Windows-DNS-Client/Operational"
DEFAULT_STATE_NAME = "elevate-state.json"


def default_state_file() -> str:
    root = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(root, "commatrix", DEFAULT_STATE_NAME)


def default_data_dir() -> str:
    root = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(root, "commatrix")


@dataclass
class ElevateResult:
    ok: bool = True
    actions: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def summary_markdown(self) -> str:
        lines = ["# elevate-windows", ""]
        if self.errors:
            lines.append("## Errors")
            lines.extend(f"- {e}" for e in self.errors)
            lines.append("")
        if self.actions:
            lines.append("## Actions")
            lines.extend(f"- {a}" for a in self.actions)
            lines.append("")
        if self.warnings:
            lines.append("## Warnings")
            lines.extend(f"- {w}" for w in self.warnings)
            lines.append("")
        lines.append(f"**Result:** {'OK' if self.ok else 'FAILED'}")
        lines.append("")
        return "\n".join(lines)


def _run(args: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, check=False,
    )


def _read_file(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _load_state(path: str) -> Optional[Dict[str, Any]]:
    raw = _read_file(path)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _save_state(path: str, state: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def _gen_password(length: int = 28) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#%^*_+-="
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _user_exists(username: str) -> bool:
    proc = _run(["net", "user", username])
    return proc.returncode == 0


def _ensure_user(result: ElevateResult, dry_run: bool) -> Optional[str]:
    """Ensure local service user exists. Returns a password usable for schtasks.

    If the user already exists, the password is rotated so the scheduled task
    can be rebound without storing a prior secret (service account only).
    """

    password = _gen_password()
    if dry_run:
        if _user_exists(SERVICE_USER):
            result.actions.append(
                f"[dry-run] would reuse/rotate password for '{SERVICE_USER}'"
            )
        else:
            result.actions.append(f"[dry-run] would create local user '{SERVICE_USER}'")
        return None

    if _user_exists(SERVICE_USER):
        proc = _run(["net", "user", SERVICE_USER, password])
        if proc.returncode != 0:
            result.warnings.append(
                f"could not rotate password for '{SERVICE_USER}'; "
                "task rebind may fail"
            )
            return None
        result.actions.append(
            f"service user '{SERVICE_USER}' exists; rotated password for task bind"
        )
        return password

    proc = _run([
        "net", "user", SERVICE_USER, password, "/add",
        "/fullname:Commatrix collector (nologin)",
        "/passwordchg:no", "/expires:never",
    ])
    if proc.returncode != 0:
        result.errors.append(
            f"net user add failed: {(proc.stderr or proc.stdout or '').strip()}"
        )
        result.ok = False
        return None
    _run(["net", "user", SERVICE_USER, "/active:yes"])
    result.actions.append(f"created local user '{SERVICE_USER}'")
    return password


def _add_to_event_log_readers(result: ElevateResult, dry_run: bool) -> None:
    if dry_run:
        result.actions.append("[dry-run] would add user to Event Log Readers")
        return
    proc = _run(["net", "localgroup", "Event Log Readers", SERVICE_USER, "/add"])
    if proc.returncode == 0:
        result.actions.append("added to group 'Event Log Readers'")
    else:
        msg = (proc.stderr or proc.stdout or "").strip()
        if "1378" in msg or "already" in msg.lower():
            result.actions.append("already in 'Event Log Readers'")
        else:
            result.warnings.append(f"Event Log Readers: {msg or 'failed'}")


def _grant_se_debug(result: ElevateResult, dry_run: bool) -> None:
    """Grant SeDebugPrivilege via temporary secedit inf (stdlib-only path)."""

    if dry_run:
        result.actions.append("[dry-run] would grant SeDebugPrivilege to service user")
        return
    # Best-effort: use ntrights if present; otherwise document manual grant.
    ntrights = _run(["where", "ntrights"])
    if ntrights.returncode == 0 and (ntrights.stdout or "").strip():
        exe = (ntrights.stdout or "").strip().splitlines()[0]
        proc = _run([exe, "+r", "SeDebugPrivilege", "-u", SERVICE_USER])
        if proc.returncode == 0:
            result.actions.append("granted SeDebugPrivilege via ntrights")
            return
    result.warnings.append(
        "SeDebugPrivilege not granted automatically (ntrights unavailable); "
        "assign SeDebugPrivilege to '{0}' via Local Security Policy if cross-process "
        "attribution is incomplete".format(SERVICE_USER)
    )


def _enable_dns_channel(result: ElevateResult, dry_run: bool) -> None:
    if dry_run:
        result.actions.append(f"[dry-run] would enable event channel {DNS_CHANNEL}")
        return
    proc = _run(["wevtutil", "sl", DNS_CHANNEL, "/e:true"])
    if proc.returncode == 0:
        result.actions.append(f"enabled event channel {DNS_CHANNEL}")
    else:
        result.warnings.append(
            f"could not enable {DNS_CHANNEL}: {(proc.stderr or '').strip()}"
        )


def _secure_data_dir(result: ElevateResult, dry_run: bool) -> None:
    data_dir = default_data_dir()
    if dry_run:
        result.actions.append(f"[dry-run] would ACL {data_dir} to SYSTEM+{SERVICE_USER}")
        return
    os.makedirs(data_dir, exist_ok=True)
    # Reset inheritance and grant SYSTEM + service user full control.
    _run(["icacls", data_dir, "/inheritance:r"])
    p1 = _run(["icacls", data_dir, "/grant:r", "SYSTEM:(OI)(CI)F"])
    p2 = _run(["icacls", data_dir, "/grant:r", f"{SERVICE_USER}:(OI)(CI)F"])
    if p1.returncode == 0 and p2.returncode == 0:
        result.actions.append(f"ACL on {data_dir}: SYSTEM + {SERVICE_USER}")
    else:
        result.warnings.append("icacls failed to fully secure data directory")


def _query_task_run_as() -> Optional[str]:
    proc = _run(["schtasks", "/query", "/tn", TASK_NAME, "/fo", "LIST", "/v"])
    if proc.returncode != 0:
        return None
    for line in (proc.stdout or "").splitlines():
        if ":" in line and (
            "Run As User" in line or "Spustit jako uživatel" in line
            or "Ausführen als Benutzer" in line
        ):
            return line.split(":", 1)[1].strip()
    return None


def _query_task_command() -> Optional[str]:
    proc = _run(["schtasks", "/query", "/tn", TASK_NAME, "/fo", "LIST", "/v"])
    if proc.returncode != 0:
        return None
    for line in (proc.stdout or "").splitlines():
        if ":" in line and (
            "Task To Run" in line or "Spustit úlohu" in line
            or "Auszuführende Aufgabe" in line
        ):
            return line.split(":", 1)[1].strip()
    return None


def _rebind_task(
    result: ElevateResult,
    *,
    password: Optional[str],
    dry_run: bool,
    config_path: Optional[str],
) -> None:
    if dry_run:
        result.actions.append(
            f"[dry-run] would rebind task '{TASK_NAME}' to user '{SERVICE_USER}' "
            "(not SYSTEM; not Administrators)"
        )
        return

    cmd = _query_task_command()
    if not cmd:
        # Fall back to a standard collect command.
        import sys
        conf = config_path or os.path.join(default_data_dir(), "commatrix.conf")
        cmd = f'"{sys.executable}" -m commatrix collect --config "{conf}"'
        result.warnings.append("existing task command not found; using default collect")

    if password is None:
        current = _query_task_run_as() or ""
        if SERVICE_USER.lower() in current.lower():
            result.actions.append(f"task already runs as {current}")
            return
        result.warnings.append(
            f"no password available for '{SERVICE_USER}'; task not rebound"
        )
        return

    # Recreate task as limited (non-highest) under dedicated user.
    create = _run([
        "schtasks", "/create", "/tn", TASK_NAME,
        "/tr", cmd, "/sc", "onstart", "/rl", "limited", "/f",
        "/ru", SERVICE_USER, "/rp", password,
    ])
    if create.returncode != 0:
        result.warnings.append(
            "schtasks create as limited user failed "
            f"({(create.stderr or create.stdout or '').strip()}); "
            "task may still be SYSTEM — SNI still needs Admin/SYSTEM"
        )
        return
    result.actions.append(
        f"scheduled task '{TASK_NAME}' now runs as '{SERVICE_USER}' (/rl limited)"
    )
    result.actions.append(
        "SNI (SIO_RCVALL) is NOT enabled by elevate-windows — needs Admin/SYSTEM"
    )


def apply_elevate(
    *,
    state_file: Optional[str] = None,
    dry_run: bool = False,
    config_path: Optional[str] = None,
) -> ElevateResult:
    from . import runtime

    result = ElevateResult()
    state_path = state_file or default_state_file()

    if not runtime.is_admin() and not dry_run:
        result.ok = False
        result.errors.append("elevate-windows requires Administrator privileges")
        return result

    if dry_run:
        result.actions.append(f"[dry-run] would write state -> {state_path}")
        _ensure_user(result, dry_run=True)
        _add_to_event_log_readers(result, dry_run=True)
        _grant_se_debug(result, dry_run=True)
        _enable_dns_channel(result, dry_run=True)
        _secure_data_dir(result, dry_run=True)
        _rebind_task(result, password=None, dry_run=True, config_path=config_path)
        result.actions.append(
            "would NOT grant: Administrators, SeImpersonatePrivilege, "
            "SeAssignPrimaryTokenPrivilege"
        )
        return result

    prev_run_as = _query_task_run_as()
    prev_cmd = _query_task_command()
    state = {
        "version": 1,
        "service_user": SERVICE_USER,
        "task_name": TASK_NAME,
        "previous_run_as": prev_run_as,
        "previous_task_command": prev_cmd,
        "user_created": False,
        "dns_channel": DNS_CHANNEL,
    }

    existed = _user_exists(SERVICE_USER)
    password = _ensure_user(result, dry_run=False)
    if not result.ok:
        return result
    state["user_created"] = not existed

    _save_state(state_path, state)
    result.actions.append(f"saved previous state -> {state_path}")

    _add_to_event_log_readers(result, dry_run=False)
    _grant_se_debug(result, dry_run=False)
    _enable_dns_channel(result, dry_run=False)
    _secure_data_dir(result, dry_run=False)
    _rebind_task(
        result, password=password, dry_run=False, config_path=config_path,
    )
    result.actions.append(
        "did NOT grant: Administrators membership, SeImpersonatePrivilege, "
        "SeAssignPrimaryTokenPrivilege"
    )
    # Do not persist the password.
    return result


def revoke_elevate(
    *,
    state_file: Optional[str] = None,
    dry_run: bool = False,
) -> ElevateResult:
    from . import runtime

    result = ElevateResult()
    state_path = state_file or default_state_file()

    if not runtime.is_admin() and not dry_run:
        result.ok = False
        result.errors.append("elevate-windows --revoke requires Administrator")
        return result

    state = _load_state(state_path)
    if state is None:
        result.warnings.append(f"no elevate state at {state_path}")
        if dry_run:
            return result
        # Best-effort: rebind task to SYSTEM if present.
        return result

    if dry_run:
        result.actions.append(f"[dry-run] would restore from {state_path}")
        return result

    prev_cmd = state.get("previous_task_command")
    import sys
    cmd = prev_cmd or (
        f'"{sys.executable}" -m commatrix collect --config '
        f'"{os.path.join(default_data_dir(), "commatrix.conf")}"'
    )
    create = _run([
        "schtasks", "/create", "/tn", TASK_NAME,
        "/tr", cmd, "/sc", "onstart", "/rl", "highest", "/f",
        "/ru", "SYSTEM",
    ])
    if create.returncode == 0:
        result.actions.append(f"restored task '{TASK_NAME}' to SYSTEM")
    else:
        result.warnings.append(
            f"could not restore SYSTEM task: {(create.stderr or '').strip()}"
        )

    if state.get("user_created"):
        proc = _run(["net", "user", SERVICE_USER, "/delete"])
        if proc.returncode == 0:
            result.actions.append(f"deleted local user '{SERVICE_USER}'")
        else:
            result.warnings.append(f"could not delete user '{SERVICE_USER}'")

    try:
        os.remove(state_path)
        result.actions.append(f"removed state file {state_path}")
    except OSError:
        result.warnings.append(f"could not remove {state_path}")

    return result
