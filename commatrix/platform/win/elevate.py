"""Least-privilege elevation for the Windows collector service account.

Creates/reuses a dedicated local user (no Administrators membership), grants
Event Log Readers for DNS visibility, rebinds the scheduled task away from
SYSTEM, and persists state for revoke.

Deliberately does NOT grant Administrators, SeImpersonatePrivilege,
SeAssignPrimaryTokenPrivilege, or -- since SEC-022 -- SeDebugPrivilege.
SeDebugPrivilege permits OpenProcess(PROCESS_ALL_ACCESS) against SYSTEM
processes and hence WriteProcessMemory/CreateRemoteThread, which is a reliable
local escalation to SYSTEM: the Windows counterpart of CAP_SYS_PTRACE. It is
not needed for attribution, because winprocess._image_path opens processes
with PROCESS_QUERY_LIMITED_INFORMATION and calls QueryFullProcessImageNameW,
which succeeds against other users' processes without it. Callers that need to
attribute protected (PPL) processes can opt in with allow_sedebug=True and
accept the residual risk.

SNI (SIO_RCVALL) still needs Admin/SYSTEM and is not promised by
elevate-windows.
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


def _run_stdin(
    args: List[str], stdin_text: str, timeout: int = 60
) -> subprocess.CompletedProcess:
    """Run a command feeding *stdin_text* on standard input.

    SEC-023: anything on a command line is world-readable for the lifetime of
    the process -- `tasklist /v`, WMI Win32_Process.CommandLine and every EDR
    agent on the box see it, and it lands in Sysmon event ID 1. Standard input
    is not in the process table, so secrets go through here.
    """

    return subprocess.run(
        args, input=stdin_text, capture_output=True, text=True,
        timeout=timeout, check=False,
    )


def _powershell() -> Optional[str]:
    """Path to a usable PowerShell, or None."""

    for candidate in ("powershell.exe", "pwsh.exe"):
        found = _run(["where", candidate])
        if found.returncode == 0 and (found.stdout or "").strip():
            return (found.stdout or "").strip().splitlines()[0]
    return None


def _powershell_script(script: str) -> Optional[subprocess.CompletedProcess]:
    """Execute a PowerShell script passed on stdin (never on argv)."""

    exe = _powershell()
    if not exe:
        return None
    return _run_stdin(
        [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", "-"],
        script,
    )


def _ps_quote(value: str) -> str:
    """Single-quote a PowerShell string literal."""

    return "'" + value.replace("'", "''") + "'"


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


def _set_password_via_powershell(username: str, password: str, create: bool) -> Optional[bool]:
    """Create or re-password a local account without putting the secret on argv.

    Returns True/False when PowerShell ran, None when PowerShell is unavailable
    and the caller has to fall back.
    """

    if create:
        body = (
            "$p = ConvertTo-SecureString -String {pw} -AsPlainText -Force;\n"
            "New-LocalUser -Name {user} -Password $p "
            "-FullName 'Commatrix collector (nologin)' "
            "-Description 'Commatrix least-privilege collector account' "
            "-PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop;\n"
            "Enable-LocalUser -Name {user} -ErrorAction Stop;\n"
        )
    else:
        body = (
            "$p = ConvertTo-SecureString -String {pw} -AsPlainText -Force;\n"
            "Set-LocalUser -Name {user} -Password $p -ErrorAction Stop;\n"
        )
    script = body.format(pw=_ps_quote(password), user=_ps_quote(username))
    proc = _powershell_script(script)
    if proc is None:
        return None
    if proc.returncode != 0:
        log.debug(
            "PowerShell local account management failed: %s",
            (proc.stderr or proc.stdout or "").strip(),
        )
    return proc.returncode == 0


def _ensure_user(result: ElevateResult, dry_run: bool) -> Optional[str]:
    """Ensure local service user exists. Returns a password usable for schtasks.

    If the user already exists, the password is rotated so the scheduled task
    can be rebound without storing a prior secret (service account only).

    SEC-023: the password is set through PowerShell on stdin. The legacy
    ``net user <name> <password>`` path puts the secret in the process table
    for every local user to read, so it is only used when PowerShell is
    genuinely unavailable, and it says so out loud.
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

    exists = _user_exists(SERVICE_USER)
    ps_result = _set_password_via_powershell(SERVICE_USER, password, create=not exists)

    if ps_result is True:
        result.actions.append(
            f"{'rotated password for' if exists else 'created'} local user "
            f"'{SERVICE_USER}' (password passed on stdin, never on the command line)"
        )
        return password

    if ps_result is None:
        result.warnings.append(
            "PowerShell not found; falling back to 'net user', which exposes the "
            "service account password in the process command line for the "
            "duration of the call (SEC-023)"
        )
    else:
        result.warnings.append(
            "PowerShell local-account call failed; falling back to 'net user' "
            "(password briefly visible in the process command line, SEC-023)"
        )

    if exists:
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


def _find_ntrights() -> Optional[str]:
    """Locate ntrights.exe, or None. Shared by the grant and revoke paths."""

    try:
        found = _run(["where", "ntrights"])
    except Exception:  # noqa: BLE001 - _run is mocked in tests
        return None
    if found.returncode == 0 and (found.stdout or "").strip():
        return (found.stdout or "").strip().splitlines()[0]
    return None


def _grant_se_debug(result: ElevateResult, dry_run: bool) -> None:
    """Grant SeDebugPrivilege via ntrights (stdlib-only path)."""

    if dry_run:
        result.actions.append("[dry-run] would grant SeDebugPrivilege to service user")
        return
    exe = _find_ntrights()
    if exe:
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
        result.actions.append(
            f"[dry-run] would re-ACL existing files under {data_dir} so "
            f"'{SERVICE_USER}' can write them"
        )
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

    # SEC-025: files created *before* elevation carry an explicit
    # SYSTEM+Administrators ACL with inheritance disabled, so granting the
    # directory is not enough -- the existing database stays unwritable for the
    # account we are about to bind the task to, and the operator's obvious fix
    # for "Access Denied" is to put the task back on SYSTEM.
    _grant_service_user_on_existing_files(result, data_dir)


def _grant_service_user_on_existing_files(result: ElevateResult, data_dir: str) -> None:
    try:
        names = sorted(os.listdir(data_dir))
    except OSError as exc:
        result.warnings.append(f"could not enumerate {data_dir}: {exc}")
        return
    granted = 0
    failed: List[str] = []
    for name in names:
        target = os.path.join(data_dir, name)
        suffix = ":(OI)(CI)F" if os.path.isdir(target) else ":F"
        proc = _run(["icacls", target, "/grant:r", f"{SERVICE_USER}{suffix}"])
        if proc.returncode == 0:
            granted += 1
        else:
            failed.append(name)
    if granted:
        result.actions.append(
            f"granted '{SERVICE_USER}' access to {granted} existing item(s) in {data_dir}"
        )
    if failed:
        result.warnings.append(
            f"could not grant '{SERVICE_USER}' on: {', '.join(failed)}; "
            "the collector may hit Access Denied after the task is rebound"
        )


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


def _task_xml(command: str) -> str:
    """Task Scheduler definition running as SERVICE_USER with an S4U logon.

    LogonType=S4U means the scheduler obtains a token for the account without
    a stored password, which is what lets us keep the secret off every command
    line (SEC-023). RunLevel=LeastPrivilege keeps the task unelevated.
    """

    import xml.sax.saxutils as _sax

    exe = command
    args = ""
    if command.startswith('"'):
        end = command.find('"', 1)
        if end > 0:
            exe, args = command[: end + 1], command[end + 1 :].strip()
    elif " " in command:
        exe, args = command.split(" ", 1)
        args = args.strip()

    esc = _sax.escape
    arguments = f"      <Arguments>{esc(args)}</Arguments>\n" if args else ""
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" '
        'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        "  <RegistrationInfo>\n"
        "    <Description>Commatrix network communication collector</Description>\n"
        "  </RegistrationInfo>\n"
        "  <Triggers>\n"
        "    <BootTrigger><Enabled>true</Enabled></BootTrigger>\n"
        "  </Triggers>\n"
        "  <Principals>\n"
        '    <Principal id="Author">\n'
        f"      <UserId>{esc(SERVICE_USER)}</UserId>\n"
        "      <LogonType>S4U</LogonType>\n"
        "      <RunLevel>LeastPrivilege</RunLevel>\n"
        "    </Principal>\n"
        "  </Principals>\n"
        "  <Settings>\n"
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        "    <AllowHardTerminate>true</AllowHardTerminate>\n"
        "    <StartWhenAvailable>true</StartWhenAvailable>\n"
        "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
        "    <Enabled>true</Enabled>\n"
        "    <Hidden>false</Hidden>\n"
        "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
        "    <Priority>7</Priority>\n"
        "  </Settings>\n"
        '  <Actions Context="Author">\n'
        "    <Exec>\n"
        f"      <Command>{esc(exe.strip(chr(34)))}</Command>\n"
        f"{arguments}"
        "    </Exec>\n"
        "  </Actions>\n"
        "</Task>\n"
    )


def _register_task_s4u(result: ElevateResult, command: str) -> bool:
    """Register the collector task with an S4U principal. True on success."""

    import tempfile

    xml_text = _task_xml(command)
    path = None
    try:
        fd, path = tempfile.mkstemp(prefix="commatrix-task-", suffix=".xml")
        with os.fdopen(fd, "w", encoding="utf-16") as fh:
            fh.write(xml_text)
        proc = _run([
            "schtasks", "/create", "/tn", TASK_NAME, "/xml", path, "/f",
        ])
        if proc.returncode != 0:
            log.debug(
                "S4U task registration failed: %s",
                (proc.stderr or proc.stdout or "").strip(),
            )
            return False
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("S4U task registration raised: %s", exc)
        return False
    finally:
        if path:
            try:
                os.remove(path)
            except OSError:
                pass


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
        # S4U needs no password, so try it even when _ensure_user gave us none.
        if _register_task_s4u(result, cmd):
            result.actions.append(
                f"scheduled task '{TASK_NAME}' now runs as '{SERVICE_USER}' "
                "(S4U logon, LeastPrivilege; no password required)"
            )
            return
        result.warnings.append(
            f"no password available for '{SERVICE_USER}'; task not rebound"
        )
        return

    # SEC-023: prefer an S4U (service-for-user) registration. It runs the task
    # as the service account without the password ever being handed to
    # schtasks, so nothing sensitive reaches the process table. /rp is only
    # used if S4U registration is refused, and then we say so.
    if _register_task_s4u(result, cmd):
        result.actions.append(
            f"scheduled task '{TASK_NAME}' now runs as '{SERVICE_USER}' "
            "(S4U logon, LeastPrivilege; no password on any command line)"
        )
        result.actions.append(
            "SNI (SIO_RCVALL) is NOT enabled by elevate-windows — needs Admin/SYSTEM"
        )
        return

    result.warnings.append(
        "S4U task registration unavailable; falling back to 'schtasks /rp', "
        "which exposes the service account password in the process command "
        "line for the duration of the call (SEC-023)"
    )
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


SEDEBUG_RATIONALE = (
    "SeDebugPrivilege is NOT granted by default (SEC-022). It allows "
    "OpenProcess(PROCESS_ALL_ACCESS) against SYSTEM processes and therefore "
    "WriteProcessMemory/CreateRemoteThread, i.e. a reliable local escalation "
    "to SYSTEM -- the Windows equivalent of CAP_SYS_PTRACE. This collector's "
    "attribution path (winprocess._image_path) opens processes with "
    "PROCESS_QUERY_LIMITED_INFORMATION and calls QueryFullProcessImageNameW, "
    "which works against other users' processes without it. Pass "
    "allow_sedebug=True only if you need to attribute protected (PPL) or "
    "hardened SYSTEM processes and accept the escalation risk."
)


def apply_elevate(
    *,
    state_file: Optional[str] = None,
    dry_run: bool = False,
    config_path: Optional[str] = None,
    allow_sedebug: bool = False,
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
        if allow_sedebug:
            _grant_se_debug(result, dry_run=True)
            result.warnings.append(SEDEBUG_RATIONALE)
        else:
            result.actions.append(
                "[dry-run] would NOT grant SeDebugPrivilege (default)"
            )
        _enable_dns_channel(result, dry_run=True)
        _secure_data_dir(result, dry_run=True)
        _rebind_task(result, password=None, dry_run=True, config_path=config_path)
        result.actions.append(
            "would NOT grant: Administrators, SeImpersonatePrivilege, "
            "SeAssignPrimaryTokenPrivilege"
        )
        return result

    # SEC-024: mirror of SEC-007 on Linux. Re-snapshotting on a second apply
    # would record the already-elevated task binding as "previous", and would
    # reset user_created to False because the account now exists -- so a later
    # --revoke would leave both the rebound task and the service account in
    # place while reporting success. The baseline is captured once.
    existing_state = _load_state(state_path)
    if existing_state:
        result.warnings.append(
            f"state already present at {state_path}; re-applying "
            "(keeping the originally recorded pre-elevation baseline)"
        )
        prev_run_as = existing_state.get("previous_run_as")
        prev_cmd = existing_state.get("previous_task_command")
        prev_user_created = bool(existing_state.get("user_created"))
    else:
        prev_run_as = _query_task_run_as()
        prev_cmd = _query_task_command()
        prev_user_created = False

    state = {
        "version": 1,
        "service_user": SERVICE_USER,
        "task_name": TASK_NAME,
        "previous_run_as": prev_run_as,
        "previous_task_command": prev_cmd,
        "user_created": prev_user_created,
        "dns_channel": DNS_CHANNEL,
        "sedebug_granted": bool(allow_sedebug),
    }

    existed = _user_exists(SERVICE_USER)
    password = _ensure_user(result, dry_run=False)
    if not result.ok:
        return result
    # Only ever latch this on: if a previous apply created the account, revoke
    # must still remove it even though it exists by the time we re-apply.
    state["user_created"] = prev_user_created or not existed

    _save_state(state_path, state)
    result.actions.append(f"saved previous state -> {state_path}")

    _add_to_event_log_readers(result, dry_run=False)
    if allow_sedebug:
        _grant_se_debug(result, dry_run=False)
        result.warnings.append(SEDEBUG_RATIONALE)
    else:
        result.actions.append(
            "did NOT grant SeDebugPrivilege; attribution uses "
            "PROCESS_QUERY_LIMITED_INFORMATION, which does not require it"
        )
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
    # CODE-025: restore whatever the task actually ran as before elevation.
    # Hardcoding SYSTEM silently promoted hosts whose task had deliberately
    # been bound to a narrower account.
    run_as = state.get("previous_run_as") or "SYSTEM"
    create = _run([
        "schtasks", "/create", "/tn", TASK_NAME,
        "/tr", cmd, "/sc", "onstart", "/rl", "highest", "/f",
        "/ru", run_as,
    ])
    if create.returncode == 0:
        result.actions.append(f"restored task '{TASK_NAME}' to {run_as}")
    else:
        result.warnings.append(
            f"could not restore task as {run_as}: {(create.stderr or '').strip()}"
        )

    # If SeDebugPrivilege was granted, take it back explicitly. Deleting the
    # account would drop it too, but the account is only deleted when *we*
    # created it -- on a pre-existing account the privilege would linger.
    if state.get("sedebug_granted"):
        exe = _find_ntrights()
        if exe:
            proc = _run([exe, "-r", "SeDebugPrivilege", "-u", SERVICE_USER])
            if proc.returncode == 0:
                result.actions.append("revoked SeDebugPrivilege")
            else:
                result.warnings.append(
                    "could not revoke SeDebugPrivilege; remove it from "
                    f"'{SERVICE_USER}' via Local Security Policy"
                )
        else:
            result.warnings.append(
                "ntrights unavailable: remove SeDebugPrivilege from "
                f"'{SERVICE_USER}' manually via Local Security Policy"
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
