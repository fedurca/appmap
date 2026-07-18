"""Least-privilege elevation for the Linux collector service account.

Grants ambient capabilities and a narrow polkit rule so the dedicated
``commatrix`` user can capture nearly everything without running as root and
without opening a path to obtain root (no sudoers, no setuid, no CAP_SETUID /
CAP_SYS_ADMIN).

State is persisted so ``--revoke`` / uninstall can restore the previous layout.
"""

from __future__ import annotations

import json
import logging
import os
import pwd
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("commatrix.elevate_linux")

SERVICE_USER = "commatrix"
SERVICE_GROUP = "commatrix"
UNIT_NAME = "commatrix-collector.service"
DEFAULT_STATE_FILE = "/var/lib/commatrix/elevate-state.json"
DROPIN_DIR = "/etc/systemd/system/commatrix-collector.service.d"
DROPIN_PATH = os.path.join(DROPIN_DIR, "60-elevate.conf")
POLKIT_PATH = "/etc/polkit-1/rules.d/50-commatrix-resolved.rules"

# Caps for max capture without escalation primitives.
ELEVATE_CAPS = (
    "CAP_DAC_READ_SEARCH",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_SYS_PTRACE",
)


def render_dropin() -> str:
    caps = " ".join(ELEVATE_CAPS)
    return (
        "# Managed by: commatrix elevate-linux\n"
        "# Do not edit by hand; revoke with: commatrix elevate-linux --revoke\n"
        "[Service]\n"
        f"User={SERVICE_USER}\n"
        f"Group={SERVICE_GROUP}\n"
        f"AmbientCapabilities={caps}\n"
        f"CapabilityBoundingSet={caps}\n"
        "NoNewPrivileges=true\n"
    )


def render_polkit() -> str:
    return (
        "/* Managed by: commatrix elevate-linux\n"
        " * Narrow grant: systemd-resolved query-result subscription for the\n"
        " * dedicated service user only. No shell, no sudo, no other actions.\n"
        " */\n"
        "polkit.addRule(function(action, subject) {\n"
        "    if (action.id.indexOf(\"org.freedesktop.resolve1\") === 0 &&\n"
        f"        subject.user == \"{SERVICE_USER}\") {{\n"
        "        return polkit.Result.YES;\n"
        "    }\n"
        "});\n"
    )


@dataclass
class ElevateResult:
    ok: bool = True
    actions: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def summary_markdown(self) -> str:
        lines = ["# elevate-linux", ""]
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


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _read_unit_user() -> Optional[str]:
    try:
        proc = subprocess.run(
            ["systemctl", "show", UNIT_NAME, "-p", "User", "--value"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if proc.returncode == 0:
            return (proc.stdout or "").strip() or None
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _read_file(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _write_file(path: str, content: str, mode: int = 0o644) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, mode)


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
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


def _ensure_service_user(result: ElevateResult, dry_run: bool) -> None:
    try:
        pwd.getpwnam(SERVICE_USER)
        result.actions.append(f"service user '{SERVICE_USER}' already exists")
        return
    except KeyError:
        pass
    if dry_run:
        result.actions.append(f"[dry-run] would create user '{SERVICE_USER}' (nologin)")
        return
    try:
        subprocess.run(
            ["useradd", "--system", "--shell", "/usr/sbin/nologin",
             "--home-dir", "/var/lib/commatrix", "--create-home",
             "--user-group", SERVICE_USER],
            capture_output=True, text=True, timeout=30, check=False,
        )
        # Prefer nologin even if useradd used a different shell default.
        try:
            pwd.getpwnam(SERVICE_USER)
            result.actions.append(f"created system user '{SERVICE_USER}' (nologin)")
        except KeyError:
            result.warnings.append(f"useradd did not create '{SERVICE_USER}'")
    except (OSError, subprocess.SubprocessError) as exc:
        result.warnings.append(f"could not create user '{SERVICE_USER}': {exc}")


def _systemctl(*args: str) -> bool:
    try:
        proc = subprocess.run(
            ["systemctl", *args],
            capture_output=True, text=True, timeout=60, check=False,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def apply_elevate(
    *,
    state_file: str = DEFAULT_STATE_FILE,
    dry_run: bool = False,
    reload: bool = True,
) -> ElevateResult:
    """Grant ambient caps + polkit DNS to the service account."""

    result = ElevateResult()
    if not _is_root() and not dry_run:
        result.ok = False
        result.errors.append("elevate-linux requires root")
        return result

    if _load_state(state_file) and os.path.exists(DROPIN_PATH):
        result.warnings.append(
            f"state already present at {state_file}; re-applying drop-in/polkit"
        )

    dropin_before = _read_file(DROPIN_PATH)
    polkit_before = _read_file(POLKIT_PATH)
    unit_user_before = _read_unit_user()

    state = {
        "version": 1,
        "dropin_path": DROPIN_PATH,
        "polkit_path": POLKIT_PATH,
        "dropin_existed": dropin_before is not None,
        "dropin_content": dropin_before,
        "polkit_existed": polkit_before is not None,
        "polkit_content": polkit_before,
        "unit_user": unit_user_before,
        "caps": list(ELEVATE_CAPS),
    }

    if dry_run:
        result.actions.append(f"[dry-run] would write state -> {state_file}")
        result.actions.append(f"[dry-run] would write drop-in -> {DROPIN_PATH}")
        result.actions.append(f"[dry-run] would write polkit -> {POLKIT_PATH}")
        result.actions.append(
            f"[dry-run] caps: {', '.join(ELEVATE_CAPS)}"
        )
        _ensure_service_user(result, dry_run=True)
        return result

    _ensure_service_user(result, dry_run=False)
    _save_state(state_file, state)
    result.actions.append(f"saved previous state -> {state_file}")

    _write_file(DROPIN_PATH, render_dropin(), 0o644)
    result.actions.append(f"wrote systemd drop-in {DROPIN_PATH}")

    try:
        _write_file(POLKIT_PATH, render_polkit(), 0o644)
        result.actions.append(f"wrote polkit rule {POLKIT_PATH}")
    except OSError as exc:
        result.warnings.append(f"polkit rule not written ({exc}); DNS monitor may still need root")

    result.actions.append(
        "granted ambient capabilities: " + ", ".join(ELEVATE_CAPS)
    )
    result.actions.append(
        "did NOT grant: sudoers, setuid, CAP_SETUID, CAP_SYS_ADMIN, interactive login"
    )

    if reload:
        if _systemctl("daemon-reload"):
            result.actions.append("systemctl daemon-reload")
        else:
            result.warnings.append("daemon-reload failed")
        if _systemctl("try-restart", UNIT_NAME):
            result.actions.append(f"try-restart {UNIT_NAME}")
        else:
            result.warnings.append(
                f"could not try-restart {UNIT_NAME} (install the unit first if missing)"
            )

    return result


def revoke_elevate(
    *,
    state_file: str = DEFAULT_STATE_FILE,
    dry_run: bool = False,
    reload: bool = True,
) -> ElevateResult:
    """Restore files from state and remove elevate artifacts."""

    result = ElevateResult()
    if not _is_root() and not dry_run:
        result.ok = False
        result.errors.append("elevate-linux --revoke requires root")
        return result

    state = _load_state(state_file)
    if state is None:
        # Best-effort cleanup even without state.
        if dry_run:
            result.actions.append(f"[dry-run] no state at {state_file}; would remove drop-in/polkit if present")
            return result
        if os.path.exists(DROPIN_PATH):
            os.remove(DROPIN_PATH)
            result.actions.append(f"removed {DROPIN_PATH} (no state file)")
        if os.path.exists(POLKIT_PATH):
            os.remove(POLKIT_PATH)
            result.actions.append(f"removed {POLKIT_PATH} (no state file)")
        if reload:
            _systemctl("daemon-reload")
            _systemctl("try-restart", UNIT_NAME)
        result.warnings.append(f"no elevate state at {state_file}")
        return result

    if dry_run:
        result.actions.append(f"[dry-run] would restore from {state_file}")
        return result

    dropin_path = state.get("dropin_path") or DROPIN_PATH
    polkit_path = state.get("polkit_path") or POLKIT_PATH

    if state.get("dropin_existed") and state.get("dropin_content") is not None:
        _write_file(dropin_path, state["dropin_content"], 0o644)
        result.actions.append(f"restored previous drop-in {dropin_path}")
    else:
        if os.path.exists(dropin_path):
            os.remove(dropin_path)
            result.actions.append(f"removed elevate drop-in {dropin_path}")

    if state.get("polkit_existed") and state.get("polkit_content") is not None:
        _write_file(polkit_path, state["polkit_content"], 0o644)
        result.actions.append(f"restored previous polkit {polkit_path}")
    else:
        if os.path.exists(polkit_path):
            os.remove(polkit_path)
            result.actions.append(f"removed elevate polkit {polkit_path}")

    try:
        os.remove(state_file)
        result.actions.append(f"removed state file {state_file}")
    except OSError:
        result.warnings.append(f"could not remove state file {state_file}")

    if reload:
        if _systemctl("daemon-reload"):
            result.actions.append("systemctl daemon-reload")
        _systemctl("try-restart", UNIT_NAME)

    return result
