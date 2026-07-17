"""Check the host's DNS-over-HTTPS (DoH) posture.

DoH lets applications resolve names over encrypted HTTPS, bypassing the system
resolver and therefore any DNS logging (see :mod:`commatrix.dns`). For SOC
visibility operators usually want DoH **disabled and enforced** so DNS falls
back to the loggable system resolver.

This module inspects, using only the standard library and without any install:
- Chrome / Chromium / Edge managed policies (``DnsOverHttpsMode``),
- Firefox enterprise policies (``DNSOverHTTPS.Enabled`` / ``Locked``),
- systemd-resolved config (``DNSOverTLS`` — DoT, the resolved-native encrypted
  transport).

It reports, per source, whether DoH is off, enforced (locked/managed), on, or
simply not configured. "Enforced off" means a managed/locked policy that users
cannot override.
"""

from __future__ import annotations

import glob
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

# Chromium-family managed policy directories (system-wide, admin-enforced).
_CHROME_POLICY_DIRS = {
    "chrome": "/etc/opt/chrome/policies/managed",
    "chromium": "/etc/chromium/policies/managed",
    "edge": "/etc/opt/edge/policies/managed",
}

_FIREFOX_POLICY_FILES = [
    "/etc/firefox/policies/policies.json",
    "/usr/lib/firefox/distribution/policies.json",
    "/usr/lib64/firefox/distribution/policies.json",
    "/usr/share/firefox/distribution/policies.json",
    "/etc/firefox/policies.json",
]

_RESOLVED_CONF = "/etc/systemd/resolved.conf"
_RESOLVED_CONF_DIR = "/etc/systemd/resolved.conf.d"


@dataclass
class DohFinding:
    source: str          # e.g. "chrome", "firefox", "systemd-resolved"
    status: str          # "off" | "on" | "enforced-off" | "not-configured" | "unknown"
    enforced: bool = False
    detail: str = ""
    origin: str = ""     # file the finding came from


def _read_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _check_chromium_family() -> List[DohFinding]:
    findings: List[DohFinding] = []
    for app, directory in _CHROME_POLICY_DIRS.items():
        if not os.path.isdir(directory):
            continue
        mode = None
        origin = ""
        for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
            data = _read_json(path)
            if data and "DnsOverHttpsMode" in data:
                mode = str(data["DnsOverHttpsMode"])
                origin = path
        if mode is None:
            findings.append(DohFinding(app, "not-configured", detail="no DnsOverHttpsMode policy"))
        elif mode == "off":
            findings.append(DohFinding(app, "enforced-off", enforced=True,
                                       detail="DnsOverHttpsMode=off (managed)", origin=origin))
        else:
            findings.append(DohFinding(app, "on", detail=f"DnsOverHttpsMode={mode}", origin=origin))
    return findings


def _check_firefox() -> List[DohFinding]:
    for path in _FIREFOX_POLICY_FILES:
        data = _read_json(path)
        if not data:
            continue
        policies = data.get("policies", data)
        doh = policies.get("DNSOverHTTPS") if isinstance(policies, dict) else None
        if isinstance(doh, dict):
            enabled = doh.get("Enabled")
            locked = bool(doh.get("Locked"))
            if enabled is False:
                return [DohFinding("firefox", "enforced-off" if locked else "off",
                                   enforced=locked,
                                   detail=f"DNSOverHTTPS.Enabled=false, Locked={locked}",
                                   origin=path)]
            if enabled is True:
                return [DohFinding("firefox", "on",
                                   detail=f"DNSOverHTTPS.Enabled=true, Locked={locked}",
                                   origin=path)]
    return [DohFinding("firefox", "not-configured", detail="no DNSOverHTTPS policy")]


def _iter_resolved_conf_lines():
    files = [_RESOLVED_CONF]
    if os.path.isdir(_RESOLVED_CONF_DIR):
        files += sorted(glob.glob(os.path.join(_RESOLVED_CONF_DIR, "*.conf")))
    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    yield path, line.strip()
        except OSError:
            continue


def _check_resolved() -> List[DohFinding]:
    dot = None
    origin = ""
    for path, line in _iter_resolved_conf_lines():
        if line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip().lower() == "dnsovertls":
            dot = value.strip().lower()
            origin = path
    if dot is None:
        return [DohFinding("systemd-resolved", "not-configured",
                           detail="DNSOverTLS not set (resolved uses plaintext DNS by default; loggable)")]
    status = "on" if dot in ("yes", "true", "opportunistic") else "off"
    return [DohFinding("systemd-resolved", status,
                       detail=f"DNSOverTLS={dot}", origin=origin)]


def summarize(findings: List[DohFinding]) -> Dict[str, object]:
    """Turn per-source findings into an overall assessment (shared by all OSes)."""

    any_on = any(f.status == "on" for f in findings)
    browser_sources = [f for f in findings if f.source in ("chrome", "chromium", "edge", "firefox")]
    browsers_present = [f for f in browser_sources if f.status != "not-configured"]
    all_browsers_enforced_off = bool(browsers_present) and all(
        f.status == "enforced-off" for f in browsers_present
    )

    if not browsers_present and not any_on:
        assessment = "no DoH policy found (browsers may use DoH by default; consider enforcing off)"
    elif any_on:
        assessment = "DoH is ENABLED somewhere - DNS visibility is reduced"
    elif all_browsers_enforced_off:
        assessment = "DoH disabled and enforced (locked) - system DNS is loggable"
    else:
        assessment = "DoH disabled but not enforced everywhere"

    return {
        "assessment": assessment,
        "doh_enabled_anywhere": any_on,
        "doh_enforced_off": all_browsers_enforced_off,
        "findings": [asdict(f) for f in findings],
    }


def doh_posture() -> Dict[str, object]:
    """Return the host's DoH posture: per-source findings + an assessment."""

    findings: List[DohFinding] = []
    findings.extend(_check_chromium_family())
    findings.extend(_check_firefox())
    findings.extend(_check_resolved())
    return summarize(findings)


def host_params() -> Dict[str, object]:
    """Flat host-parameter view of the DoH posture (merged into hostparams)."""

    posture = doh_posture()
    return {
        "doh.assessment": posture["assessment"],
        "doh.enabled_anywhere": posture["doh_enabled_anywhere"],
        "doh.enforced_off": posture["doh_enforced_off"],
    }


def markdown() -> str:
    posture = doh_posture()
    lines = ["# DNS-over-HTTPS (DoH) posture", ""]
    lines.append(f"**Assessment:** {posture['assessment']}")
    lines.append("")
    lines.append("| Source | Status | Enforced | Detail |")
    lines.append("|---|---|---|---|")
    for f in posture["findings"]:
        lines.append(
            f"| {f['source']} | {f['status']} | {'yes' if f['enforced'] else 'no'} | {f['detail']} |"
        )
    return "\n".join(lines) + "\n"
