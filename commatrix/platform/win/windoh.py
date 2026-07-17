"""DoH posture on Windows via the registry (winreg, stdlib).

Checks the same intent as the Linux :mod:`commatrix.dohcheck` but through
Windows managed policies:
- Chrome / Edge: ``SOFTWARE\\Policies\\{Google\\Chrome,Microsoft\\Edge}`` value
  ``DnsOverHttpsMode`` (off = enforced off).
- Firefox: ``SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS`` (Enabled/Locked).
- Windows built-in DoH: ``SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters``
  ``EnableAutoDoh`` (2 = on).

Reuses :func:`commatrix.dohcheck.summarize` for the assessment and returns the
same host-parameter shape.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from ...dohcheck import DohFinding, summarize

log = logging.getLogger("commatrix.win.windoh")

_CHROME_KEYS = {
    "chrome": r"SOFTWARE\Policies\Google\Chrome",
    "edge": r"SOFTWARE\Policies\Microsoft\Edge",
}
_FIREFOX_KEY = r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"
_DNSCACHE_KEY = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"


def _default_read():
    import winreg

    def read(subkey: str, name: str):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return value
        except OSError:
            return None
    return read


def _check_chromium(read=None) -> List[DohFinding]:
    read = read or _default_read()
    out: List[DohFinding] = []
    for app, subkey in _CHROME_KEYS.items():
        mode = read(subkey, "DnsOverHttpsMode")
        if mode is None:
            out.append(DohFinding(app, "not-configured", detail="no DnsOverHttpsMode policy"))
        elif str(mode) == "off":
            out.append(DohFinding(app, "enforced-off", enforced=True,
                                  detail="DnsOverHttpsMode=off (managed)", origin=subkey))
        else:
            out.append(DohFinding(app, "on", detail=f"DnsOverHttpsMode={mode}", origin=subkey))
    return out


def _check_firefox(read=None) -> List[DohFinding]:
    read = read or _default_read()
    enabled = read(_FIREFOX_KEY, "Enabled")
    locked = bool(read(_FIREFOX_KEY, "Locked"))
    if enabled is None:
        return [DohFinding("firefox", "not-configured", detail="no DNSOverHTTPS policy")]
    if int(enabled) == 0:
        return [DohFinding("firefox", "enforced-off" if locked else "off", enforced=locked,
                           detail=f"DNSOverHTTPS.Enabled=0, Locked={locked}", origin=_FIREFOX_KEY)]
    return [DohFinding("firefox", "on", detail="DNSOverHTTPS.Enabled=1", origin=_FIREFOX_KEY)]


def _check_windows_doh(read=None) -> List[DohFinding]:
    read = read or _default_read()
    val = read(_DNSCACHE_KEY, "EnableAutoDoh")
    if val is None:
        return [DohFinding("windows-resolver", "not-configured", detail="EnableAutoDoh not set")]
    status = "on" if int(val) == 2 else "off"
    return [DohFinding("windows-resolver", status, detail=f"EnableAutoDoh={val}", origin=_DNSCACHE_KEY)]


def doh_posture(read=None) -> Dict[str, object]:
    findings: List[DohFinding] = []
    findings.extend(_check_chromium(read))
    findings.extend(_check_firefox(read))
    findings.extend(_check_windows_doh(read))
    return summarize(findings)


def host_params() -> Dict[str, object]:
    posture = doh_posture()
    return {
        "doh.assessment": posture["assessment"],
        "doh.enabled_anywhere": posture["doh_enabled_anywhere"],
        "doh.enforced_off": posture["doh_enforced_off"],
    }
