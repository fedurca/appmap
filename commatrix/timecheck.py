"""Check the host's time-synchronisation posture and clock accuracy.

commatrix's uptime/coverage statistics, ``max_gap`` beaconing signal and any
cross-host correlation all rely on the wall clock, so an unsynced or skewed
clock silently corrupts the data. This module reports, using only the standard
library:

- whether NTP is enabled and the clock is synchronised (``timedatectl``),
- which sync daemon is in use (systemd-timesyncd / chrony / ntpd),
- the current clock offset from true time (in seconds), read from the local
  daemon (chrony ``System time`` / timesyncd ``Offset``) with an optional
  SNTP probe fallback (needs UDP/123 egress; off unless a server is given).

Everything is best-effort: on hosts without these tools it returns "unknown"
rather than failing.
"""

from __future__ import annotations

import logging
import re
import shutil
import socket
import struct
import subprocess
import time
from typing import Dict, Optional

log = logging.getLogger("commatrix.timecheck")

# Offset above which we consider the clock materially inaccurate for our stats.
LARGE_OFFSET_SECONDS = 1.0

_OFFSET_UNITS = {"s": 1.0, "ms": 1e-3, "us": 1e-6, "\u00b5s": 1e-6, "ns": 1e-9}


def _run(args, timeout: float = 4.0) -> Optional[str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _timedatectl_props() -> Dict[str, str]:
    out = _run(["timedatectl", "show"])
    props: Dict[str, str] = {}
    if out:
        for line in out.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                props[key.strip()] = value.strip()
    return props


def _parse_offset_to_seconds(text: str) -> Optional[float]:
    m = re.search(r"([+-]?\d+(?:\.\d+)?)\s*(ms|us|\u00b5s|ns|s)?", text)
    if not m:
        return None
    value = float(m.group(1))
    unit = m.group(2) or "s"
    return value * _OFFSET_UNITS.get(unit, 1.0)


def _chrony_offset() -> Optional[float]:
    if not shutil.which("chronyc"):
        return None
    out = _run(["chronyc", "-n", "tracking"])
    if not out:
        return None
    for line in out.splitlines():
        low = line.lower()
        if low.startswith("system time"):
            m = re.search(r":\s*([\d.]+)\s*seconds\s*(slow|fast)", line)
            if m:
                val = float(m.group(1))
                # "slow" => system clock is behind true time (negative offset).
                return -val if m.group(2) == "slow" else val
    return None


def _timesyncd_offset() -> Optional[float]:
    out = _run(["timedatectl", "timesync-status"])
    if not out:
        return None
    for line in out.splitlines():
        if line.strip().lower().startswith("offset"):
            return _parse_offset_to_seconds(line.split(":", 1)[1])
    return None


def sntp_offset(server: str, timeout: float = 3.0) -> Optional[float]:
    """Measure clock offset against an NTP server via SNTP (stdlib, UDP/123)."""

    NTP_EPOCH = 2208988800
    packet = b"\x1b" + 47 * b"\0"  # LI=0, VN=3, Mode=3 (client)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        t1 = time.time()
        sock.sendto(packet, (server, 123))
        data, _ = sock.recvfrom(48)
        t4 = time.time()
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()
    if len(data) < 48:
        return None
    fields = struct.unpack("!12I", data[:48])
    recv_ts = fields[8] + fields[9] / 2 ** 32 - NTP_EPOCH   # server receive (T2)
    xmit_ts = fields[10] + fields[11] / 2 ** 32 - NTP_EPOCH  # server transmit (T3)
    # NTP offset = ((T2 - T1) + (T3 - T4)) / 2
    return ((recv_ts - t1) + (xmit_ts - t4)) / 2.0


def _detect_service() -> Optional[str]:
    for name, unit in (("systemd-timesyncd", "systemd-timesyncd"),
                       ("chrony", "chronyd"),
                       ("ntpd", "ntpd")):
        out = _run(["systemctl", "is-active", unit])
        if out and out.strip() == "active":
            return name
    if shutil.which("chronyc"):
        return "chrony"
    if shutil.which("ntpq"):
        return "ntpd"
    return None


def ntp_posture(server: Optional[str] = None) -> Dict[str, object]:
    """Return NTP posture + clock offset with an overall assessment."""

    props = _timedatectl_props()
    ntp_enabled = props.get("NTP") == "yes"
    synchronized = props.get("NTPSynchronized") == "yes"
    service = _detect_service()

    offset = _chrony_offset()
    offset_source = "chrony" if offset is not None else None
    if offset is None:
        offset = _timesyncd_offset()
        offset_source = "timesyncd" if offset is not None else None
    if offset is None and server:
        offset = sntp_offset(server)
        offset_source = f"sntp:{server}" if offset is not None else None

    if not props:
        assessment = "time sync status unknown (timedatectl unavailable)"
    elif not ntp_enabled:
        assessment = "NTP is DISABLED - clock may drift and corrupt uptime/beacon stats"
    elif not synchronized:
        assessment = "NTP enabled but NOT synchronized"
    elif offset is not None and abs(offset) > LARGE_OFFSET_SECONDS:
        assessment = f"synchronized but clock offset is large ({offset:+.3f}s)"
    elif synchronized:
        assessment = "clock synchronized"
    else:
        assessment = "unknown"

    return {
        "assessment": assessment,
        "ntp_enabled": ntp_enabled,
        "synchronized": synchronized,
        "service": service,
        "offset_seconds": offset,
        "offset_source": offset_source,
    }


def host_params(server: Optional[str] = None) -> Dict[str, object]:
    """Flat host-parameter view of the time posture (merged into hostparams)."""

    posture = ntp_posture(server)
    params: Dict[str, object] = {
        "time.assessment": posture["assessment"],
        "time.ntp_enabled": posture["ntp_enabled"],
        "time.synchronized": posture["synchronized"],
    }
    if posture["service"]:
        params["time.service"] = posture["service"]
    if posture["offset_seconds"] is not None:
        params["time.offset_seconds"] = round(float(posture["offset_seconds"]), 6)
    return params


def markdown(server: Optional[str] = None) -> str:
    posture = ntp_posture(server)
    off = posture["offset_seconds"]
    off_str = f"{off:+.6f}s ({posture['offset_source']})" if off is not None else "unknown"
    lines = [
        "# Time synchronization",
        "",
        f"**Assessment:** {posture['assessment']}",
        "",
        f"- NTP enabled: {posture['ntp_enabled']}",
        f"- Synchronized: {posture['synchronized']}",
        f"- Sync service: {posture['service'] or 'unknown'}",
        f"- Clock offset: {off_str}",
    ]
    return "\n".join(lines) + "\n"
