"""Time-sync posture on Windows via w32tm (subprocess) + shared SNTP probe.

Mirrors :mod:`commatrix.timecheck`: reports whether the clock is synchronized,
the source, and the phase offset from true time (parsed from
``w32tm /query /status``), with the same optional SNTP fallback and the same
host-parameter shape.
"""

from __future__ import annotations

import logging
import re
import subprocess
from typing import Dict, Optional

from ...timecheck import LARGE_OFFSET_SECONDS, sntp_offset

log = logging.getLogger("commatrix.win.wintime")


def _run(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)
        return p.stdout if p.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def parse_w32tm_status(text: str) -> Dict[str, object]:
    """Parse 'w32tm /query /status' output (pure)."""

    source = None
    offset = None
    synchronized = False
    for line in text.splitlines():
        low = line.lower().strip()
        if low.startswith("source:"):
            source = line.split(":", 1)[1].strip()
        elif low.startswith("phase offset:"):
            m = re.search(r"([+-]?\d+(?:\.\d+)?)\s*s", line)
            if m:
                offset = float(m.group(1))
        elif low.startswith("leap indicator:"):
            synchronized = True  # a status response at all implies the service answered
    if source and ("local cmos" in source.lower() or "free-running" in source.lower()):
        synchronized = False
    elif source:
        synchronized = True
    return {"source": source, "offset_seconds": offset, "synchronized": synchronized}


def ntp_posture(server: Optional[str] = None) -> Dict[str, object]:
    out = _run(["w32tm", "/query", "/status"])
    status = parse_w32tm_status(out) if out else {"source": None, "offset_seconds": None, "synchronized": False}
    offset = status["offset_seconds"]
    offset_source = "w32tm" if offset is not None else None
    if offset is None and server:
        offset = sntp_offset(server)
        offset_source = f"sntp:{server}" if offset is not None else None

    synced = status["synchronized"]
    if out is None:
        assessment = "time sync status unknown (w32tm unavailable)"
    elif not synced:
        assessment = "W32Time not synchronized (or using local CMOS clock)"
    elif offset is not None and abs(offset) > LARGE_OFFSET_SECONDS:
        assessment = f"synchronized but clock offset is large ({offset:+.3f}s)"
    else:
        assessment = "clock synchronized"

    return {
        "assessment": assessment,
        "ntp_enabled": out is not None,
        "synchronized": synced,
        "service": "w32time",
        "offset_seconds": offset,
        "offset_source": offset_source,
    }


def host_params(server: Optional[str] = None) -> Dict[str, object]:
    posture = ntp_posture(server)
    params: Dict[str, object] = {
        "time.assessment": posture["assessment"],
        "time.ntp_enabled": posture["ntp_enabled"],
        "time.synchronized": posture["synchronized"],
        "time.service": posture["service"],
    }
    if posture["offset_seconds"] is not None:
        params["time.offset_seconds"] = round(float(posture["offset_seconds"]), 6)
    return params
