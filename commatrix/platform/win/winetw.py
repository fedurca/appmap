"""DNS query logging on Windows.

Analogue of the Linux systemd-resolved monitor. The robust stdlib path polls the
DNS-Client event channel via ``wevtutil`` (XML) and parses query name + returned
addresses; a true ETW real-time consumer (advapi32/tdh via ctypes) is a
documented follow-up for lower latency. Reuses :class:`commatrix.dns.DnsEvent`
so storage/enrichment are unchanged.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree

from ...dns import DnsEvent, _MAP_TTL

log = logging.getLogger("commatrix.win.winetw")

_CHANNEL = "Microsoft-Windows-DNS-Client/Operational"
_QTYPES = {"1": "A", "28": "AAAA", "5": "CNAME", "12": "PTR", "15": "MX", "16": "TXT"}


def _addrs_from_results(results: str) -> List[str]:
    """Parse the ';'-separated QueryResults field into IP addresses."""

    out: List[str] = []
    for token in (results or "").split(";"):
        token = token.strip()
        if not token or token.startswith("type:"):
            continue
        # IPv4-mapped IPv6 form '::ffff:1.2.3.4' -> keep the v4 tail.
        if token.startswith("::ffff:") and "." in token:
            token = token[len("::ffff:"):]
        out.append(token)
    return out


def parse_dns_events(xml_text: str) -> List[DnsEvent]:
    """Parse 'wevtutil qe ... /f:xml' output into DnsEvents (pure)."""

    events: List[DnsEvent] = []
    # wevtutil emits a sequence of <Event>...</Event> without a root; wrap it.
    try:
        root = ElementTree.fromstring("<Events>" + xml_text + "</Events>")
    except ElementTree.ParseError:
        return events
    for ev in root.iter():
        tag = ev.tag.rsplit("}", 1)[-1]
        if tag != "EventData":
            continue
        fields: Dict[str, str] = {}
        for data in ev:
            name = data.attrib.get("Name")
            if name:
                fields[name] = (data.text or "").strip()
        qname = fields.get("QueryName")
        if not qname:
            continue
        answers = _addrs_from_results(fields.get("QueryResults", ""))
        events.append(DnsEvent(
            ts=time.time(), qname=qname,
            qtype=_QTYPES.get(fields.get("QueryType", ""), fields.get("QueryType") or None),
            rcode=fields.get("QueryStatus"), answers=answers, source="dns-client-etw",
        ))
    return events


def available() -> bool:
    try:
        import sys
        if not sys.platform.startswith("win"):
            return False
        p = subprocess.run(["wevtutil", "gl", _CHANNEL],
                           capture_output=True, text=True, timeout=10, check=False)
        return p.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class WinDnsMonitor(threading.Thread):
    """Poll the DNS-Client channel for recent queries (drain/lookup like DnsMonitor)."""

    def __init__(self, poll_interval: float = 5.0, batch: int = 200):
        super().__init__(name="commatrix-windns", daemon=True)
        self.poll_interval = poll_interval
        self.batch = batch
        self._lock = threading.Lock()
        self._events: List[DnsEvent] = []
        self._ip_names: Dict[str, Tuple[str, float]] = {}
        self._stop = threading.Event()

    def drain(self) -> List[DnsEvent]:
        with self._lock:
            out = self._events
            self._events = []
        return out

    def lookup(self, ip: str, now: Optional[float] = None) -> Optional[str]:
        now = now or time.time()
        with self._lock:
            hit = self._ip_names.get(ip)
        if hit and (now - hit[1]) <= _MAP_TTL:
            return hit[0]
        return None

    def stop(self) -> None:
        self._stop.set()

    def _poll(self) -> None:
        try:
            p = subprocess.run(
                ["wevtutil", "qe", _CHANNEL, "/q:*", "/f:xml", "/rd:true",
                 f"/c:{self.batch}"],
                capture_output=True, text=True, timeout=20, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return
        if p.returncode != 0 or not p.stdout:
            return
        for ev in parse_dns_events(p.stdout):
            with self._lock:
                if len(self._events) < 10000:
                    self._events.append(ev)
                for ip in ev.answers:
                    self._ip_names[ip] = (ev.qname or "", ev.ts)

    def run(self) -> None:
        while not self._stop.is_set():
            self._poll()
            self._stop.wait(self.poll_interval)
