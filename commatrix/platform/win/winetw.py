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

# SEC-028: wevtutil output is trusted-ish (it comes from the local event log)
# but it is still attacker-influenced content -- a query name is whatever a
# process on the box asked to resolve. xml.etree's expat parser happily
# processes an internal DTD, which is all a billion-laughs bomb needs. We
# reject DOCTYPE and entity declarations outright, and cap the document size.
MAX_XML_BYTES = 32 * 1024 * 1024

# CODE-027: bound on how many EventRecordIDs are remembered between polls. The
# monitor only needs the high-water mark, this is belt and braces for a log
# that was cleared (record ids restart at 1).
_SEEN_RECORD_IDS_MAX = 20000


class XmlSecurityError(ValueError):
    """Raised when the event XML contains a DTD or entity declaration."""


def _safe_parser() -> ElementTree.XMLParser:
    parser = ElementTree.XMLParser()

    def _reject_doctype(name, sysid, pubid, has_internal_subset):
        raise XmlSecurityError(f"DOCTYPE declaration rejected: {name!r}")

    def _reject_entity(*args, **kwargs):
        raise XmlSecurityError("entity declaration rejected")

    expat = getattr(parser, "parser", None)
    if expat is not None:
        expat.StartDoctypeDeclHandler = _reject_doctype
        expat.EntityDeclHandler = _reject_entity
        # Belt and braces: refuse to load anything from outside the document.
        try:
            expat.ExternalEntityRefHandler = lambda *a: False
        except AttributeError:
            pass
    return parser


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

    return [ev for _rid, ev in parse_dns_events_with_ids(xml_text)]


def parse_dns_events_with_ids(xml_text: str) -> List[Tuple[Optional[int], DnsEvent]]:
    """Like :func:`parse_dns_events` but keeps each event's EventRecordID.

    The record id is what lets :class:`WinDnsMonitor` tell a newly logged query
    from one it already ingested on the previous poll (CODE-027).
    """

    events: List[Tuple[Optional[int], DnsEvent]] = []
    if not xml_text:
        return events
    # SEC-028: refuse an implausibly large document rather than feeding it to
    # the parser and hoping.
    if len(xml_text) > MAX_XML_BYTES:
        log.warning(
            "dns event XML of %d bytes exceeds the %d byte cap; discarding batch",
            len(xml_text), MAX_XML_BYTES,
        )
        return events
    # wevtutil emits a sequence of <Event>...</Event> without a root; wrap it.
    try:
        root = ElementTree.fromstring(
            "<Events>" + xml_text + "</Events>", parser=_safe_parser()
        )
    except (ElementTree.ParseError, XmlSecurityError) as exc:
        log.debug("dns event XML rejected: %s", exc)
        return events

    for event_el in root:
        record_id: Optional[int] = None
        fields: Dict[str, str] = {}
        for child in event_el.iter():
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "EventRecordID":
                try:
                    record_id = int((child.text or "").strip())
                except ValueError:
                    record_id = None
            elif tag == "EventData":
                for data in child:
                    name = data.attrib.get("Name")
                    if name:
                        fields[name] = (data.text or "").strip()
        qname = fields.get("QueryName")
        if not qname:
            continue
        answers = _addrs_from_results(fields.get("QueryResults", ""))
        events.append((record_id, DnsEvent(
            ts=time.time(), qname=qname,
            qtype=_QTYPES.get(fields.get("QueryType", ""), fields.get("QueryType") or None),
            rcode=fields.get("QueryStatus"), answers=answers, source="dns-client-etw",
        )))
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
        # CODE-027: wevtutil is asked for the last `batch` records every poll,
        # so with a 5 s interval and a batch of 200 the same event was
        # re-recorded up to 40 times a minute -- roughly 3.4 million duplicate
        # rows a day on a quiet host. Track the highest EventRecordID already
        # ingested and skip anything at or below it.
        self._last_record_id: Optional[int] = None
        self._seen_without_id: set = set()

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

    def _is_new(self, record_id: Optional[int], ev: DnsEvent) -> bool:
        """True if this event has not been ingested by an earlier poll."""

        if record_id is not None:
            if self._last_record_id is not None and record_id <= self._last_record_id:
                return False
            return True
        # No record id (malformed or synthetic event): fall back to a bounded
        # content fingerprint so we still do not duplicate it every poll.
        key = (ev.qname, ev.qtype, ev.rcode, tuple(ev.answers))
        if key in self._seen_without_id:
            return False
        if len(self._seen_without_id) >= _SEEN_RECORD_IDS_MAX:
            self._seen_without_id.clear()
        self._seen_without_id.add(key)
        return True

    def ingest(self, xml_text: str) -> int:
        """Parse one wevtutil batch, record the new events, return how many."""

        parsed = parse_dns_events_with_ids(xml_text)
        # /rd:true returns newest-first; process oldest-first so the high-water
        # mark advances monotonically.
        parsed.sort(key=lambda item: (item[0] is None, item[0] or 0))
        new_count = 0
        highest = self._last_record_id
        for record_id, ev in parsed:
            if not self._is_new(record_id, ev):
                continue
            new_count += 1
            if record_id is not None and (highest is None or record_id > highest):
                highest = record_id
            with self._lock:
                if len(self._events) < 10000:
                    self._events.append(ev)
                for ip in ev.answers:
                    self._ip_names[ip] = (ev.qname or "", ev.ts)
                if len(self._ip_names) > 20000:
                    cutoff = time.time() - _MAP_TTL
                    self._ip_names = {
                        k: v for k, v in self._ip_names.items() if v[1] >= cutoff
                    }
        self._last_record_id = highest
        return new_count

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
        self.ingest(p.stdout)

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as exc:  # noqa: BLE001 - never let the thread die
                log.warning("windns poll failed: %s", exc, exc_info=True)
            self._stop.wait(self.poll_interval)
