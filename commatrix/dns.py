"""DNS query logging via the systemd-resolved varlink monitor.

``systemd-resolved`` exposes a monitor endpoint (the same one ``resolvectl
monitor`` uses) at ``/run/systemd/resolve/io.systemd.Resolve.Monitor``. It
streams every query it answers, with the questions asked and the addresses
returned.  We speak its tiny varlink protocol (NUL-terminated JSON over a Unix
socket) using only the standard library — no packages.

Limitations (documented for operators):
- **Requires root.** The socket is connectable by anyone, but the
  ``SubscribeQueryResults`` method is privileged; unprivileged callers get
  ``InteractiveAuthenticationRequired``. Run the collector as root
  (``install.sh --as-root``) to enable DNS logging. When denied, the monitor
  gives up gracefully and logs once.
- Only queries that go through the *system* resolver are seen. Applications
  doing their own DoH/DoT (encrypted DNS, e.g. some browsers) bypass resolved
  and are invisible here — see :mod:`commatrix.dohcheck`.
- Requires systemd-resolved active and systemd >= 247 (the monitor interface).
  On hosts without it (e.g. RHEL 8, or NetworkManager without resolved) DNS
  logging simply stays off.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("commatrix.dns")

MONITOR_SOCKET = "/run/systemd/resolve/io.systemd.Resolve.Monitor"
_SUBSCRIBE = {"method": "io.systemd.Resolve.Monitor.SubscribeQueryResults", "more": True}

# DNS record types we care to name; anything else is shown numerically.
_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
           16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 65: "HTTPS", 64: "SVCB"}

# How long a resolved name is kept usable for enriching flows.
_MAP_TTL = 900.0


@dataclass
class DnsEvent:
    ts: float
    qname: Optional[str]
    qtype: Optional[str]
    rcode: Optional[str]
    answers: List[str] = field(default_factory=list)
    source: str = "resolved-monitor"

    def to_row(self) -> Dict[str, object]:
        return {
            "ts": self.ts,
            "qname": self.qname,
            "qtype": self.qtype,
            "rcode": self.rcode,
            "answers": ",".join(self.answers) if self.answers else None,
            "source": self.source,
        }


def monitor_available(path: str = MONITOR_SOCKET) -> bool:
    """True if the resolved monitor socket exists and accepts a connection."""

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(1.0)
            s.connect(path)
        finally:
            s.close()
        return True
    except OSError:
        return False


def _qtype_name(value: object) -> Optional[str]:
    if isinstance(value, int):
        return _QTYPES.get(value, str(value))
    if isinstance(value, str) and value:
        return value
    return None


def _addr_from_bytes(raw: object) -> Optional[str]:
    if not isinstance(raw, list):
        return None
    try:
        b = bytes(int(x) & 0xFF for x in raw)
    except (TypeError, ValueError):
        return None
    try:
        if len(b) == 4:
            return socket.inet_ntop(socket.AF_INET, b)
        if len(b) == 16:
            return socket.inet_ntop(socket.AF_INET6, b)
    except OSError:
        return None
    return None


def parse_query_result(params: Dict[str, object]) -> Optional[DnsEvent]:
    """Turn one monitor ``QueryResult`` payload into a :class:`DnsEvent`."""

    if not isinstance(params, dict):
        return None
    questions = params.get("question") or params.get("query") or []
    qname = None
    qtype = None
    if isinstance(questions, list) and questions:
        q0 = questions[0]
        if isinstance(q0, dict):
            qname = q0.get("name")
            qtype = _qtype_name(q0.get("type"))
    if qname is None:
        # Nothing useful (e.g. an initial/keepalive empty message).
        return None

    rcode = params.get("rcode")
    state = params.get("state")
    rcode_str = str(rcode) if rcode is not None else (str(state) if state else None)

    answers: List[str] = []
    ans = params.get("answer")
    if isinstance(ans, list):
        for a in ans:
            if not isinstance(a, dict):
                continue
            rr = a.get("rr")
            if isinstance(rr, dict):
                addr = _addr_from_bytes(rr.get("address"))
                if addr:
                    answers.append(addr)
    return DnsEvent(
        ts=time.time(), qname=qname, qtype=qtype, rcode=rcode_str, answers=answers
    )


class DnsMonitor(threading.Thread):
    """Background thread that streams DNS query results from resolved.

    Thread-safe: :meth:`drain` returns and clears buffered events; :meth:`lookup`
    maps a resolved answer IP back to the queried name for flow enrichment.
    """

    def __init__(self, path: str = MONITOR_SOCKET, max_buffer: int = 10000):
        super().__init__(name="commatrix-dns", daemon=True)
        self.path = path
        self.max_buffer = max_buffer
        self._lock = threading.Lock()
        self._events: List[DnsEvent] = []
        self._ip_names: Dict[str, Tuple[str, float]] = {}
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        # Set when the resolver rejected the subscription (needs root/polkit);
        # retrying would just spam, so we give up in that case.
        self.auth_failed = False

    # -- consumer side (main collector thread) -------------------------
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
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    # -- producer side (monitor thread) --------------------------------
    def _record(self, ev: DnsEvent) -> None:
        with self._lock:
            if len(self._events) < self.max_buffer:
                self._events.append(ev)
            for ip in ev.answers:
                self._ip_names[ip] = (ev.qname or "", ev.ts)
            # Bound the map.
            if len(self._ip_names) > 20000:
                cutoff = time.time() - _MAP_TTL
                self._ip_names = {
                    k: v for k, v in self._ip_names.items() if v[1] >= cutoff
                }

    def run(self) -> None:
        while not self._stop.is_set() and not self.auth_failed:
            try:
                self._run_once()
            except OSError as exc:
                if self._stop.is_set():
                    break
                log.debug("dns monitor connection error: %s; retrying", exc)
                self._stop.wait(5.0)

    def _run_once(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock = sock
        try:
            sock.settimeout(5.0)
            sock.connect(self.path)
            sock.sendall(json.dumps(_SUBSCRIBE).encode("utf-8") + b"\x00")
            buf = b""
            while not self._stop.is_set():
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf += chunk
                while b"\x00" in buf:
                    raw, buf = buf.split(b"\x00", 1)
                    if raw:
                        self._handle_message(raw)
        finally:
            self._sock = None
            try:
                sock.close()
            except OSError:
                pass

    def _handle_message(self, raw: bytes) -> None:
        try:
            msg = json.loads(raw.decode("utf-8", "replace"))
        except (json.JSONDecodeError, ValueError):
            return
        if not isinstance(msg, dict):
            return
        err = msg.get("error")
        if err:
            if "Authentication" in str(err) or "Permission" in str(err):
                # Privileged operation: needs root (or a polkit grant). Give up
                # quietly rather than retrying forever.
                self.auth_failed = True
                self._stop.set()
                log.warning(
                    "DNS query logging needs root: systemd-resolved rejected the "
                    "monitor subscription (%s). Run the collector as root "
                    "(install.sh --as-root) to enable DNS logging.",
                    err,
                )
            else:
                log.warning("dns monitor error: %s", err)
            return
        params = msg.get("parameters")
        if isinstance(params, dict):
            ev = parse_query_result(params)
            if ev is not None:
                self._record(ev)
