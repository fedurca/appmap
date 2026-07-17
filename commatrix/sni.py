"""Opt-in SNI capture from TLS ClientHello via an AF_PACKET raw socket.

For ordinary HTTPS the destination hostname is visible in the TLS ClientHello's
Server Name Indication (SNI) extension - even though DNS may be encrypted
(DoH/DoT). Sniffing ClientHello therefore recovers destination names that the
DNS monitor misses. Standard library only (raw packet parsing).

Requires root / CAP_NET_RAW. Big caveats (documented for operators):
- Encrypted Client Hello (ECH) encrypts the SNI too -> then the name is not
  recoverable (reported as "<ech>").
- Raw capture has a cost; this is off by default and only inspects the first
  bytes of TCP segments to the configured ports (443/853), skipping the rest.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("commatrix.sni")

_ETH_P_ALL = 0x0003
_ETH_P_IP = 0x0800
_ETH_P_IPV6 = 0x86DD
_ETH_P_8021Q = 0x8100
_IPPROTO_TCP = 6
_TLS_HANDSHAKE = 0x16
_HS_CLIENT_HELLO = 0x01
_EXT_SERVER_NAME = 0x0000
_EXT_ECH = 0xFE0D
_MAP_TTL = 900.0


@dataclass
class SniEvent:
    ts: float
    dst_ip: str
    dst_port: int
    sni: str

    def to_row(self) -> Dict[str, object]:
        return {
            "ts": self.ts,
            "qname": self.sni,
            "qtype": "SNI",
            "rcode": None,
            "answers": self.dst_ip,
            "source": "sni-clienthello",
        }


def parse_client_hello(payload: bytes) -> Optional[Tuple[Optional[str], bool]]:
    """Parse a TCP payload; return (sni_or_None, ech_present) or None.

    Defensive: every field length is bounds-checked; malformed input yields None.
    """

    try:
        if len(payload) < 6 or payload[0] != _TLS_HANDSHAKE:
            return None
        # TLS record header: type(1) version(2) length(2)
        pos = 5
        if payload[pos] != _HS_CLIENT_HELLO:
            return None
        # Handshake header: type(1) length(3)
        pos += 4
        pos += 2  # client_version
        pos += 32  # random
        if pos + 1 > len(payload):
            return None
        sid_len = payload[pos]; pos += 1 + sid_len
        if pos + 2 > len(payload):
            return None
        cs_len = struct.unpack_from("!H", payload, pos)[0]; pos += 2 + cs_len
        if pos + 1 > len(payload):
            return None
        comp_len = payload[pos]; pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None
        ext_total = struct.unpack_from("!H", payload, pos)[0]; pos += 2
        end = min(len(payload), pos + ext_total)

        sni = None
        ech = False
        while pos + 4 <= end:
            etype, elen = struct.unpack_from("!HH", payload, pos)
            pos += 4
            edata = payload[pos: pos + elen]
            pos += elen
            if etype == _EXT_ECH:
                ech = True
            elif etype == _EXT_SERVER_NAME and len(edata) >= 5:
                # server_name_list: list_len(2), name_type(1), name_len(2), name
                name_len = struct.unpack_from("!H", edata, 3)[0]
                name = edata[5: 5 + name_len]
                if name:
                    sni = name.decode("ascii", "replace")
        return (sni, ech)
    except (struct.error, IndexError):
        return None


def _parse_frame(frame: bytes, ports: set) -> Optional[SniEvent]:
    n = len(frame)
    if n < 14:
        return None
    eth_type = struct.unpack_from("!H", frame, 12)[0]
    off = 14
    if eth_type == _ETH_P_8021Q:
        if n < 18:
            return None
        eth_type = struct.unpack_from("!H", frame, 16)[0]
        off = 18

    if eth_type == _ETH_P_IP:
        if n < off + 20:
            return None
        ihl = (frame[off] & 0x0F) * 4
        proto = frame[off + 9]
        dst_ip = socket.inet_ntop(socket.AF_INET, frame[off + 16: off + 20])
        l4 = off + ihl
    elif eth_type == _ETH_P_IPV6:
        if n < off + 40:
            return None
        proto = frame[off + 6]
        dst_ip = socket.inet_ntop(socket.AF_INET6, frame[off + 24: off + 40])
        l4 = off + 40
    else:
        return None

    if proto != _IPPROTO_TCP or n < l4 + 20:
        return None
    dst_port = struct.unpack_from("!H", frame, l4 + 2)[0]
    if dst_port not in ports:
        return None
    data_off = (frame[l4 + 12] >> 4) * 4
    payload = frame[l4 + data_off:]
    parsed = parse_client_hello(payload)
    if parsed is None:
        return None
    sni, ech = parsed
    name = sni if sni else ("<ech>" if ech else None)
    if not name:
        return None
    return SniEvent(ts=time.time(), dst_ip=dst_ip, dst_port=dst_port, sni=name)


def available() -> bool:
    """True if an AF_PACKET raw socket can be opened (needs CAP_NET_RAW)."""

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
        s.close()
        return True
    except (OSError, AttributeError):
        return False


class SniMonitor(threading.Thread):
    """Background thread capturing TLS SNI from ClientHello packets."""

    def __init__(self, interface: Optional[str] = None, ports=(443, 853), max_buffer: int = 10000):
        super().__init__(name="commatrix-sni", daemon=True)
        self.interface = interface
        self.ports = set(ports)
        self.max_buffer = max_buffer
        self._lock = threading.Lock()
        self._events: List[SniEvent] = []
        self._ip_names: Dict[str, Tuple[str, float]] = {}
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self.failed = False

    def drain(self) -> List[SniEvent]:
        with self._lock:
            out = self._events
            self._events = []
        return out

    def lookup(self, ip: str, now: Optional[float] = None) -> Optional[str]:
        now = now or time.time()
        with self._lock:
            hit = self._ip_names.get(ip)
        if hit and hit[0] != "<ech>" and (now - hit[1]) <= _MAP_TTL:
            return hit[0]
        return None

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def _record(self, ev: SniEvent) -> None:
        with self._lock:
            if len(self._events) < self.max_buffer:
                self._events.append(ev)
            self._ip_names[ev.dst_ip] = (ev.sni, ev.ts)
            if len(self._ip_names) > 20000:
                cutoff = time.time() - _MAP_TTL
                self._ip_names = {k: v for k, v in self._ip_names.items() if v[1] >= cutoff}

    def run(self) -> None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
            if self.interface:
                sock.bind((self.interface, 0))
        except (OSError, AttributeError) as exc:
            self.failed = True
            log.warning(
                "SNI capture unavailable: cannot open AF_PACKET socket (%s). "
                "Needs root/CAP_NET_RAW.", exc,
            )
            return
        self._sock = sock
        try:
            sock.settimeout(2.0)
            while not self._stop.is_set():
                try:
                    frame = sock.recv(2048)
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    continue
                try:
                    ev = _parse_frame(frame, self.ports)
                except (struct.error, IndexError, OSError):
                    ev = None
                if ev is not None:
                    self._record(ev)
        finally:
            self._sock = None
            try:
                sock.close()
            except OSError:
                pass
