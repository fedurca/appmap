"""SNI capture on Windows via a raw socket in SIO_RCVALL (promiscuous) mode.

The Windows analogue of the Linux AF_PACKET listener: a raw IP socket put into
``SIO_RCVALL`` delivers IP-layer packets, which we feed to the shared
:func:`commatrix.sni.parse_ip_packet` (same TLS ClientHello parser, ECH aware).
Requires Administrator privileges. Off by default (``[sni] enabled``).
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from ...sni import SniEvent, _MAP_TTL, parse_ip_packet

log = logging.getLogger("commatrix.win.winsni")


def available() -> bool:
    try:
        import sys
        if not sys.platform.startswith("win"):
            return False
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.close()
        return True
    except (OSError, AttributeError):
        return False


def _local_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "0.0.0.0"


class WinSniMonitor(threading.Thread):
    def __init__(self, interface: Optional[str] = None, ports=(443, 853), max_buffer: int = 10000):
        super().__init__(name="commatrix-winsni", daemon=True)
        self.bind_ip = interface or _local_ip()
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((self.bind_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # promiscuous
        except (OSError, AttributeError) as exc:
            self.failed = True
            log.warning("SNI capture unavailable: raw socket/SIO_RCVALL failed (%s). "
                        "Needs Administrator.", exc)
            return
        self._sock = sock
        try:
            sock.settimeout(2.0)
            while not self._stop.is_set():
                try:
                    pkt = sock.recv(2048)
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    continue
                try:
                    ev = parse_ip_packet(pkt, self.ports)
                except (IndexError, OSError):
                    ev = None
                if ev is not None:
                    self._record(ev)
        finally:
            self._sock = None
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except (OSError, AttributeError):
                pass
            try:
                sock.close()
            except OSError:
                pass
