"""SNI capture on Windows via a raw socket in SIO_RCVALL (promiscuous) mode.

The Windows analogue of the Linux AF_PACKET listener: a raw IP socket put into
``SIO_RCVALL`` delivers IP-layer packets, which we feed to the shared
:func:`commatrix.sni.parse_ip_packet` (same TLS ClientHello parser, ECH aware).
Requires Administrator privileges. Off by default (``[sni] enabled``).
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple

from ...dns import IpNameCache
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
        self._ip_names = IpNameCache()
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
            name = self._ip_names.get(ip, now)
        if name is not None and name != "<ech>":
            return name
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
            # SEC-009/SEC-027: hard-bounded LRU, not TTL-only pruning.
            self._ip_names.put(ev.dst_ip, ev.sni, ev.ts)

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
                except (IndexError, OSError, struct.error, ValueError):
                    # CODE-026: struct.error was not caught here, so one
                    # malformed frame unwound the capture thread and SNI
                    # enrichment went quiet with nothing in the log.
                    ev = None
                except Exception as exc:  # noqa: BLE001 - never kill the thread
                    log.warning("SNI parse failed: %s", exc, exc_info=True)
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
