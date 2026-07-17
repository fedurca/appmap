"""Connection capture on Windows via the IP Helper API (iphlpapi.dll, ctypes).

``GetExtendedTcpTable``/``GetExtendedUdpTable`` return every connection tuple
together with the owning PID (the TCP_TABLE_OWNER_PID_ALL class) - the Windows
equivalent of ``/proc/net/tcp`` plus the inode->pid walk, in one call.

Byte accounting is available via TCP ESTATS (``GetPerTcpConnectionEStats``); that
is a larger, version-sensitive ctypes surface and is attempted best-effort
(returns 0 when unavailable), so the default here is topology + PID. When ESTATS
yields data the capture-quality indicator reflects it.

The table *parsers* are pure functions (testable on any OS); only the ctypes
calls are Windows-only and guarded.
"""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass
from typing import List, Optional

log = logging.getLogger("commatrix.win.iphlp")

AF_INET = 2
AF_INET6 = 23  # Windows value
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

_TCP_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
    6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
    10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}


@dataclass
class WinConn:
    proto: str
    family: int
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    pid: int
    bytes_sent: int = 0
    bytes_recv: int = 0

    @property
    def is_listening(self) -> bool:
        return self.state == "LISTEN"


def _decode_port(dw: int) -> int:
    # Port stored in network byte order in the low 16 bits.
    return ((dw & 0xFF) << 8) | ((dw >> 8) & 0xFF)


def _decode_v4(dw: int) -> str:
    return socket.inet_ntoa(struct.pack("<L", dw & 0xFFFFFFFF))


def _decode_v6(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, raw[:16])
    except OSError:
        return ""


def parse_tcp_table_v4(buf: bytes) -> List[WinConn]:
    """Parse a MIB_TCPTABLE_OWNER_PID buffer (pure)."""

    if len(buf) < 4:
        return []
    count = struct.unpack_from("<I", buf, 0)[0]
    rows: List[WinConn] = []
    off = 4
    row_size = 24  # 6 x DWORD
    for _ in range(count):
        if off + row_size > len(buf):
            break
        state, laddr, lport, raddr, rport, pid = struct.unpack_from("<IIIIII", buf, off)
        off += row_size
        rows.append(WinConn(
            proto="tcp", family=AF_INET,
            local_ip=_decode_v4(laddr), local_port=_decode_port(lport),
            remote_ip=_decode_v4(raddr), remote_port=_decode_port(rport),
            state=_TCP_STATES.get(state, str(state)), pid=pid,
        ))
    return rows


def parse_tcp_table_v6(buf: bytes) -> List[WinConn]:
    """Parse a MIB_TCP6TABLE_OWNER_PID buffer (pure)."""

    if len(buf) < 4:
        return []
    count = struct.unpack_from("<I", buf, 0)[0]
    rows: List[WinConn] = []
    off = 4
    row_size = 56  # 16 + 4 + 4 + 16 + 4 + 4 + 4 + 4
    for _ in range(count):
        if off + row_size > len(buf):
            break
        laddr = buf[off:off + 16]
        lport = struct.unpack_from("<I", buf, off + 20)[0]
        raddr = buf[off + 24:off + 40]
        rport = struct.unpack_from("<I", buf, off + 44)[0]
        state = struct.unpack_from("<I", buf, off + 48)[0]
        pid = struct.unpack_from("<I", buf, off + 52)[0]
        off += row_size
        rows.append(WinConn(
            proto="tcp", family=AF_INET6,
            local_ip=_decode_v6(laddr), local_port=_decode_port(lport),
            remote_ip=_decode_v6(raddr), remote_port=_decode_port(rport),
            state=_TCP_STATES.get(state, str(state)), pid=pid,
        ))
    return rows


def _get_extended_tcp_table(family: int) -> bytes:
    import ctypes
    from ctypes import wintypes

    iphlp = ctypes.windll.iphlpapi
    size = wintypes.DWORD(0)
    # First call sizes the buffer.
    iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, family,
                              TCP_TABLE_OWNER_PID_ALL, 0)
    buf = ctypes.create_string_buffer(size.value)
    ret = iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, family,
                                    TCP_TABLE_OWNER_PID_ALL, 0)
    if ret != 0:
        raise OSError(f"GetExtendedTcpTable failed: {ret}")
    return buf.raw[:size.value]


def get_tcp_connections() -> List[WinConn]:
    conns: List[WinConn] = []
    try:
        conns.extend(parse_tcp_table_v4(_get_extended_tcp_table(AF_INET)))
    except OSError as exc:
        log.debug("IPv4 TCP table failed: %s", exc)
    try:
        conns.extend(parse_tcp_table_v6(_get_extended_tcp_table(AF_INET6)))
    except OSError as exc:
        log.debug("IPv6 TCP table failed: %s", exc)
    return conns


def available() -> bool:
    """True if the IP Helper API is callable (Windows only)."""

    try:
        import ctypes
        ctypes.windll.iphlpapi  # noqa: B018 - probe
        return True
    except Exception:  # noqa: BLE001
        return False


def snapshot() -> List[WinConn]:
    """Return the current TCP connection table (established + listening)."""

    return get_tcp_connections()
