"""Per-socket byte accounting via the kernel ``sock_diag`` netlink interface.

This is the mechanism ``ss -i`` uses.  It lets commatrix report *real*
per-connection byte/packet volume for TCP sockets **without any external
package** (pure standard-library netlink) and **without**
``/proc/net/nf_conntrack`` — closing the byte-accounting gap on hosts where
neither the conntrack procfs nor ``conntrack-tools`` are available.  It also
works unprivileged (the dump returns all sockets, like ``/proc/net/tcp``).

Only the standard-library :mod:`socket` and :mod:`struct` modules are used.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import List, Optional

NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLM_F_REQUEST = 0x01
NLM_F_DUMP = 0x300  # NLM_F_ROOT | NLM_F_MATCH
NLMSG_ERROR = 2
NLMSG_DONE = 3

INET_DIAG_INFO = 2
_EXT_INFO = 1 << (INET_DIAG_INFO - 1)
_ALL_STATES = 0xFFFFFFFF
_TCP_LISTEN = 10

# tcp_info field byte offsets. Stable since Linux 4.6 because struct tcp_info
# only ever appends fields; we guard every read against the actual length.
_OFF_BYTES_ACKED = 120     # __u64 tcpi_bytes_acked   (bytes we sent, acked)
_OFF_BYTES_RECEIVED = 128  # __u64 tcpi_bytes_received
_OFF_SEGS_OUT = 136        # __u32 tcpi_segs_out
_OFF_SEGS_IN = 140         # __u32 tcpi_segs_in

_TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
    5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
    9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING",
}


@dataclass
class DiagSocket:
    proto: str
    family: int
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    inode: int
    uid: int
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int


def _align4(n: int) -> int:
    return (n + 3) & ~3


def _build_request(family: int, seq: int = 1) -> bytes:
    # struct inet_diag_req_v2: family, protocol, ext, pad, states + sockid(48B)
    body = struct.pack("=BBBBI", family, socket.IPPROTO_TCP, _EXT_INFO, 0, _ALL_STATES)
    body += b"\x00" * 48
    msg_len = 16 + len(body)
    header = struct.pack(
        "=IHHII", msg_len, SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP, seq, 0,
    )
    return header + body


def _parse_tcp_info(info: bytes):
    n = len(info)
    sent = recv = ps = pr = 0
    if n >= _OFF_BYTES_ACKED + 8:
        sent = struct.unpack_from("=Q", info, _OFF_BYTES_ACKED)[0]
    if n >= _OFF_BYTES_RECEIVED + 8:
        recv = struct.unpack_from("=Q", info, _OFF_BYTES_RECEIVED)[0]
    if n >= _OFF_SEGS_OUT + 4:
        ps = struct.unpack_from("=I", info, _OFF_SEGS_OUT)[0]
    if n >= _OFF_SEGS_IN + 4:
        pr = struct.unpack_from("=I", info, _OFF_SEGS_IN)[0]
    return sent, recv, ps, pr


def _decode_addr(family: int, raw: bytes) -> str:
    try:
        if family == socket.AF_INET:
            return socket.inet_ntop(socket.AF_INET, raw[:4])
        return socket.inet_ntop(socket.AF_INET6, raw[:16])
    except (OSError, ValueError):
        return ""


def _parse_messages(buf: bytes, out: List[DiagSocket]) -> bool:
    """Parse one netlink buffer; return True when the dump is complete."""

    off = 0
    total = len(buf)
    while off + 16 <= total:
        msg_len, msg_type, _flags, _seq, _pid = struct.unpack_from("=IHHII", buf, off)
        if msg_len < 16 or off + msg_len > total:
            break
        payload = buf[off + 16: off + msg_len]
        if msg_type in (NLMSG_DONE, NLMSG_ERROR):
            return True
        if len(payload) >= 72:
            fam = payload[0]
            state = payload[1]
            sport, dport = struct.unpack_from("!HH", payload, 4)
            src_raw = payload[8:24]
            dst_raw = payload[24:40]
            uid = struct.unpack_from("=I", payload, 64)[0]
            inode = struct.unpack_from("=I", payload, 68)[0]

            sent = recv = ps = pr = 0
            pos = 72
            plen = len(payload)
            while pos + 4 <= plen:
                rta_len, rta_type = struct.unpack_from("=HH", payload, pos)
                if rta_len < 4:
                    break
                if rta_type == INET_DIAG_INFO:
                    sent, recv, ps, pr = _parse_tcp_info(payload[pos + 4: pos + rta_len])
                pos += _align4(rta_len)

            if state != _TCP_LISTEN and dport != 0:
                out.append(DiagSocket(
                    proto="tcp", family=fam,
                    local_ip=_decode_addr(fam, src_raw), local_port=sport,
                    remote_ip=_decode_addr(fam, dst_raw), remote_port=dport,
                    state=_TCP_STATES.get(state, str(state)),
                    inode=inode, uid=uid,
                    bytes_sent=sent, bytes_recv=recv,
                    packets_sent=ps, packets_recv=pr,
                ))
        off += _align4(msg_len)
    return False


def _dump_family(family: int, timeout: float = 2.0) -> List[DiagSocket]:
    out: List[DiagSocket] = []
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG)
    try:
        sock.settimeout(timeout)
        sock.sendto(_build_request(family), (0, 0))
        while True:
            try:
                buf = sock.recv(1 << 20)
            except socket.timeout:
                break
            if not buf or _parse_messages(buf, out):
                break
    finally:
        sock.close()
    return out


def read_tcp_diag() -> List[DiagSocket]:
    """Return all IPv4/IPv6 TCP sockets with per-socket byte/packet counters."""

    result: List[DiagSocket] = []
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            result.extend(_dump_family(family))
        except OSError:
            continue
    return result


_available: Optional[bool] = None


def available() -> bool:
    """True if the sock_diag netlink interface responds (cached)."""

    global _available
    if _available is None:
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG)
            try:
                sock.settimeout(1.0)
                sock.sendto(_build_request(socket.AF_INET), (0, 0))
                sock.recv(65535)
            finally:
                sock.close()
            _available = True
        except OSError:
            _available = False
    return _available
