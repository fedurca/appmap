"""Event-driven conntrack capture via the kernel's nfnetlink event socket.

Subscribes to the ``NFNLGRP_CONNTRACK_{NEW,UPDATE,DESTROY}`` netlink multicast
groups (``NETLINK_NETFILTER``) and parses nfnetlink conntrack messages -- the
same event stream ``conntrack -E`` exposes, but with **no external package**
(pure standard-library netlink, like :mod:`commatrix.sockdiag`).

Why event-driven: snapshot polling of ``/proc/net/nf_conntrack`` misses flows
that are created *and* destroyed between two polls (fast C2 check-ins). Reading
the event stream continuously captures those: DESTROY events carry the final
byte/packet counters, so short flows are not lost.

Requires root / CAP_NET_ADMIN (binding conntrack multicast groups is
privileged). When denied or unavailable it degrades gracefully.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
from typing import Dict, List, Optional, Tuple

from .conntrack import ConntrackEntry

log = logging.getLogger("commatrix.ctnetlink")

NETLINK_NETFILTER = 12
NFNL_SUBSYS_CTNETLINK = 1
IPCTNL_MSG_CT_NEW = 0
IPCTNL_MSG_CT_DELETE = 2

# Multicast groups: NEW=1, UPDATE=2, DESTROY=3 -> nl_groups bitmask (1<<(g-1)).
_GROUPS_MASK = 0x7

NLMSG_NOOP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3

_NLA_TYPE_MASK = 0x3FFF

# Top-level conntrack attributes.
CTA_TUPLE_ORIG = 1
CTA_TUPLE_REPLY = 2
CTA_PROTOINFO = 4
CTA_COUNTERS_ORIG = 9
CTA_COUNTERS_REPLY = 10
# Tuple sub-attributes.
CTA_TUPLE_IP = 1
CTA_TUPLE_PROTO = 2
CTA_IP_V4_SRC = 1
CTA_IP_V4_DST = 2
CTA_IP_V6_SRC = 3
CTA_IP_V6_DST = 4
CTA_PROTO_NUM = 1
CTA_PROTO_SRC_PORT = 2
CTA_PROTO_DST_PORT = 3
# Counter sub-attributes.
CTA_COUNTERS_PACKETS = 1
CTA_COUNTERS_BYTES = 2
# Protoinfo (TCP state).
CTA_PROTOINFO_TCP = 1
CTA_PROTOINFO_TCP_STATE = 1

_L4_NAMES = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6", 132: "sctp", 33: "dccp", 47: "gre"}
_TCP_STATES = {
    0: "NONE", 1: "SYN_SENT", 2: "SYN_RECV", 3: "ESTABLISHED", 4: "FIN_WAIT",
    5: "CLOSE_WAIT", 6: "LAST_ACK", 7: "TIME_WAIT", 8: "CLOSE", 9: "SYN_SENT2",
}


def _align4(n: int) -> int:
    return (n + 3) & ~3


def parse_attrs(data: bytes) -> Dict[int, bytes]:
    """Parse a flat netlink attribute (nlattr) list into {type: payload}."""

    attrs: Dict[int, bytes] = {}
    pos = 0
    n = len(data)
    while pos + 4 <= n:
        la, lt = struct.unpack_from("=HH", data, pos)
        if la < 4 or pos + la > n:
            break
        attrs[lt & _NLA_TYPE_MASK] = data[pos + 4: pos + la]
        pos += _align4(la)
    return attrs


def _decode_ip(ip_attrs: Dict[int, bytes], family: int) -> Tuple[str, str]:
    def dec(v4_key, v6_key):
        if family == socket.AF_INET and v4_key in ip_attrs:
            try:
                return socket.inet_ntop(socket.AF_INET, ip_attrs[v4_key][:4])
            except OSError:
                return ""
        if family == socket.AF_INET6 and v6_key in ip_attrs:
            try:
                return socket.inet_ntop(socket.AF_INET6, ip_attrs[v6_key][:16])
            except OSError:
                return ""
        return ""
    return dec(CTA_IP_V4_SRC, CTA_IP_V6_SRC), dec(CTA_IP_V4_DST, CTA_IP_V6_DST)


def _u16(data: Optional[bytes]) -> Optional[int]:
    return struct.unpack("!H", data[:2])[0] if data and len(data) >= 2 else None


def _counter(data: Optional[bytes]) -> int:
    if not data:
        return 0
    if len(data) >= 8:
        return struct.unpack("!Q", data[:8])[0]
    if len(data) >= 4:
        return struct.unpack("!I", data[:4])[0]
    return 0


def _tuple_fields(tuple_attrs: Dict[int, bytes], family: int):
    ip = parse_attrs(tuple_attrs.get(CTA_TUPLE_IP, b""))
    proto = parse_attrs(tuple_attrs.get(CTA_TUPLE_PROTO, b""))
    src, dst = _decode_ip(ip, family)
    proto_num = proto[CTA_PROTO_NUM][0] if CTA_PROTO_NUM in proto and proto[CTA_PROTO_NUM] else None
    sport = _u16(proto.get(CTA_PROTO_SRC_PORT))
    dport = _u16(proto.get(CTA_PROTO_DST_PORT))
    return src, dst, sport, dport, proto_num


def parse_ct_message(msgtype: int, payload: bytes) -> Optional[ConntrackEntry]:
    """Parse one nfnetlink conntrack message body into a :class:`ConntrackEntry`.

    ``payload`` is the message body after the 16-byte nlmsghdr (i.e. starts with
    ``nfgenmsg``). ``msgtype`` is the low byte of the netlink message type.
    """

    if len(payload) < 4:
        return None
    family = payload[0]  # nfgenmsg.nfgen_family
    attrs = parse_attrs(payload[4:])
    if CTA_TUPLE_ORIG not in attrs:
        return None

    orig = parse_attrs(attrs[CTA_TUPLE_ORIG])
    o_src, o_dst, o_sport, o_dport, proto_num = _tuple_fields(orig, family)

    r_src = r_dst = None
    r_sport = r_dport = None
    if CTA_TUPLE_REPLY in attrs:
        reply = parse_attrs(attrs[CTA_TUPLE_REPLY])
        r_src, r_dst, r_sport, r_dport, _ = _tuple_fields(reply, family)

    o_counters = parse_attrs(attrs.get(CTA_COUNTERS_ORIG, b""))
    r_counters = parse_attrs(attrs.get(CTA_COUNTERS_REPLY, b""))
    orig_bytes = _counter(o_counters.get(CTA_COUNTERS_BYTES))
    orig_packets = _counter(o_counters.get(CTA_COUNTERS_PACKETS))
    reply_bytes = _counter(r_counters.get(CTA_COUNTERS_BYTES))
    reply_packets = _counter(r_counters.get(CTA_COUNTERS_PACKETS))

    state = None
    if CTA_PROTOINFO in attrs:
        pinfo = parse_attrs(attrs[CTA_PROTOINFO])
        if CTA_PROTOINFO_TCP in pinfo:
            tcp = parse_attrs(pinfo[CTA_PROTOINFO_TCP])
            sdata = tcp.get(CTA_PROTOINFO_TCP_STATE)
            if sdata:
                state = _TCP_STATES.get(sdata[0], str(sdata[0]))

    event = "DESTROY" if msgtype == IPCTNL_MSG_CT_DELETE else "NEW"
    return ConntrackEntry(
        l4proto=_L4_NAMES.get(proto_num, "unknown") if proto_num is not None else "unknown",
        state=state,
        orig_src=o_src, orig_dst=o_dst, orig_sport=o_sport, orig_dport=o_dport,
        orig_bytes=orig_bytes, orig_packets=orig_packets,
        reply_src=r_src, reply_dst=r_dst, reply_sport=r_sport, reply_dport=r_dport,
        reply_bytes=reply_bytes, reply_packets=reply_packets,
        event=event,
    )


def parse_messages(buf: bytes) -> List[ConntrackEntry]:
    """Parse a raw netlink buffer into a list of conntrack entries."""

    out: List[ConntrackEntry] = []
    off = 0
    total = len(buf)
    while off + 16 <= total:
        msg_len, msg_type, _flags, _seq, _pid = struct.unpack_from("=IHHII", buf, off)
        if msg_len < 16 or off + msg_len > total:
            break
        if msg_type in (NLMSG_DONE, NLMSG_NOOP, NLMSG_ERROR):
            off += _align4(msg_len)
            continue
        subsys = (msg_type >> 8) & 0xFF
        subtype = msg_type & 0xFF
        if subsys == NFNL_SUBSYS_CTNETLINK:
            entry = parse_ct_message(subtype, buf[off + 16: off + msg_len])
            if entry is not None:
                out.append(entry)
        off += _align4(msg_len)
    return out


def _open_socket() -> socket.socket:
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    sock.bind((0, _GROUPS_MASK))  # subscribe to conntrack event groups
    return sock


def available() -> bool:
    """True if we can subscribe to conntrack netlink events (needs root)."""

    try:
        sock = _open_socket()
        sock.close()
        return True
    except OSError:
        return False


def _flow_key(e: ConntrackEntry) -> Tuple[str, str, str, int, int]:
    return (e.l4proto, e.orig_src, e.orig_dst, e.orig_sport or 0, e.orig_dport or 0)


class ConntrackEventListener(threading.Thread):
    """Background thread accumulating conntrack events for periodic draining.

    Keeps the latest counters for each active flow (NEW/UPDATE) and, for flows
    destroyed since the last drain, their final counters (so short-lived flows
    are captured). :meth:`drain` returns the union and clears the destroyed set.
    """

    def __init__(self):
        super().__init__(name="commatrix-ctnetlink", daemon=True)
        self._lock = threading.Lock()
        self._active: Dict[Tuple, ConntrackEntry] = {}
        self._destroyed: List[ConntrackEntry] = []
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self.auth_failed = False

    def drain(self) -> List[ConntrackEntry]:
        with self._lock:
            entries = list(self._active.values()) + self._destroyed
            self._destroyed = []
        return entries

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def _record(self, entry: ConntrackEntry) -> None:
        key = _flow_key(entry)
        if not entry.orig_src or not entry.orig_dst:
            return
        with self._lock:
            if entry.event == "DESTROY":
                self._active.pop(key, None)
                self._destroyed.append(entry)
                # Bound memory under a flood.
                if len(self._destroyed) > 50000:
                    self._destroyed = self._destroyed[-50000:]
            else:
                self._active[key] = entry
                if len(self._active) > 200000:
                    self._active.clear()

    def run(self) -> None:
        try:
            sock = _open_socket()
        except OSError as exc:
            self.auth_failed = True
            log.warning(
                "event-driven conntrack capture unavailable: cannot subscribe to "
                "netlink conntrack events (%s). Needs root/CAP_NET_ADMIN; falling "
                "back to polling.", exc,
            )
            return
        self._sock = sock
        try:
            sock.settimeout(2.0)
            # Larger receive buffer helps avoid ENOBUFS under bursts.
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            except OSError:
                pass
            while not self._stop.is_set():
                try:
                    buf = sock.recv(1 << 20)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if self._stop.is_set():
                        break
                    log.debug("ctnetlink recv error: %s", exc)
                    continue
                if not buf:
                    continue
                for entry in parse_messages(buf):
                    self._record(entry)
        finally:
            self._sock = None
            try:
                sock.close()
            except OSError:
                pass
