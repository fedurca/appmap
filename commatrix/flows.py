"""Normalize raw conntrack entries into stable communication edges.

A conntrack entry contains ephemeral client ports which would otherwise explode
the number of distinct rows.  We fold each connection onto a *service edge*
keyed by the stable (listening) side, and determine the direction relative to
the local host.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from .conntrack import ConntrackEntry
from .sockets import SocketEntry

Direction = str  # "inbound" | "outbound" | "loopback" | "other"
PeerClass = str  # "internal" | "external" | "loopback"


@dataclass
class NormalizedFlow:
    proto: str
    direction: Direction
    local_ip: str
    peer_ip: str
    service_port: int
    local_port: int
    peer_port: int
    peer_class: PeerClass
    bytes: int
    packets: int
    service_side: str  # "local" (we serve) | "peer" (we consume) | "unknown"
    state: Optional[str] = None

    def key(self) -> Tuple[str, str, str, str, int]:
        return (self.proto, self.direction, self.local_ip, self.peer_ip, self.service_port)


class NetworkClassifier:
    """Classify peer addresses as internal or external."""

    def __init__(self, internal_cidrs: Iterable[str]):
        self._nets = []
        for cidr in internal_cidrs:
            try:
                self._nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue

    def classify(self, ip: str) -> PeerClass:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "external"
        if addr.is_loopback:
            return "loopback"
        for net in self._nets:
            if addr.version == net.version and addr in net:
                return "internal"
        return "external"


def local_ips_from_sockets(sockets: Sequence[SocketEntry]) -> Set[str]:
    """Derive the set of local host IPs from bound sockets.

    Wildcard binds (0.0.0.0 / ::) are ignored; loopback is always included.
    """

    ips: Set[str] = {"127.0.0.1", "::1"}
    for s in sockets:
        ip = s.local_ip
        if ip in ("0.0.0.0", "::", ""):
            continue
        ips.add(ip)
    return ips


def normalize_entry(
    entry: ConntrackEntry,
    local_ips: Set[str],
    listening_ports: Set[int],
    classifier: NetworkClassifier,
) -> Optional[NormalizedFlow]:
    """Fold one conntrack entry into a :class:`NormalizedFlow`.

    Returns ``None`` when the entry cannot be attributed to the local host
    (e.g. pure forwarded traffic with no local endpoint and no listening match).
    """

    proto = entry.l4proto
    src, dst = entry.orig_src, entry.orig_dst
    sport = entry.orig_sport or 0
    dport = entry.orig_dport or 0

    src_local = src in local_ips
    dst_local = dst in local_ips

    total_bytes = entry.total_bytes
    total_packets = entry.total_packets

    # Loopback (both ends local, or classifier says loopback).
    if src_local and dst_local and (
        classifier.classify(src) == "loopback" or classifier.classify(dst) == "loopback"
    ):
        return NormalizedFlow(
            proto=proto,
            direction="loopback",
            local_ip=dst,
            peer_ip=src,
            service_port=dport,
            local_port=dport,
            peer_port=sport,
            peer_class="loopback",
            bytes=total_bytes,
            packets=total_packets,
            service_side="local",
            state=entry.state,
        )

    inbound = False
    outbound = False

    if dst_local and (dport in listening_ports or not local_ips):
        inbound = True
    elif src_local:
        outbound = True
    elif dst_local:
        # local destination but not a known listening port; still inbound.
        inbound = True
    elif not local_ips:
        # No local IP knowledge: assume the lower/known port is the service.
        if dport in listening_ports:
            inbound = True
        else:
            outbound = True

    if inbound:
        return NormalizedFlow(
            proto=proto,
            direction="inbound",
            local_ip=dst,
            peer_ip=src,
            service_port=dport,
            local_port=dport,
            peer_port=sport,
            peer_class=classifier.classify(src),
            bytes=total_bytes,
            packets=total_packets,
            service_side="local",
            state=entry.state,
        )
    if outbound:
        return NormalizedFlow(
            proto=proto,
            direction="outbound",
            local_ip=src,
            peer_ip=dst,
            service_port=dport,
            local_port=sport,
            peer_port=dport,
            peer_class=classifier.classify(dst),
            bytes=total_bytes,
            packets=total_packets,
            service_side="peer",
            state=entry.state,
        )

    return None


def normalize_entries(
    entries: Iterable[ConntrackEntry],
    local_ips: Set[str],
    listening_ports: Set[int],
    classifier: NetworkClassifier,
) -> List[NormalizedFlow]:
    flows: List[NormalizedFlow] = []
    for entry in entries:
        flow = normalize_entry(entry, local_ips, listening_ports, classifier)
        if flow is not None:
            flows.append(flow)
    return flows
