"""Windows edge builder: IP Helper connections -> normalized edges.

The Windows-native equivalent of the Linux socket/conntrack path in
``Collector.build_edges``. Reuses the shared flow normalization, service
identification, DoH detection and DNS/SNI enrichment; only the connection source
(IP Helper) and process attribution (winprocess) differ.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from ...catalog import identify_service
from ...conntrack import ConntrackEntry
from ...flows import normalize_entries
from ...store import EdgeObservation
from . import iphlp, winprocess


def build_edges(collector) -> List[EdgeObservation]:
    conns = iphlp.snapshot()

    local_ips: Set[str] = {"127.0.0.1", "::1"}
    listening_ports: Set[int] = set()
    listen_pid: Dict[Tuple[str, int], int] = {}
    pid_map: Dict[Tuple[str, str, int, str, int], int] = {}
    entries: List[ConntrackEntry] = []
    have_bytes = False

    for c in conns:
        if c.local_ip and c.local_ip not in ("0.0.0.0", "::"):
            local_ips.add(c.local_ip)
        if c.is_listening:
            listening_ports.add(c.local_port)
            listen_pid.setdefault((c.proto, c.local_port), c.pid)
            continue
        if not c.remote_ip or c.remote_ip in ("0.0.0.0", "::") or c.remote_port == 0:
            continue
        if c.bytes_sent or c.bytes_recv:
            have_bytes = True
        entries.append(ConntrackEntry(
            l4proto=c.proto, state=c.state,
            orig_src=c.local_ip, orig_dst=c.remote_ip,
            orig_sport=c.local_port, orig_dport=c.remote_port,
            orig_bytes=c.bytes_sent, orig_packets=0,
            reply_src=c.remote_ip, reply_dst=c.local_ip,
            reply_sport=c.remote_port, reply_dport=c.local_port,
            reply_bytes=c.bytes_recv, reply_packets=0,
        ))
        pid_map[(c.proto, c.local_ip, c.local_port, c.remote_ip, c.remote_port)] = c.pid

    flows = normalize_entries(entries, local_ips, listening_ports, collector.classifier)

    def resolve_pid(flow) -> Optional[int]:
        if flow.direction in ("inbound", "loopback"):
            key = (flow.proto, flow.local_ip, flow.service_port, flow.peer_ip, flow.peer_port)
            return pid_map.get(key) or listen_pid.get((flow.proto, flow.service_port))
        key = (flow.proto, flow.local_ip, flow.local_port, flow.peer_ip, flow.peer_port)
        return pid_map.get(key)

    aggregated: Dict[Tuple, Dict[str, object]] = {}
    pids: Set[int] = set()
    for flow in flows:
        pid = resolve_pid(flow)
        if pid:
            pids.add(pid)
        key = flow.key()
        agg = aggregated.get(key)
        if agg is None:
            aggregated[key] = {"flow": flow, "bytes": flow.bytes, "packets": flow.packets, "pid": pid}
        else:
            agg["bytes"] += flow.bytes
            agg["packets"] += flow.packets
            if not agg["pid"] and pid:
                agg["pid"] = pid

    processes = winprocess.collect_processes(list(pids))

    edges: List[EdgeObservation] = []
    for agg in aggregated.values():
        flow = agg["flow"]
        proc = processes.get(agg["pid"]) if agg["pid"] else None
        identity = identify_service(flow.service_port, collector.signatures, proc)

        peer_domain = None
        if collector.dns_monitor is not None:
            peer_domain = collector.dns_monitor.lookup(flow.peer_ip)
        if peer_domain is None and collector.sni_monitor is not None:
            peer_domain = collector.sni_monitor.lookup(flow.peer_ip)

        l7 = identity.l7_protocol
        doh = collector.doh_signatures.classify(flow.peer_ip, flow.service_port, peer_domain)
        if doh and flow.peer_class == "external":
            l7 = doh

        data_quality = None if have_bytes else "socket-snapshot"

        edges.append(EdgeObservation(
            proto=flow.proto, direction=flow.direction,
            local_ip=flow.local_ip, peer_ip=flow.peer_ip,
            service_port=flow.service_port, peer_class=flow.peer_class,
            snapshot_bytes=agg["bytes"], snapshot_packets=agg["packets"],
            service_side=flow.service_side,
            service_name=identity.service_name,
            process_comm=proc.comm if proc else None,
            process_exe=proc.exe if proc else None,
            unit=proc.unit if proc else None,
            l7_protocol=l7, data_quality=data_quality,
            peer_domain=peer_domain, netns="host",
        ))
    return edges
