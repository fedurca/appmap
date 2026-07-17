"""Collection orchestration: tie conntrack, sockets, processes and catalog
signatures together, then persist aggregated edges to the store.
"""

from __future__ import annotations

import atexit
import logging
import signal
import socket as _socket
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from . import conntrack as ct
from . import dns as dnsmod
from . import dohcheck
from . import resources as rsrc
from .catalog import Signatures, identify_service, load_signatures
from .config import Config
from .flows import NetworkClassifier, NormalizedFlow, local_ips_from_sockets, normalize_entries
from .processes import ProcessInfo, collect_processes
from .sockets import SocketEntry, build_inode_to_pid, listening_port_map, read_all_sockets
from .store import EdgeObservation, Store
from .zabbix import collect_host_params

log = logging.getLogger("commatrix.collector")

# key -> aggregated snapshot values while building one poll's result.
_AggKey = Tuple[str, str, str, str, int]


@dataclass
class _Agg:
    flow: NormalizedFlow
    snapshot_bytes: int = 0
    snapshot_packets: int = 0
    pid: Optional[int] = None


class Collector:
    def __init__(self, config: Config):
        self.config = config
        self.classifier = NetworkClassifier(config.internal_cidrs)
        self.signatures: Signatures = load_signatures(config.signatures_dir)
        self._dns_cache: Dict[str, Optional[str]] = {}
        self._accounting_warned = False
        self.capture_backend = ct.capture_backend(config.source)
        # Optional DNS monitor used to annotate peers with the resolved domain.
        self.dns_monitor: Optional["dnsmod.DnsMonitor"] = None

    # -- socket / process context --------------------------------------
    def _socket_indexes(
        self, sockets: List[SocketEntry]
    ) -> Tuple[Dict[Tuple[str, str, int, str, int], int], Dict[Tuple[str, int], int]]:
        inode_to_pid = build_inode_to_pid()
        established: Dict[Tuple[str, str, int, str, int], int] = {}
        listening: Dict[Tuple[str, int], int] = {}
        for s in sockets:
            pid = inode_to_pid.get(s.inode)
            if pid is None:
                continue
            if s.is_listening:
                listening.setdefault((s.proto, s.local_port), pid)
            else:
                established[
                    (s.proto, s.local_ip, s.local_port, s.remote_ip, s.remote_port)
                ] = pid
        return established, listening

    def _resolve_pid(
        self,
        flow: NormalizedFlow,
        established: Dict[Tuple[str, str, int, str, int], int],
        listening: Dict[Tuple[str, int], int],
    ) -> Optional[int]:
        if flow.direction in ("inbound", "loopback"):
            key = (flow.proto, flow.local_ip, flow.service_port, flow.peer_ip, flow.peer_port)
            pid = established.get(key)
            if pid is not None:
                return pid
            return listening.get((flow.proto, flow.service_port))
        if flow.direction == "outbound":
            key = (flow.proto, flow.local_ip, flow.local_port, flow.peer_ip, flow.peer_port)
            return established.get(key)
        return None

    def _reverse_dns(self, ip: str) -> Optional[str]:
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        name: Optional[str] = None
        old_timeout = _socket.getdefaulttimeout()
        try:
            _socket.setdefaulttimeout(1.0)
            name = _socket.gethostbyaddr(ip)[0]
        except (OSError, IndexError):
            name = None
        finally:
            _socket.setdefaulttimeout(old_timeout)
        self._dns_cache[ip] = name
        return name

    # -- one poll ------------------------------------------------------
    def build_edges(self, entries: List[ct.ConntrackEntry]) -> List[EdgeObservation]:
        sockets = read_all_sockets()
        local_ips = local_ips_from_sockets(sockets)
        listening_ports = set(listening_port_map(sockets).keys())
        established_idx, listening_idx = self._socket_indexes(sockets)

        flows = normalize_entries(entries, local_ips, listening_ports, self.classifier)

        # Aggregate over ephemeral ports; attach owning pid per (pre-agg) flow.
        aggregated: Dict[_AggKey, _Agg] = {}
        pids_needed: Set[int] = set()
        for flow in flows:
            pid = self._resolve_pid(flow, established_idx, listening_idx)
            if pid is not None:
                pids_needed.add(pid)
            key = flow.key()
            agg = aggregated.get(key)
            if agg is None:
                aggregated[key] = _Agg(
                    flow=flow,
                    snapshot_bytes=flow.bytes,
                    snapshot_packets=flow.packets,
                    pid=pid,
                )
            else:
                agg.snapshot_bytes += flow.bytes
                agg.snapshot_packets += flow.packets
                if agg.pid is None and pid is not None:
                    agg.pid = pid

        processes = collect_processes(list(pids_needed))
        accounting = ct.accounting_enabled()
        if not accounting and not self._accounting_warned:
            log.warning(
                "nf_conntrack accounting is disabled; byte/packet counts will be "
                "zero. Enable with: sysctl -w net.netfilter.nf_conntrack_acct=1"
            )
            self._accounting_warned = True

        edges: List[EdgeObservation] = []
        for key, agg in aggregated.items():
            flow = agg.flow
            proc: Optional[ProcessInfo] = processes.get(agg.pid) if agg.pid else None
            identity = identify_service(flow.service_port, self.signatures, proc)

            peer_name = None
            if self.config.resolve_external and flow.peer_class == "external":
                peer_name = self._reverse_dns(flow.peer_ip)

            # Domain the peer IP was resolved from (via the DNS monitor), kept
            # as a separate field alongside the raw IP.
            peer_domain = None
            if self.dns_monitor is not None:
                peer_domain = self.dns_monitor.lookup(flow.peer_ip)

            data_quality = None
            if self.capture_backend == "sockets":
                data_quality = "socket-snapshot"
            elif self.capture_backend == "socket-diag":
                # Real per-socket byte counts (TCP). UDP has none but that is
                # inherent, not a capture limitation, so leave it unflagged.
                data_quality = None
            elif not accounting or (agg.snapshot_bytes == 0 and agg.snapshot_packets == 0):
                data_quality = "no-accounting"

            edges.append(
                EdgeObservation(
                    proto=flow.proto,
                    direction=flow.direction,
                    local_ip=flow.local_ip,
                    peer_ip=flow.peer_ip,
                    service_port=flow.service_port,
                    peer_class=flow.peer_class,
                    snapshot_bytes=agg.snapshot_bytes,
                    snapshot_packets=agg.snapshot_packets,
                    service_side=flow.service_side,
                    peer_name=peer_name,
                    service_name=identity.service_name,
                    process_comm=proc.comm if proc else None,
                    process_exe=proc.exe if proc else None,
                    unit=proc.unit if proc else None,
                    package=proc.package if proc else None,
                    container_id=proc.container_id if proc else None,
                    l7_protocol=identity.l7_protocol,
                    data_quality=data_quality,
                    peer_domain=peer_domain,
                )
            )
        return edges

    def poll_once(self, store: Store, host: str, now: Optional[float] = None) -> int:
        try:
            entries = ct.read_conntrack_snapshot(self.config.source)
        except PermissionError:
            log.error(
                "cannot read conntrack data: root privileges are required"
            )
            raise
        except FileNotFoundError as exc:
            log.error("%s", exc)
            raise
        except RuntimeError as exc:
            log.error("%s", exc)
            raise
        edges = self.build_edges(entries)
        return store.record_edges(host, edges, now=now)

    def refresh_host_params(self, store: Store, host: str) -> None:
        params = collect_host_params(
            self.config.agent_conf,
            zabbix_get_bin=self.config.zabbix_get,
            hostname_override=self.config.hostname,
        )
        # Enrich with the host's DoH posture (disabled/enforced?).
        try:
            params.update(dohcheck.host_params())
        except Exception as exc:  # noqa: BLE001 - posture is best-effort
            log.debug("DoH posture check failed: %s", exc)
        store.upsert_host(host, params)


def resolve_host(config: Config) -> str:
    from .zabbix import parse_agent_config, resolve_hostname

    agent_cfg = parse_agent_config(config.agent_conf)
    return resolve_hostname(agent_cfg, config.hostname)


def _enforce_disk(config: Config, store: Store, governor: rsrc.ResourceGovernor) -> bool:
    """Apply retention + disk budget. Returns True if writes should be paused."""

    if config.retention_days > 0:
        cutoff = time.time() - config.retention_days * 86400
        removed = store.prune_older_than(cutoff)
        if removed:
            log.info("retention: pruned %d edges older than %.0f days", removed, config.retention_days)
        removed_events = store.prune_events_older_than(cutoff)
        if removed_events:
            log.info(
                "retention: pruned %d IR events older than %.0f days",
                removed_events, config.retention_days,
            )
        removed_dns = store.prune_dns_events_older_than(cutoff)
        if removed_dns:
            log.info(
                "retention: pruned %d DNS events older than %.0f days",
                removed_dns, config.retention_days,
            )

    status = governor.disk_status(config.database, store.db_size_bytes())
    if status.over_budget:
        removed = store.prune_to_budget(status.budget_bytes)
        log.warning(
            "disk budget exceeded (db=%d B > budget=%d B); pruned %d edges",
            status.db_bytes, status.budget_bytes, removed,
        )
        status = governor.disk_status(config.database, store.db_size_bytes())

    if governor.should_pause_writes(status):
        log.warning(
            "free disk %.1f%% below floor %.1f%%; pausing writes this cycle",
            status.free_fraction * 100, config.min_free_disk * 100,
        )
        return True
    return False


def _install_restore_handlers(guard: "ct.SysctlGuard") -> None:
    """Ensure sysctls are restored on SIGTERM/SIGHUP and at interpreter exit.

    SIGINT already raises KeyboardInterrupt (handled by the loop's finally).
    systemd's ``systemctl stop`` sends SIGTERM, which by default terminates the
    process without running ``finally`` blocks; we convert it (and SIGHUP) into
    KeyboardInterrupt so the normal shutdown/restore path runs.  ``atexit`` is a
    last-resort belt-and-braces (it does not run on SIGKILL / power loss, which
    is why the state file also enables recovery on the next start).
    """

    def _raise_interrupt(signum, _frame):
        raise KeyboardInterrupt

    for signame in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, signame, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _raise_interrupt)
        except (ValueError, OSError):
            # Not in the main thread (e.g. under a test harness); skip.
            pass

    atexit.register(guard.restore)


def run_loop(config: Config, iterations: Optional[int] = None) -> None:
    """Run the collection loop.  ``iterations=None`` runs forever.

    The loop is governed by :class:`resources.ResourceGovernor` so it never
    averages more than ``cpu_budget`` of total compute and never lets the
    database exceed ``disk_budget`` of free space.
    """

    collector = Collector(config)
    host = resolve_host(config)
    store = Store(config.database, event_min_gap=config.event_min_gap_seconds)
    collector.refresh_host_params(store, host)
    run_id = store.start_run(host)

    governor = rsrc.ResourceGovernor(
        cpu_budget=config.cpu_budget,
        disk_budget=config.disk_budget,
        min_free_disk=config.min_free_disk,
        min_interval=max(1.0, config.poll_interval),
    )
    rsrc.lower_priority()

    # Turn on byte/packet accounting + flow timestamps for the duration of the
    # run and restore the host's original settings on exit (see SysctlGuard).
    accounting = ct.SysctlGuard(state_file=config.sysctl_state_file)
    accounting.apply()
    _install_restore_handlers(accounting)

    if accounting.recovered_stale:
        log.info(
            "recovered nf_conntrack sysctls from a previous unclean shutdown (%s)",
            config.sysctl_state_file,
        )
    if not accounting.available:
        log.warning(
            "nf_conntrack sysctls unavailable (%s); the module is likely not "
            "loaded (try: modprobe nf_conntrack). Byte/packet counts will be zero",
            ", ".join(accounting.unavailable) or "none readable",
        )
    elif accounting.enable_failed:
        log.warning(
            "could not enable nf_conntrack sysctls despite them being present; "
            "root privileges are required to write them"
        )
    elif accounting.changed:
        log.info(
            "enabled nf_conntrack sysctls for this run (%s; will restore on exit)",
            ", ".join(sorted(accounting.changed)),
        )
    else:
        log.debug("nf_conntrack sysctls already enabled; leaving as-is")

    count = 0
    backend = ct.capture_backend(config.source)
    log.info(
        "commatrix collector started for host %s (db=%s, capture=%s, cpu<=%.0f%% of %d cores, disk<=%.0f%% free)",
        host, config.database, backend, config.cpu_budget_percent, governor.ncpu, config.disk_budget_percent,
    )
    if backend == "sockets":
        log.info(
            "using /proc/net/{tcp,udp} fallback (no nf_conntrack procfs, no "
            "conntrack tool, no sock_diag); byte/packet counts will be zero"
        )
    elif backend == "socket-diag":
        log.info(
            "using sock_diag netlink for per-socket TCP byte/packet accounting "
            "(no nf_conntrack/conntrack-tools needed)"
        )

    # Optional DNS query logging via the systemd-resolved monitor.
    dns_monitor: Optional[dnsmod.DnsMonitor] = None
    if config.dns_enabled:
        if dnsmod.monitor_available():
            dns_monitor = dnsmod.DnsMonitor()
            dns_monitor.start()
            if config.dns_enrich_flows:
                collector.dns_monitor = dns_monitor
            log.info(
                "DNS query logging enabled via systemd-resolved monitor%s "
                "(note: apps using their own DoH/DoT bypass this)",
                " with flow enrichment" if config.dns_enrich_flows else "",
            )
        else:
            log.info(
                "DNS logging requested but the systemd-resolved monitor is "
                "unavailable (needs systemd-resolved active, systemd >= 247); "
                "DNS logging disabled"
            )

    try:
        while iterations is None or count < iterations:
            start = time.time()
            cpu_before = rsrc.process_cpu_seconds()

            # Enforce disk limits before writing anything.
            paused = _enforce_disk(config, store, governor)

            try:
                if paused:
                    # Still read (cheap) so timing/CPU accounting is realistic,
                    # but skip recording to protect the disk.
                    ct.read_conntrack_snapshot(config.source)
                    n = 0
                else:
                    n = collector.poll_once(store, host, now=start)
                log.debug("poll %d recorded %d edges", count, n)
                if dns_monitor is not None and not paused:
                    events = dns_monitor.drain()
                    if events:
                        store.record_dns_events(host, [e.to_row() for e in events])
                        log.debug("recorded %d DNS events", len(events))
            except (PermissionError, FileNotFoundError):
                break

            store.heartbeat_run(run_id, now=start)
            if count % 60 == 0 and count > 0:
                collector.refresh_host_params(store, host)
            count += 1
            if iterations is not None and count >= iterations:
                break

            elapsed = time.time() - start
            cpu_used = rsrc.process_cpu_seconds() - cpu_before
            sleep_for = governor.throttle_sleep(cpu_used, elapsed, config.poll_interval)
            log.debug(
                "poll took %.3fs (cpu %.3fs); sleeping %.2fs", elapsed, cpu_used, sleep_for
            )
            time.sleep(sleep_for)
    except KeyboardInterrupt:
        log.info("collector interrupted; shutting down")
    finally:
        if dns_monitor is not None:
            dns_monitor.stop()
        store.finish_run(run_id)
        if config.html_report:
            from . import report as rp

            out_path = config.html_report_path or rp.default_html_report_path(config.database)
            try:
                rp.write_html_report(store, out_path)
                log.info("HTML report written to %s", out_path)
            except OSError as exc:
                log.warning("failed to write HTML report to %s: %s", out_path, exc)
        store.close()
        if accounting.changed:
            accounting.restore()
            if accounting.changed:
                log.warning(
                    "failed to restore nf_conntrack sysctls (%s) to their original state",
                    ", ".join(sorted(accounting.changed)),
                )
            else:
                log.info("restored nf_conntrack sysctls to their original state")
