"""Windows collection loop (polling IP Helper + Job Object + ACL + posture).

Reuses the shared core (Store, ResourceGovernor, disk enforcement, run/coverage
stats, HTML report, DNS/SNI enrichment) with Windows capture and resource
control. Kept separate from the Linux ``run_loop`` (systemd/sysctl/netlink) to
keep each platform path clean.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

log = logging.getLogger("commatrix.win.runloop")


def run(config, iterations: Optional[int] = None) -> None:
    from ...collector import Collector, resolve_host, _enforce_disk
    from ...resources import ResourceGovernor
    from ...store import Store
    from .. import lower_priority
    from . import winetw, winresources, winsni

    collector = Collector(config)
    collector.capture_backend = "iphlp"
    host = resolve_host(config)
    store = Store(config.database, event_min_gap=config.event_min_gap_seconds)
    collector.refresh_host_params(store, host)
    run_id = store.start_run(host)

    governor = ResourceGovernor(
        cpu_budget=config.cpu_budget, disk_budget=config.disk_budget,
        min_free_disk=config.min_free_disk, min_interval=max(1.0, config.poll_interval),
    )
    lower_priority()
    winresources.apply_job_limits(config.cpu_budget_percent * governor.ncpu, config.memory_max_mb)

    log.info(
        "commatrix collector started for host %s (db=%s, capture=iphlp, cpu<=%.0f%% of %d cores)",
        host, config.database, config.cpu_budget_percent, governor.ncpu,
    )

    # Optional DNS logging (DNS-Client channel) and SNI capture.
    dns_monitor = None
    if config.dns_enabled and winetw.available():
        dns_monitor = winetw.WinDnsMonitor(poll_interval=max(2.0, config.poll_interval))
        dns_monitor.start()
        collector.dns_monitor = dns_monitor
        log.info("DNS query logging enabled via DNS-Client event channel")

    sni_monitor = None
    if config.sni_enabled and winsni.available():
        sni_monitor = winsni.WinSniMonitor(interface=config.sni_interface, ports=tuple(config.sni_ports))
        sni_monitor.start()
        collector.sni_monitor = sni_monitor
        log.info("SNI capture enabled (SIO_RCVALL); note: ECH hides SNI")

    count = 0
    try:
        while iterations is None or count < iterations:
            start = time.time()
            paused = _enforce_disk(config, store, governor)
            if not paused:
                edges = collector.build_edges([])  # dispatches to windows capture
                n = store.record_edges(host, edges, now=start)
                log.debug("poll %d recorded %d edges", count, n)
                for mon in (dns_monitor, sni_monitor):
                    if mon is not None:
                        evs = mon.drain()
                        if evs:
                            store.record_dns_events(host, [e.to_row() for e in evs])
            store.heartbeat_run(run_id, now=start)
            if count % 60 == 0 and count > 0:
                collector.refresh_host_params(store, host)
            count += 1
            if iterations is not None and count >= iterations:
                break
            time.sleep(governor.throttle_sleep(0.0, time.time() - start, config.poll_interval))
    except KeyboardInterrupt:
        log.info("collector interrupted; shutting down")
    finally:
        if dns_monitor is not None:
            dns_monitor.stop()
        if sni_monitor is not None:
            sni_monitor.stop()
        store.finish_run(run_id)
        if config.html_report:
            from ... import report as rp
            out_path = config.html_report_path or rp.default_html_report_path(config.database)
            try:
                rp.write_html_report(store, out_path)
                log.info("HTML report written to %s", out_path)
            except OSError as exc:
                log.warning("failed to write HTML report to %s: %s", out_path, exc)
        store.close()
