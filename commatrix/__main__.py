"""Command line interface for commatrix.

Subcommands:

* ``collect``     -- poll nf_conntrack and record edges into the local DB.
* ``export``      -- write a JSON snapshot of the local DB.
* ``push``        -- export and POST a snapshot to a central collector server.
* ``serve``       -- run the central HTTP collector server.
* ``aggregate``   -- merge snapshots / databases into a central DB.
* ``report``      -- generate matrix / catalog / diagram / security outputs.
* ``hostparams``  -- print resolved Zabbix host parameters (debug / UserParameter).
* ``diff``        -- drift report between two JSON snapshots.
* ``history``     -- print the append-only IR event log (edge first-seen /
  reactivation timeline).
* ``dns``         -- print the DNS query log (from the system resolver monitor).
* ``doh``         -- report the host's DNS-over-HTTPS posture (disabled/enforced?).
* ``time``        -- report time-sync posture and clock offset (NTP accuracy).
* ``restore-sysctls`` -- restore nf_conntrack sysctls from the persisted state
  file (used by the systemd ExecStopPost hook / crash recovery).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import urllib.request
from typing import List, Optional

from . import __version__
from .config import load_config


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-c", "--config", help="path to commatrix.conf")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")


def _write_output(text: str, output: Optional[str]) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)


def cmd_collect(args: argparse.Namespace) -> int:
    import os

    from .collector import run_loop
    from .conntrack import is_root, running_under_systemd

    log = logging.getLogger("commatrix")
    config = load_config(args.config)
    if args.database:
        config.database = args.database

    # Root is optional: by default the collector runs unprivileged (topology is
    # still captured). Only hard-require root when asked (flag or config), e.g.
    # when full sysctl accounting / cross-user attribution is mandatory.
    require_root = args.require_root or config.require_root
    if require_root and not is_root():
        log.warning(
            "root required (--require-root/require_root set) but running as "
            "uid=%d; refusing to start",
            os.geteuid(),
        )
        return 1

    # By design commatrix is run as a systemd service (which also enforces the
    # CPU/memory limits, capabilities and sysctl restore). Refuse to run
    # otherwise unless explicitly overridden for labs/testing.
    if not running_under_systemd() and not args.allow_manual:
        log.warning(
            "commatrix collect is intended to run as a systemd service; not "
            "started by systemd (no INVOCATION_ID) and --allow-manual not given "
            "- doing nothing"
        )
        return 0

    if not is_root():
        log.info(
            "running unprivileged (uid=%d): topology is captured; toggling "
            "nf_conntrack sysctls and attributing other users' processes need "
            "CAP_NET_ADMIN / CAP_DAC_READ_SEARCH (or root)",
            os.geteuid(),
        )

    iterations = 1 if args.once else args.iterations
    run_loop(config, iterations=iterations)
    return 0


def cmd_restore_sysctls(args: argparse.Namespace) -> int:
    from .conntrack import DEFAULT_SYSCTL_STATE_FILE, SysctlGuard

    config = load_config(args.config)
    state_file = args.state_file or getattr(
        config, "sysctl_state_file", DEFAULT_SYSCTL_STATE_FILE
    )
    restored = SysctlGuard.restore_from_file(state_file)
    log = logging.getLogger("commatrix")
    if restored:
        log.info("restored nf_conntrack sysctls from %s", state_file)
    else:
        log.debug("no nf_conntrack sysctls to restore (%s)", state_file)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from .aggregate import export_snapshot

    config = load_config(args.config)
    db = args.database or config.database
    out = args.output or "-"
    if out == "-":
        from .store import Store

        store = Store(db, read_only=True)
        try:
            payload = store.export_dict(args.host)
        finally:
            store.close()
        _write_output(json.dumps(payload, indent=2, sort_keys=True, default=str), None)
    else:
        export_snapshot(db, out, args.host)
        logging.getLogger("commatrix").info("snapshot written to %s", out)
    return 0


def cmd_push(args: argparse.Namespace) -> int:
    from .store import Store

    config = load_config(args.config)
    db = args.database or config.database
    store = Store(db)
    try:
        payload = store.export_dict(args.host)
    finally:
        store.close()

    data = json.dumps(payload, default=str).encode("utf-8")
    url = args.server.rstrip("/") + "/ingest"
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if args.token:
        req.add_header("X-Commatrix-Token", args.token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            logging.getLogger("commatrix").info("push ok: %s", body)
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("commatrix").error("push failed: %s", exc)
        return 1
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .collector_server import serve

    config = load_config(args.config)
    db = args.database or config.database
    serve(db, host=args.host, port=args.port, token=args.token)
    return 0


def cmd_aggregate(args: argparse.Namespace) -> int:
    from .aggregate import aggregate_databases, aggregate_snapshots, discover_snapshots

    total = 0
    if args.snapshot_dir:
        total += aggregate_snapshots(args.central, discover_snapshots(args.snapshot_dir))
    if args.snapshots:
        total += aggregate_snapshots(args.central, args.snapshots)
    if args.databases:
        total += aggregate_databases(args.central, args.databases)
    logging.getLogger("commatrix").info("aggregated %d flow rows into %s", total, args.central)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from . import report as rp
    from .store import Store

    config = load_config(args.config)
    db = args.database or config.database
    store = Store(db, read_only=True)
    try:
        fmt = args.format
        if fmt == "csv":
            text = rp.matrix_csv(store, args.host)
        elif fmt == "json":
            text = rp.matrix_json(store, args.host)
        elif fmt == "markdown":
            text = rp.matrix_markdown(store, args.host)
        elif fmt == "mermaid":
            text = rp.topology_mermaid(store)
        elif fmt == "dot":
            text = rp.topology_dot(store)
        elif fmt == "catalog":
            text = rp.catalog_json(store)
        elif fmt == "sheets":
            text = rp.service_sheets(store)
        elif fmt == "security":
            text = rp.security_markdown(store)
        elif fmt == "html":
            text = rp.report_html(store, args.host)
        else:  # pragma: no cover - argparse restricts choices
            raise ValueError(fmt)
    finally:
        store.close()
    _write_output(text, args.output)
    return 0


def cmd_hostparams(args: argparse.Namespace) -> int:
    from .zabbix import collect_host_params

    config = load_config(args.config)
    params = collect_host_params(
        config.agent_conf,
        zabbix_get_bin=config.zabbix_get,
        hostname_override=config.hostname,
    )
    _write_output(json.dumps(params, indent=2, sort_keys=True, default=str) + "\n", args.output)
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    """Print the append-only IR event log (edge first-seen / reactivation)."""

    import time as _time

    from .store import Store

    config = load_config(args.config)
    db = args.database or config.database
    since = None
    if args.since_seconds:
        since = _time.time() - args.since_seconds
    store = Store(db, read_only=True)
    try:
        rows = [dict(r) for r in store.iter_events(
            host=args.host, since=since, kind=args.kind, limit=args.limit
        )]
    finally:
        store.close()

    if args.format == "jsonl":
        text = "".join(json.dumps(r, default=str) + "\n" for r in rows)
    else:  # markdown
        header = "| Time | Host | Kind | Dir | Service | Port | L7 | Peer | Class | Process | Idle gap |"
        sep = "|---|---|---|---|---|---|---|---|---|---|---|"
        lines = [header, sep]
        for r in rows:
            ts = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(r.get("ts") or 0))
            lines.append(
                "| {ts} | {host} | {kind} | {direction} | {service_name} | {service_port} | "
                "{l7_protocol} | {peer_ip} | {peer_class} | {process_comm} | {idle:.0f}s |".format(
                    ts=ts,
                    host=r.get("host", ""),
                    kind=r.get("kind", ""),
                    direction=r.get("direction", "") or "",
                    service_name=r.get("service_name", "") or "",
                    service_port=r.get("service_port", "") or "",
                    l7_protocol=r.get("l7_protocol", "") or "",
                    peer_ip=r.get("peer_ip", "") or "",
                    peer_class=r.get("peer_class", "") or "",
                    process_comm=r.get("process_comm", "") or "",
                    idle=float(r.get("idle_gap") or 0),
                )
            )
        text = "\n".join(lines) + "\n"
    _write_output(text, args.output)
    return 0


def cmd_dns(args: argparse.Namespace) -> int:
    """Print the append-only DNS query log."""

    import time as _time

    from .store import Store

    config = load_config(args.config)
    db = args.database or config.database
    since = _time.time() - args.since_seconds if args.since_seconds else None
    store = Store(db, read_only=True)
    try:
        rows = [dict(r) for r in store.iter_dns_events(
            host=args.host, since=since, qname=args.qname, limit=args.limit
        )]
    finally:
        store.close()

    if args.format == "jsonl":
        text = "".join(json.dumps(r, default=str) + "\n" for r in rows)
    else:
        lines = ["| Time | Host | Query | Type | Rcode | Answers |",
                 "|---|---|---|---|---|---|"]
        for r in rows:
            ts = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(r.get("ts") or 0))
            lines.append(
                f"| {ts} | {r.get('host','')} | {r.get('qname') or ''} | "
                f"{r.get('qtype') or ''} | {r.get('rcode') or ''} | {r.get('answers') or ''} |"
            )
        text = "\n".join(lines) + "\n"
    _write_output(text, args.output)
    return 0


def cmd_doh(args: argparse.Namespace) -> int:
    """Report the host's DNS-over-HTTPS posture (disabled/enforced?)."""

    from . import dohcheck

    if args.format == "json":
        text = json.dumps(dohcheck.doh_posture(), indent=2, default=str) + "\n"
    else:
        text = dohcheck.markdown()
    _write_output(text, args.output)
    # Non-zero exit if DoH is enabled somewhere (useful for monitoring/CI).
    return 2 if dohcheck.doh_posture().get("doh_enabled_anywhere") else 0


def cmd_time(args: argparse.Namespace) -> int:
    """Report the host's time-sync posture and clock offset."""

    from . import timecheck

    config = load_config(args.config)
    server = args.server or config.ntp_check_server
    if args.format == "json":
        text = json.dumps(timecheck.ntp_posture(server), indent=2, default=str) + "\n"
    else:
        text = timecheck.markdown(server)
    _write_output(text, args.output)
    posture = timecheck.ntp_posture(server)
    # Non-zero exit if the clock is unsynced or materially off (for monitoring).
    off = posture.get("offset_seconds")
    bad = (not posture.get("synchronized")) or (
        off is not None and abs(float(off)) > timecheck.LARGE_OFFSET_SECONDS
    )
    return 2 if bad else 0


def cmd_diff(args: argparse.Namespace) -> int:
    from .catalog import diff_edges

    with open(args.baseline, "r", encoding="utf-8") as fh:
        baseline = json.load(fh).get("flows", [])
    with open(args.current, "r", encoding="utf-8") as fh:
        current = json.load(fh).get("flows", [])
    report = diff_edges(baseline, current)
    out = {
        "added": [list(k) for k in report.added],
        "removed": [list(k) for k in report.removed],
        "common_count": len(report.common),
        "has_changes": report.has_changes,
    }
    _write_output(json.dumps(out, indent=2, default=str) + "\n", args.output)
    return 0 if not report.has_changes else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="commatrix", description=__doc__)
    parser.add_argument("--version", action="version", version=f"commatrix {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_collect = sub.add_parser("collect", help="poll nf_conntrack and record edges")
    _add_common(p_collect)
    p_collect.add_argument("--database", help="override database path")
    p_collect.add_argument("--iterations", type=int, default=None, help="stop after N polls")
    p_collect.add_argument("--once", action="store_true", help="run a single poll and exit")
    p_collect.add_argument(
        "--allow-manual",
        action="store_true",
        help="allow running outside systemd (labs/testing)",
    )
    p_collect.add_argument(
        "--require-root",
        action="store_true",
        help="refuse to start unless running as root",
    )
    p_collect.set_defaults(func=cmd_collect)

    p_restore = sub.add_parser(
        "restore-sysctls",
        help="restore nf_conntrack sysctls from the persisted state file (ExecStopPost)",
    )
    _add_common(p_restore)
    p_restore.add_argument(
        "--state-file", help="path to the persisted sysctl state file"
    )
    p_restore.set_defaults(func=cmd_restore_sysctls)

    p_export = sub.add_parser("export", help="export a JSON snapshot")
    _add_common(p_export)
    p_export.add_argument("--database", help="override database path")
    p_export.add_argument("--host", help="restrict to a single host")
    p_export.add_argument("-o", "--output", help="output file (default stdout)")
    p_export.set_defaults(func=cmd_export)

    p_push = sub.add_parser("push", help="push a snapshot to a central server")
    _add_common(p_push)
    p_push.add_argument("--database", help="override database path")
    p_push.add_argument("--host", help="restrict to a single host")
    p_push.add_argument("--server", required=True, help="central server base URL, e.g. http://host:8899")
    p_push.add_argument("--token", help="shared token (X-Commatrix-Token)")
    p_push.set_defaults(func=cmd_push)

    p_serve = sub.add_parser("serve", help="run the central collector server")
    _add_common(p_serve)
    p_serve.add_argument("--database", help="central database path")
    p_serve.add_argument("--host", default="0.0.0.0", help="bind address")
    p_serve.add_argument("--port", type=int, default=8899, help="bind port")
    p_serve.add_argument("--token", help="require this shared token")
    p_serve.set_defaults(func=cmd_serve)

    p_agg = sub.add_parser("aggregate", help="merge snapshots/databases into a central DB")
    _add_common(p_agg)
    p_agg.add_argument("--central", required=True, help="central database path")
    p_agg.add_argument("--snapshot-dir", dest="snapshot_dir", help="dir of *.json snapshots")
    p_agg.add_argument("--snapshots", nargs="*", help="snapshot files")
    p_agg.add_argument("--databases", nargs="*", help="per-host sqlite databases")
    p_agg.set_defaults(func=cmd_aggregate)

    p_report = sub.add_parser("report", help="generate reports and diagrams")
    _add_common(p_report)
    p_report.add_argument("--database", help="database path")
    p_report.add_argument("--host", help="restrict matrix to a host")
    p_report.add_argument(
        "-f",
        "--format",
        required=True,
        choices=["csv", "json", "markdown", "mermaid", "dot", "catalog", "sheets", "security", "html"],
    )
    p_report.add_argument("-o", "--output", help="output file (default stdout)")
    p_report.set_defaults(func=cmd_report)

    p_hp = sub.add_parser("hostparams", help="print resolved Zabbix host parameters")
    _add_common(p_hp)
    p_hp.add_argument("-o", "--output", help="output file (default stdout)")
    p_hp.set_defaults(func=cmd_hostparams)

    p_hist = sub.add_parser("history", help="print the append-only IR event log")
    _add_common(p_hist)
    p_hist.add_argument("--database", help="database path")
    p_hist.add_argument("--host", help="restrict to a single host")
    p_hist.add_argument("--kind", choices=["new", "reactivated"], help="filter by event kind")
    p_hist.add_argument("--since-seconds", type=float, help="only events newer than N seconds")
    p_hist.add_argument("--limit", type=int, default=200, help="max rows (default 200)")
    p_hist.add_argument("-f", "--format", choices=["markdown", "jsonl"], default="markdown")
    p_hist.add_argument("-o", "--output", help="output file (default stdout)")
    p_hist.set_defaults(func=cmd_history)

    p_dns = sub.add_parser("dns", help="print the DNS query log")
    _add_common(p_dns)
    p_dns.add_argument("--database", help="database path")
    p_dns.add_argument("--host", help="restrict to a single host")
    p_dns.add_argument("--qname", help="filter by query name substring")
    p_dns.add_argument("--since-seconds", type=float, help="only events newer than N seconds")
    p_dns.add_argument("--limit", type=int, default=200, help="max rows (default 200)")
    p_dns.add_argument("-f", "--format", choices=["markdown", "jsonl"], default="markdown")
    p_dns.add_argument("-o", "--output", help="output file (default stdout)")
    p_dns.set_defaults(func=cmd_dns)

    p_doh = sub.add_parser("doh", help="report DNS-over-HTTPS posture (disabled/enforced?)")
    _add_common(p_doh)
    p_doh.add_argument("-f", "--format", choices=["markdown", "json"], default="markdown")
    p_doh.add_argument("-o", "--output", help="output file (default stdout)")
    p_doh.set_defaults(func=cmd_doh)

    p_time = sub.add_parser("time", help="report time-sync posture and clock offset")
    _add_common(p_time)
    p_time.add_argument("--server", help="NTP server for an active SNTP offset probe (UDP/123)")
    p_time.add_argument("-f", "--format", choices=["markdown", "json"], default="markdown")
    p_time.add_argument("-o", "--output", help="output file (default stdout)")
    p_time.set_defaults(func=cmd_time)

    p_diff = sub.add_parser("diff", help="drift report between two snapshots")
    _add_common(p_diff)
    p_diff.add_argument("baseline", help="baseline snapshot JSON")
    p_diff.add_argument("current", help="current snapshot JSON")
    p_diff.add_argument("-o", "--output", help="output file (default stdout)")
    p_diff.set_defaults(func=cmd_diff)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(getattr(args, "verbose", False))
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
