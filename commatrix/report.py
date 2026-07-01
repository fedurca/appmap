"""Reporting and documentation outputs.

Turns the aggregated flow database into:

* a communication matrix (CSV / JSON / Markdown),
* a topology diagram (Graphviz DOT and Mermaid),
* per-application "service sheets",
* a machine-readable application catalog (JSON), and
* security highlights.
"""

from __future__ import annotations

import csv
import io
import json
import time
from collections import defaultdict
from typing import Dict, List, Optional

from .store import Store

CLEARTEXT_L7 = {
    "http", "ftp", "telnet", "smtp", "pop3", "imap", "ldap", "snmp",
    "syslog", "tftp", "rsync", "git", "memcached", "redis",
}

MATRIX_COLUMNS = [
    "host", "direction", "local_ip", "service_port", "service_name", "l7_protocol",
    "peer_ip", "peer_name", "peer_class", "bytes", "packets",
    "first_seen", "last_seen", "max_gap", "observations",
    "process_comm", "unit", "package", "container_id", "data_quality",
]


def _rows(store: Store, host: Optional[str] = None) -> List[Dict[str, object]]:
    return [dict(r) for r in store.iter_flows(host)]


def human_bytes(value: Optional[float]) -> str:
    if not value:
        return "0 B"
    num = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024.0
    return f"{num:.1f} EiB"


def fmt_time(ts: Optional[float]) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def fmt_duration(seconds: Optional[float]) -> str:
    if not seconds or seconds <= 0:
        return "0s"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return "".join(parts)


# -- communication matrix ------------------------------------------------
def matrix_json(store: Store, host: Optional[str] = None) -> str:
    rows = _rows(store, host)
    return json.dumps(rows, indent=2, sort_keys=True, default=str)


def matrix_csv(store: Store, host: Optional[str] = None) -> str:
    rows = _rows(store, host)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=MATRIX_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r.get(k, "") for k in MATRIX_COLUMNS})
    return buf.getvalue()


def matrix_markdown(store: Store, host: Optional[str] = None) -> str:
    rows = _rows(store, host)
    lines = ["# Communication matrix", ""]
    header = [
        "Host", "Dir", "Service", "Port", "L7", "Peer", "Class",
        "Bytes", "First seen", "Last seen", "Max gap", "Process",
    ]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join(["---"] * len(header)) + "|")
    for r in sorted(rows, key=lambda x: (str(x.get("host")), str(x.get("direction")), x.get("service_port") or 0)):
        peer = r.get("peer_name") or r.get("peer_ip")
        lines.append(
            "| "
            + " | ".join(
                [
                    str(r.get("host", "")),
                    str(r.get("direction", "")),
                    str(r.get("service_name", "")),
                    str(r.get("service_port", "")),
                    str(r.get("l7_protocol") or ""),
                    str(peer or ""),
                    str(r.get("peer_class") or ""),
                    human_bytes(r.get("bytes")),
                    fmt_time(r.get("first_seen")),
                    fmt_time(r.get("last_seen")),
                    fmt_duration(r.get("max_gap")),
                    str(r.get("process_comm") or ""),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


# -- topology diagrams ---------------------------------------------------
def _ip_to_host(rows: List[Dict[str, object]]) -> Dict[str, str]:
    """Map known local IPs to their host so inter-VM edges can be linked."""

    mapping: Dict[str, str] = {}
    for r in rows:
        if r.get("direction") in ("inbound", "loopback"):
            ip = str(r.get("local_ip"))
            if ip:
                mapping[ip] = str(r.get("host"))
    return mapping


def _node_id(label: str) -> str:
    safe = "".join(ch if ch.isalnum() else "_" for ch in label)
    return "n_" + safe


def topology_dot(store: Store) -> str:
    rows = _rows(store)
    ip_host = _ip_to_host(rows)
    edges = set()
    nodes = set()
    for r in rows:
        host = str(r.get("host"))
        nodes.add(host)
        peer_ip = str(r.get("peer_ip"))
        peer = ip_host.get(peer_ip) or (str(r.get("peer_name")) if r.get("peer_name") else peer_ip)
        nodes.add(peer)
        label = f"{r.get('service_name') or r.get('service_port')}"
        if r.get("direction") == "outbound":
            edges.add((host, peer, label))
        else:  # inbound / loopback -> peer initiates
            edges.add((peer, host, label))

    lines = ["digraph commatrix {", "  rankdir=LR;", '  node [shape=box];']
    for n in sorted(nodes):
        lines.append(f'  {_node_id(n)} [label="{n}"];')
    for src, dst, label in sorted(edges):
        lines.append(f'  {_node_id(src)} -> {_node_id(dst)} [label="{label}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def topology_mermaid(store: Store) -> str:
    rows = _rows(store)
    ip_host = _ip_to_host(rows)
    edges = set()
    for r in rows:
        host = str(r.get("host"))
        peer_ip = str(r.get("peer_ip"))
        peer = ip_host.get(peer_ip) or (str(r.get("peer_name")) if r.get("peer_name") else peer_ip)
        label = f"{r.get('service_name') or r.get('service_port')}"
        if r.get("direction") == "outbound":
            edges.add((host, peer, label))
        else:
            edges.add((peer, host, label))

    lines = ["```mermaid", "flowchart LR"]
    node_ids: Dict[str, str] = {}

    def nid(name: str) -> str:
        if name not in node_ids:
            node_ids[name] = _node_id(name)
        return node_ids[name]

    for name in sorted({n for e in edges for n in (e[0], e[1])}):
        lines.append(f'  {nid(name)}["{name}"]')
    for src, dst, label in sorted(edges):
        lines.append(f'  {nid(src)} -->|"{label}"| {nid(dst)}')
    lines.append("```")
    return "\n".join(lines) + "\n"


# -- application catalog -------------------------------------------------
def build_catalog(store: Store) -> Dict[str, object]:
    """Structured, machine-readable application catalog keyed by host."""

    rows = _rows(store)
    ip_host = _ip_to_host(rows)
    hosts: Dict[str, Dict[str, object]] = {}

    for host in store.list_hosts():
        hosts[host] = {
            "host": host,
            "params": store.get_host_params(host),
            "applications": {},
        }

    def app_bucket(host: str, app: str) -> Dict[str, object]:
        hosts.setdefault(host, {"host": host, "params": {}, "applications": {}})
        apps = hosts[host]["applications"]  # type: ignore[index]
        if app not in apps:  # type: ignore[operator]
            apps[app] = {  # type: ignore[index]
                "name": app,
                "listens": [],
                "callers": [],
                "depends_on": [],
                "l7_protocols": [],
            }
        return apps[app]  # type: ignore[index]

    for r in rows:
        host = str(r.get("host"))
        app = str(r.get("service_name") or f"port-{r.get('service_port')}")
        direction = r.get("direction")
        peer_ip = str(r.get("peer_ip"))
        peer = ip_host.get(peer_ip) or (str(r.get("peer_name")) if r.get("peer_name") else peer_ip)
        l7 = r.get("l7_protocol")

        bucket = app_bucket(host, app)
        if l7 and l7 not in bucket["l7_protocols"]:  # type: ignore[operator,index]
            bucket["l7_protocols"].append(l7)  # type: ignore[union-attr]

        if direction == "inbound":
            listen = {"port": r.get("service_port"), "proto": r.get("proto")}
            if listen not in bucket["listens"]:  # type: ignore[operator,index]
                bucket["listens"].append(listen)  # type: ignore[union-attr]
            bucket["callers"].append(  # type: ignore[union-attr]
                {
                    "peer": peer,
                    "peer_class": r.get("peer_class"),
                    "bytes": r.get("bytes"),
                    "last_seen": r.get("last_seen"),
                    "max_gap": r.get("max_gap"),
                }
            )
        elif direction == "outbound":
            bucket["depends_on"].append(  # type: ignore[union-attr]
                {
                    "peer": peer,
                    "port": r.get("service_port"),
                    "service": r.get("service_name"),
                    "peer_class": r.get("peer_class"),
                    "bytes": r.get("bytes"),
                    "last_seen": r.get("last_seen"),
                    "max_gap": r.get("max_gap"),
                }
            )

    return {
        "generated": time.time(),
        "generated_human": fmt_time(time.time()),
        "hosts": list(hosts.values()),
    }


def catalog_json(store: Store) -> str:
    return json.dumps(build_catalog(store), indent=2, sort_keys=True, default=str)


def service_sheets(store: Store) -> str:
    """Human-readable per-application documentation (Markdown)."""

    catalog = build_catalog(store)
    lines = ["# Application catalog", "", f"Generated: {catalog['generated_human']}", ""]
    for host_entry in sorted(catalog["hosts"], key=lambda h: str(h["host"])):  # type: ignore[index,arg-type]
        host = host_entry["host"]  # type: ignore[index]
        params = host_entry.get("params", {})  # type: ignore[union-attr]
        lines.append(f"## Host: {host}")
        uname = params.get("system.uname") or params.get("os.system")
        if uname:
            lines.append(f"- System: {uname}")
        if params.get("host_metadata"):
            lines.append(f"- Zabbix metadata: {params.get('host_metadata')}")
        lines.append("")

        apps = host_entry.get("applications", {})  # type: ignore[union-attr]
        if not apps:
            lines.append("_No applications observed._\n")
            continue
        for app_name in sorted(apps):  # type: ignore[union-attr]
            app = apps[app_name]  # type: ignore[index]
            lines.append(f"### {app_name}")
            l7 = ", ".join(app.get("l7_protocols") or []) or "-"  # type: ignore[union-attr]
            lines.append(f"- Layer-7: {l7}")
            listens = app.get("listens") or []  # type: ignore[union-attr]
            if listens:
                ports = ", ".join(f"{l['proto']}/{l['port']}" for l in listens)
                lines.append(f"- Listens on: {ports}")
            callers = app.get("callers") or []  # type: ignore[union-attr]
            if callers:
                lines.append("- Called by:")
                for c in _dedupe_peers(callers):
                    lines.append(
                        f"    - {c['peer']} ({c['peer_class']}), {human_bytes(c['bytes'])}, "
                        f"last {fmt_time(c['last_seen'])}, max gap {fmt_duration(c['max_gap'])}"
                    )
            deps = app.get("depends_on") or []  # type: ignore[union-attr]
            if deps:
                lines.append("- Depends on:")
                for d in _dedupe_peers(deps):
                    svc = d.get("service") or d.get("port")
                    lines.append(
                        f"    - {d['peer']}:{d.get('port')} ({svc}, {d['peer_class']}), "
                        f"{human_bytes(d['bytes'])}, last {fmt_time(d['last_seen'])}"
                    )
            lines.append("")
    return "\n".join(lines) + "\n"


def _dedupe_peers(items: List[Dict[str, object]]) -> List[Dict[str, object]]:
    seen = {}
    for it in items:
        key = (it.get("peer"), it.get("port"))
        if key not in seen:
            seen[key] = it
    return list(seen.values())


# -- security highlights -------------------------------------------------
def security_highlights(store: Store) -> Dict[str, List[Dict[str, object]]]:
    rows = _rows(store)
    external_inbound: List[Dict[str, object]] = []
    cleartext_external: List[Dict[str, object]] = []
    no_accounting: List[Dict[str, object]] = []

    for r in rows:
        l7 = str(r.get("l7_protocol") or "")
        peer_class = r.get("peer_class")
        direction = r.get("direction")
        summary = {
            "host": r.get("host"),
            "service": r.get("service_name"),
            "port": r.get("service_port"),
            "peer": r.get("peer_name") or r.get("peer_ip"),
            "l7": l7 or None,
            "direction": direction,
        }
        if direction == "inbound" and peer_class == "external":
            external_inbound.append(summary)
        if peer_class == "external" and l7 in CLEARTEXT_L7:
            cleartext_external.append(summary)
        if r.get("data_quality") == "no-accounting":
            no_accounting.append(summary)

    return {
        "external_inbound": external_inbound,
        "cleartext_external": cleartext_external,
        "no_accounting": no_accounting,
    }


def security_markdown(store: Store) -> str:
    data = security_highlights(store)
    lines = ["# Security highlights", ""]

    def section(title: str, items: List[Dict[str, object]], desc: str) -> None:
        lines.append(f"## {title} ({len(items)})")
        lines.append(desc)
        if not items:
            lines.append("- None observed.")
        for it in items:
            lines.append(
                f"- {it['host']} {it['service']}:{it['port']} <-> {it['peer']} "
                f"[{it.get('l7') or '-'}]"
            )
        lines.append("")

    section(
        "External inbound exposure",
        data["external_inbound"],
        "Services reachable from external (non-internal) peers.",
    )
    section(
        "Cleartext protocols with external peers",
        data["cleartext_external"],
        "Unencrypted protocols observed talking to external peers.",
    )
    section(
        "Flows without byte accounting",
        data["no_accounting"],
        "Enable net.netfilter.nf_conntrack_acct=1 to capture byte/packet counts.",
    )
    return "\n".join(lines) + "\n"
