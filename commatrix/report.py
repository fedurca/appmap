"""Reporting and documentation outputs.

Turns the aggregated flow database into:

* a communication matrix (CSV / JSON / Markdown),
* a topology diagram (Graphviz DOT and Mermaid),
* per-application "service sheets",
* a machine-readable application catalog (JSON), and
* security highlights,
* a self-contained HTML dashboard with inline SVG traffic graphs.
"""

from __future__ import annotations

import csv
import html
import io
import json
import math
import time
from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

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
        "Bytes", "First seen", "Last seen", "Max gap", "Seen (n)", "Process",
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
                    str(r.get("observations") or 0),
                    str(r.get("process_comm") or ""),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


# -- HTML dashboard (self-contained, inline SVG graphs) --------------------
ChartItem = Tuple[str, float]


def default_html_report_path(database: str) -> str:
    if database.endswith(".db"):
        return database[:-3] + "-report.html"
    return database + "-report.html"


def write_html_report(store: Store, path: str, host: Optional[str] = None) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report_html(store, host))


def _sum_by(rows: List[Dict[str, object]], key: str) -> Dict[str, float]:
    totals: Dict[str, float] = defaultdict(float)
    for row in rows:
        label = str(row.get(key) or "unknown")
        totals[label] += float(row.get("bytes") or 0)
    return dict(totals)


def _top_items(totals: Dict[str, float], limit: int = 10) -> List[ChartItem]:
    return sorted(totals.items(), key=lambda item: item[1], reverse=True)[:limit]


def _svg_bar_chart(title: str, items: Sequence[ChartItem], width: int = 1000, height: int = 460) -> str:
    if not items:
        return (
            f'<svg viewBox="0 0 {width} 120" role="img" aria-label="{html.escape(title)}">'
            f'<text x="16" y="34" font-size="22" font-weight="600">{html.escape(title)}</text>'
            f'<text x="16" y="76" font-size="16" fill="#94a3b8">No data</text></svg>'
        )

    margin = {"top": 52, "right": 24, "bottom": 116, "left": 96}
    plot_w = width - margin["left"] - margin["right"]
    plot_h = height - margin["top"] - margin["bottom"]
    max_val = max(v for _, v in items) or 1.0
    bar_w = plot_w / max(len(items), 1)
    baseline = margin["top"] + plot_h
    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}">',
        f'<text x="{margin["left"]}" y="30" font-size="22" font-weight="700">{html.escape(title)}</text>',
        f'<line x1="{margin["left"]}" y1="{baseline:.1f}" x2="{width - margin["right"]}" '
        f'y2="{baseline:.1f}" stroke="#334155" stroke-width="1"/>',
    ]
    for idx, (label, value) in enumerate(items):
        bar_h = (value / max_val) * plot_h if max_val else 0
        x = margin["left"] + idx * bar_w + bar_w * 0.12
        y = baseline - bar_h
        w = max(bar_w * 0.76, 1)
        cx = x + w / 2
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{bar_h:.1f}" fill="#2563eb" rx="4"/>'
        )
        parts.append(
            f'<text x="{cx:.1f}" y="{baseline + 18:.1f}" font-size="15" fill="#cbd5e1" text-anchor="end" '
            f'transform="rotate(-35 {cx:.1f} {baseline + 18:.1f})">{html.escape(label[:26])}</text>'
        )
        parts.append(
            f'<text x="{cx:.1f}" y="{y - 8:.1f}" font-size="15" font-weight="600" text-anchor="middle">'
            f'{html.escape(human_bytes(value))}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts)


def _svg_pie_chart(title: str, items: Sequence[ChartItem], width: int = 680, height: int = 360) -> str:
    if not items:
        return (
            f'<svg viewBox="0 0 {width} 120" role="img" aria-label="{html.escape(title)}">'
            f'<text x="16" y="34" font-size="22" font-weight="600">{html.escape(title)}</text>'
            f'<text x="16" y="76" font-size="16" fill="#94a3b8">No data</text></svg>'
        )

    cx, cy = 180.0, 200.0
    radius = 130.0
    total = sum(v for _, v in items) or 1.0
    palette = ["#2563eb", "#16a34a", "#dc2626", "#9333ea", "#ea580c", "#0891b2", "#64748b"]
    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}">',
        f'<text x="24" y="34" font-size="22" font-weight="700">{html.escape(title)}</text>',
    ]
    start = -math.pi / 2
    legend_x = 2 * cx + 40
    legend_y = 96
    for idx, (label, value) in enumerate(items):
        angle = (value / total) * 2 * math.pi
        end = start + angle
        color = palette[idx % len(palette)]
        if angle > 0:
            # Full circle needs special handling (arc can't span 360°).
            if angle >= 2 * math.pi - 1e-9:
                parts.append(
                    f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{radius:.1f}" fill="{color}"/>'
                )
            else:
                x1 = cx + radius * math.cos(start)
                y1 = cy + radius * math.sin(start)
                x2 = cx + radius * math.cos(end)
                y2 = cy + radius * math.sin(end)
                large = 1 if angle > math.pi else 0
                parts.append(
                    f'<path d="M {cx:.1f} {cy:.1f} L {x1:.1f} {y1:.1f} A {radius:.1f} {radius:.1f} 0 '
                    f'{large} 1 {x2:.1f} {y2:.1f} Z" fill="{color}"/>'
                )
        pct = (value / total) * 100.0
        ly = legend_y + idx * 34
        parts.append(
            f'<rect x="{legend_x:.1f}" y="{ly - 15:.1f}" width="20" height="20" rx="4" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{legend_x + 30:.1f}" y="{ly:.1f}" font-size="17">'
            f'{html.escape(label)} ({pct:.1f}%, {html.escape(human_bytes(value))})</text>'
        )
        start = end
    parts.append("</svg>")
    return "\n".join(parts)


VT_IP_URL = "https://www.virustotal.com/gui/ip-address/"
VT_DOMAIN_URL = "https://www.virustotal.com/gui/domain/"


def vt_peer_html(row: Dict[str, object]) -> str:
    """Render the peer cell, linking external IoCs to VirusTotal.

    External peers are indicators of compromise candidates, so their IP (and
    reverse-DNS name, if any) become one-click VirusTotal lookups. Internal /
    loopback peers are rendered as plain escaped text.
    """

    peer_ip = str(row.get("peer_ip") or "")
    display = str(row.get("peer_name") or peer_ip)
    if row.get("peer_class") == "external" and peer_ip:
        url = VT_IP_URL + peer_ip
        return (
            f'<a href="{html.escape(url)}" target="_blank" rel="noopener noreferrer" '
            f'title="Check {html.escape(peer_ip)} on VirusTotal">{html.escape(display)} \u2197</a>'
        )
    return html.escape(display)


def _matrix_html_table(rows: List[Dict[str, object]], limit: int = 100) -> str:
    header = [
        "Host", "Dir", "Service", "Port", "Peer", "Class", "Bytes",
        "First seen", "Last seen", "Seen (n)", "Process",
    ]
    lines = ["<table>", "<thead><tr>" + "".join(f"<th>{html.escape(h)}</th>" for h in header) + "</tr></thead>", "<tbody>"]
    for row in sorted(rows, key=lambda x: float(x.get("bytes") or 0), reverse=True)[:limit]:
        # Peer cell is raw HTML (VirusTotal link for external IoCs); the rest
        # are plain escaped values.
        plain_cells = [
            html.escape(str(row.get("host", ""))),
            html.escape(str(row.get("direction", ""))),
            html.escape(str(row.get("service_name", ""))),
            html.escape(str(row.get("service_port", ""))),
            vt_peer_html(row),
            html.escape(str(row.get("peer_class") or "")),
            html.escape(human_bytes(row.get("bytes"))),
            html.escape(fmt_time(row.get("first_seen"))),
            html.escape(fmt_time(row.get("last_seen"))),
            html.escape(str(row.get("observations") or 0)),
            html.escape(str(row.get("process_comm") or "")),
        ]
        lines.append("<tr>" + "".join(f"<td>{c}</td>" for c in plain_cells) + "</tr>")
    lines.extend(["</tbody>", "</table>"])
    return "\n".join(lines)


def _mermaid_body(store: Store) -> str:
    lines = topology_mermaid(store).strip().splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines)


def report_html(store: Store, host: Optional[str] = None) -> str:
    rows = _rows(store, host)
    generated = fmt_time(time.time())
    host_filter = f" (host={host})" if host else ""
    security = security_highlights(store)

    service_items = _top_items(_sum_by(rows, "service_name"))
    peer_items = _top_items(_sum_by(rows, "peer_ip"))
    class_items = _top_items(_sum_by(rows, "peer_class"), limit=6)
    direction_items = _top_items(_sum_by(rows, "direction"), limit=6)
    total_bytes = sum(float(r.get("bytes") or 0) for r in rows)
    total_flows = len(rows)

    # Explain missing volume instead of silently showing 0 B everywhere.
    no_acct = len(security["no_accounting"])
    banner = ""
    if total_flows and total_bytes == 0 and no_acct:
        banner = (
            '<div class="note">&#9888; Byte/packet volume is unavailable: the '
            "active capture backend cannot measure traffic (no nf_conntrack "
            "accounting and no sock_diag). Volume shows as 0&nbsp;B. commatrix "
            "uses sock_diag automatically when available (no install needed); "
            "otherwise enable nf_conntrack with "
            "<code>net.netfilter.nf_conntrack_acct=1</code>.</div>"
        )
    elif no_acct:
        banner = (
            f'<div class="note">&#9888; {no_acct} flow(s) lack byte accounting '
            "(e.g. UDP or socket-snapshot capture); their volume shows as "
            "0&nbsp;B.</div>"
        )

    sec_sections = []
    for title, items in (
        ("External inbound exposure", security["external_inbound"]),
        ("Cleartext external protocols", security["cleartext_external"]),
        ("Flows without byte accounting", security["no_accounting"]),
    ):
        if items:
            lis = "".join(
                f"<li>{html.escape(str(it['host']))} {html.escape(str(it['service']))}:"
                f"{html.escape(str(it['port']))} &lt;-&gt; {vt_peer_html(it)}</li>"
                for it in items
            )
            sec_sections.append(f"<section><h3>{html.escape(title)} ({len(items)})</h3><ul>{lis}</ul></section>")
        else:
            sec_sections.append(f"<section><h3>{html.escape(title)}</h3><p>None observed.</p></section>")

    mermaid = _mermaid_body(store)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Commatrix report{html.escape(host_filter)}</title>
  <style>
    :root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
    body {{ margin: 0; background: #0b1220; color: #e5e7eb; }}
    header, main, footer {{ max-width: 1200px; margin: 0 auto; padding: 1rem 1.25rem; }}
    header {{ border-bottom: 1px solid #334155; }}
    h1, h2, h3 {{ margin: 0 0 .75rem; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; }}
    .card {{ background: #111827; border: 1px solid #334155; border-radius: 12px; padding: 1rem; }}
    .metric {{ font-size: 1.6rem; font-weight: 700; }}
    .charts {{ display: flex; flex-direction: column; gap: 1.5rem; margin: 1rem 0; }}
    .panel {{ background: #111827; border: 1px solid #334155; border-radius: 12px; padding: 1rem 1.25rem; overflow: auto; }}
    .panel svg {{ width: 100%; height: auto; display: block; }}
    .panel.pie {{ max-width: 720px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
    th, td {{ border-bottom: 1px solid #334155; padding: .45rem .5rem; text-align: left; vertical-align: top; }}
    th {{ position: sticky; top: 0; background: #111827; }}
    pre.mermaid {{ background: transparent; white-space: pre-wrap; }}
    .note {{ background: #3f2d0b; border: 1px solid #a16207; color: #fde68a; border-radius: 10px; padding: .75rem 1rem; margin: 1rem 0; }}
    .note code {{ background: rgba(0,0,0,.35); padding: 0 .3rem; border-radius: 4px; }}
    a {{ color: #93c5fd; }}
    footer {{ color: #94a3b8; border-top: 1px solid #334155; }}
  </style>
  <script type="module">
    import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
    mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
  </script>
</head>
<body>
  <header>
    <h1>Commatrix communication report</h1>
    <p>Generated {html.escape(generated)}{html.escape(host_filter)}</p>
  </header>
  <main>
    <section class="cards">
      <div class="card"><div>Flows</div><div class="metric">{total_flows}</div></div>
      <div class="card"><div>Total traffic</div><div class="metric">{html.escape(human_bytes(total_bytes))}</div></div>
      <div class="card"><div>Hosts</div><div class="metric">{len(store.list_hosts())}</div></div>
      <div class="card"><div>Security findings</div><div class="metric">{len(security['external_inbound']) + len(security['cleartext_external'])}</div></div>
    </section>
    {banner}

    <h2>Traffic graphs</h2>
    <div class="charts">
      <div class="panel">{_svg_bar_chart("Top services by bytes", service_items)}</div>
      <div class="panel">{_svg_bar_chart("Top peers by bytes", peer_items)}</div>
      <div class="panel pie">{_svg_pie_chart("Peer class mix", class_items)}</div>
      <div class="panel pie">{_svg_pie_chart("Direction mix", direction_items)}</div>
    </div>

    <h2>Topology</h2>
    <div class="panel"><pre class="mermaid">{mermaid}</pre></div>

    <h2>Communication matrix</h2>
    <div class="panel">{_matrix_html_table(rows)}</div>

    <h2>Security highlights</h2>
    <div class="panel">{''.join(sec_sections)}</div>
  </main>
  <footer>Commatrix HTML report — stdlib collector, inline SVG charts</footer>
</body>
</html>
"""


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
            "peer_ip": r.get("peer_ip"),
            "peer_class": peer_class,
            "l7": l7 or None,
            "direction": direction,
        }
        if direction == "inbound" and peer_class == "external":
            external_inbound.append(summary)
        if peer_class == "external" and l7 in CLEARTEXT_L7:
            cleartext_external.append(summary)
        # Flag flows whose capture backend cannot measure byte volume: both the
        # nf_conntrack "no accounting" case and the /proc socket-snapshot fallback.
        if r.get("data_quality") in ("no-accounting", "socket-snapshot"):
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
        "Byte/packet volume unavailable for these flows. Use a capture backend "
        "that measures volume: sock_diag (automatic, no install) or "
        "nf_conntrack with net.netfilter.nf_conntrack_acct=1.",
    )
    return "\n".join(lines) + "\n"
