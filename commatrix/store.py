"""SQLite persistence for observed communication edges and host metadata.

The same schema is used for the local per-host database and for the central
aggregated database (rows are distinguished by the ``host`` column).  Only the
standard library :mod:`sqlite3` module is used.

Because ``nf_conntrack`` polling only ever sees a *snapshot* of currently
tracked connections, exact byte accounting is impossible.  We therefore keep a
best-effort cumulative estimate: per poll we sum the bytes of all connections
that fold onto an edge and accumulate the positive delta versus the previous
poll.  "Activity" (a positive byte/packet delta or a re-appearance) drives the
``max_gap`` computation -- the longest idle interval between two communications.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    host TEXT PRIMARY KEY,
    params_json TEXT,
    updated REAL
);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY,
    host TEXT NOT NULL,
    proto TEXT NOT NULL,
    direction TEXT NOT NULL,
    local_ip TEXT NOT NULL,
    peer_ip TEXT NOT NULL,
    service_port INTEGER NOT NULL,
    peer_class TEXT,
    peer_name TEXT,
    bytes INTEGER DEFAULT 0,
    packets INTEGER DEFAULT 0,
    last_snapshot_bytes INTEGER DEFAULT 0,
    last_snapshot_packets INTEGER DEFAULT 0,
    first_seen REAL,
    last_seen REAL,
    last_active REAL,
    max_gap REAL DEFAULT 0,
    observations INTEGER DEFAULT 0,
    service_side TEXT,
    service_name TEXT,
    process_comm TEXT,
    process_exe TEXT,
    unit TEXT,
    package TEXT,
    container_id TEXT,
    l7_protocol TEXT,
    data_quality TEXT,
    UNIQUE (host, proto, direction, local_ip, peer_ip, service_port)
);

CREATE INDEX IF NOT EXISTS idx_flows_host ON flows (host);
CREATE INDEX IF NOT EXISTS idx_flows_service ON flows (host, service_port, direction);
"""


@dataclass
class EdgeObservation:
    """One aggregated edge as seen in a single poll."""

    proto: str
    direction: str
    local_ip: str
    peer_ip: str
    service_port: int
    peer_class: str
    snapshot_bytes: int
    snapshot_packets: int
    service_side: str = "unknown"
    peer_name: Optional[str] = None
    service_name: Optional[str] = None
    process_comm: Optional[str] = None
    process_exe: Optional[str] = None
    unit: Optional[str] = None
    package: Optional[str] = None
    container_id: Optional[str] = None
    l7_protocol: Optional[str] = None
    data_quality: Optional[str] = None


class Store:
    def __init__(self, path: str):
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(_SCHEMA)
        self.conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- host metadata ---------------------------------------------------
    def upsert_host(self, host: str, params: Dict[str, object]) -> None:
        self.conn.execute(
            """
            INSERT INTO hosts (host, params_json, updated)
            VALUES (?, ?, ?)
            ON CONFLICT(host) DO UPDATE SET params_json=excluded.params_json,
                                            updated=excluded.updated
            """,
            (host, json.dumps(params, sort_keys=True), time.time()),
        )
        self.conn.commit()

    def get_host_params(self, host: str) -> Dict[str, object]:
        row = self.conn.execute(
            "SELECT params_json FROM hosts WHERE host=?", (host,)
        ).fetchone()
        if not row or not row["params_json"]:
            return {}
        try:
            return json.loads(row["params_json"])
        except json.JSONDecodeError:
            return {}

    def list_hosts(self) -> List[str]:
        return [r["host"] for r in self.conn.execute("SELECT host FROM hosts ORDER BY host")]

    # -- flow upsert -----------------------------------------------------
    def record_edge(self, host: str, obs: EdgeObservation, now: Optional[float] = None) -> None:
        if now is None:
            now = time.time()

        row = self.conn.execute(
            """
            SELECT bytes, packets, last_snapshot_bytes, last_snapshot_packets,
                   last_active, max_gap, observations
            FROM flows
            WHERE host=? AND proto=? AND direction=? AND local_ip=? AND peer_ip=? AND service_port=?
            """,
            (host, obs.proto, obs.direction, obs.local_ip, obs.peer_ip, obs.service_port),
        ).fetchone()

        if row is None:
            self.conn.execute(
                """
                INSERT INTO flows (
                    host, proto, direction, local_ip, peer_ip, service_port,
                    peer_class, peer_name, bytes, packets, last_snapshot_bytes,
                    last_snapshot_packets, first_seen, last_seen, last_active,
                    max_gap, observations, service_side, service_name,
                    process_comm, process_exe, unit, package, container_id,
                    l7_protocol, data_quality
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    host, obs.proto, obs.direction, obs.local_ip, obs.peer_ip, obs.service_port,
                    obs.peer_class, obs.peer_name, obs.snapshot_bytes, obs.snapshot_packets,
                    obs.snapshot_bytes, obs.snapshot_packets, now, now, now,
                    obs.service_side, obs.service_name, obs.process_comm, obs.process_exe,
                    obs.unit, obs.package, obs.container_id, obs.l7_protocol, obs.data_quality,
                ),
            )
            self.conn.commit()
            return

        prev_bytes = row["bytes"] or 0
        prev_packets = row["packets"] or 0
        last_snapshot_bytes = row["last_snapshot_bytes"] or 0
        last_snapshot_packets = row["last_snapshot_packets"] or 0
        last_active = row["last_active"]
        max_gap = row["max_gap"] or 0.0
        observations = (row["observations"] or 0) + 1

        # Best-effort cumulative estimate from snapshot deltas. A drop in the
        # snapshot counter means old connections closed and new ones started, so
        # the whole new snapshot value counts as fresh traffic.
        byte_delta = (
            obs.snapshot_bytes - last_snapshot_bytes
            if obs.snapshot_bytes >= last_snapshot_bytes
            else obs.snapshot_bytes
        )
        packet_delta = (
            obs.snapshot_packets - last_snapshot_packets
            if obs.snapshot_packets >= last_snapshot_packets
            else obs.snapshot_packets
        )
        new_bytes = prev_bytes + byte_delta
        new_packets = prev_packets + packet_delta

        activity = byte_delta > 0 or packet_delta > 0
        if activity and last_active is not None:
            gap = now - last_active
            if gap > max_gap:
                max_gap = gap
        new_last_active = now if activity else last_active

        self.conn.execute(
            """
            UPDATE flows SET
                peer_class=?, peer_name=COALESCE(?, peer_name),
                bytes=?, packets=?, last_snapshot_bytes=?, last_snapshot_packets=?,
                last_seen=?, last_active=?, max_gap=?, observations=?,
                service_side=?, service_name=COALESCE(?, service_name),
                process_comm=COALESCE(?, process_comm),
                process_exe=COALESCE(?, process_exe),
                unit=COALESCE(?, unit), package=COALESCE(?, package),
                container_id=COALESCE(?, container_id),
                l7_protocol=COALESCE(?, l7_protocol),
                data_quality=?
            WHERE host=? AND proto=? AND direction=? AND local_ip=? AND peer_ip=? AND service_port=?
            """,
            (
                obs.peer_class, obs.peer_name,
                new_bytes, new_packets, obs.snapshot_bytes, obs.snapshot_packets,
                now, new_last_active, max_gap, observations,
                obs.service_side, obs.service_name,
                obs.process_comm, obs.process_exe,
                obs.unit, obs.package, obs.container_id, obs.l7_protocol,
                obs.data_quality,
                host, obs.proto, obs.direction, obs.local_ip, obs.peer_ip, obs.service_port,
            ),
        )
        self.conn.commit()

    def record_edges(self, host: str, edges: Iterable[EdgeObservation], now: Optional[float] = None) -> int:
        if now is None:
            now = time.time()
        count = 0
        for edge in edges:
            self.record_edge(host, edge, now=now)
            count += 1
        return count

    # -- read / export ---------------------------------------------------
    def iter_flows(self, host: Optional[str] = None) -> List[sqlite3.Row]:
        if host:
            return list(
                self.conn.execute("SELECT * FROM flows WHERE host=? ORDER BY id", (host,))
            )
        return list(self.conn.execute("SELECT * FROM flows ORDER BY host, id"))

    def export_dict(self, host: Optional[str] = None) -> Dict[str, object]:
        """Export hosts + flows to a JSON-serialisable dict (for snapshots)."""

        hosts_rows = (
            self.conn.execute("SELECT * FROM hosts WHERE host=?", (host,))
            if host
            else self.conn.execute("SELECT * FROM hosts")
        )
        hosts = []
        for r in hosts_rows:
            try:
                params = json.loads(r["params_json"]) if r["params_json"] else {}
            except json.JSONDecodeError:
                params = {}
            hosts.append({"host": r["host"], "params": params, "updated": r["updated"]})

        flows = [dict(r) for r in self.iter_flows(host)]
        return {"schema_version": SCHEMA_VERSION, "hosts": hosts, "flows": flows}

    def import_dict(self, payload: Dict[str, object]) -> int:
        """Merge an exported snapshot dict into this database.

        Flows are replaced wholesale per (host, edge-key) with the incoming
        values (the source database already holds the authoritative cumulative
        counters for that host).  Returns the number of flow rows merged.
        """

        for host_entry in payload.get("hosts", []):  # type: ignore[union-attr]
            self.upsert_host(host_entry.get("host", "unknown"), host_entry.get("params", {}))

        flows = payload.get("flows", [])  # type: ignore[assignment]
        count = 0
        for f in flows:  # type: ignore[union-attr]
            self.conn.execute(
                """
                INSERT INTO flows (
                    host, proto, direction, local_ip, peer_ip, service_port,
                    peer_class, peer_name, bytes, packets, last_snapshot_bytes,
                    last_snapshot_packets, first_seen, last_seen, last_active,
                    max_gap, observations, service_side, service_name,
                    process_comm, process_exe, unit, package, container_id,
                    l7_protocol, data_quality
                ) VALUES (
                    :host, :proto, :direction, :local_ip, :peer_ip, :service_port,
                    :peer_class, :peer_name, :bytes, :packets, :last_snapshot_bytes,
                    :last_snapshot_packets, :first_seen, :last_seen, :last_active,
                    :max_gap, :observations, :service_side, :service_name,
                    :process_comm, :process_exe, :unit, :package, :container_id,
                    :l7_protocol, :data_quality
                )
                ON CONFLICT (host, proto, direction, local_ip, peer_ip, service_port)
                DO UPDATE SET
                    peer_class=excluded.peer_class,
                    peer_name=excluded.peer_name,
                    bytes=excluded.bytes,
                    packets=excluded.packets,
                    last_snapshot_bytes=excluded.last_snapshot_bytes,
                    first_seen=MIN(flows.first_seen, excluded.first_seen),
                    last_seen=MAX(flows.last_seen, excluded.last_seen),
                    last_active=MAX(flows.last_active, excluded.last_active),
                    max_gap=MAX(flows.max_gap, excluded.max_gap),
                    observations=excluded.observations,
                    service_side=excluded.service_side,
                    service_name=excluded.service_name,
                    process_comm=excluded.process_comm,
                    process_exe=excluded.process_exe,
                    unit=excluded.unit,
                    package=excluded.package,
                    container_id=excluded.container_id,
                    l7_protocol=excluded.l7_protocol,
                    data_quality=excluded.data_quality
                """,
                _flow_row_defaults(f),
            )
            count += 1
        self.conn.commit()
        return count


def _flow_row_defaults(f: Dict[str, object]) -> Dict[str, object]:
    keys = [
        "host", "proto", "direction", "local_ip", "peer_ip", "service_port",
        "peer_class", "peer_name", "bytes", "packets", "last_snapshot_bytes",
        "last_snapshot_packets",
        "first_seen", "last_seen", "last_active", "max_gap", "observations",
        "service_side", "service_name", "process_comm", "process_exe", "unit",
        "package", "container_id", "l7_protocol", "data_quality",
    ]
    return {k: f.get(k) for k in keys}
