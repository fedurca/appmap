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

SCHEMA_VERSION = 3

# Restrictive permissions: the database is a full internal network map and must
# not be world-readable.
DB_FILE_MODE = 0o640
DB_DIR_MODE = 0o750

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
    peer_domain TEXT,
    UNIQUE (host, proto, direction, local_ip, peer_ip, service_port)
);

CREATE INDEX IF NOT EXISTS idx_flows_host ON flows (host);
CREATE INDEX IF NOT EXISTS idx_flows_service ON flows (host, service_port, direction);

-- Append-only event log for incident response: a timeline of when edges first
-- appeared and when they became active again after being idle. Never updated,
-- only inserted (and pruned by retention/disk budget).
CREATE TABLE IF NOT EXISTS flow_events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    host TEXT NOT NULL,
    kind TEXT NOT NULL,            -- 'new' | 'reactivated'
    proto TEXT,
    direction TEXT,
    local_ip TEXT,
    peer_ip TEXT,
    service_port INTEGER,
    peer_class TEXT,
    peer_name TEXT,
    service_name TEXT,
    l7_protocol TEXT,
    process_comm TEXT,
    process_exe TEXT,
    bytes_delta INTEGER DEFAULT 0,
    packets_delta INTEGER DEFAULT 0,
    idle_gap REAL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON flow_events (ts);
CREATE INDEX IF NOT EXISTS idx_events_host ON flow_events (host, ts);

-- Append-only DNS query log (from the system resolver monitor). Gives the
-- actual names looked up and the addresses returned, for IR and for enriching
-- flows with the domain a peer IP was resolved from.
CREATE TABLE IF NOT EXISTS dns_events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    host TEXT NOT NULL,
    qname TEXT,
    qtype TEXT,
    rcode TEXT,
    answers TEXT,          -- comma-separated resolved addresses
    source TEXT            -- e.g. resolved-monitor
);

CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_events (ts);
CREATE INDEX IF NOT EXISTS idx_dns_host ON dns_events (host, ts);
CREATE INDEX IF NOT EXISTS idx_dns_qname ON dns_events (qname);
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
    peer_domain: Optional[str] = None


class Store:
    def __init__(
        self,
        path: str,
        read_only: bool = False,
        event_min_gap: float = 60.0,
    ):
        self.path = path
        self.read_only = read_only
        # Only log a "reactivated" IR event when an edge resumes activity after
        # being idle at least this long.
        self.event_min_gap = event_min_gap

        if read_only:
            # Open without creating or writing anything (works on a DB owned by
            # another user as long as it is group/other readable).
            self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            self.conn.row_factory = sqlite3.Row
            return

        directory = os.path.dirname(os.path.abspath(path))
        created_dir = False
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, mode=DB_DIR_MODE, exist_ok=True)
            created_dir = True
        db_existed = os.path.exists(path)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=5000;")
        self.init_schema()
        # Tighten permissions on files/dirs we create (best-effort).
        self._restrict_permissions(path, directory, created_dir, db_existed)

    @staticmethod
    def _restrict_permissions(path, directory, created_dir, db_existed) -> None:
        try:
            if not db_existed:
                os.chmod(path, DB_FILE_MODE)
                for suffix in ("-wal", "-shm"):
                    if os.path.exists(path + suffix):
                        os.chmod(path + suffix, DB_FILE_MODE)
            if created_dir and directory:
                os.chmod(directory, DB_DIR_MODE)
        except OSError:
            pass

    def _readonly_guard(self) -> None:
        if self.read_only:
            raise RuntimeError("Store opened read-only; writes are not permitted")

    def init_schema(self) -> None:
        self.conn.executescript(_SCHEMA)
        self._migrate()
        self.conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns/tables introduced after v1 to pre-existing databases.

        ``CREATE TABLE IF NOT EXISTS`` cannot add a column to an existing table,
        so new columns are added with ALTER TABLE when missing.
        """

        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(flows)")}
        if "peer_domain" not in cols:
            self.conn.execute("ALTER TABLE flows ADD COLUMN peer_domain TEXT")

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
                    l7_protocol, data_quality, peer_domain
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    host, obs.proto, obs.direction, obs.local_ip, obs.peer_ip, obs.service_port,
                    obs.peer_class, obs.peer_name, obs.snapshot_bytes, obs.snapshot_packets,
                    obs.snapshot_bytes, obs.snapshot_packets, now, now, now,
                    obs.service_side, obs.service_name, obs.process_comm, obs.process_exe,
                    obs.unit, obs.package, obs.container_id, obs.l7_protocol, obs.data_quality,
                    obs.peer_domain,
                ),
            )
            self._append_event("new", host, obs, now, obs.snapshot_bytes, obs.snapshot_packets, 0.0)
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
            # Append-only IR event when a flow wakes up after a meaningful idle.
            if gap >= self.event_min_gap > 0:
                self._append_event(
                    "reactivated", host, obs, now, byte_delta, packet_delta, gap
                )
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
                data_quality=?,
                peer_domain=COALESCE(?, peer_domain)
            WHERE host=? AND proto=? AND direction=? AND local_ip=? AND peer_ip=? AND service_port=?
            """,
            (
                obs.peer_class, obs.peer_name,
                new_bytes, new_packets, obs.snapshot_bytes, obs.snapshot_packets,
                now, new_last_active, max_gap, observations,
                obs.service_side, obs.service_name,
                obs.process_comm, obs.process_exe,
                obs.unit, obs.package, obs.container_id, obs.l7_protocol,
                obs.data_quality, obs.peer_domain,
                host, obs.proto, obs.direction, obs.local_ip, obs.peer_ip, obs.service_port,
            ),
        )
        self.conn.commit()

    def _append_event(
        self,
        kind: str,
        host: str,
        obs: "EdgeObservation",
        ts: float,
        bytes_delta: int,
        packets_delta: int,
        idle_gap: float,
    ) -> None:
        """Insert an append-only IR event. Never updates existing rows."""

        self.conn.execute(
            """
            INSERT INTO flow_events (
                ts, host, kind, proto, direction, local_ip, peer_ip,
                service_port, peer_class, peer_name, service_name, l7_protocol,
                process_comm, process_exe, bytes_delta, packets_delta, idle_gap
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts, host, kind, obs.proto, obs.direction, obs.local_ip, obs.peer_ip,
                obs.service_port, obs.peer_class, obs.peer_name, obs.service_name,
                obs.l7_protocol, obs.process_comm, obs.process_exe,
                int(bytes_delta or 0), int(packets_delta or 0), float(idle_gap or 0.0),
            ),
        )

    def iter_events(
        self,
        host: Optional[str] = None,
        since: Optional[float] = None,
        kind: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[sqlite3.Row]:
        """Read the append-only IR event log, newest first."""

        clauses = []
        params: List[object] = []
        if host:
            clauses.append("host=?")
            params.append(host)
        if since is not None:
            clauses.append("ts>=?")
            params.append(since)
        if kind:
            clauses.append("kind=?")
            params.append(kind)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM flow_events{where} ORDER BY ts DESC, id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        return list(self.conn.execute(sql, params))

    def event_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS c FROM flow_events").fetchone()
        return int(row["c"]) if row else 0

    def prune_events_older_than(self, cutoff_ts: float) -> int:
        cur = self.conn.execute("DELETE FROM flow_events WHERE ts < ?", (cutoff_ts,))
        self.conn.commit()
        return cur.rowcount

    # -- DNS query log (append-only) ------------------------------------
    def record_dns_event(
        self,
        host: str,
        ts: float,
        qname: Optional[str],
        qtype: Optional[str],
        rcode: Optional[str],
        answers: Optional[str],
        source: str = "resolved-monitor",
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO dns_events (ts, host, qname, qtype, rcode, answers, source)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, host, qname, qtype, rcode, answers, source),
        )

    def record_dns_events(self, host: str, events: Iterable[Dict[str, object]]) -> int:
        count = 0
        for ev in events:
            self.record_dns_event(
                host,
                float(ev.get("ts") or time.time()),
                ev.get("qname"),
                ev.get("qtype"),
                ev.get("rcode"),
                ev.get("answers"),
                str(ev.get("source") or "resolved-monitor"),
            )
            count += 1
        if count:
            self.conn.commit()
        return count

    def iter_dns_events(
        self,
        host: Optional[str] = None,
        since: Optional[float] = None,
        qname: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[sqlite3.Row]:
        clauses: List[str] = []
        params: List[object] = []
        if host:
            clauses.append("host=?")
            params.append(host)
        if since is not None:
            clauses.append("ts>=?")
            params.append(since)
        if qname:
            clauses.append("qname LIKE ?")
            params.append(f"%{qname}%")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM dns_events{where} ORDER BY ts DESC, id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        return list(self.conn.execute(sql, params))

    def dns_event_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS c FROM dns_events").fetchone()
        return int(row["c"]) if row else 0

    def prune_dns_events_older_than(self, cutoff_ts: float) -> int:
        cur = self.conn.execute("DELETE FROM dns_events WHERE ts < ?", (cutoff_ts,))
        self.conn.commit()
        return cur.rowcount

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
                    l7_protocol, data_quality, peer_domain
                ) VALUES (
                    :host, :proto, :direction, :local_ip, :peer_ip, :service_port,
                    :peer_class, :peer_name, :bytes, :packets, :last_snapshot_bytes,
                    :last_snapshot_packets, :first_seen, :last_seen, :last_active,
                    :max_gap, :observations, :service_side, :service_name,
                    :process_comm, :process_exe, :unit, :package, :container_id,
                    :l7_protocol, :data_quality, :peer_domain
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
                    data_quality=excluded.data_quality,
                    peer_domain=COALESCE(excluded.peer_domain, flows.peer_domain)
                """,
                _flow_row_defaults(f),
            )
            count += 1
        self.conn.commit()
        return count


    # -- maintenance / retention ----------------------------------------
    def db_size_bytes(self) -> int:
        """Approximate on-disk size including WAL/SHM sidecar files."""

        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total

    def flow_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS c FROM flows").fetchone()
        return int(row["c"]) if row else 0

    def prune_older_than(self, cutoff_ts: float) -> int:
        """Delete edges whose ``last_seen`` is older than *cutoff_ts*."""

        cur = self.conn.execute("DELETE FROM flows WHERE last_seen < ?", (cutoff_ts,))
        self.conn.commit()
        return cur.rowcount

    def _checkpoint_and_vacuum(self) -> None:
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            self.conn.execute("VACUUM;")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

    def prune_to_budget(self, max_bytes: int, batch_fraction: float = 0.1) -> int:
        """Delete the least-recently-active edges until the DB fits *max_bytes*.

        Returns the number of rows deleted.  Runs a bounded number of passes to
        avoid spinning; each pass drops roughly ``batch_fraction`` of rows and
        VACUUMs to reclaim space.
        """

        deleted = 0
        self._checkpoint_and_vacuum()
        for _ in range(20):
            if self.db_size_bytes() <= max_bytes:
                break
            total = self.flow_count()
            if total == 0:
                break
            # Trim the oldest IR events alongside flows so history cannot grow
            # unbounded under disk pressure (retention still applies too).
            ev_total = self.event_count()
            if ev_total > 0:
                ev_batch = max(1, int(ev_total * batch_fraction))
                self.conn.execute(
                    "DELETE FROM flow_events WHERE id IN "
                    "(SELECT id FROM flow_events ORDER BY ts ASC LIMIT ?)",
                    (ev_batch,),
                )
                self.conn.commit()
            batch = max(1, int(total * batch_fraction))
            cur = self.conn.execute(
                """
                DELETE FROM flows WHERE id IN (
                    SELECT id FROM flows
                    ORDER BY COALESCE(last_active, last_seen) ASC
                    LIMIT ?
                )
                """,
                (batch,),
            )
            deleted += cur.rowcount
            self.conn.commit()
            self._checkpoint_and_vacuum()
        return deleted


def _flow_row_defaults(f: Dict[str, object]) -> Dict[str, object]:
    keys = [
        "host", "proto", "direction", "local_ip", "peer_ip", "service_port",
        "peer_class", "peer_name", "bytes", "packets", "last_snapshot_bytes",
        "last_snapshot_packets",
        "first_seen", "last_seen", "last_active", "max_gap", "observations",
        "service_side", "service_name", "process_comm", "process_exe", "unit",
        "package", "container_id", "l7_protocol", "data_quality", "peer_domain",
    ]
    return {k: f.get(k) for k in keys}
