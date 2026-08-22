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
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from . import platform as _plat

log = logging.getLogger("commatrix.store")

SCHEMA_VERSION = 4

# CODE-016: a full VACUUM rewrites the entire database into a temporary file in
# the same directory, so it needs roughly as much free space again as the
# database occupies. Running one after *every* prune batch -- which is exactly
# what prune_to_budget() used to do, up to 20 times per cycle -- is the worst
# possible behaviour on the one machine state that triggers it: a full disk.
# The batch loop now reclaims incrementally (cheap, in-place, no temp file) and
# a full VACUUM runs at most once, and only when the free space is there.
VACUUM_FREE_SPACE_FACTOR = 1.2

# The columns that make up the flows UNIQUE key. A snapshot row missing any of
# them cannot be merged meaningfully.
_FLOW_KEY_COLUMNS = (
    "host", "proto", "direction", "local_ip", "peer_ip", "service_port",
)

# Restrictive permissions: the database is a full internal network map and must
# not be world-readable.
# CODE-023: these are re-exports of the single source of truth in
# commatrix.platform, kept under their historical names so existing imports
# keep working. DB_FILE_MODE used to be dead code -- it is now what
# secure_permissions() actually applies.
DB_FILE_MODE = _plat.DATA_FILE_MODE
DB_DIR_MODE = _plat.DATA_DIR_MODE

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
    pod TEXT,
    netns TEXT,
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

-- Collector run/uptime ledger: one row per collection session. Enables
-- first-seen, number of runs, total runtime and coverage-gap ("blind spot")
-- statistics. ``last_seen`` is a heartbeat so an unclean exit still bounds the
-- session length; ``stopped`` is set on clean shutdown.
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    host TEXT,
    started REAL NOT NULL,
    last_seen REAL,
    stopped REAL
);

CREATE INDEX IF NOT EXISTS idx_runs_started ON runs (started);
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
    pod: Optional[str] = None
    netns: Optional[str] = None


class SchemaVersionError(RuntimeError):
    """Raised when the on-disk schema is newer than this build understands."""


class Store:
    def __init__(
        self,
        path: str,
        read_only: bool = False,
        event_min_gap: float = 60.0,
        allow_schema_mismatch: bool = False,
    ):
        # When set, record_edge() skips its own commit so a whole poll lands in
        # a single transaction (see record_edges). One fsync per edge made a
        # poll cost thousands of them; measured ~40x slower on a fast SSD and
        # far worse on a throttled VPS, which broke the CPU budget promise.
        self._batching = False
        self.path = path
        self.read_only = read_only
        # Only log a "reactivated" IR event when an edge resumes activity after
        # being idle at least this long.
        self.event_min_gap = event_min_gap

        if read_only:
            self.conn = self._connect_read_only(path)
            self.conn.row_factory = sqlite3.Row
            self._check_schema_version(allow_schema_mismatch)
            return

        directory = os.path.dirname(os.path.abspath(path))
        created_dir = False
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, mode=DB_DIR_MODE, exist_ok=True)
            created_dir = True
        db_existed = os.path.exists(path)
        # SEC-016: sqlite3.connect() creates the file under the process umask
        # (0644 by default) and secure_permissions() only tightens it
        # afterwards. Anything that opened it in that window keeps read access
        # on the fd forever, so narrow the umask across creation instead of
        # racing to fix it.
        old_umask = None
        if not db_existed and hasattr(os, "umask"):
            old_umask = os.umask(0o137)
        try:
            self.conn = sqlite3.connect(path)
        finally:
            if old_umask is not None:
                os.umask(old_umask)
        self.conn.row_factory = sqlite3.Row
        if not db_existed:
            # CODE-016: only settable on an empty database, and it has to be
            # set before anything writes the file header -- journal_mode=WAL
            # included. With INCREMENTAL, freed pages go on a freelist that
            # `PRAGMA incremental_vacuum` can hand back to the filesystem in
            # bounded chunks, with no whole-file rewrite and no temp copy.
            self.conn.execute("PRAGMA auto_vacuum=INCREMENTAL;")
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=5000;")
        self._check_schema_version(allow_schema_mismatch)
        self.init_schema()
        # Tighten permissions on files/dirs we create (best-effort).
        self._restrict_permissions(path, directory, created_dir, db_existed)

    @staticmethod
    def _connect_read_only(path: str) -> sqlite3.Connection:
        """Open *path* read-only, coping with a read-only parent directory.

        The database runs in WAL mode, and a WAL reader -- even a strictly
        read-only one -- has to create and write the ``-shm`` shared-memory
        file next to the database. That needs write permission on the
        *directory*, not on the database file, and SQLite does not report the
        problem at connect() time: it raises "attempt to write a readonly
        database" from the first SELECT.

        This is exactly the shape of the container setup the README documents:
        `collect` runs as --user 0 and leaves /var/lib/commatrix owned by root,
        then `report` runs as the image's default UID 65532 and cannot write
        that directory, so every read-only command fails on a plain query.

        The fallback is `immutable=1`, which tells SQLite the file will not
        change and skips the -shm entirely. That assumption is only safe when
        nothing is writing concurrently, so it is a fallback and it says so.
        """

        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            # Force the -shm allocation now rather than at the first real
            # query, so the fallback happens here and not halfway through a
            # report.
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            return conn
        except sqlite3.OperationalError as exc:
            if "readonly" not in str(exc).lower():
                conn.close()
                raise
            conn.close()

        immutable = sqlite3.connect(f"file:{path}?immutable=1", uri=True)
        log.warning(
            "%s is a WAL database in a directory this process cannot write, so "
            "the usual read-only open failed; falling back to immutable mode. "
            "Any data still in the write-ahead log is NOT visible, and the "
            "result is undefined if a collector is writing right now. Fix by "
            "making the database directory writable for this user (in a "
            "container: --user \"$(id -u):$(id -g)\", or chown the bind mount "
            "to 65532), or by checkpointing the database first.",
            path,
        )
        return immutable

    @staticmethod
    def _restrict_permissions(path, directory, created_dir, db_existed) -> None:
        # Delegated to the platform layer: chmod on Linux, NTFS ACL on Windows.
        from . import platform as _plat

        if not db_existed:
            _plat.secure_permissions(path)
            for suffix in ("-wal", "-shm"):
                if os.path.exists(path + suffix):
                    _plat.secure_permissions(path + suffix)
        if created_dir and directory:
            _plat.secure_permissions(directory, is_dir=True)

    def _readonly_guard(self) -> None:
        if self.read_only:
            raise RuntimeError("Store opened read-only; writes are not permitted")

    def stored_schema_version(self) -> Optional[int]:
        """The schema_version recorded in ``meta``, or None if not recorded."""

        try:
            row = self.conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.Error:
            # meta table does not exist yet -> brand new database.
            return None
        if row is None:
            return None
        try:
            return int(row["value"])
        except (TypeError, ValueError):
            return None

    def _check_schema_version(self, allow_mismatch: bool) -> None:
        """Refuse to open a database written by a newer build.

        The old code only ever ran ``INSERT OR IGNORE`` on schema_version, so a
        database created at v1 still claimed v1 forever, and -- worse -- an
        older binary would happily open a v5 database, silently ignore the
        columns it did not know about and write partial rows back.
        """

        found = self.stored_schema_version()
        if found is None or found <= SCHEMA_VERSION:
            return
        message = (
            f"database {self.path!r} was written by a newer Commatrix "
            f"(schema v{found}, this build understands v{SCHEMA_VERSION}). "
            "Upgrade Commatrix, or pass allow_schema_mismatch=True to read it "
            "anyway (data written by the newer version may be lost)."
        )
        if not allow_mismatch:
            raise SchemaVersionError(message)
        log.warning("%s", message)

    def init_schema(self) -> None:
        self.conn.executescript(_SCHEMA)
        self._migrate()
        # Record (or advance) the schema version. INSERT OR IGNORE alone left
        # every pre-existing database permanently pinned to whatever version it
        # was created at, which made the stored value useless as a guard.
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value "
            "WHERE CAST(meta.value AS INTEGER) < CAST(excluded.value AS INTEGER)",
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
        if "pod" not in cols:
            self.conn.execute("ALTER TABLE flows ADD COLUMN pod TEXT")
        if "netns" not in cols:
            self.conn.execute("ALTER TABLE flows ADD COLUMN netns TEXT")

        # CODE-002: retention pruning runs every poll and filters on
        # last_seen, which was a full table scan of every flow on every cycle
        # (measured 13.25 ms vs 0.01 ms per prune at 200k rows). Created here
        # rather than in _SCHEMA because _SCHEMA also runs against pre-existing
        # databases, whose flows table may not have the column yet.
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(flows)")}
        if "last_seen" in cols:
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows (last_seen)"
            )

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
                    l7_protocol, data_quality, peer_domain, pod, netns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    host, obs.proto, obs.direction, obs.local_ip, obs.peer_ip, obs.service_port,
                    obs.peer_class, obs.peer_name, obs.snapshot_bytes, obs.snapshot_packets,
                    obs.snapshot_bytes, obs.snapshot_packets, now, now, now,
                    obs.service_side, obs.service_name, obs.process_comm, obs.process_exe,
                    obs.unit, obs.package, obs.container_id, obs.l7_protocol, obs.data_quality,
                    obs.peer_domain, obs.pod, obs.netns,
                ),
            )
            self._append_event("new", host, obs, now, obs.snapshot_bytes, obs.snapshot_packets, 0.0)
            if not self._batching:
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
                peer_domain=COALESCE(?, peer_domain),
                pod=COALESCE(?, pod),
                netns=COALESCE(?, netns)
            WHERE host=? AND proto=? AND direction=? AND local_ip=? AND peer_ip=? AND service_port=?
            """,
            (
                obs.peer_class, obs.peer_name,
                new_bytes, new_packets, obs.snapshot_bytes, obs.snapshot_packets,
                now, new_last_active, max_gap, observations,
                obs.service_side, obs.service_name,
                obs.process_comm, obs.process_exe,
                obs.unit, obs.package, obs.container_id, obs.l7_protocol,
                obs.data_quality, obs.peer_domain, obs.pod, obs.netns,
                host, obs.proto, obs.direction, obs.local_ip, obs.peer_ip, obs.service_port,
            ),
        )
        if not self._batching:
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

    # -- run / uptime ledger --------------------------------------------
    def start_run(self, host: str, now: Optional[float] = None) -> int:
        now = now if now is not None else time.time()
        cur = self.conn.execute(
            "INSERT INTO runs (host, started, last_seen) VALUES (?, ?, ?)",
            (host, now, now),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def heartbeat_run(self, run_id: int, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        self.conn.execute("UPDATE runs SET last_seen=? WHERE id=?", (now, run_id))
        self.conn.commit()

    def finish_run(self, run_id: int, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        self.conn.execute(
            "UPDATE runs SET last_seen=?, stopped=? WHERE id=?", (now, now, run_id)
        )
        self.conn.commit()

    def run_stats(self, host: Optional[str] = None, now: Optional[float] = None) -> Dict[str, object]:
        """Aggregate collector uptime into coverage statistics.

        Returns first-run time, number of runs, total runtime (seconds), the
        wall-clock span since first run, and the "blind spot" percentage: the
        share of that span during which the collector was NOT running.
        """

        now = now if now is not None else time.time()
        q = "SELECT started, last_seen, stopped FROM runs"
        params: List[object] = []
        if host:
            q += " WHERE host=?"
            params.append(host)
        rows = list(self.conn.execute(q, params))
        rows = [r for r in rows if r["started"] is not None]
        if not rows:
            return {
                "first_run": None, "run_count": 0, "total_runtime": 0.0,
                "span": 0.0, "blind_spot_pct": 0.0,
            }

        first = min(r["started"] for r in rows)
        total = 0.0
        for r in rows:
            start = r["started"]
            end = r["stopped"] if r["stopped"] is not None else r["last_seen"]
            if end is None:
                end = start
            total += max(0.0, end - start)

        span = max(0.0, now - first)
        if span > 0:
            total = min(total, span)  # sessions cannot exceed wall clock
            blind_pct = max(0.0, (span - total) / span * 100.0)
        else:
            blind_pct = 0.0
        return {
            "first_run": first,
            "run_count": len(rows),
            "total_runtime": total,
            "span": span,
            "blind_spot_pct": blind_pct,
        }

    def record_edges(self, host: str, edges: Iterable[EdgeObservation], now: Optional[float] = None) -> int:
        """Record a whole poll's worth of edges in one transaction.

        Committing per edge meant one fsync per tracked connection per poll.
        On a host with a few thousand conntrack entries that dominated the
        poll and blew the CPU/IO budget the collector promises to stay inside.
        """

        self._readonly_guard()
        if now is None:
            now = time.time()
        count = 0
        self._batching = True
        try:
            for edge in edges:
                self.record_edge(host, edge, now=now)
                count += 1
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            self._batching = False
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
        if not isinstance(flows, list):
            raise ValueError("snapshot 'flows' must be a list")
        count = 0
        skipped = 0
        for f in flows:  # type: ignore[union-attr]
            # CODE-015: a flow missing part of the edge key would insert a row
            # keyed on NULLs, which is useless and collides with every other
            # such row. Reject it rather than corrupt the table.
            if not isinstance(f, dict) or any(
                f.get(k) in (None, "") for k in _FLOW_KEY_COLUMNS
            ):
                skipped += 1
                continue
            self.conn.execute(
                """
                INSERT INTO flows (
                    host, proto, direction, local_ip, peer_ip, service_port,
                    peer_class, peer_name, bytes, packets, last_snapshot_bytes,
                    last_snapshot_packets, first_seen, last_seen, last_active,
                    max_gap, observations, service_side, service_name,
                    process_comm, process_exe, unit, package, container_id,
                    l7_protocol, data_quality, peer_domain, pod, netns
                ) VALUES (
                    :host, :proto, :direction, :local_ip, :peer_ip, :service_port,
                    :peer_class, :peer_name, :bytes, :packets, :last_snapshot_bytes,
                    :last_snapshot_packets, :first_seen, :last_seen, :last_active,
                    :max_gap, :observations, :service_side, :service_name,
                    :process_comm, :process_exe, :unit, :package, :container_id,
                    :l7_protocol, :data_quality, :peer_domain, :pod, :netns
                )
                ON CONFLICT (host, proto, direction, local_ip, peer_ip, service_port)
                DO UPDATE SET
                    peer_class=COALESCE(excluded.peer_class, flows.peer_class),
                    peer_name=COALESCE(excluded.peer_name, flows.peer_name),
                    bytes=COALESCE(excluded.bytes, flows.bytes),
                    packets=COALESCE(excluded.packets, flows.packets),
                    last_snapshot_bytes=COALESCE(
                        excluded.last_snapshot_bytes, flows.last_snapshot_bytes),
                    last_snapshot_packets=COALESCE(
                        excluded.last_snapshot_packets, flows.last_snapshot_packets),
                    first_seen=COALESCE(
                        MIN(flows.first_seen, excluded.first_seen),
                        flows.first_seen, excluded.first_seen),
                    last_seen=COALESCE(
                        MAX(flows.last_seen, excluded.last_seen),
                        flows.last_seen, excluded.last_seen),
                    last_active=COALESCE(
                        MAX(flows.last_active, excluded.last_active),
                        flows.last_active, excluded.last_active),
                    max_gap=COALESCE(
                        MAX(flows.max_gap, excluded.max_gap),
                        flows.max_gap, excluded.max_gap),
                    observations=COALESCE(excluded.observations, flows.observations),
                    service_side=COALESCE(excluded.service_side, flows.service_side),
                    service_name=COALESCE(excluded.service_name, flows.service_name),
                    process_comm=COALESCE(excluded.process_comm, flows.process_comm),
                    process_exe=COALESCE(excluded.process_exe, flows.process_exe),
                    unit=COALESCE(excluded.unit, flows.unit),
                    package=COALESCE(excluded.package, flows.package),
                    container_id=COALESCE(excluded.container_id, flows.container_id),
                    l7_protocol=COALESCE(excluded.l7_protocol, flows.l7_protocol),
                    data_quality=COALESCE(excluded.data_quality, flows.data_quality),
                    peer_domain=COALESCE(excluded.peer_domain, flows.peer_domain),
                    pod=COALESCE(excluded.pod, flows.pod),
                    netns=COALESCE(excluded.netns, flows.netns)
                """,
                _flow_row_defaults(f),
            )
            count += 1
        if skipped:
            log.warning(
                "import: skipped %d flow row(s) missing part of the edge key "
                "(host/proto/direction/local_ip/peer_ip/service_port)", skipped
            )
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

    def _checkpoint(self) -> None:
        """Fold the WAL back into the main database file (cheap, in-place)."""

        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

    def _incremental_reclaim(self, max_pages: int = 4096) -> None:
        """Hand a bounded number of freed pages back to the filesystem.

        No temporary file, no whole-database rewrite -- the two properties that
        made a full VACUUM the wrong tool inside the prune loop (CODE-016).
        """

        try:
            self.conn.execute(f"PRAGMA incremental_vacuum({int(max_pages)});")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

    def _free_space_bytes(self) -> Optional[int]:
        try:
            st = os.statvfs(os.path.dirname(os.path.abspath(self.path)) or ".")
        except (OSError, AttributeError):
            return None
        return st.f_bavail * st.f_frsize

    def _full_vacuum(self) -> bool:
        """Run a full VACUUM, but only if there is room for the rebuild.

        Returns True if the VACUUM ran. A VACUUM needs about as much free space
        again as the database occupies; attempting one on the almost-full disk
        that triggered pruning in the first place is how you turn a disk
        pressure warning into a hard failure.
        """

        db_bytes = self.db_size_bytes()
        free = self._free_space_bytes()
        if free is not None and free < db_bytes * VACUUM_FREE_SPACE_FACTOR:
            log.info(
                "skipping VACUUM: %d B free is below the %.1fx of the %d B "
                "database that the rebuild needs",
                free, VACUUM_FREE_SPACE_FACTOR, db_bytes,
            )
            return False
        try:
            self.conn.execute("VACUUM;")
            self.conn.commit()
        except sqlite3.OperationalError as exc:
            log.warning("VACUUM failed: %s", exc)
            return False
        return True

    def _checkpoint_and_vacuum(self) -> None:
        """Backwards-compatible full reclaim (checkpoint + guarded VACUUM)."""

        self._checkpoint()
        self._full_vacuum()

    def prune_to_budget(self, max_bytes: int, batch_fraction: float = 0.1) -> int:
        """Delete the least-recently-active edges until the DB fits *max_bytes*.

        Returns the number of rows deleted. Runs a bounded number of passes to
        avoid spinning. CODE-016: each pass reclaims incrementally instead of
        running a full VACUUM, and a single guarded VACUUM is attempted at the
        end only if the incremental reclaim did not get us under budget.
        """

        deleted = 0
        self._checkpoint()
        self._incremental_reclaim()
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
            self._checkpoint()
            self._incremental_reclaim()
        if deleted and self.db_size_bytes() > max_bytes:
            # Last resort: a database created before auto_vacuum=INCREMENTAL
            # was set has no freelist to reclaim from, so only a rewrite will
            # shrink it. _full_vacuum() declines when the disk cannot take it.
            self._full_vacuum()
        return deleted


def _flow_row_defaults(f: Dict[str, object]) -> Dict[str, object]:
    keys = [
        "host", "proto", "direction", "local_ip", "peer_ip", "service_port",
        "peer_class", "peer_name", "bytes", "packets", "last_snapshot_bytes",
        "last_snapshot_packets",
        "first_seen", "last_seen", "last_active", "max_gap", "observations",
        "service_side", "service_name", "process_comm", "process_exe", "unit",
        "package", "container_id", "l7_protocol", "data_quality", "peer_domain",
        "pod", "netns",
    ]
    return {k: f.get(k) for k in keys}
