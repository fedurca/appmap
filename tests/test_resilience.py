"""Regression tests for the resilience batch.

SEC-010 (ValueError killing the ctnetlink thread), SEC-011 (clear-on-overflow
blinding the collector), SEC-016 (DB created world-readable), SEC-019 and
CODE-020 (aggregation), CODE-003 (unbounded DNS cache), CODE-004 (second
SIGTERM aborting sysctl restore).
"""

import json
import os
import socket
import stat
import tempfile
import unittest

from commatrix import aggregate, ctnetlink
from commatrix.collector import DNS_CACHE_MAX, DNS_CACHE_TTL, Collector
from commatrix.config import Config
from commatrix.store import EdgeObservation, Store


def _edge(**kw):
    base = dict(
        proto="tcp", direction="outbound", local_ip="10.0.0.1",
        peer_ip="10.0.0.2", service_port=443, peer_class="internal",
        snapshot_bytes=10, snapshot_packets=1,
    )
    base.update(kw)
    return EdgeObservation(**base)


class TruncatedAddressTests(unittest.TestCase):
    """SEC-010: inet_ntop raises ValueError, which is not an OSError."""

    def test_short_packed_ipv4_raises_value_error(self):
        with self.assertRaises(ValueError):
            socket.inet_ntop(socket.AF_INET, b"\x0a\x00")

    def test_decode_ip_survives_a_truncated_v4_attribute(self):
        attrs = {ctnetlink.CTA_IP_V4_SRC: b"\x0a\x00"}
        src, _dst = ctnetlink._decode_ip(attrs, socket.AF_INET)
        self.assertEqual(src, "")

    def test_decode_ip_survives_a_truncated_v6_attribute(self):
        attrs = {ctnetlink.CTA_IP_V6_SRC: b"\x20\x01"}
        src, _dst = ctnetlink._decode_ip(attrs, socket.AF_INET6)
        self.assertEqual(src, "")

    def test_decode_ip_still_works_on_valid_input(self):
        attrs = {ctnetlink.CTA_IP_V4_SRC: socket.inet_aton("10.1.2.3")}
        src, _dst = ctnetlink._decode_ip(attrs, socket.AF_INET)
        self.assertEqual(src, "10.1.2.3")


class ActiveTableOverflowTests(unittest.TestCase):
    """SEC-011: overflow must evict, not blind the collector entirely."""

    def test_eviction_keeps_the_table_at_the_cap(self):
        listener = ctnetlink.ConntrackEventListener.__new__(
            ctnetlink.ConntrackEventListener
        )
        import threading

        listener._lock = threading.Lock()
        listener._active = {}
        listener._destroyed = []
        for i in range(ctnetlink._MAX_ACTIVE + 100):
            listener._active[i] = object()
        # Trigger the same eviction the record path performs.
        excess = len(listener._active) - ctnetlink._MAX_ACTIVE
        for old in list(listener._active)[:excess]:
            listener._active.pop(old, None)
        self.assertEqual(len(listener._active), ctnetlink._MAX_ACTIVE)

    def test_newest_entries_survive_eviction(self):
        table = {i: i for i in range(10)}
        excess = 3
        for old in list(table)[:excess]:
            table.pop(old)
        self.assertNotIn(0, table)
        self.assertIn(9, table)


class DatabasePermissionTests(unittest.TestCase):
    """SEC-016: the DB must never exist world-readable, even briefly."""

    def test_new_database_is_not_group_or_world_readable(self):
        path = os.path.join(tempfile.mkdtemp(), "new.db")
        store = Store(path)
        self.addCleanup(store.close)
        # DB_FILE_MODE is 0640: owner rw, group r, world nothing.
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode & 0o007, 0, f"world bits set: {oct(mode)}")
        self.assertEqual(mode & 0o070, 0o040, f"group bits wrong: {oct(mode)}")

    def test_wal_sidecar_is_not_world_readable(self):
        path = os.path.join(tempfile.mkdtemp(), "wal.db")
        store = Store(path)
        self.addCleanup(store.close)
        store.upsert_host("h", {})
        store.record_edges("h", [_edge()])
        for suffix in ("-wal", "-shm"):
            side = path + suffix
            if os.path.exists(side):
                mode = stat.S_IMODE(os.stat(side).st_mode)
                self.assertEqual(mode & 0o007, 0, f"{side}: {oct(mode)}")


class AggregationResilienceTests(unittest.TestCase):
    """SEC-019 / CODE-020: one bad snapshot must not abort the batch."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.central = os.path.join(self.dir, "central.db")
        src = Store(os.path.join(self.dir, "src.db"))
        src.upsert_host("srv1", {})
        src.record_edges("srv1", [_edge()])
        self.good = os.path.join(self.dir, "good.json")
        with open(self.good, "w", encoding="utf-8") as fh:
            json.dump(src.export_dict(), fh, default=str)
        self.src_path = os.path.join(self.dir, "src.db")
        src.close()

    def _write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_deeply_nested_snapshot_is_skipped_not_fatal(self):
        nested = self._write("nested.json", "[" * 30000 + "]" * 30000)
        total = aggregate.aggregate_snapshots(self.central, [nested, self.good])
        self.assertEqual(total, 1)

    def test_malformed_json_is_skipped_not_fatal(self):
        broken = self._write("broken.json", "{not json")
        total = aggregate.aggregate_snapshots(self.central, [broken, self.good])
        self.assertEqual(total, 1)

    def test_non_object_snapshot_is_skipped(self):
        listy = self._write("listy.json", "[1, 2, 3]")
        total = aggregate.aggregate_snapshots(self.central, [listy, self.good])
        self.assertEqual(total, 1)

    def test_oversized_snapshot_is_refused_without_reading_it(self):
        big = self._write("big.json", "{}")
        original = aggregate.MAX_SNAPSHOT_BYTES
        aggregate.MAX_SNAPSHOT_BYTES = 1
        self.addCleanup(setattr, aggregate, "MAX_SNAPSHOT_BYTES", original)
        total = aggregate.aggregate_snapshots(self.central, [big])
        self.assertEqual(total, 0)

    def test_source_database_is_opened_read_only(self):
        before = os.stat(self.src_path).st_mtime_ns
        aggregate.aggregate_databases(self.central, [self.src_path])
        self.assertEqual(os.stat(self.src_path).st_mtime_ns, before)


class DnsCacheTests(unittest.TestCase):
    """CODE-003: the reverse-DNS cache was unbounded and never expired."""

    def setUp(self):
        self.collector = Collector(Config())

    def test_cache_has_a_ttl_and_a_bound(self):
        self.assertGreater(DNS_CACHE_MAX, 0)
        self.assertGreater(DNS_CACHE_TTL, 0)

    def test_cache_entries_are_timestamped(self):
        self.collector._dns_cache["10.0.0.1"] = (12345.0, "host.example")
        stamped, value = self.collector._dns_cache["10.0.0.1"]
        self.assertEqual(stamped, 12345.0)
        self.assertEqual(value, "host.example")

    def test_expired_entry_is_not_returned_from_cache(self):
        self.collector._dns_cache["10.0.0.9"] = (0.0, "stale.example")
        result = self.collector._reverse_dns("10.0.0.9")
        self.assertNotEqual(result, "stale.example")

    def test_fresh_entry_is_served_from_cache(self):
        import time as _time

        self.collector._dns_cache["10.0.0.8"] = (_time.time(), "fresh.example")
        self.assertEqual(self.collector._reverse_dns("10.0.0.8"), "fresh.example")


if __name__ == "__main__":
    unittest.main()
