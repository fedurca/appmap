import os
import tempfile
import unittest

from commatrix.store import EdgeObservation, Store


def make_obs(snapshot_bytes, snapshot_packets=1):
    return EdgeObservation(
        proto="tcp",
        direction="inbound",
        local_ip="10.0.0.10",
        peer_ip="10.0.0.5",
        service_port=5432,
        peer_class="internal",
        snapshot_bytes=snapshot_bytes,
        snapshot_packets=snapshot_packets,
        service_side="local",
        service_name="postgresql",
        l7_protocol="postgres",
    )


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "test.db")
        self.store = Store(self.db)

    def tearDown(self):
        self.store.close()

    def test_gap_and_cumulative_bytes(self):
        host = "web01"
        self.store.record_edge(host, make_obs(100, 2), now=0.0)
        # No change -> no activity, no gap update.
        self.store.record_edge(host, make_obs(100, 2), now=10.0)
        # Activity after idle -> gap = 30.
        self.store.record_edge(host, make_obs(250, 5), now=30.0)
        # Counter reset (new connections) -> full snapshot counts as fresh.
        self.store.record_edge(host, make_obs(50, 1), now=35.0)

        rows = self.store.iter_flows(host)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["bytes"], 300)  # 100 + 0 + 150 + 50
        self.assertEqual(row["packets"], 6)  # 2 + 0 + 3 + 1
        self.assertAlmostEqual(row["max_gap"], 30.0)
        self.assertEqual(row["observations"], 4)
        self.assertEqual(row["first_seen"], 0.0)
        self.assertEqual(row["last_seen"], 35.0)

    def test_host_params_roundtrip(self):
        self.store.upsert_host("web01", {"hostname": "web01", "cpu.num": 4})
        params = self.store.get_host_params("web01")
        self.assertEqual(params["cpu.num"], 4)
        self.assertIn("web01", self.store.list_hosts())

    def test_export_import_roundtrip(self):
        self.store.upsert_host("web01", {"hostname": "web01"})
        self.store.record_edge("web01", make_obs(500, 4), now=100.0)
        payload = self.store.export_dict()

        other_db = os.path.join(self.tmp, "central.db")
        central = Store(other_db)
        try:
            merged = central.import_dict(payload)
            self.assertEqual(merged, 1)
            rows = central.iter_flows("web01")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["bytes"], 500)
            self.assertIn("web01", central.list_hosts())
        finally:
            central.close()


class StorePeerDomainTest(unittest.TestCase):
    def test_peer_domain_stored_and_exported(self):
        tmp = tempfile.mkdtemp()
        s = Store(os.path.join(tmp, "t.db"))
        obs = make_obs(100, 2)
        obs.peer_domain = "db.internal.example.com"
        s.record_edge("web01", obs, now=1.0)
        rows = s.iter_flows("web01")
        self.assertEqual(rows[0]["peer_domain"], "db.internal.example.com")
        payload = s.export_dict()
        self.assertEqual(payload["flows"][0]["peer_domain"], "db.internal.example.com")
        s.close()

    def test_migration_adds_peer_domain_to_old_db(self):
        import sqlite3
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "old.db")
        # Simulate a pre-v3 flows table without peer_domain.
        conn = sqlite3.connect(db)
        conn.execute(
            "CREATE TABLE flows (id INTEGER PRIMARY KEY, host TEXT, proto TEXT, "
            "direction TEXT, local_ip TEXT, peer_ip TEXT, service_port INTEGER, "
            "UNIQUE(host, proto, direction, local_ip, peer_ip, service_port))"
        )
        conn.commit()
        conn.close()
        s = Store(db)  # should ALTER TABLE to add peer_domain
        cols = {r[1] for r in s.conn.execute("PRAGMA table_info(flows)")}
        self.assertIn("peer_domain", cols)
        s.close()


class StoreDnsEventsTest(unittest.TestCase):
    def test_record_and_query_dns_events(self):
        tmp = tempfile.mkdtemp()
        s = Store(os.path.join(tmp, "t.db"))
        n = s.record_dns_events("web01", [
            {"ts": 1000.0, "qname": "a.example.com", "qtype": "A", "rcode": "0", "answers": "1.2.3.4"},
            {"ts": 1001.0, "qname": "b.example.com", "qtype": "AAAA", "rcode": "0", "answers": "::1"},
        ])
        self.assertEqual(n, 2)
        self.assertEqual(s.dns_event_count(), 2)
        rows = s.iter_dns_events(qname="a.example")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["answers"], "1.2.3.4")
        self.assertEqual(s.prune_dns_events_older_than(1000.5), 1)
        self.assertEqual(s.dns_event_count(), 1)
        s.close()


class StorePermissionsTest(unittest.TestCase):
    def test_db_created_not_world_readable(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "sub", "test.db")
        store = Store(db)
        try:
            mode = os.stat(db).st_mode & 0o777
            self.assertEqual(mode & 0o007, 0, "DB must not be world-accessible")
            dir_mode = os.stat(os.path.dirname(db)).st_mode & 0o777
            self.assertEqual(dir_mode & 0o007, 0, "dir must not be world-accessible")
        finally:
            store.close()


class StoreReadOnlyTest(unittest.TestCase):
    def test_read_only_open_and_write_guard(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "test.db")
        w = Store(db)
        w.record_edge("web01", make_obs(100, 2), now=1.0)
        w.close()

        ro = Store(db, read_only=True)
        try:
            rows = ro.iter_flows("web01")
            self.assertEqual(len(rows), 1)
        finally:
            ro.close()


class StoreEventsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "test.db")
        self.store = Store(self.db, event_min_gap=30.0)

    def tearDown(self):
        self.store.close()

    def test_new_edge_logs_event(self):
        self.store.record_edge("web01", make_obs(100, 2), now=0.0)
        events = self.store.iter_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["kind"], "new")
        self.assertEqual(events[0]["peer_ip"], "10.0.0.5")
        self.assertEqual(events[0]["service_port"], 5432)

    def test_reactivation_logs_event_after_gap(self):
        self.store.record_edge("web01", make_obs(100, 2), now=0.0)      # new
        self.store.record_edge("web01", make_obs(100, 2), now=10.0)     # idle
        self.store.record_edge("web01", make_obs(250, 5), now=50.0)     # active, gap 50
        kinds = [e["kind"] for e in self.store.iter_events()]
        self.assertIn("reactivated", kinds)
        self.assertEqual(kinds.count("new"), 1)

    def test_small_gap_does_not_log_reactivation(self):
        self.store.record_edge("web01", make_obs(100, 2), now=0.0)
        self.store.record_edge("web01", make_obs(200, 4), now=5.0)  # gap 5 < 30
        self.assertEqual([e["kind"] for e in self.store.iter_events()], ["new"])

    def test_prune_events_older_than(self):
        self.store.record_edge("web01", make_obs(100, 2), now=1000.0)
        self.assertEqual(self.store.event_count(), 1)
        self.assertEqual(self.store.prune_events_older_than(2000.0), 1)
        self.assertEqual(self.store.event_count(), 0)


if __name__ == "__main__":
    unittest.main()
