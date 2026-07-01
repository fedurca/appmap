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


if __name__ == "__main__":
    unittest.main()
