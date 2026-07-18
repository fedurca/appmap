import os
import tempfile
import time
import unittest
from unittest import mock

from commatrix import resources as rsrc
from commatrix.resources import DiskStatus, ResourceGovernor
from commatrix.store import EdgeObservation, Store


class GovernorCpuTest(unittest.TestCase):
    def setUp(self):
        self.gov = ResourceGovernor(cpu_budget=0.10, ncpu=4, min_interval=1.0)
        # Pin load average low so the (host-dependent) load backoff does not make
        # these assertions flaky under CI/build load.
        patcher = mock.patch.object(rsrc.os, "getloadavg", return_value=(0.0, 0.0, 0.0))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_light_poll_respects_base_interval(self):
        # 0.4 CPU-seconds over 4 cores at 10% => required cycle 1.0s < base 5s.
        sleep = self.gov.throttle_sleep(cpu_used_seconds=0.4, elapsed_seconds=0.2, base_interval=5.0)
        # Should target the 5s base interval.
        self.assertAlmostEqual(sleep, 4.8, places=1)

    def test_heavy_poll_extends_cycle(self):
        # 4 CPU-seconds over 4 cores at 10% => required cycle 10s > base 5s.
        sleep = self.gov.throttle_sleep(cpu_used_seconds=4.0, elapsed_seconds=1.0, base_interval=5.0)
        self.assertGreaterEqual(sleep, 9.0)  # ~10 - 1

    def test_never_negative(self):
        sleep = self.gov.throttle_sleep(cpu_used_seconds=0.0, elapsed_seconds=100.0, base_interval=5.0)
        self.assertEqual(sleep, 0.0)


class GovernorDiskTest(unittest.TestCase):
    def setUp(self):
        self.gov = ResourceGovernor(disk_budget=0.10, min_free_disk=0.05)
        self.tmp = tempfile.mkdtemp()

    def test_budget_is_fraction_of_free(self):
        path = os.path.join(self.tmp, "x.db")
        status = self.gov.disk_status(path, db_bytes=100)
        self.assertEqual(status.budget_bytes, int((status.free + 100) * 0.10))
        self.assertFalse(status.over_budget)

    def test_over_budget_detected(self):
        path = os.path.join(self.tmp, "x.db")
        status = self.gov.disk_status(path, db_bytes=10 ** 18)
        self.assertTrue(status.over_budget)

    def test_pause_writes_below_floor(self):
        low = DiskStatus(total=100, free=2, db_bytes=0, budget_bytes=10, free_fraction=0.02)
        high = DiskStatus(total=100, free=50, db_bytes=0, budget_bytes=10, free_fraction=0.5)
        self.assertTrue(self.gov.should_pause_writes(low))
        self.assertFalse(self.gov.should_pause_writes(high))


class StorePruneTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.tmp, "p.db"))
        for i in range(20):
            self.store.record_edge(
                "h",
                EdgeObservation(
                    proto="tcp", direction="outbound", local_ip="10.0.0.1",
                    peer_ip=f"10.0.0.{100 + i}", service_port=1000 + i,
                    peer_class="internal", snapshot_bytes=100, snapshot_packets=1,
                ),
                now=float(i),
            )

    def tearDown(self):
        self.store.close()

    def test_prune_older_than(self):
        removed = self.store.prune_older_than(cutoff_ts=10.0)
        self.assertEqual(removed, 10)  # last_seen 0..9
        self.assertEqual(self.store.flow_count(), 10)

    def test_prune_to_budget(self):
        # Force pruning by demanding a tiny max size.
        before = self.store.flow_count()
        self.store.prune_to_budget(max_bytes=1)
        self.assertLess(self.store.flow_count(), before)


if __name__ == "__main__":
    unittest.main()
