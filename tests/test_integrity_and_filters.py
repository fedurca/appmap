"""Regression tests for the correctness and data-integrity batch.

CODE-015 (snapshot merge destroying history), CODE-018/019 (--host filter
ignored in report outputs), CODE-021/022 (config parsing fragility) and the
per-edge commit that broke the resource budget.
"""

import logging
import os
import sqlite3
import tempfile
import unittest

from commatrix import report
from commatrix.config import load_config
from commatrix.store import EdgeObservation, Store


def _edge(**kw):
    base = dict(
        proto="tcp",
        direction="outbound",
        local_ip="10.0.0.1",
        peer_ip="10.0.0.9",
        service_port=443,
        peer_class="internal",
        snapshot_bytes=5000,
        snapshot_packets=50,
        service_name="https",
    )
    base.update(kw)
    return EdgeObservation(**base)


class SnapshotMergeTests(unittest.TestCase):
    """CODE-015: a snapshot missing a field must never erase what we have."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, "central.db"))
        self.addCleanup(self.store.close)
        self.store.upsert_host("srv1", {})
        self.store.record_edge("srv1", _edge(), now=1000.0)
        self.store.record_edge(
            "srv1", _edge(snapshot_bytes=9000, snapshot_packets=90), now=9000.0
        )

    def _row(self):
        return dict(self.store.iter_flows("srv1")[0])

    def _key_only_snapshot(self):
        return {
            "hosts": [{"host": "srv1", "params": {}}],
            "flows": [{
                "host": "srv1", "proto": "tcp", "direction": "outbound",
                "local_ip": "10.0.0.1", "peer_ip": "10.0.0.9",
                "service_port": 443,
            }],
        }

    def test_partial_snapshot_preserves_history(self):
        before = self._row()
        self.store.import_dict(self._key_only_snapshot())
        after = self._row()
        for field in ("first_seen", "last_seen", "max_gap", "bytes",
                      "packets", "observations", "service_name"):
            self.assertEqual(after[field], before[field], field)

    def test_partial_snapshot_does_not_duplicate_the_row(self):
        self.store.import_dict(self._key_only_snapshot())
        self.assertEqual(len(self.store.iter_flows("srv1")), 1)

    def test_first_seen_takes_the_earlier_value(self):
        payload = self._key_only_snapshot()
        payload["flows"][0]["first_seen"] = 500.0
        self.store.import_dict(payload)
        self.assertEqual(self._row()["first_seen"], 500.0)

    def test_first_seen_ignores_a_later_value(self):
        payload = self._key_only_snapshot()
        payload["flows"][0]["first_seen"] = 5000.0
        self.store.import_dict(payload)
        self.assertEqual(self._row()["first_seen"], 1000.0)

    def test_max_gap_takes_the_larger_value(self):
        payload = self._key_only_snapshot()
        payload["flows"][0]["max_gap"] = 99999.0
        self.store.import_dict(payload)
        self.assertEqual(self._row()["max_gap"], 99999.0)

    def test_rows_missing_the_edge_key_are_skipped(self):
        payload = self._key_only_snapshot()
        payload["flows"].append({"host": "srv1", "proto": "tcp"})
        payload["flows"].append({"peer_ip": "10.0.0.9"})
        merged = self.store.import_dict(payload)
        self.assertEqual(merged, 1)
        self.assertEqual(len(self.store.iter_flows("srv1")), 1)

    def test_non_list_flows_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.import_dict({"hosts": [], "flows": "not-a-list"})

    def test_full_roundtrip_is_lossless(self):
        src = Store(os.path.join(self.dir, "src.db"))
        self.addCleanup(src.close)
        src.upsert_host("srv2", {})
        src.record_edge("srv2", _edge(peer_ip="10.0.0.77"), now=2000.0)
        exported = src.export_dict("srv2")
        self.store.import_dict(exported)
        merged = dict(self.store.iter_flows("srv2")[0])
        original = dict(src.iter_flows("srv2")[0])
        for field in ("first_seen", "last_seen", "bytes", "packets", "service_name"):
            self.assertEqual(merged[field], original[field], field)


class HostFilterTests(unittest.TestCase):
    """CODE-018/019: per-host output must not disclose other hosts."""

    LEAK = "198.51.100.7"

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, "central.db"))
        self.addCleanup(self.store.close)
        for host, peer in (("srv1", "203.0.113.1"), ("srv2", self.LEAK)):
            self.store.upsert_host(host, {})
            self.store.record_edge("srv1" if host == "srv1" else "srv2", _edge(
                direction="inbound", peer_ip=peer, peer_class="external",
                service_port=23, service_name="telnet", l7_protocol="telnet",
            ))

    def test_no_report_format_leaks_another_host(self):
        outputs = {
            "security_markdown": report.security_markdown(self.store, "srv1"),
            "report_html": report.report_html(self.store, "srv1"),
            "topology_mermaid": report.topology_mermaid(self.store, "srv1"),
            "topology_dot": report.topology_dot(self.store, "srv1"),
            "catalog_json": report.catalog_json(self.store, "srv1"),
            "service_sheets": report.service_sheets(self.store, "srv1"),
            "matrix_csv": report.matrix_csv(self.store, "srv1"),
        }
        for name, text in outputs.items():
            self.assertNotIn(self.LEAK, text, f"{name} leaked another host")

    def test_filtered_output_still_contains_its_own_host(self):
        self.assertIn("203.0.113.1", report.report_html(self.store, "srv1"))

    def test_unfiltered_output_still_covers_every_host(self):
        self.assertIn(self.LEAK, report.report_html(self.store))

    def test_security_highlights_respects_the_filter(self):
        only_srv1 = report.security_highlights(self.store, "srv1")
        hosts = {
            str(item.get("host"))
            for items in only_srv1.values()
            for item in items
        }
        self.assertNotIn("srv2", hosts)


class ConfigRobustnessTests(unittest.TestCase):
    """CODE-021/022: bad or unreadable config must degrade, not abort."""

    def _write(self, text):
        path = os.path.join(tempfile.mkdtemp(), "commatrix.conf")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_malformed_values_fall_back_to_defaults(self):
        path = self._write(
            "[collector]\nrequire_root = enabled\npoll_interval = every 5s\n"
            "[resources]\nmemory_max_mb = lots\n"
        )
        with self.assertLogs("commatrix.config", level=logging.WARNING):
            cfg = load_config(path)
        self.assertFalse(cfg.require_root)
        self.assertEqual(cfg.poll_interval, 5.0)
        self.assertEqual(cfg.memory_max_mb, 128)

    def test_good_values_next_to_bad_ones_are_still_applied(self):
        path = self._write(
            "[resources]\nmemory_max_mb = lots\ncpu_budget_percent = 7.5\n"
        )
        with self.assertLogs("commatrix.config", level=logging.WARNING):
            cfg = load_config(path)
        self.assertEqual(cfg.cpu_budget_percent, 7.5)

    def test_unreadable_config_is_reported_not_silently_ignored(self):
        path = self._write("[collector]\npoll_interval = 9\n")
        os.chmod(path, 0o000)
        self.addCleanup(os.chmod, path, 0o644)
        if os.geteuid() == 0:
            self.skipTest("root bypasses the permission check")
        with self.assertLogs("commatrix.config", level=logging.WARNING):
            load_config(path)


class BatchedWriteTests(unittest.TestCase):
    """A poll must land in one transaction, not one fsync per edge."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "b.db")
        self.store = Store(self.db)
        self.addCleanup(self.store.close)
        self.store.upsert_host("h", {})

    def test_record_edges_persists_everything(self):
        edges = [_edge(peer_ip=f"10.1.0.{i}") for i in range(50)]
        self.assertEqual(self.store.record_edges("h", edges), 50)
        self.assertEqual(len(self.store.iter_flows("h")), 50)

    def test_data_is_committed_and_visible_to_another_connection(self):
        self.store.record_edges("h", [_edge(peer_ip="10.2.0.1")])
        other = sqlite3.connect(self.db)
        try:
            count = other.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        finally:
            other.close()
        self.assertEqual(count, 1)

    def test_batching_flag_is_cleared_after_the_batch(self):
        self.store.record_edges("h", [_edge()])
        self.assertFalse(self.store._batching)

    def test_single_record_edge_still_commits_on_its_own(self):
        self.store.record_edge("h", _edge(peer_ip="10.3.0.1"))
        other = sqlite3.connect(self.db)
        try:
            count = other.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        finally:
            other.close()
        self.assertEqual(count, 1)

    def test_retention_index_exists(self):
        names = {
            r[1] for r in self.store.conn.execute("PRAGMA index_list(flows)")
        }
        self.assertIn("idx_flows_last_seen", names)


if __name__ == "__main__":
    unittest.main()
