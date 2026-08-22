"""CODE-005: collector.py is the most complex module and had no unit tests.

Everything here drives the real Collector against synthetic conntrack entries
and socket tables, so the covered behaviour is the orchestration itself:
direction and peer classification, pid attribution, per-edge data_quality,
DNS/SNI enrichment precedence, DoH classification, netns fan-out, and the
run-loop's disk-pressure and shutdown paths.
"""

import os
import tempfile
import unittest
from unittest import mock

from commatrix import conntrack as ct
from commatrix.collector import Collector, _enforce_disk, run_loop
from commatrix.config import Config
from commatrix.sockets import SocketEntry
from commatrix.store import Store


def _entry(src, sport, dst, dport, proto="tcp", obytes=1000, rbytes=2000, state="ESTABLISHED"):
    return ct.ConntrackEntry(
        l4proto=proto, state=state,
        orig_src=src, orig_dst=dst, orig_sport=sport, orig_dport=dport,
        orig_bytes=obytes, orig_packets=10,
        reply_src=dst, reply_dst=src, reply_sport=dport, reply_dport=sport,
        reply_bytes=rbytes, reply_packets=8,
    )


def _sock(local_ip, local_port, remote_ip="0.0.0.0", remote_port=0,
          state="LISTEN", inode=1, proto="tcp"):
    return SocketEntry(
        proto=proto, family=2, local_ip=local_ip, local_port=local_port,
        remote_ip=remote_ip, remote_port=remote_port, state=state,
        inode=inode, uid=0,
    )


class CollectorEdgeBuildingTest(unittest.TestCase):
    def setUp(self):
        self.config = Config(database=":memory:", resolve_external=False)
        self.collector = Collector(self.config)
        self.collector.capture_backend = "procfs"

    def _edges(self, entries, sockets, inode_to_pid=None, processes=None):
        with mock.patch("commatrix.collector.collect_processes",
                        return_value=processes or {}), \
             mock.patch("commatrix.collector.ct.accounting_enabled", return_value=True):
            return self.collector._edges_from(
                entries, sockets, "host", inode_to_pid=inode_to_pid or {}
            )

    def test_inbound_edge_from_a_listening_socket(self):
        edges = self._edges(
            [_entry("203.0.113.9", 51000, "10.0.0.10", 443)],
            [_sock("10.0.0.10", 443)],
        )
        self.assertEqual(len(edges), 1)
        e = edges[0]
        self.assertEqual(e.direction, "inbound")
        self.assertEqual(e.service_port, 443)
        self.assertEqual(e.peer_ip, "203.0.113.9")
        self.assertEqual(e.peer_class, "external")

    def test_outbound_edge_to_a_remote_service(self):
        edges = self._edges(
            [_entry("10.0.0.10", 44444, "10.0.0.20", 5432)],
            [_sock("10.0.0.10", 44444, "10.0.0.20", 5432, state="ESTABLISHED", inode=7)],
        )
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].direction, "outbound")
        self.assertEqual(edges[0].service_port, 5432)
        self.assertEqual(edges[0].peer_class, "internal")

    def test_pid_attribution_reaches_the_edge(self):
        from commatrix.processes import ProcessInfo

        proc = ProcessInfo(pid=4242, comm="nginx", exe="/usr/sbin/nginx",
                           unit="nginx.service", package="nginx-core")
        edges = self._edges(
            [_entry("203.0.113.9", 51000, "10.0.0.10", 443)],
            [_sock("10.0.0.10", 443, inode=99)],
            inode_to_pid={99: 4242},
            processes={4242: proc},
        )
        self.assertEqual(edges[0].process_comm, "nginx")
        self.assertEqual(edges[0].unit, "nginx.service")
        self.assertEqual(edges[0].package, "nginx-core")

    def test_multiple_connections_fold_onto_one_edge(self):
        entries = [
            _entry("203.0.113.9", 51000 + i, "10.0.0.10", 443, obytes=100, rbytes=200)
            for i in range(5)
        ]
        edges = self._edges(entries, [_sock("10.0.0.10", 443)])
        self.assertEqual(len(edges), 1, "ephemeral client ports must not explode the matrix")
        self.assertEqual(edges[0].snapshot_bytes, 5 * 300)

    def test_data_quality_flags_the_socket_snapshot_backend(self):
        self.collector.capture_backend = "sockets"
        edges = self._edges(
            [_entry("203.0.113.9", 51000, "10.0.0.10", 443)],
            [_sock("10.0.0.10", 443)],
        )
        self.assertEqual(edges[0].data_quality, "socket-snapshot")

    def test_data_quality_flags_missing_accounting(self):
        with mock.patch("commatrix.collector.collect_processes", return_value={}), \
             mock.patch("commatrix.collector.ct.accounting_enabled", return_value=False):
            edges = self.collector._edges_from(
                [_entry("203.0.113.9", 51000, "10.0.0.10", 443, obytes=0, rbytes=0)],
                [_sock("10.0.0.10", 443)], "host", inode_to_pid={},
            )
        self.assertEqual(edges[0].data_quality, "no-accounting")

    def test_non_host_namespace_is_always_socket_snapshot(self):
        with mock.patch("commatrix.collector.collect_processes", return_value={}), \
             mock.patch("commatrix.collector.ct.accounting_enabled", return_value=True):
            edges = self.collector._edges_from(
                [_entry("203.0.113.9", 51000, "10.0.0.10", 443)],
                [_sock("10.0.0.10", 443)], "netns:abc123", inode_to_pid={},
            )
        self.assertEqual(edges[0].data_quality, "socket-snapshot")
        self.assertEqual(edges[0].netns, "netns:abc123")

    def test_dns_monitor_wins_over_sni_for_the_peer_domain(self):
        self.collector.dns_monitor = mock.Mock(lookup=mock.Mock(return_value="a.example"))
        self.collector.sni_monitor = mock.Mock(lookup=mock.Mock(return_value="b.example"))
        edges = self._edges(
            [_entry("10.0.0.10", 44444, "203.0.113.9", 443)],
            [_sock("10.0.0.10", 44444, "203.0.113.9", 443, state="ESTABLISHED", inode=3)],
        )
        self.assertEqual(edges[0].peer_domain, "a.example")

    def test_sni_fills_in_when_dns_has_nothing(self):
        self.collector.dns_monitor = mock.Mock(lookup=mock.Mock(return_value=None))
        self.collector.sni_monitor = mock.Mock(lookup=mock.Mock(return_value="b.example"))
        edges = self._edges(
            [_entry("10.0.0.10", 44444, "203.0.113.9", 443)],
            [_sock("10.0.0.10", 44444, "203.0.113.9", 443, state="ESTABLISHED", inode=3)],
        )
        self.assertEqual(edges[0].peer_domain, "b.example")

    def test_doh_classification_applies_only_to_external_peers(self):
        self.collector.doh_signatures = mock.Mock(
            classify=mock.Mock(return_value="doh:cloudflare")
        )
        external = self._edges(
            [_entry("10.0.0.10", 44444, "203.0.113.9", 443)],
            [_sock("10.0.0.10", 44444, "203.0.113.9", 443, state="ESTABLISHED", inode=3)],
        )
        self.assertEqual(external[0].l7_protocol, "doh:cloudflare")

        internal = self._edges(
            [_entry("10.0.0.10", 44445, "10.0.0.53", 443)],
            [_sock("10.0.0.10", 44445, "10.0.0.53", 443, state="ESTABLISHED", inode=4)],
        )
        self.assertNotEqual(internal[0].l7_protocol, "doh:cloudflare")

    def test_reverse_dns_is_cached_and_bounded(self):
        self.collector.config.resolve_external = True
        with mock.patch("commatrix.collector._socket.gethostbyaddr",
                        return_value=("peer.example", [], [])) as lookup:
            for _ in range(5):
                self.collector._reverse_dns("203.0.113.9")
        self.assertEqual(lookup.call_count, 1)

    def test_reverse_dns_failure_is_cached_as_a_miss(self):
        with mock.patch("commatrix.collector._socket.gethostbyaddr",
                        side_effect=OSError("nxdomain")) as lookup:
            self.assertIsNone(self.collector._reverse_dns("203.0.113.9"))
            self.assertIsNone(self.collector._reverse_dns("203.0.113.9"))
        self.assertEqual(lookup.call_count, 1)

    def test_accounting_warning_is_logged_once(self):
        with mock.patch("commatrix.collector.collect_processes", return_value={}), \
             mock.patch("commatrix.collector.ct.accounting_enabled", return_value=False), \
             mock.patch("commatrix.collector.log") as log:
            for _ in range(3):
                self.collector._edges_from(
                    [_entry("203.0.113.9", 51000, "10.0.0.10", 443)],
                    [_sock("10.0.0.10", 443)], "host", inode_to_pid={},
                )
        self.assertEqual(log.warning.call_count, 1)


class CollectorPollTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.config = Config(database=os.path.join(self.tmp, "c.db"))
        self.collector = Collector(self.config)
        self.store = Store(self.config.database)
        self.addCleanup(self.store.close)

    def test_poll_once_persists_edges(self):
        with mock.patch("commatrix.collector.ct.read_conntrack_snapshot",
                        return_value=[_entry("203.0.113.9", 51000, "10.0.0.10", 443)]), \
             mock.patch("commatrix.collector.read_all_sockets",
                        return_value=[_sock("10.0.0.10", 443)]), \
             mock.patch("commatrix.collector.build_inode_to_pid", return_value={}), \
             mock.patch("commatrix.collector.collect_processes", return_value={}), \
             mock.patch("commatrix.collector.ct.accounting_enabled", return_value=True):
            n = self.collector.poll_once(self.store, "host1", now=100.0)
        self.assertEqual(n, 1)
        self.assertEqual(self.store.flow_count(), 1)

    def test_poll_once_propagates_a_permission_error(self):
        with mock.patch("commatrix.collector.ct.read_conntrack_snapshot",
                        side_effect=PermissionError("need root")):
            with self.assertRaises(PermissionError):
                self.collector.poll_once(self.store, "host1")

    def test_repeated_polls_accumulate_bytes_not_rows(self):
        entries = [_entry("203.0.113.9", 51000, "10.0.0.10", 443, obytes=1000, rbytes=0)]
        with mock.patch("commatrix.collector.ct.read_conntrack_snapshot",
                        return_value=entries), \
             mock.patch("commatrix.collector.read_all_sockets",
                        return_value=[_sock("10.0.0.10", 443)]), \
             mock.patch("commatrix.collector.build_inode_to_pid", return_value={}), \
             mock.patch("commatrix.collector.collect_processes", return_value={}), \
             mock.patch("commatrix.collector.ct.accounting_enabled", return_value=True):
            self.collector.poll_once(self.store, "host1", now=100.0)
            entries[0].orig_bytes = 3000
            self.collector.poll_once(self.store, "host1", now=200.0)
        self.assertEqual(self.store.flow_count(), 1)
        row = dict(self.store.iter_flows()[0])
        self.assertGreaterEqual(row["observations"], 2)


class EnforceDiskTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.config = Config(database=os.path.join(self.tmp, "c.db"), retention_days=1)
        self.store = Store(self.config.database)
        self.addCleanup(self.store.close)

    def test_retention_prunes_and_reports(self):
        governor = mock.Mock()
        governor.disk_status.return_value = mock.Mock(
            over_budget=False, budget_bytes=10 ** 9, db_bytes=1000, free_fraction=0.5
        )
        governor.should_pause_writes.return_value = False
        with mock.patch.object(self.store, "prune_older_than", return_value=7) as prune:
            paused = _enforce_disk(self.config, self.store, governor)
        prune.assert_called_once()
        self.assertFalse(paused)

    def test_writes_pause_when_free_space_is_below_the_floor(self):
        governor = mock.Mock()
        governor.disk_status.return_value = mock.Mock(
            over_budget=False, budget_bytes=10 ** 9, db_bytes=1000, free_fraction=0.01
        )
        governor.should_pause_writes.return_value = True
        self.assertTrue(_enforce_disk(self.config, self.store, governor))

    def test_over_budget_triggers_a_prune_to_budget(self):
        governor = mock.Mock()
        over = mock.Mock(over_budget=True, budget_bytes=1000, db_bytes=5000,
                         free_fraction=0.5)
        under = mock.Mock(over_budget=False, budget_bytes=1000, db_bytes=900,
                          free_fraction=0.5)
        governor.disk_status.side_effect = [over, under]
        governor.should_pause_writes.return_value = False
        with mock.patch.object(self.store, "prune_to_budget", return_value=42) as prune:
            _enforce_disk(self.config, self.store, governor)
        prune.assert_called_once_with(1000)


class RunLoopTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.config = Config(
            database=os.path.join(self.tmp, "c.db"),
            poll_interval=0.01, dns_enabled=False, sni_enabled=False,
            html_report=False, capture_mode="poll",
            sysctl_state_file=os.path.join(self.tmp, "sysctl.state"),
        )

    def _patches(self):
        return [
            mock.patch("commatrix.collector.ct.read_conntrack_snapshot", return_value=[]),
            mock.patch("commatrix.collector.read_all_sockets", return_value=[]),
            mock.patch("commatrix.collector.build_inode_to_pid", return_value={}),
            mock.patch("commatrix.collector.ct.accounting_enabled", return_value=True),
            mock.patch("commatrix.collector.ctnetlink.available", return_value=False),
            mock.patch("commatrix.collector._platform.lower_priority"),
            mock.patch("commatrix.collector._install_restore_handlers"),
            mock.patch("commatrix.collector.collect_host_params",
                       return_value={"hostname": "h"}),
            mock.patch("commatrix.collector.resolve_host", return_value="h"),
            mock.patch.object(ct.SysctlGuard, "apply"),
            mock.patch.object(ct.SysctlGuard, "restore"),
            mock.patch("commatrix.collector.time.sleep"),
        ]

    def test_bounded_run_records_a_run_and_closes_the_store(self):
        patches = self._patches()
        for p in patches:
            p.start()
        try:
            run_loop(self.config, iterations=3)
        finally:
            for p in patches:
                p.stop()
        store = Store(self.config.database, read_only=True)
        try:
            runs = store.run_stats()
        finally:
            store.close()
        self.assertGreaterEqual(runs["run_count"], 1)

    def test_a_paused_cycle_records_nothing(self):
        patches = self._patches()
        patches.append(
            mock.patch("commatrix.collector._enforce_disk", return_value=True)
        )
        for p in patches:
            p.start()
        try:
            run_loop(self.config, iterations=2)
        finally:
            for p in patches:
                p.stop()
        store = Store(self.config.database, read_only=True)
        try:
            self.assertEqual(store.flow_count(), 0)
        finally:
            store.close()

    def test_windows_delegates_to_the_windows_loop(self):
        with mock.patch("commatrix.collector._platform.IS_WINDOWS", True), \
             mock.patch("commatrix.platform.win.runloop.run") as winrun:
            run_loop(self.config, iterations=1)
        winrun.assert_called_once()


if __name__ == "__main__":
    unittest.main()
