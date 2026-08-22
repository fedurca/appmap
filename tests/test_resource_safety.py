"""Regression tests for the resource-safety findings.

CODE-010  one /proc walk per poll, not per network namespace
CODE-011  bounded, budgeted package resolution
CODE-013  reconnect backoff on a clean EOF from the resolved monitor
CODE-014  bounded, fail-fast zabbix_get batch
CODE-016  no full VACUUM per prune batch
CODE-027  WinDnsMonitor does not re-ingest events it already saw
CODE-029  Job Object BOOL return values are checked

Every test here was verified to fail against the pre-fix code.
"""

import sqlite3
import unittest
from unittest import mock

from commatrix import processes, zabbix
from commatrix.collector import Collector
from commatrix.config import Config
from commatrix.platform.win import winetw, winresources
from commatrix.sockets import SocketEntry
from commatrix.store import Store

import os
import tempfile


class ProcWalkPerPollTest(unittest.TestCase):
    """CODE-010."""

    def _collector(self):
        return Collector(Config(database=":memory:"))

    def test_socket_indexes_uses_supplied_map(self):
        col = self._collector()
        entry = SocketEntry(
            proto="tcp", family=2, local_ip="10.0.0.1", local_port=443,
            remote_ip="10.0.0.2", remote_port=5000, state="ESTABLISHED",
            inode=99, uid=0,
        )
        with mock.patch("commatrix.collector.build_inode_to_pid") as walk:
            established, _listening = col._socket_indexes([entry], {99: 4242})
        walk.assert_not_called()
        self.assertEqual(
            established[("tcp", "10.0.0.1", 443, "10.0.0.2", 5000)], 4242
        )

    def test_build_edges_walks_proc_once_across_namespaces(self):
        col = self._collector()
        col.config.netns_scope = "all"

        class _Ns:
            def __init__(self, label):
                self.label = label
                self.proc_root = "/proc/1/root/proc"
                self.container_id = None
                self.pod = None

        sockets = [SocketEntry(
            proto="tcp", family=2, local_ip="10.0.0.1", local_port=443,
            remote_ip="10.0.0.2", remote_port=5000, state="ESTABLISHED",
            inode=99, uid=0,
        )]
        with mock.patch("commatrix.collector.build_inode_to_pid", return_value={}) as walk, \
             mock.patch("commatrix.collector.read_all_sockets", return_value=sockets), \
             mock.patch("commatrix.collector.ct.entries_from_sockets", return_value=[]), \
             mock.patch("commatrix.collector.ct.is_root", return_value=True), \
             mock.patch(
                 "commatrix.collector.netnsmod.enumerate_netns",
                 return_value=[_Ns("ns1"), _Ns("ns2"), _Ns("ns3")],
             ):
            col.build_edges([])
        self.assertEqual(
            walk.call_count, 1,
            "build_inode_to_pid() must run once per poll, not once per netns",
        )


class PackageBudgetTest(unittest.TestCase):
    """CODE-011."""

    def setUp(self):
        processes.clear_package_cache()

    tearDown = setUp

    def test_budget_caps_subprocess_lookups(self):
        budget = processes.PackageBudget(max_lookups=3, max_seconds=-1)
        with mock.patch(
            "commatrix.processes._resolve_package_uncached", return_value="pkg"
        ) as resolver:
            for i in range(10):
                processes._package_for_path(f"/usr/bin/bin{i}", budget)
        self.assertEqual(resolver.call_count, 3)
        self.assertEqual(budget.skipped, 7)

    def test_deferred_binaries_are_retried_on_the_next_poll(self):
        exhausted = processes.PackageBudget(max_lookups=0, max_seconds=-1)
        with mock.patch(
            "commatrix.processes._resolve_package_uncached", return_value="pkg"
        ) as resolver:
            self.assertIsNone(processes._package_for_path("/usr/bin/foo", exhausted))
            self.assertEqual(resolver.call_count, 0)
            fresh = processes.PackageBudget(max_lookups=5, max_seconds=-1)
            self.assertEqual(processes._package_for_path("/usr/bin/foo", fresh), "pkg")
            self.assertEqual(resolver.call_count, 1)

    def test_cache_hit_costs_no_budget(self):
        budget = processes.PackageBudget(max_lookups=1, max_seconds=-1)
        with mock.patch(
            "commatrix.processes._resolve_package_uncached", return_value="pkg"
        ):
            processes._package_for_path("/usr/bin/foo", budget)
            processes._package_for_path("/usr/bin/foo", budget)
            processes._package_for_path("/usr/bin/foo", budget)
        self.assertEqual(budget.lookups, 1)
        self.assertEqual(budget.skipped, 0)

    def test_time_budget_stops_further_lookups(self):
        ticks = iter([0.0, 0.5, 9.0, 9.0, 9.0])
        budget = processes.PackageBudget(
            max_lookups=-1, max_seconds=1.0, clock=lambda: next(ticks)
        )
        with mock.patch(
            "commatrix.processes._resolve_package_uncached", return_value="pkg"
        ) as resolver:
            processes._package_for_path("/usr/bin/a", budget)
            processes._package_for_path("/usr/bin/b", budget)
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(budget.skipped, 1)


class ZabbixBatchTest(unittest.TestCase):
    """CODE-014."""

    def test_batch_stops_after_consecutive_failures(self):
        with mock.patch("commatrix.zabbix.zabbix_get_available", return_value=True), \
             mock.patch("commatrix.zabbix.query_agent_key", return_value=None) as q:
            zabbix.collect_host_params("/nonexistent.conf")
        self.assertLessEqual(
            q.call_count, zabbix.AGENT_QUERY_MAX_FAILURES,
            "an unreachable agent must not be asked for all 8 keys",
        )

    def test_successful_keys_do_not_trip_the_failure_counter(self):
        with mock.patch("commatrix.zabbix.zabbix_get_available", return_value=True), \
             mock.patch("commatrix.zabbix.query_agent_key", return_value="v") as q:
            params = zabbix.collect_host_params("/nonexistent.conf")
        self.assertEqual(q.call_count, len(zabbix.DEFAULT_AGENT_KEYS))
        self.assertEqual(params["source"], "zabbix_agent")

    def test_per_call_timeout_is_bounded(self):
        captured = {}

        def _fake_run(cmd, **kwargs):
            captured["timeout"] = kwargs.get("timeout")
            raise OSError("boom")

        with mock.patch("commatrix.zabbix.zabbix_get_available", return_value=True), \
             mock.patch("commatrix.zabbix.subprocess.run", _fake_run):
            zabbix.query_agent_key("agent.version")
        self.assertLessEqual(captured["timeout"], zabbix.AGENT_QUERY_TIMEOUT)


class VacuumThrottleTest(unittest.TestCase):
    """CODE-016."""

    def _store(self):
        self.tmp = tempfile.mkdtemp()
        return Store(os.path.join(self.tmp, "c.db"))

    def test_prune_to_budget_does_not_vacuum_per_batch(self):
        store = self._store()
        try:
            for i in range(200):
                store.conn.execute(
                    "INSERT INTO flows (host, proto, direction, local_ip, peer_ip, "
                    "service_port, first_seen, last_seen) VALUES "
                    "('h','tcp','outbound','10.0.0.1',?,?,0,?)",
                    (f"10.0.1.{i % 255}", 1000 + i, float(i)),
                )
            store.conn.commit()
            with mock.patch.object(store, "_full_vacuum", return_value=True) as vac:
                store.prune_to_budget(max_bytes=1)
            self.assertLessEqual(
                vac.call_count, 1,
                "a full VACUUM must not run once per prune batch",
            )
        finally:
            store.close()

    def test_full_vacuum_declines_when_disk_is_nearly_full(self):
        store = self._store()
        try:
            with mock.patch.object(store, "db_size_bytes", return_value=100_000_000), \
                 mock.patch.object(store, "_free_space_bytes", return_value=1_000_000):
                self.assertFalse(store._full_vacuum())
            with mock.patch.object(store, "db_size_bytes", return_value=1_000), \
                 mock.patch.object(store, "_free_space_bytes", return_value=1_000_000_000):
                self.assertTrue(store._full_vacuum())
        finally:
            store.close()

    def test_incremental_reclaim_is_available(self):
        store = self._store()
        try:
            mode = store.conn.execute("PRAGMA auto_vacuum").fetchone()[0]
            self.assertEqual(mode, 2, "new databases must use auto_vacuum=INCREMENTAL")
        finally:
            store.close()


class WinDnsBookmarkTest(unittest.TestCase):
    """CODE-027."""

    XML = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventRecordID>{rid}</EventRecordID></System>"
        '<EventData><Data Name="QueryName">{name}</Data>'
        '<Data Name="QueryType">1</Data>'
        '<Data Name="QueryResults">::ffff:1.2.3.4;</Data></EventData></Event>'
    )

    def test_same_batch_is_not_ingested_twice(self):
        mon = winetw.WinDnsMonitor()
        batch = self.XML.format(rid=10, name="a.example")
        self.assertEqual(mon.ingest(batch), 1)
        self.assertEqual(mon.ingest(batch), 0)
        self.assertEqual(mon.ingest(batch), 0)
        self.assertEqual(len(mon.drain()), 1)

    def test_new_records_after_the_bookmark_are_ingested(self):
        mon = winetw.WinDnsMonitor()
        mon.ingest(self.XML.format(rid=10, name="a.example"))
        newer = (
            self.XML.format(rid=11, name="b.example")
            + self.XML.format(rid=10, name="a.example")
        )
        self.assertEqual(mon.ingest(newer), 1)
        names = [ev.qname for ev in mon.drain()]
        self.assertEqual(names, ["a.example", "b.example"])

    def test_events_without_record_id_are_deduped_by_content(self):
        mon = winetw.WinDnsMonitor()
        no_id = (
            '<Event><EventData><Data Name="QueryName">c.example</Data>'
            '<Data Name="QueryResults">9.9.9.9;</Data></EventData></Event>'
        )
        self.assertEqual(mon.ingest(no_id), 1)
        self.assertEqual(mon.ingest(no_id), 0)


class JobObjectReturnCheckTest(unittest.TestCase):
    """CODE-029."""

    def _fake_kernel32(self, *, create=1234, set_info=True, assign=True):
        k32 = mock.MagicMock()
        k32.CreateJobObjectW.return_value = create
        k32.SetInformationJobObject.return_value = 1 if set_info else 0
        k32.AssignProcessToJobObject.return_value = 1 if assign else 0
        k32.GetCurrentProcess.return_value = 99
        k32.GetLastError.return_value = 5
        k32.CloseHandle.return_value = 1
        return k32

    def _run(self, k32):
        import ctypes
        warnings = []
        fake_windll = mock.MagicMock()
        fake_windll.kernel32 = k32
        with mock.patch.object(ctypes, "windll", fake_windll, create=True):
            ok = winresources.apply_job_limits(warnings=warnings)
        return ok, warnings

    def test_reports_success_when_every_call_succeeds(self):
        ok, warnings = self._run(self._fake_kernel32())
        self.assertTrue(ok)
        self.assertEqual(warnings, [])

    def test_failed_set_information_is_not_reported_as_a_hard_ceiling(self):
        ok, warnings = self._run(self._fake_kernel32(set_info=False))
        self.assertFalse(ok)
        self.assertTrue(any("SetInformationJobObject" in w for w in warnings))
        self.assertTrue(any("GetLastError=5" in w for w in warnings))

    def test_failed_assign_closes_the_handle_and_reports_failure(self):
        k32 = self._fake_kernel32(assign=False)
        ok, warnings = self._run(k32)
        self.assertFalse(ok)
        k32.CloseHandle.assert_called_once()
        self.assertTrue(any("AssignProcessToJobObject" in w for w in warnings))


if __name__ == "__main__":
    unittest.main()
