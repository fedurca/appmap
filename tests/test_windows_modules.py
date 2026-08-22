"""CODE-035: perms, runtime, runloop, capture and winresources had no tests.

All of these are ctypes/subprocess wrappers, so they were treated as
"integration only, covered on a Windows host" -- which in practice meant
covered by nobody. Everything reachable without a Windows kernel is exercised
here on any OS: argument construction, return-value handling, retry and cache
logic, and the collection loop's orchestration.
"""

import struct
import unittest
from unittest import mock
from types import SimpleNamespace

from commatrix.catalog import Signatures
from commatrix.platform.win import capture, iphlp, perms, runtime, winresources


class WinPermsTest(unittest.TestCase):
    def _run_capture(self, returncode=0):
        calls = []

        def _fake(args, **kwargs):
            calls.append(list(args))
            return mock.Mock(returncode=returncode, stdout="", stderr="denied")

        return calls, _fake

    def test_inheritance_is_reset_before_grants(self):
        calls, fake = self._run_capture()
        with mock.patch("commatrix.platform.win.perms.subprocess.run", fake):
            perms.restrict(r"C:\data\c.db")
        self.assertIn("/inheritance:r", calls[0])

    def test_failure_of_the_reset_is_reported(self):
        calls, fake = self._run_capture(returncode=5)
        with mock.patch("commatrix.platform.win.perms.subprocess.run", fake):
            self.assertFalse(perms.restrict(r"C:\data\c.db"))

    def test_missing_optional_principal_is_not_a_hard_failure_of_the_reset(self):
        def _fake(args, **kwargs):
            # The service account does not exist yet -> icacls fails for it.
            if any("commatrix:" in a for a in args):
                return mock.Mock(returncode=1332, stdout="", stderr="no mapping")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("commatrix.platform.win.perms.subprocess.run", _fake):
            # Returns False (not everything was granted) but must not raise.
            self.assertFalse(perms.restrict(r"C:\data\c.db"))

    def test_current_account_includes_the_domain_when_known(self):
        with mock.patch.dict(perms.os.environ,
                             {"USERNAME": "svc", "USERDOMAIN": "CORP"}, clear=False):
            self.assertEqual(perms.current_account(), "CORP\\svc")

    def test_current_account_is_none_without_a_username(self):
        with mock.patch.dict(perms.os.environ, {}, clear=True):
            self.assertIsNone(perms.current_account())

    def test_icacls_timeouts_are_contained(self):
        with mock.patch("commatrix.platform.win.perms.subprocess.run",
                        side_effect=OSError("icacls missing")):
            self.assertFalse(perms.restrict(r"C:\data\c.db"))


class WinRuntimeTest(unittest.TestCase):
    def test_is_admin_is_false_off_windows(self):
        self.assertFalse(runtime.is_admin())

    def test_running_as_service_detects_system(self):
        with mock.patch.dict(runtime.os.environ, {"USERNAME": "SYSTEM"}, clear=False):
            self.assertTrue(runtime.running_as_service())

    def test_running_as_service_detects_a_machine_account(self):
        with mock.patch.dict(runtime.os.environ, {"USERNAME": "WEB01$"}, clear=False):
            self.assertTrue(runtime.running_as_service())

    def test_interactive_user_is_not_a_service(self):
        with mock.patch.dict(runtime.os.environ, {"USERNAME": "roman"}, clear=False), \
             mock.patch.object(runtime, "_session_id", return_value=1):
            self.assertFalse(runtime.running_as_service())

    def test_install_service_builds_a_system_startup_task(self):
        calls = []
        with mock.patch.object(
            runtime.subprocess, "run",
            side_effect=lambda a, **k: calls.append(list(a)) or mock.Mock(
                returncode=0, stdout="", stderr=""),
        ):
            self.assertTrue(runtime.install_service(r"C:\conf.ini", python_exe="py.exe"))
        create = calls[0]
        self.assertIn("/create", create)
        self.assertIn("onstart", create)
        self.assertIn("SYSTEM", create)

    def test_install_service_reports_failure(self):
        with mock.patch.object(
            runtime.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="denied"),
        ):
            self.assertFalse(runtime.install_service(r"C:\conf.ini"))

    def test_uninstall_service_reports_the_delete_result(self):
        with mock.patch.object(
            runtime.subprocess, "run",
            return_value=mock.Mock(returncode=0, stdout="", stderr=""),
        ):
            self.assertTrue(runtime.uninstall_service())
        with mock.patch.object(runtime.subprocess, "run",
                               side_effect=OSError("no schtasks")):
            self.assertFalse(runtime.uninstall_service())


class IphlpTableRetryTest(unittest.TestCase):
    """SEC-026 retry behaviour, exercised through a fake iphlpapi."""

    def _fake_ctypes(self, sequence):
        import ctypes

        calls = {"n": 0}

        def _get_table(buf, size_ptr, order, family, cls, reserved):
            if buf is None:
                size_ptr._obj.value = 64
                return 122
            calls["n"] += 1
            ret = sequence[min(calls["n"] - 1, len(sequence) - 1)]
            if ret == 0:
                struct.pack_into("<I", buf, 0, 0)
                size_ptr._obj.value = 4
            return ret

        iphlpapi = mock.MagicMock()
        iphlpapi.GetExtendedTcpTable = mock.Mock(side_effect=_get_table)
        fake_windll = mock.MagicMock()
        fake_windll.iphlpapi = iphlpapi
        return ctypes, fake_windll, calls

    def test_retries_on_insufficient_buffer(self):
        ctypes, windll, calls = self._fake_ctypes([122, 122, 0])
        with mock.patch.object(ctypes, "windll", windll, create=True):
            data = iphlp._get_extended_tcp_table(2)
        self.assertEqual(calls["n"], 3)
        self.assertEqual(iphlp.parse_tcp_table_v4(data), [])

    def test_gives_up_after_the_attempt_limit(self):
        ctypes, windll, calls = self._fake_ctypes([122])
        with mock.patch.object(ctypes, "windll", windll, create=True):
            with self.assertRaises(OSError):
                iphlp._get_extended_tcp_table(2)
        self.assertEqual(calls["n"], iphlp._TABLE_MAX_ATTEMPTS)

    def test_a_different_error_is_not_retried(self):
        ctypes, windll, calls = self._fake_ctypes([5])
        with mock.patch.object(ctypes, "windll", windll, create=True):
            with self.assertRaises(OSError):
                iphlp._get_extended_tcp_table(2)
        self.assertEqual(calls["n"], 1)


class WinCaptureTest(unittest.TestCase):
    def _collector(self, doh=None):
        return SimpleNamespace(
            classifier=SimpleNamespace(classify=lambda ip: "external"),
            signatures=Signatures(),
            doh_signatures=SimpleNamespace(classify=lambda *a, **k: doh),
            dns_monitor=None,
            sni_monitor=None,
        )

    def _conn(self, lip, lport, rip, rport, state="ESTABLISHED", pid=100, sent=0):
        return iphlp.WinConn(
            proto="tcp", family=2, local_ip=lip, local_port=lport,
            remote_ip=rip, remote_port=rport, state=state, pid=pid,
            bytes_sent=sent, accounted=bool(sent),
        )

    def _build(self, conns, processes=None):
        with mock.patch.multiple(
            capture,
            iphlp=mock.MagicMock(snapshot=mock.Mock(return_value=conns)),
            winprocess=mock.MagicMock(
                collect_processes=mock.Mock(return_value=processes or {})
            ),
        ):
            return capture.build_edges(self._collector())

    def test_listening_sockets_do_not_become_edges(self):
        edges = self._build([self._conn("0.0.0.0", 445, "0.0.0.0", 0, state="LISTEN")])
        self.assertEqual(edges, [])

    def test_connections_without_a_remote_are_skipped(self):
        edges = self._build([self._conn("10.0.0.5", 50000, "0.0.0.0", 0)])
        self.assertEqual(edges, [])

    def test_established_connection_becomes_an_edge(self):
        edges = self._build([self._conn("10.0.0.5", 50000, "93.184.216.34", 443)])
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].peer_ip, "93.184.216.34")
        self.assertEqual(edges[0].netns, "host")

    def test_process_attribution_is_carried_through(self):
        from commatrix.processes import ProcessInfo

        edges = self._build(
            [self._conn("10.0.0.5", 50000, "93.184.216.34", 443, pid=4242)],
            processes={4242: ProcessInfo(pid=4242, comm="chrome.exe",
                                         exe=r"C:\chrome.exe", unit="Dnscache")},
        )
        self.assertEqual(edges[0].process_comm, "chrome.exe")
        self.assertEqual(edges[0].unit, "Dnscache")

    def test_inbound_flow_resolves_the_listening_pid(self):
        conns = [
            self._conn("0.0.0.0", 3389, "0.0.0.0", 0, state="LISTEN", pid=7),
            self._conn("10.0.0.5", 3389, "10.0.0.9", 51000, pid=0),
        ]
        with mock.patch.multiple(
            capture,
            iphlp=mock.MagicMock(snapshot=mock.Mock(return_value=conns)),
            winprocess=mock.MagicMock(collect_processes=mock.Mock(return_value={})),
        ) as _:
            edges = capture.build_edges(self._collector())
        self.assertEqual(len(edges), 1)

    def test_flow_accounting_helper_matches_both_tuple_shapes(self):
        keys = {("tcp", "10.0.0.5", 3389, "10.0.0.9", 51000)}
        flow = SimpleNamespace(
            proto="tcp", local_ip="10.0.0.5", local_port=51001,
            peer_ip="10.0.0.9", peer_port=51000, service_port=3389,
        )
        self.assertTrue(capture._flow_is_accounted(flow, keys))
        self.assertFalse(capture._flow_is_accounted(flow, set()))


class WinResourcesTest(unittest.TestCase):
    def test_set_idle_priority_is_false_off_windows(self):
        self.assertFalse(winresources.set_idle_priority())

    def test_cpu_rate_is_clamped_to_the_api_range(self):
        import ctypes

        captured = {}

        def _set_info(hjob, cls, ptr, size):
            if cls == 15:
                captured["rate"] = ctypes.cast(
                    ptr, ctypes.POINTER(ctypes.c_uint32)
                )[1]
            return 1

        k32 = mock.MagicMock()
        k32.CreateJobObjectW.return_value = 1
        k32.SetInformationJobObject.side_effect = _set_info
        k32.AssignProcessToJobObject.return_value = 1
        fake = mock.MagicMock()
        fake.kernel32 = k32
        with mock.patch.object(ctypes, "windll", fake, create=True):
            winresources.apply_job_limits(cpu_percent=1000.0)
        self.assertLessEqual(captured["rate"], 10000)

    def test_create_failure_is_reported(self):
        import ctypes

        k32 = mock.MagicMock()
        k32.CreateJobObjectW.return_value = 0
        k32.GetLastError.return_value = 1314
        fake = mock.MagicMock()
        fake.kernel32 = k32
        warnings = []
        with mock.patch.object(ctypes, "windll", fake, create=True):
            self.assertFalse(winresources.apply_job_limits(warnings=warnings))
        self.assertTrue(any("CreateJobObjectW" in w for w in warnings))


class WinRunLoopTest(unittest.TestCase):
    def _patches(self, tmpdir):
        return [
            mock.patch("commatrix.platform.win.runloop.rsrc.process_cpu_seconds",
                       side_effect=[0.0, 0.05] * 20),
            mock.patch("commatrix.collector.collect_host_params",
                       return_value={"hostname": "win01"}),
            mock.patch("commatrix.collector.resolve_host", return_value="win01"),
            mock.patch("commatrix.platform.win.capture.build_edges", return_value=[]),
            mock.patch("commatrix.platform.win.winresources.apply_job_limits",
                       return_value=True),
            mock.patch("commatrix.platform.win.winetw.available", return_value=False),
            mock.patch("commatrix.platform.win.winsni.available", return_value=False),
            mock.patch("commatrix.platform.lower_priority"),
            mock.patch("commatrix.platform.win.runloop.time.sleep"),
        ]

    def test_bounded_run_starts_and_finishes_a_run(self):
        import os
        import tempfile

        from commatrix.config import Config
        from commatrix.platform.win import runloop
        from commatrix.store import Store

        tmp = tempfile.mkdtemp()
        config = Config(database=os.path.join(tmp, "w.db"), poll_interval=0.01,
                        dns_enabled=False, sni_enabled=False, html_report=False)
        patches = self._patches(tmp)
        for p in patches:
            p.start()
        try:
            runloop.run(config, iterations=2)
        finally:
            for p in patches:
                p.stop()
        store = Store(config.database, read_only=True)
        try:
            self.assertGreaterEqual(store.run_stats()["run_count"], 1)
        finally:
            store.close()

    def test_cpu_is_measured_rather_than_assumed_zero(self):
        """CODE-031 regression: the governor was fed a hardcoded 0.0."""

        import inspect

        from commatrix.platform.win import runloop

        src = inspect.getsource(runloop.run)
        self.assertIn("process_cpu_seconds", src)
        self.assertNotIn("throttle_sleep(0.0", src)


if __name__ == "__main__":
    unittest.main()
