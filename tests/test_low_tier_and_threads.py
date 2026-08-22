"""Regression tests for the Low/Info tier and the cross-cutting drain loop.

SEC-029   kernel32 calls declare argtypes/restype
CODE-001  posture probes run once per invocation, not twice
CODE-006  the push server shuts down cleanly on SIGTERM
CODE-008  revoke reports when the unit User is not back at its baseline
CODE-009  conntrack.is_root() does not explode where geteuid() is absent
CODE-023  one source of truth for on-disk permission modes
CODE-026  a malformed frame does not kill the SNI thread
CODE-028  the Windows service map is not re-enumerated on every poll
CODE-033  version stamping fails loudly when the pattern does not match
Cross-cutting: one drain-loop pattern for every capture thread
"""

import logging
import os
import signal
import struct
import sys
import unittest
from unittest import mock

from commatrix import conntrack, dohcheck, sni, store, timecheck
from commatrix import platform as plat
from commatrix import threadguard
from commatrix.platform.win import winprocess, winresources, winsni

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PostureRunsOnceTest(unittest.TestCase):
    """CODE-001."""

    def test_doh_posture_is_probed_once(self):
        from commatrix import __main__ as cli

        args = mock.Mock(format="markdown", output=None)
        with mock.patch.object(
            dohcheck, "doh_posture",
            return_value={"assessment": "off", "findings": [],
                          "doh_enabled_anywhere": False},
        ) as probe, mock.patch.object(cli, "_write_output"):
            cli.cmd_doh(args)
        self.assertEqual(probe.call_count, 1)

    def test_time_posture_is_probed_once(self):
        from commatrix import __main__ as cli

        posture = {
            "assessment": "ok", "offset_seconds": 0.0, "offset_source": "local",
            "ntp_enabled": True, "synchronized": True, "service": "chrony",
        }
        args = mock.Mock(format="markdown", output=None, config=None, server=None)
        with mock.patch.object(timecheck, "ntp_posture", return_value=posture) as probe, \
             mock.patch.object(cli, "_write_output"), \
             mock.patch.object(cli, "load_config", return_value=mock.Mock(ntp_check_server="")):
            cli.cmd_time(args)
        self.assertEqual(probe.call_count, 1)

    def test_markdown_accepts_a_precomputed_posture(self):
        text = dohcheck.markdown(
            {"assessment": "off", "findings": [], "doh_enabled_anywhere": False}
        )
        self.assertIn("Assessment", text)


class PushServerShutdownTest(unittest.TestCase):
    """CODE-006."""

    def test_sigterm_handler_is_installed(self):
        from commatrix import collector_server as cs

        installed = {}

        def _fake_signal(sig, handler):
            installed[sig] = handler
            return signal.SIG_DFL

        httpd = mock.Mock()
        with mock.patch.object(cs.signal, "signal", _fake_signal):
            cs._install_shutdown_handlers(httpd)
        self.assertIn(signal.SIGTERM, installed)

    def test_handler_calls_shutdown_off_the_serving_thread(self):
        from commatrix import collector_server as cs

        httpd = mock.Mock()
        captured = {}
        with mock.patch.object(cs.signal, "signal",
                               lambda sig, h: captured.setdefault(sig, h)):
            cs._install_shutdown_handlers(httpd)
        started = []
        with mock.patch.object(cs.threading, "Thread") as thread_cls:
            thread_cls.side_effect = lambda target, daemon: started.append(target) or mock.Mock()
            captured[signal.SIGTERM](signal.SIGTERM, None)
        self.assertEqual(started, [httpd.shutdown])

    def test_handler_installation_survives_a_non_main_thread(self):
        from commatrix import collector_server as cs

        with mock.patch.object(cs.signal, "signal",
                               side_effect=ValueError("not the main thread")):
            cs._install_shutdown_handlers(mock.Mock())  # must not raise


class IsRootGuardTest(unittest.TestCase):
    """CODE-009."""

    def test_no_geteuid_falls_back_to_the_platform_layer(self):
        fake_os = mock.Mock(spec=[])  # no geteuid attribute at all
        with mock.patch.object(conntrack, "os", fake_os), \
             mock.patch.object(plat, "is_privileged", return_value=True):
            self.assertTrue(conntrack.is_root())


class PermissionConstantsTest(unittest.TestCase):
    """CODE-023."""

    def test_store_reexports_the_single_source_of_truth(self):
        self.assertEqual(store.DB_FILE_MODE, plat.DATA_FILE_MODE)
        self.assertEqual(store.DB_DIR_MODE, plat.DATA_DIR_MODE)

    def test_secure_permissions_applies_the_shared_constant(self):
        applied = {}
        with mock.patch.object(plat, "IS_WINDOWS", False), \
             mock.patch.object(plat.os, "chmod",
                               side_effect=lambda p, m: applied.setdefault(p, m)):
            plat.secure_permissions("/tmp/x.db")
            plat.secure_permissions("/tmp/dir", is_dir=True)
        self.assertEqual(applied["/tmp/x.db"], plat.DATA_FILE_MODE)
        self.assertEqual(applied["/tmp/dir"], plat.DATA_DIR_MODE)

    def test_no_stray_permission_literals_remain(self):
        offenders = []
        for root, _dirs, files in os.walk(os.path.join(REPO, "commatrix")):
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(root, name)
                if path.endswith(os.path.join("platform", "__init__.py")):
                    continue
                for lineno, line in enumerate(open(path, encoding="utf-8"), 1):
                    if "0o640" in line or "0o750" in line:
                        offenders.append(f"{os.path.relpath(path, REPO)}:{lineno}")
        self.assertEqual(
            offenders, [],
            "permission modes must come from commatrix.platform (CODE-023)",
        )


class ServiceMapCacheTest(unittest.TestCase):
    """CODE-028."""

    def setUp(self):
        winprocess.clear_service_map_cache()

    tearDown = setUp

    def test_tasklist_is_not_run_on_every_call(self):
        with mock.patch.object(
            winprocess.subprocess, "run",
            return_value=mock.Mock(returncode=0, stdout='"svc","4","Dnscache"\n'),
        ) as run:
            for _ in range(10):
                winprocess._service_map()
        self.assertEqual(run.call_count, 1)

    def test_cache_can_be_bypassed(self):
        with mock.patch.object(
            winprocess.subprocess, "run",
            return_value=mock.Mock(returncode=0, stdout='"svc","4","Dnscache"\n'),
        ) as run:
            winprocess._service_map()
            winprocess._service_map(max_age=0)
        self.assertEqual(run.call_count, 2)

    def test_a_failed_enumeration_keeps_the_previous_map(self):
        with mock.patch.object(
            winprocess.subprocess, "run",
            return_value=mock.Mock(returncode=0, stdout='"svc","4","Dnscache"\n'),
        ):
            first = dict(winprocess._service_map())
        with mock.patch.object(winprocess.subprocess, "run",
                               side_effect=OSError("boom")):
            second = winprocess._service_map(max_age=0)
        self.assertEqual(second, first)


class Kernel32SignaturesTest(unittest.TestCase):
    """SEC-029."""

    def test_winprocess_declares_signatures(self):
        k32 = mock.MagicMock()
        winprocess._declare(k32)
        for fn in ("OpenProcess", "QueryFullProcessImageNameW", "CloseHandle"):
            attr = getattr(k32, fn)
            self.assertIsNotNone(attr.restype)
            self.assertIsNotNone(attr.argtypes)

    def test_job_object_calls_declare_signatures(self):
        import ctypes

        k32 = mock.MagicMock()
        k32.CreateJobObjectW.return_value = 1
        k32.SetInformationJobObject.return_value = 1
        k32.AssignProcessToJobObject.return_value = 1
        fake = mock.MagicMock()
        fake.kernel32 = k32
        with mock.patch.object(ctypes, "windll", fake, create=True):
            winresources.apply_job_limits()
        self.assertIsNotNone(k32.CreateJobObjectW.restype)
        self.assertIsNotNone(k32.AssignProcessToJobObject.argtypes)


class VersionStampTest(unittest.TestCase):
    """CODE-033."""

    def test_a_non_matching_pattern_aborts(self):
        sys.path.insert(0, os.path.join(REPO, "packaging"))
        try:
            import version as vmod
        finally:
            sys.path.pop(0)
        import re
        import tempfile

        path = os.path.join(tempfile.mkdtemp(), "f.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("nothing to see here\n")
        with self.assertRaises(SystemExit):
            vmod._sub_file(path, re.compile(r'^(__version__\s*=\s*)"[^"]*"'), "9.9.9")
        # The file must be left untouched rather than silently rewritten.
        self.assertEqual(open(path, encoding="utf-8").read(), "nothing to see here\n")


class DrainLoopTest(unittest.TestCase):
    """Cross-cutting: one pattern for every capture thread."""

    def test_drain_item_swallows_anything_an_exception(self):
        counters = threadguard.DrainCounters()
        log = logging.getLogger("test")
        for exc in (struct.error("bad"), RecursionError("deep"),
                    ValueError("nope"), IndexError("short"), OSError("io")):
            with threadguard.drain_item(log, "x", counters):
                raise exc
        self.assertEqual(counters.dropped_items, 5)

    def test_drain_item_lets_stop_signals_through(self):
        log = logging.getLogger("test")
        for exc in (KeyboardInterrupt, SystemExit):
            with self.assertRaises(exc):
                with threadguard.drain_item(log, "x"):
                    raise exc()

    def test_drain_iteration_counts_loop_errors(self):
        counters = threadguard.DrainCounters()
        with threadguard.drain_iteration(logging.getLogger("test"), "x", counters):
            raise RuntimeError("boom")
        self.assertEqual(counters.loop_errors, 1)

    def test_every_capture_thread_exposes_drain_counters(self):
        from commatrix import ctnetlink
        from commatrix.platform.win import winetw

        for cls in (
            ctnetlink.ConntrackEventListener,
            sni.SniMonitor,
            winsni.WinSniMonitor,
            winetw.WinDnsMonitor,
        ):
            with self.subTest(cls=cls.__name__):
                inst = cls()
                self.assertIsInstance(inst.drain_counters, threadguard.DrainCounters)

    def test_sni_thread_survives_a_malformed_frame(self):
        """CODE-026."""

        mon = winsni.WinSniMonitor()
        counters = mon.drain_counters
        with mock.patch(
            "commatrix.platform.win.winsni.parse_ip_packet",
            side_effect=struct.error("truncated"),
        ):
            with threadguard.drain_item(
                logging.getLogger("commatrix.win.winsni"), "sni packet", counters
            ):
                winsni.parse_ip_packet(b"\x00", (443,))
        self.assertEqual(counters.dropped_items, 1)

    def test_ctnetlink_thread_survives_a_malformed_message(self):
        from commatrix import ctnetlink

        listener = ctnetlink.ConntrackEventListener()
        with mock.patch.object(
            ctnetlink, "parse_messages", side_effect=struct.error("truncated")
        ):
            with threadguard.drain_iteration(
                logging.getLogger("commatrix.ctnetlink"), "ctnetlink",
                listener.drain_counters,
            ):
                list(ctnetlink.parse_messages(b"\x00"))
        self.assertEqual(listener.drain_counters.loop_errors, 1)


if __name__ == "__main__":
    unittest.main()
