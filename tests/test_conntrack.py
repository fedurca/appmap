import os
import tempfile
import unittest
from unittest import mock

from commatrix import conntrack as ct

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class ConntrackParseTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(FIXTURES, "nf_conntrack.sample"), encoding="utf-8") as fh:
            self.entries = ct.parse_conntrack_text(fh.read())

    def test_parses_all_lines(self):
        self.assertEqual(len(self.entries), 4)

    def test_tcp_service_entry(self):
        e = self.entries[0]
        self.assertEqual(e.l4proto, "tcp")
        self.assertEqual(e.state, "ESTABLISHED")
        self.assertEqual(e.orig_src, "10.0.0.5")
        self.assertEqual(e.orig_dst, "10.0.0.10")
        self.assertEqual(e.orig_sport, 44321)
        self.assertEqual(e.orig_dport, 5432)
        self.assertEqual(e.orig_bytes, 1500)
        self.assertEqual(e.reply_bytes, 2400)
        self.assertEqual(e.total_bytes, 3900)
        self.assertEqual(e.total_packets, 18)
        self.assertEqual(e.delta_time, 42)
        self.assertTrue(e.assured)
        self.assertTrue(e.has_accounting)

    def test_udp_entry_has_no_state(self):
        udp = self.entries[2]
        self.assertEqual(udp.l4proto, "udp")
        self.assertIsNone(udp.state)
        self.assertEqual(udp.orig_dport, 53)

    def test_event_line_parsing(self):
        line = (
            "[1612345678.123456]\t[DESTROY] tcp 6 src=1.1.1.1 dst=2.2.2.2 "
            "sport=1000 dport=80 packets=4 bytes=400 src=2.2.2.2 dst=1.1.1.1 "
            "sport=80 dport=1000 packets=3 bytes=900"
        )
        e = ct.parse_conntrack_line(line)
        self.assertIsNotNone(e)
        self.assertEqual(e.event, "DESTROY")
        self.assertEqual(e.orig_dport, 80)
        self.assertEqual(e.total_bytes, 1300)

    def test_blank_line_returns_none(self):
        self.assertIsNone(ct.parse_conntrack_line("   "))

    def test_resolve_source(self):
        self.assertEqual(ct.resolve_source("procfs"), "procfs")
        self.assertEqual(ct.resolve_source("sockets"), "sockets")
        with self.assertRaises(ValueError):
            ct.resolve_source("bogus")

    def test_resolve_source_auto_prefers_procfs(self):
        with mock.patch.object(ct, "proc_available", return_value=True):
            self.assertEqual(ct.resolve_source("auto"), "procfs")

    def test_resolve_source_auto_falls_back_to_sockets(self):
        with mock.patch.object(ct, "proc_available", return_value=False), \
             mock.patch.object(ct, "conntrack_tool_available", return_value=False):
            self.assertEqual(ct.resolve_source("auto"), "sockets")

    def test_entries_from_sockets(self):
        from commatrix.sockets import SocketEntry

        socks = [
            SocketEntry(
                proto="tcp", family=2, local_ip="10.0.0.5", local_port=44321,
                remote_ip="10.0.0.10", remote_port=5432, state="ESTABLISHED",
                inode=1, uid=0,
            ),
            SocketEntry(
                proto="tcp", family=2, local_ip="0.0.0.0", local_port=22,
                remote_ip="0.0.0.0", remote_port=0, state="LISTEN",
                inode=2, uid=0,
            ),
        ]
        entries = ct.entries_from_sockets(socks)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].orig_dport, 5432)


class SysctlFlagTest(unittest.TestCase):
    def _tmp_flag(self, value):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write(value)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_read_sysctl_flag_values(self):
        self.assertIs(ct.read_sysctl_flag(self._tmp_flag("1\n")), True)
        self.assertIs(ct.read_sysctl_flag(self._tmp_flag("0\n")), False)

    def test_read_sysctl_flag_missing_returns_none(self):
        self.assertIsNone(ct.read_sysctl_flag("/nonexistent/sysctl/flag"))

    def test_write_sysctl_flag_roundtrip(self):
        path = self._tmp_flag("0\n")
        self.assertTrue(ct.write_sysctl_flag(path, True))
        self.assertIs(ct.read_sysctl_flag(path), True)
        self.assertTrue(ct.write_sysctl_flag(path, False))
        self.assertIs(ct.read_sysctl_flag(path), False)

    def test_write_sysctl_flag_failure_returns_false(self):
        self.assertFalse(ct.write_sysctl_flag("/proc/does/not/exist", True))


class SysctlGuardTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True))
        self.state = os.path.join(self.dir, "sysctl.state")

    def _flag(self, name, value):
        path = os.path.join(self.dir, name)
        with open(path, "w") as fh:
            fh.write(value)
        return path

    def test_enables_then_restores_when_originally_off(self):
        acct = self._flag("acct", "0\n")
        ts = self._flag("ts", "0\n")
        guard = ct.SysctlGuard(sysctls=[acct, ts], state_file=self.state)
        guard.apply()
        self.assertTrue(guard.available)
        self.assertEqual(set(guard.changed), {acct, ts})
        self.assertIs(ct.read_sysctl_flag(acct), True)
        self.assertIs(ct.read_sysctl_flag(ts), True)
        self.assertTrue(os.path.exists(self.state))
        guard.restore()
        self.assertIs(ct.read_sysctl_flag(acct), False)
        self.assertIs(ct.read_sysctl_flag(ts), False)
        self.assertFalse(guard.changed)
        self.assertFalse(os.path.exists(self.state))

    def test_leaves_enabled_untouched(self):
        acct = self._flag("acct", "1\n")
        guard = ct.SysctlGuard(sysctls=[acct], state_file=self.state)
        guard.apply()
        self.assertFalse(guard.changed)
        self.assertIs(ct.read_sysctl_flag(acct), True)
        guard.restore()
        self.assertIs(ct.read_sysctl_flag(acct), True)

    def test_unavailable_sysctl_is_noop(self):
        missing = os.path.join(self.dir, "nope")
        guard = ct.SysctlGuard(sysctls=[missing], state_file=self.state)
        guard.apply()
        self.assertFalse(guard.available)
        self.assertIn(missing, guard.unavailable)
        self.assertFalse(guard.enable_failed)

    def test_restore_from_file_recovers_state(self):
        acct = self._flag("acct", "1\n")  # currently on, but baseline was off
        with open(self.state, "w") as fh:
            fh.write(f'{{"{acct}": "0"}}')
        restored = ct.SysctlGuard.restore_from_file(self.state)
        self.assertTrue(restored)
        self.assertIs(ct.read_sysctl_flag(acct), False)
        self.assertFalse(os.path.exists(self.state))

    def test_restore_from_missing_file_is_false(self):
        self.assertFalse(ct.SysctlGuard.restore_from_file(self.state))

    def test_apply_recovers_stale_state_first(self):
        acct = self._flag("acct", "1\n")  # left ON by a crashed run
        with open(self.state, "w") as fh:
            fh.write(f'{{"{acct}": "0"}}')  # crashed run recorded baseline OFF
        guard = ct.SysctlGuard(sysctls=[acct], state_file=self.state)
        guard.apply()
        self.assertTrue(guard.recovered_stale)
        # baseline recovered to OFF, then re-enabled for this run
        self.assertEqual(guard.originals.get(acct), False)
        self.assertIs(ct.read_sysctl_flag(acct), True)
        guard.restore()
        self.assertIs(ct.read_sysctl_flag(acct), False)


class SystemdDetectionTest(unittest.TestCase):
    def test_running_under_systemd_true(self):
        with mock.patch.dict(os.environ, {"INVOCATION_ID": "abc123"}):
            self.assertTrue(ct.running_under_systemd())

    def test_running_under_systemd_false(self):
        env = {k: v for k, v in os.environ.items() if k != "INVOCATION_ID"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertFalse(ct.running_under_systemd())


if __name__ == "__main__":
    unittest.main()
