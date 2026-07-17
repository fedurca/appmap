import argparse
import unittest
from unittest import mock

from commatrix import __main__ as cli


class CollectGateTest(unittest.TestCase):
    def _args(self, **kw):
        ns = argparse.Namespace(
            config=None,
            database=None,
            iterations=None,
            once=True,
            allow_manual=False,
            verbose=False,
        )
        for k, v in kw.items():
            setattr(ns, k, v)
        return ns

    def test_refuses_without_root(self):
        with mock.patch("commatrix.conntrack.is_root", return_value=False), \
             mock.patch("commatrix.collector.run_loop") as run_loop:
            rc = cli.cmd_collect(self._args())
        self.assertEqual(rc, 1)
        run_loop.assert_not_called()

    def test_refuses_when_not_under_systemd(self):
        with mock.patch("commatrix.conntrack.is_root", return_value=True), \
             mock.patch("commatrix.conntrack.running_under_systemd", return_value=False), \
             mock.patch("commatrix.collector.run_loop") as run_loop:
            rc = cli.cmd_collect(self._args(allow_manual=False))
        self.assertEqual(rc, 0)
        run_loop.assert_not_called()

    def test_runs_with_allow_manual_when_root(self):
        with mock.patch("commatrix.conntrack.is_root", return_value=True), \
             mock.patch("commatrix.conntrack.running_under_systemd", return_value=False), \
             mock.patch("commatrix.collector.run_loop") as run_loop:
            rc = cli.cmd_collect(self._args(allow_manual=True))
        self.assertEqual(rc, 0)
        run_loop.assert_called_once()

    def test_runs_under_systemd(self):
        with mock.patch("commatrix.conntrack.is_root", return_value=True), \
             mock.patch("commatrix.conntrack.running_under_systemd", return_value=True), \
             mock.patch("commatrix.collector.run_loop") as run_loop:
            rc = cli.cmd_collect(self._args(allow_manual=False))
        self.assertEqual(rc, 0)
        run_loop.assert_called_once()


class RestoreSysctlsCliTest(unittest.TestCase):
    def test_restore_invokes_guard(self):
        args = argparse.Namespace(config=None, state_file="/tmp/does-not-exist.state", verbose=False)
        with mock.patch("commatrix.conntrack.SysctlGuard.restore_from_file", return_value=True) as rf:
            rc = cli.cmd_restore_sysctls(args)
        self.assertEqual(rc, 0)
        rf.assert_called_once_with("/tmp/does-not-exist.state")


if __name__ == "__main__":
    unittest.main()
