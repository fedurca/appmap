import argparse
import unittest
from unittest import mock

from commatrix import __main__ as cli


class CollectGateTest(unittest.TestCase):
    def _args(self, **kw):
        ns = argparse.Namespace(
            config="/nonexistent/commatrix.conf",
            database=None,
            iterations=None,
            once=True,
            allow_manual=False,
            require_root=False,
            verbose=False,
        )
        for k, v in kw.items():
            setattr(ns, k, v)
        return ns

    def test_refuses_when_not_under_service(self):
        with mock.patch("commatrix.platform.is_privileged", return_value=False), \
             mock.patch("commatrix.platform.running_as_service", return_value=False), \
             mock.patch("commatrix.collector.run_loop") as run_loop:
            rc = cli.cmd_collect(self._args())
        self.assertEqual(rc, 0)
        run_loop.assert_not_called()

    def test_runs_unprivileged_with_allow_manual(self):
        # Privilege is NOT required by default; unprivileged run is allowed.
        with mock.patch("commatrix.platform.is_privileged", return_value=False), \
             mock.patch("commatrix.platform.running_as_service", return_value=False), \
             mock.patch("commatrix.collector.run_loop") as run_loop:
            rc = cli.cmd_collect(self._args(allow_manual=True))
        self.assertEqual(rc, 0)
        run_loop.assert_called_once()

    def test_require_root_refuses_non_privileged(self):
        with mock.patch("commatrix.platform.is_privileged", return_value=False), \
             mock.patch("commatrix.platform.running_as_service", return_value=True), \
             mock.patch("commatrix.collector.run_loop") as run_loop:
            rc = cli.cmd_collect(self._args(require_root=True))
        self.assertEqual(rc, 1)
        run_loop.assert_not_called()

    def test_runs_under_service(self):
        with mock.patch("commatrix.platform.is_privileged", return_value=True), \
             mock.patch("commatrix.platform.running_as_service", return_value=True), \
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
