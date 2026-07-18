"""Unit tests for elevate-windows (mocked subprocess; no Admin required)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from commatrix.platform.win import elevate as ew


class ElevateWindowsDryRunTest(unittest.TestCase):
    def test_dry_run_ok_without_admin(self):
        with mock.patch.object(ew, "_user_exists", return_value=False), \
             mock.patch("commatrix.platform.win.runtime.is_admin", return_value=False):
            result = ew.apply_elevate(dry_run=True)
        self.assertTrue(result.ok)
        self.assertTrue(any("dry-run" in a for a in result.actions))
        self.assertTrue(
            any("Administrators" in a for a in result.actions)
        )


class ElevateWindowsApplyRevokeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "elevate-state.json")
        self.calls = []

        def fake_run(args, **kwargs):
            self.calls.append(list(args))
            cmd0 = args[0] if args else ""
            # net user <name>  -> existence check
            if cmd0 == "net" and len(args) >= 2 and args[1] == "user":
                if len(args) == 3:
                    # existence probe
                    return mock.Mock(returncode=1, stdout="", stderr="")
                return mock.Mock(returncode=0, stdout="ok", stderr="")
            if cmd0 == "net" and args[1] == "localgroup":
                return mock.Mock(returncode=0, stdout="", stderr="")
            if cmd0 == "where":
                return mock.Mock(returncode=1, stdout="", stderr="")
            if cmd0 == "wevtutil":
                return mock.Mock(returncode=0, stdout="", stderr="")
            if cmd0 == "icacls":
                return mock.Mock(returncode=0, stdout="", stderr="")
            if cmd0 == "schtasks":
                if "/query" in args:
                    return mock.Mock(
                        returncode=0,
                        stdout="Run As User:                 SYSTEM\n"
                               "Task To Run:                 C:\\Python\\python.exe -m commatrix collect\n",
                        stderr="",
                    )
                return mock.Mock(returncode=0, stdout="", stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")

        self.patches = [
            mock.patch.object(ew, "_run", side_effect=fake_run),
            mock.patch("commatrix.platform.win.runtime.is_admin", return_value=True),
            mock.patch.object(ew, "default_data_dir", return_value=self.tmp.name),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_apply_writes_state_and_rebinds(self):
        result = ew.apply_elevate(state_file=self.state, dry_run=False)
        self.assertTrue(result.ok)
        self.assertTrue(os.path.exists(self.state))
        with open(self.state, encoding="utf-8") as fh:
            state = json.loads(fh.read())
        self.assertEqual(state["previous_run_as"], "SYSTEM")
        self.assertTrue(state["user_created"])
        # Password must not be persisted.
        self.assertNotIn("password", state)
        schtasks_creates = [
            c for c in self.calls
            if c and c[0] == "schtasks" and "/create" in c and "commatrix" in c
        ]
        self.assertTrue(schtasks_creates)
        self.assertIn("/ru", schtasks_creates[0])
        self.assertIn("commatrix", schtasks_creates[0])
        self.assertIn("/rl", schtasks_creates[0])
        self.assertIn("limited", schtasks_creates[0])

    def test_revoke_restores_system_task(self):
        with open(self.state, "w", encoding="utf-8") as fh:
            json.dump({
                "version": 1,
                "user_created": True,
                "previous_task_command": "python -m commatrix collect",
                "previous_run_as": "SYSTEM",
            }, fh)
        rev = ew.revoke_elevate(state_file=self.state, dry_run=False)
        self.assertTrue(rev.ok)
        self.assertFalse(os.path.exists(self.state))
        creates = [c for c in self.calls if c and c[0] == "schtasks" and "/create" in c]
        self.assertTrue(any("SYSTEM" in c for c in creates))
        deletes = [c for c in self.calls if c[:3] == ["net", "user", "commatrix"] and "/delete" in c]
        self.assertTrue(deletes)

    def test_apply_requires_admin(self):
        with mock.patch("commatrix.platform.win.runtime.is_admin", return_value=False):
            result = ew.apply_elevate(state_file=self.state, dry_run=False)
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
