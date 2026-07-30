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

    def test_reapply_keeps_user_created_and_baseline(self):
        """SEC-024 regression: apply -> apply -> revoke must still clean up.

        The second apply re-snapshotted the already-rebound task as
        "previous_run_as" and reset user_created to False (the account exists
        by then), so revoke left both the elevated binding and the service
        account behind while reporting success.
        """

        self.assertTrue(ew.apply_elevate(state_file=self.state, dry_run=False).ok)
        with open(self.state, encoding="utf-8") as fh:
            first = json.loads(fh.read())
        self.assertTrue(first["user_created"])
        self.assertEqual(first["previous_run_as"], "SYSTEM")

        # Second apply: the account now exists, and the task is already bound
        # to it -- neither must be allowed to overwrite the baseline.
        with mock.patch.object(ew, "_user_exists", return_value=True):
            second = ew.apply_elevate(state_file=self.state, dry_run=False)
        self.assertTrue(second.ok)
        self.assertTrue(any("already present" in w for w in second.warnings))

        with open(self.state, encoding="utf-8") as fh:
            state = json.loads(fh.read())
        self.assertTrue(state["user_created"], "revoke would leave the account")
        self.assertEqual(state["previous_run_as"], "SYSTEM")

        self.calls.clear()
        self.assertTrue(ew.revoke_elevate(state_file=self.state, dry_run=False).ok)
        deletes = [
            c for c in self.calls
            if c[:3] == ["net", "user", "commatrix"] and "/delete" in c
        ]
        self.assertTrue(deletes, "service account must still be removed")

    def test_revoke_honours_recorded_run_as(self):
        """CODE-025: revoke must not hardcode SYSTEM."""

        with open(self.state, "w", encoding="utf-8") as fh:
            json.dump({
                "version": 1,
                "user_created": False,
                "previous_task_command": "python -m commatrix collect",
                "previous_run_as": "DOMAIN\\svc-collector",
            }, fh)
        self.assertTrue(ew.revoke_elevate(state_file=self.state, dry_run=False).ok)
        creates = [c for c in self.calls if c and c[0] == "schtasks" and "/create" in c]
        self.assertTrue(creates)
        self.assertIn("DOMAIN\\svc-collector", creates[-1])
        self.assertNotIn("SYSTEM", creates[-1])

    def test_sedebug_not_granted_by_default(self):
        """SEC-022: SeDebugPrivilege is a reliable escalation to SYSTEM.

        winprocess._image_path opens processes with
        PROCESS_QUERY_LIMITED_INFORMATION and calls
        QueryFullProcessImageNameW, which works cross-user without it.
        """

        with mock.patch.object(ew, "_find_ntrights", return_value="C:\\ntrights.exe"):
            result = ew.apply_elevate(state_file=self.state, dry_run=False)
        self.assertTrue(result.ok)
        granted = [c for c in self.calls if c and "SeDebugPrivilege" in c]
        self.assertFalse(granted, "SeDebugPrivilege must not be granted by default")
        self.assertTrue(any("did NOT grant SeDebugPrivilege" in a for a in result.actions))
        with open(self.state, encoding="utf-8") as fh:
            self.assertFalse(json.loads(fh.read())["sedebug_granted"])

    def test_sedebug_opt_in_is_recorded_and_warned(self):
        with mock.patch.object(ew, "_find_ntrights", return_value="C:\\ntrights.exe"):
            result = ew.apply_elevate(
                state_file=self.state, dry_run=False, allow_sedebug=True
            )
        self.assertTrue(result.ok)
        granted = [c for c in self.calls if c and "SeDebugPrivilege" in c and "+r" in c]
        self.assertTrue(granted, "opt-in must actually grant the privilege")
        with open(self.state, encoding="utf-8") as fh:
            self.assertTrue(json.loads(fh.read())["sedebug_granted"])
        self.assertTrue(any("escalation" in w for w in result.warnings))

    def test_attribution_uses_limited_information_right(self):
        """The narrow default is only defensible if the code really uses it."""

        from commatrix.platform.win import winprocess

        self.assertEqual(winprocess._PROCESS_QUERY_LIMITED_INFORMATION, 0x1000)
        import inspect

        src = inspect.getsource(winprocess._image_path)
        self.assertIn("_PROCESS_QUERY_LIMITED_INFORMATION", src)
        self.assertNotIn("PROCESS_ALL_ACCESS", src)

    def test_revoke_takes_back_sedebug_when_granted(self):
        with open(self.state, "w", encoding="utf-8") as fh:
            json.dump({
                "version": 1,
                "user_created": False,
                "previous_run_as": "SYSTEM",
                "sedebug_granted": True,
            }, fh)
        self.calls.clear()
        with mock.patch.object(ew, "_find_ntrights", return_value="C:\\ntrights.exe"):
            result = ew.revoke_elevate(state_file=self.state, dry_run=False)
        self.assertTrue(result.ok)
        revoked = [c for c in self.calls if "SeDebugPrivilege" in c and "-r" in c]
        if revoked:
            self.assertIn(ew.SERVICE_USER, revoked[0])
        else:
            # ntrights is absent in this mock; the operator must then be told
            # to remove it by hand rather than left believing it is gone.
            self.assertTrue(
                any("SeDebugPrivilege" in w for w in result.warnings),
                "revoke must not silently leave SeDebugPrivilege in place",
            )

    def test_revoke_says_nothing_about_sedebug_when_never_granted(self):
        with open(self.state, "w", encoding="utf-8") as fh:
            json.dump({
                "version": 1,
                "user_created": False,
                "previous_run_as": "SYSTEM",
                "sedebug_granted": False,
            }, fh)
        result = ew.revoke_elevate(state_file=self.state, dry_run=False)
        self.assertTrue(result.ok)
        self.assertFalse(any("SeDebugPrivilege" in w for w in result.warnings))

    def test_apply_requires_admin(self):
        with mock.patch("commatrix.platform.win.runtime.is_admin", return_value=False):
            result = ew.apply_elevate(state_file=self.state, dry_run=False)
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
