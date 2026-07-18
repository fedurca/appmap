"""Unit tests for elevate-linux (no real systemd / root required)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from commatrix import elevate_linux as el


class ElevateLinuxRenderTest(unittest.TestCase):
    def test_dropin_lists_caps_and_user(self):
        text = el.render_dropin()
        self.assertIn("User=commatrix", text)
        self.assertIn("CAP_DAC_READ_SEARCH", text)
        self.assertIn("CAP_NET_ADMIN", text)
        self.assertIn("CAP_NET_RAW", text)
        self.assertIn("CAP_SYS_PTRACE", text)
        self.assertIn("NoNewPrivileges=true", text)
        self.assertNotIn("CAP_SYS_ADMIN", text)
        self.assertNotIn("CAP_SETUID", text)

    def test_polkit_scoped_to_service_user(self):
        text = el.render_polkit()
        self.assertIn('subject.user == "commatrix"', text)
        self.assertIn("org.freedesktop.resolve1", text)


class ElevateLinuxApplyRevokeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.dropin = os.path.join(self.root, "60-elevate.conf")
        self.polkit = os.path.join(self.root, "50-commatrix-resolved.rules")
        self.state = os.path.join(self.root, "elevate-state.json")
        self.patches = [
            mock.patch.object(el, "DROPIN_PATH", self.dropin),
            mock.patch.object(el, "DROPIN_DIR", self.root),
            mock.patch.object(el, "POLKIT_PATH", self.polkit),
            mock.patch.object(el, "_is_root", return_value=True),
            mock.patch.object(el, "_ensure_service_user"),
            mock.patch.object(el, "_systemctl", return_value=True),
            mock.patch.object(el, "_read_unit_user", return_value="commatrix"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_dry_run_writes_nothing(self):
        result = el.apply_elevate(state_file=self.state, dry_run=True, reload=False)
        self.assertTrue(result.ok)
        self.assertFalse(os.path.exists(self.dropin))
        self.assertFalse(os.path.exists(self.state))
        self.assertTrue(any("dry-run" in a for a in result.actions))

    def test_apply_and_revoke_roundtrip(self):
        # Pre-existing drop-in to restore.
        with open(self.dropin, "w", encoding="utf-8") as fh:
            fh.write("[Service]\nUser=commatrix\nAmbientCapabilities=CAP_NET_ADMIN\n")

        result = el.apply_elevate(state_file=self.state, dry_run=False, reload=True)
        self.assertTrue(result.ok)
        self.assertTrue(os.path.exists(self.state))
        with open(self.dropin, encoding="utf-8") as fh:
            dropin = fh.read()
        self.assertIn("CAP_SYS_PTRACE", dropin)
        with open(self.polkit, encoding="utf-8") as fh:
            self.assertIn("commatrix", fh.read())

        with open(self.state, encoding="utf-8") as fh:
            state = json.loads(fh.read())
        self.assertTrue(state["dropin_existed"])
        self.assertIn("CAP_NET_ADMIN", state["dropin_content"])

        rev = el.revoke_elevate(state_file=self.state, dry_run=False, reload=True)
        self.assertTrue(rev.ok)
        self.assertFalse(os.path.exists(self.state))
        with open(self.dropin, encoding="utf-8") as fh:
            restored = fh.read()
        self.assertEqual(
            restored,
            "[Service]\nUser=commatrix\nAmbientCapabilities=CAP_NET_ADMIN\n",
        )
        self.assertFalse(os.path.exists(self.polkit))

    def test_revoke_without_state_removes_artifacts(self):
        with open(self.dropin, "w", encoding="utf-8") as fh:
            fh.write(el.render_dropin())
        with open(self.polkit, "w", encoding="utf-8") as fh:
            fh.write(el.render_polkit())
        rev = el.revoke_elevate(state_file=self.state, dry_run=False, reload=False)
        self.assertTrue(rev.ok)
        self.assertFalse(os.path.exists(self.dropin))
        self.assertFalse(os.path.exists(self.polkit))

    def test_apply_requires_root(self):
        with mock.patch.object(el, "_is_root", return_value=False):
            result = el.apply_elevate(state_file=self.state, dry_run=False)
        self.assertFalse(result.ok)
        self.assertTrue(any("root" in e.lower() for e in result.errors))


class CapEffPrivilegedTest(unittest.TestCase):
    def test_is_privileged_with_caps(self):
        from commatrix import platform as plat

        # CapEff with DAC_READ_SEARCH (2) and NET_ADMIN (12) set.
        mask = (1 << 2) | (1 << 12)
        status = f"Name:\tpython\nCapEff:\t{mask:016x}\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=status)), \
             mock.patch.object(plat, "IS_WINDOWS", False), \
             mock.patch("os.geteuid", return_value=1000):
            self.assertTrue(plat.is_privileged())

    def test_is_privileged_false_without_caps(self):
        from commatrix import platform as plat

        status = "Name:\tpython\nCapEff:\t0000000000000000\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=status)), \
             mock.patch.object(plat, "IS_WINDOWS", False), \
             mock.patch("os.geteuid", return_value=1000):
            self.assertFalse(plat.is_privileged())


if __name__ == "__main__":
    unittest.main()
