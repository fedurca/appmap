"""Verification the review deferred to "a real machine", done in CI instead.

The review listed `visudo -cf`, `systemd-analyze security` and the container's
UID 65532 behaviour as manual checks. Running them once by hand answers the
question for one commit; these tests keep answering it.

Also covers the bug that surfaced while doing the UID 65532 check: a read-only
open of a WAL database needs write access to the *directory*, so every
read-only command failed under the image's default user.
"""

import os
import shutil
import subprocess
import sqlite3
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "packaging"))
import check_hardening  # noqa: E402
sys.path.pop(0)

from commatrix.store import EdgeObservation, Store  # noqa: E402


class _FailingConnection:
    """A stand-in connection whose first query fails.

    sqlite3.Connection.execute is read-only, so the failure that an unwritable
    directory produces has to be simulated with a substitute object rather
    than by patching a real connection.
    """

    def __init__(self, message):
        self._message = message
        self.closed = False

    def execute(self, *_args, **_kwargs):
        raise sqlite3.OperationalError(self._message)

    def close(self):
        self.closed = True


def _root_and_setpriv():
    return (
        hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("setpriv")
    )


class SudoersTest(unittest.TestCase):
    def setUp(self):
        if not shutil.which("visudo"):
            self.skipTest("visudo not installed")

    def test_generated_sudoers_files_parse(self):
        problems, skipped = [], []
        check_hardening.check_sudoers(problems, skipped)
        self.assertEqual(problems, [])
        self.assertEqual(skipped, [])

    def test_a_username_with_a_dot_is_covered(self):
        self.assertTrue(
            any("roman.maier" in name for name in check_hardening._sudoers_samples()),
            "a firstname.lastname account is the shape that breaks sudoers "
            "parsing; keep it in the sample set",
        )


class SystemdUnitExposureTest(unittest.TestCase):
    def setUp(self):
        if not shutil.which("systemd-analyze"):
            self.skipTest("systemd-analyze not installed")
        probe = subprocess.run(
            ["systemd-analyze", "security", "--help"],
            capture_output=True, text=True, check=False,
        )
        if "--offline" not in (probe.stdout + probe.stderr):
            self.skipTest("systemd-analyze predates --offline (needs v247+)")

    def test_every_unit_is_within_its_exposure_budget(self):
        problems, skipped = [], []
        check_hardening.check_units(problems, skipped)
        self.assertEqual(problems, [], "\n".join(problems))

    def test_every_shipped_unit_has_a_recorded_budget(self):
        shipped = {
            n for n in os.listdir(os.path.join(REPO, "systemd"))
            if n.endswith(".service")
        }
        missing = shipped - set(check_hardening.EXPOSURE_BUDGET)
        self.assertEqual(missing, set())

    def test_the_lower_privilege_profile_is_not_the_less_confined_one(self):
        """The finding this check surfaced.

        The whole sandbox block used to live inside the `attribution` branch,
        so `--profile topology` -- chosen precisely when you want less
        privilege -- produced a less confined unit than `attribution`.
        """

        from commatrix.elevate_linux import render_dropin

        topology = render_dropin("topology")
        attribution = render_dropin("attribution")
        for directive in (
            "ProtectSystem=strict", "RestrictNamespaces=true",
            "LockPersonality=true", "MemoryDenyWriteExecute=true",
            "SystemCallArchitectures=native", "RestrictSUIDSGID=true",
        ):
            self.assertIn(directive, topology, f"{directive} missing from topology")
            self.assertIn(directive, attribution)

    def test_ptrace_confinement_stays_specific_to_attribution(self):
        from commatrix.elevate_linux import render_dropin

        self.assertIn("ptrace", render_dropin("attribution"))
        self.assertNotIn("ptrace", render_dropin("topology"))

    def test_collector_never_protects_kernel_tunables(self):
        """Toggling the nf_conntrack sysctls is the collector's job."""

        unit = open(
            os.path.join(REPO, "systemd", "commatrix-collector.service"),
            encoding="utf-8",
        ).read()
        self.assertIn("ProtectKernelTunables=false", unit)
        self.assertNotIn("ProtectKernelTunables=true", unit)
        from commatrix.elevate_linux import render_dropin
        for profile in ("topology", "attribution"):
            self.assertNotIn("ProtectKernelTunables=true", render_dropin(profile))


class ProtectSystemReadWritePathsTest(unittest.TestCase):
    """The 'does ProtectSystem=strict clash with StateDirectory' question."""

    def test_state_and_runtime_directories_need_no_explicit_grant(self):
        from commatrix.elevate_linux import _extra_read_write_paths

        cfg = type("C", (), {
            "database": "/var/lib/commatrix/commatrix.db",
            "html_report_path": None,
            "snapshot_dir": "/var/lib/commatrix/snapshots",
            "sysctl_state_file": "/run/commatrix/sysctl.state",
        })()
        self.assertEqual(
            _extra_read_write_paths(cfg), [],
            "StateDirectory=/RuntimeDirectory= already make these writable "
            "under ProtectSystem=strict",
        )

    def test_configured_paths_outside_the_state_dir_are_granted(self):
        from commatrix.elevate_linux import _extra_read_write_paths

        cfg = type("C", (), {
            "database": "/srv/commatrix/central.db",
            "html_report_path": "/var/www/html/commatrix.html",
            "snapshot_dir": "/var/lib/commatrix/snapshots",
            "sysctl_state_file": "/run/commatrix/sysctl.state",
        })()
        self.assertEqual(
            _extra_read_write_paths(cfg),
            ["/srv/commatrix", "/var/www/html"],
        )

    def test_dropin_emits_the_grants(self):
        from commatrix.elevate_linux import render_dropin

        cfg = type("C", (), {
            "database": "/srv/commatrix/central.db",
            "html_report_path": None,
            "snapshot_dir": None,
            "sysctl_state_file": None,
        })()
        self.assertIn("ReadWritePaths=/srv/commatrix", render_dropin("topology", cfg))

    def test_no_config_still_renders(self):
        from commatrix.elevate_linux import render_dropin

        self.assertIn("ProtectSystem=strict", render_dropin("topology", None))


class ReadOnlyWalDatabaseTest(unittest.TestCase):
    """Docker UID 65532: read-only commands against a WAL DB.

    A WAL reader has to create the -shm file, which needs write access to the
    database's *directory*. The container image runs as UID 65532 against a
    bind mount owned by whoever ran `collect`, so every read-only command --
    report, export, aggregate -- failed with "attempt to write a readonly
    database" from its first SELECT.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "c.db")
        store = Store(self.db)
        store.upsert_host("h", {"hostname": "h"})
        store.record_edge("h", EdgeObservation(
            proto="tcp", direction="inbound", local_ip="10.0.0.1",
            peer_ip="203.0.113.9", service_port=443, peer_class="external",
            snapshot_bytes=10, snapshot_packets=1, service_side="local",
        ), now=100.0)
        store.close()

    def test_the_database_really_is_in_wal_mode(self):
        conn = sqlite3.connect(self.db)
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(mode.lower(), "wal")

    def test_plain_read_only_open_still_works_normally(self):
        store = Store(self.db, read_only=True)
        try:
            self.assertEqual(store.flow_count(), 1)
        finally:
            store.close()

    def test_read_only_open_survives_an_unwritable_directory(self):
        if not _root_and_setpriv():
            self.skipTest("needs root + setpriv to drop to another uid")
        os.chmod(self.tmp, 0o755)
        os.chmod(self.db, 0o644)
        for suffix in ("-wal", "-shm"):
            side = self.db + suffix
            if os.path.exists(side):
                os.chmod(side, 0o644)
        script = (
            "import sys; sys.path.insert(0, %r)\n"
            "from commatrix.store import Store\n"
            "s = Store(%r, read_only=True)\n"
            "print('FLOWS', s.flow_count())\n"
            "s.close()\n" % (REPO, self.db)
        )
        proc = subprocess.run(
            ["setpriv", "--reuid", "65532", "--regid", "65532", "--clear-groups",
             sys.executable, "-c", script],
            capture_output=True, text=True, check=False, cwd=REPO,
        )
        self.assertIn("FLOWS 1", proc.stdout, proc.stdout + proc.stderr)

    def test_the_fallback_warns_about_what_it_gives_up(self):
        import logging
        from unittest import mock

        from commatrix import store as store_mod

        real_connect = sqlite3.connect
        calls = {"n": 0}

        def fake_connect(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                # First open is the plain mode=ro one; make its probe query
                # fail exactly the way an unwritable directory makes it fail.
                return _FailingConnection(
                    "attempt to write a readonly database"
                )
            return real_connect(*args, **kwargs)

        with mock.patch.object(store_mod.sqlite3, "connect", fake_connect), \
             self.assertLogs(store_mod.log, level=logging.WARNING) as caught:
            conn = Store._connect_read_only(self.db)
        try:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM flows").fetchone()[0], 1,
                "the immutable fallback must still return the committed rows",
            )
        finally:
            conn.close()
        self.assertEqual(calls["n"], 2, "expected exactly one retry")
        joined = "\n".join(caught.output)
        self.assertIn("immutable", joined)
        self.assertIn("65532", joined)

    def test_a_non_readonly_error_is_not_swallowed(self):
        from unittest import mock

        from commatrix import store as store_mod

        def fake_connect(*args, **kwargs):
            return _FailingConnection("database disk image is malformed")

        with mock.patch.object(store_mod.sqlite3, "connect", fake_connect):
            with self.assertRaises(sqlite3.OperationalError):
                Store._connect_read_only(self.db)


if __name__ == "__main__":
    unittest.main()
