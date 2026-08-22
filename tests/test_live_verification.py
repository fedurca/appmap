"""The remaining 'verify on a real host' items, verified here instead.

CODE-006  SIGTERM on `commatrix serve` must not cut an in-flight /ingest
CODE-008  revoke's unit-User check must not cry wolf on a normal install
SEC-033   the embedded interpreter is verified by signature, not by MD5
topology  how much attribution the lower-privilege profile actually costs
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from commatrix import collector_server as cs  # noqa: E402
from commatrix import elevate_linux as el  # noqa: E402


class GracefulShutdownTest(unittest.TestCase):
    """CODE-006, the half that handling the signal does not fix.

    ThreadingHTTPServer runs handlers on daemon threads, so once
    serve_forever() returns the interpreter exits and anything still being
    handled dies where it stands. Measured before the fix: SIGTERM during an
    /ingest merge left the client with an empty reply and zero rows written.
    """

    def test_server_tracks_in_flight_requests(self):
        server = cs.GracefulHTTPServer.__new__(cs.GracefulHTTPServer)
        server._active_lock = threading.Lock()
        server._active = set()
        self.assertEqual(server.inflight(), 0)

        started = threading.Event()
        release = threading.Event()

        def _work():
            with server._active_lock:
                server._active.add(threading.current_thread())
            started.set()
            release.wait(5)
            with server._active_lock:
                server._active.discard(threading.current_thread())

        worker = threading.Thread(target=_work)
        worker.start()
        started.wait(5)
        try:
            self.assertEqual(server.inflight(), 1)
        finally:
            release.set()
            worker.join(5)
        self.assertEqual(server.inflight(), 0)

    def test_wait_for_inflight_waits_then_returns_true(self):
        server = cs.GracefulHTTPServer.__new__(cs.GracefulHTTPServer)
        server._active_lock = threading.Lock()
        server._active = set()
        server.shutdown_grace_seconds = 5.0

        done = threading.Event()

        def _work():
            with server._active_lock:
                server._active.add(threading.current_thread())
            time.sleep(0.4)
            with server._active_lock:
                server._active.discard(threading.current_thread())
            done.set()

        worker = threading.Thread(target=_work)
        worker.start()
        time.sleep(0.05)
        started = time.monotonic()
        self.assertTrue(server.wait_for_inflight())
        self.assertGreaterEqual(time.monotonic() - started, 0.2)
        worker.join(5)
        self.assertTrue(done.is_set())

    def test_a_wedged_request_cannot_block_shutdown_forever(self):
        server = cs.GracefulHTTPServer.__new__(cs.GracefulHTTPServer)
        server._active_lock = threading.Lock()
        server._active = set()
        server.shutdown_grace_seconds = 0.3

        stop = threading.Event()

        def _wedged():
            with server._active_lock:
                server._active.add(threading.current_thread())
            stop.wait(30)

        worker = threading.Thread(target=_wedged, daemon=True)
        worker.start()
        time.sleep(0.05)
        started = time.monotonic()
        self.assertFalse(server.wait_for_inflight())
        self.assertLess(time.monotonic() - started, 5.0)
        stop.set()

    def test_serve_waits_before_closing(self):
        order = []
        fake = mock.MagicMock()
        fake.serve_forever.side_effect = lambda: order.append("served")
        fake.wait_for_inflight.side_effect = lambda: order.append("waited")
        fake.server_close.side_effect = lambda: order.append("closed")
        with mock.patch.object(cs, "GracefulHTTPServer", return_value=fake), \
             mock.patch.object(cs, "_install_shutdown_handlers"):
            cs.serve("/tmp/does-not-matter.db", token="t")
        self.assertEqual(order, ["served", "waited", "closed"])

    @unittest.skipUnless(shutil.which("curl"), "needs curl")
    def test_end_to_end_sigterm_does_not_lose_an_in_flight_merge(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "c.db")
        runner = os.path.join(tmp, "run.py")
        with open(runner, "w", encoding="utf-8") as fh:
            fh.write(
                "import sys, time\n"
                f"sys.path.insert(0, {REPO!r})\n"
                "from commatrix import collector_server as cs\n"
                "from commatrix.store import Store\n"
                "real = Store.import_dict\n"
                "def slow(self, payload):\n"
                "    time.sleep(2.5)\n"
                "    return real(self, payload)\n"
                "Store.import_dict = slow\n"
                f"cs.serve({db!r}, host='127.0.0.1', port=8891, token='t')\n"
            )
        server = subprocess.Popen([sys.executable, runner],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            time.sleep(1.5)
            payload = json.dumps({
                "schema_version": 4,
                "hosts": [{"host": "h1", "params": {}}],
                "flows": [{
                    "host": "h1", "proto": "tcp", "direction": "inbound",
                    "local_ip": "10.0.0.1", "peer_ip": "203.0.113.9",
                    "service_port": 443, "peer_class": "external",
                    "bytes": 10, "packets": 1, "first_seen": 100, "last_seen": 100,
                }],
            })
            client = subprocess.Popen(
                ["curl", "-s", "-m", "25", "--noproxy", "127.0.0.1",
                 "-X", "POST", "-H", "X-Commatrix-Token: t",
                 "-H", "Content-Type: application/json", "--data", payload,
                 "http://127.0.0.1:8891/ingest"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            time.sleep(1.0)
            server.terminate()
            out, _ = client.communicate(timeout=30)
            server.wait(timeout=30)
        finally:
            if server.poll() is None:
                server.kill()
        self.assertIn(b'"status": "ok"', out,
                      "the in-flight ingest must complete, not be cut off")

        from commatrix.store import Store
        store = Store(db, read_only=True)
        try:
            self.assertEqual(store.flow_count(), 1)
        finally:
            store.close()


class RevokeUnitUserCheckTest(unittest.TestCase):
    """CODE-008: the check must be silent on a normal install."""

    def _result(self):
        return el.ElevateResult()

    def test_matching_user_reports_success_not_a_warning(self):
        result = self._result()
        with mock.patch.object(el, "_read_unit_user", return_value="commatrix"):
            el._verify_unit_user_restored(result, "commatrix", reload=True)
        self.assertEqual(result.warnings, [])
        self.assertTrue(any("restored" in a for a in result.actions))

    def test_both_unset_is_also_a_match(self):
        result = self._result()
        with mock.patch.object(el, "_read_unit_user", return_value=""):
            el._verify_unit_user_restored(result, None, reload=True)
        self.assertEqual(result.warnings, [])

    def test_drift_is_reported(self):
        result = self._result()
        with mock.patch.object(el, "_read_unit_user", return_value="root"):
            el._verify_unit_user_restored(result, "commatrix", reload=True)
        self.assertTrue(any("not back at its original" in w for w in result.warnings))

    def test_unreadable_user_warns_without_claiming_drift(self):
        result = self._result()
        with mock.patch.object(el, "_read_unit_user", return_value=None):
            el._verify_unit_user_restored(result, "commatrix", reload=True)
        self.assertTrue(any("could not read" in w for w in result.warnings))
        self.assertFalse(any("not back at its original" in w for w in result.warnings))

    def test_skipped_without_a_daemon_reload(self):
        result = self._result()
        with mock.patch.object(el, "_read_unit_user") as read:
            el._verify_unit_user_restored(result, "commatrix", reload=False)
        read.assert_not_called()
        self.assertEqual(result.warnings, [])


class TopologyProfileCostTest(unittest.TestCase):
    """The measured cost of --profile topology is stated, not guessed."""

    def test_apply_warns_about_what_topology_gives_up(self):
        self.assertIn("0%", el._TOPOLOGY_NOTE)
        self.assertIn("measure_attribution", el._TOPOLOGY_NOTE)

    def test_both_profiles_emit_their_note_on_dry_run(self):
        for profile, needle in (("attribution", "read-equivalent to root"),
                                ("topology", "effectively")):
            with mock.patch.object(el, "_is_root", return_value=False), \
                 mock.patch.object(el, "_ensure_service_user"):
                result = el.apply_elevate(dry_run=True, profile=profile)
            self.assertTrue(
                any(needle in w for w in result.warnings),
                f"{profile}: expected a note mentioning {needle!r}",
            )

    def test_measurement_script_reports_the_fields_operators_need(self):
        sys.path.insert(0, os.path.join(REPO, "packaging"))
        try:
            import measure_attribution as ma
        finally:
            sys.path.pop(0)
        result = ma.measure()
        for key in ("sockets_total", "sockets_with_pid_pct",
                    "sockets_owned_by_other_uid",
                    "sockets_owned_by_other_uid_attributed_pct",
                    "cap_dac_read_search"):
            self.assertIn(key, result)


class PythonEmbedTrustTest(unittest.TestCase):
    """SEC-033: signature verification, and MD5 explicitly not accepted."""

    def setUp(self):
        with open(os.path.join(REPO, "packaging", "windows",
                               "python-embed-trust.json"), encoding="utf-8") as fh:
            self.trust = json.load(fh)
        with open(os.path.join(REPO, "packaging", "windows", "build_msi.ps1"),
                  encoding="utf-8") as fh:
            self.script = fh.read()

    def test_the_series_the_build_defaults_to_has_an_anchor(self):
        sys.path.insert(0, os.path.join(REPO, "packaging"))
        try:
            import pin_supply_chain as psc
            version = psc.default_python_version()
        finally:
            sys.path.pop(0)
        series = ".".join(version.split(".")[:2])
        self.assertIn(series, self.trust["series"])

    def test_every_anchor_has_an_identity_and_an_issuer(self):
        for series, entry in self.trust["series"].items():
            with self.subTest(series=series):
                self.assertTrue(entry["cert_identity"])
                self.assertTrue(entry["cert_oidc_issuer"].startswith("https://"))

    def test_issuers_are_not_assumed_to_be_google(self):
        issuers = {e["cert_oidc_issuer"] for e in self.trust["series"].values()}
        self.assertGreater(
            len(issuers), 1,
            "python.org's release managers do not all use the same OIDC "
            "issuer; hardcoding one silently verifies against the wrong thing",
        )

    def test_the_build_verifies_the_signature_before_unpacking(self):
        verify_at = self.script.index("sigstore verify identity")
        expand_at = self.script.index("Expand-Archive -Path $tmp")
        self.assertLess(verify_at, expand_at)

    def test_a_failed_signature_aborts(self):
        self.assertIn("Sigstore verification FAILED", self.script)

    def test_md5_is_never_computed_or_compared(self):
        """The word may appear in a comment explaining why; the call must not.

        python.org prints an MD5 beside the download and it is the obvious
        thing to reach for. Chosen-prefix collisions against MD5 are practical,
        so it proves nothing against someone able to serve a different file.
        """

        lowered = self.script.lower()
        for forbidden in ("-algorithm md5", "algorithm md5", "md5crypto",
                          "[system.security.cryptography.md5]"):
            self.assertNotIn(forbidden, lowered)
        self.assertIn("-algorithm sha256", lowered)


if __name__ == "__main__":
    unittest.main()
