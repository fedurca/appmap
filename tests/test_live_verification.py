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


class TaskSchedulerXmlOrderTest(unittest.TestCase):
    """SEC-023: Task Scheduler rejects XML whose elements are out of order.

    The schema uses xsd:sequence, not xsd:all, so `schtasks /create /xml`
    fails on a document that is otherwise perfectly valid but lists, say,
    Enabled before StartWhenAvailable. Registration is the one step that
    cannot be tried here, so the shape of what we would register is checked
    against the documented sequences instead.

    Sources:
      learn.microsoft.com/.../taskschedulerschema-task-element
      learn.microsoft.com/.../taskschedulerschema-settingstype-complextype
      learn.microsoft.com/.../taskschedulerschema-principaltype-complextype
    """

    NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"

    TASK_ORDER = ["RegistrationInfo", "Triggers", "Principals", "Settings",
                  "Data", "Actions"]
    SETTINGS_ORDER = [
        "AllowStartOnDemand", "RestartOnFailure", "MultipleInstancesPolicy",
        "DisallowStartIfOnBatteries", "StopIfGoingOnBatteries",
        "AllowHardTerminate", "StartWhenAvailable", "NetworkProfileName",
        "RunOnlyIfNetworkAvailable", "WakeToRun", "Enabled", "Hidden",
        "DeleteExpiredTaskAfter", "IdleSettings", "NetworkSettings",
        "ExecutionTimeLimit", "Priority", "RunOnlyIfIdle",
        "UseUnifiedSchedulingEngine", "DisallowStartOnRemoteAppSession",
        "MaintenanceSettings", "Volatile",
    ]
    PRINCIPAL_ORDER = ["UserId", "LogonType", "GroupId", "DisplayName",
                       "RunLevel", "ProcessTokenSidType", "RequiredPrivileges"]
    EXEC_ORDER = ["Command", "Arguments", "WorkingDirectory"]

    def setUp(self):
        from xml.etree import ElementTree

        from commatrix.platform.win import elevate as ew

        self.xml = ew._task_xml(
            '"C:\\Python\\python.exe" -m commatrix collect --config "C:\\x.conf"'
        )
        self.root = ElementTree.fromstring(self.xml)

    def _children(self, element):
        return [c.tag.replace(self.NS, "") for c in element]

    def _assert_ordered(self, actual, documented, where):
        positions = []
        for name in actual:
            self.assertIn(name, documented, f"{where}: unknown element {name}")
            positions.append(documented.index(name))
        self.assertEqual(
            positions, sorted(positions),
            f"{where}: elements are out of schema order -> {actual}",
        )

    def test_it_is_well_formed_and_in_the_task_namespace(self):
        self.assertTrue(self.root.tag.endswith("}Task"))
        self.assertEqual(self.root.attrib.get("version"), "1.2")

    def test_task_level_elements_are_in_order(self):
        self._assert_ordered(self._children(self.root), self.TASK_ORDER, "Task")

    def test_settings_elements_are_in_order(self):
        settings = self.root.find(f"{self.NS}Settings")
        self.assertIsNotNone(settings)
        self._assert_ordered(
            self._children(settings), self.SETTINGS_ORDER, "Settings"
        )

    def test_principal_elements_are_in_order(self):
        principal = self.root.find(f"{self.NS}Principals/{self.NS}Principal")
        self.assertIsNotNone(principal)
        self._assert_ordered(
            self._children(principal), self.PRINCIPAL_ORDER, "Principal"
        )

    def test_exec_elements_are_in_order(self):
        exec_el = self.root.find(f"{self.NS}Actions/{self.NS}Exec")
        self.assertIsNotNone(exec_el)
        self._assert_ordered(self._children(exec_el), self.EXEC_ORDER, "Exec")

    def test_the_principal_is_s4u_and_least_privilege(self):
        principal = self.root.find(f"{self.NS}Principals/{self.NS}Principal")
        self.assertEqual(principal.findtext(f"{self.NS}LogonType"), "S4U")
        self.assertEqual(principal.findtext(f"{self.NS}RunLevel"), "LeastPrivilege")
        self.assertEqual(principal.findtext(f"{self.NS}UserId"), "commatrix")

    def test_actions_context_matches_the_principal_id(self):
        principal = self.root.find(f"{self.NS}Principals/{self.NS}Principal")
        actions = self.root.find(f"{self.NS}Actions")
        self.assertEqual(actions.attrib.get("Context"), principal.attrib.get("id"))

    def test_the_command_and_arguments_are_split_correctly(self):
        exec_el = self.root.find(f"{self.NS}Actions/{self.NS}Exec")
        self.assertEqual(exec_el.findtext(f"{self.NS}Command"),
                         r"C:\Python\python.exe")
        self.assertIn("-m commatrix collect",
                      exec_el.findtext(f"{self.NS}Arguments"))

    def test_special_characters_in_the_command_are_escaped(self):
        from xml.etree import ElementTree

        from commatrix.platform.win import elevate as ew

        xml = ew._task_xml('"C:\\py.exe" -m commatrix --config "C:\\a&b<c>.conf"')
        root = ElementTree.fromstring(xml)  # must not raise
        args = root.find(f"{self.NS}Actions/{self.NS}Exec/{self.NS}Arguments")
        self.assertIn("a&b<c>", args.text)
