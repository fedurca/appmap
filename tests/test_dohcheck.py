import json
import os
import tempfile
import unittest
from unittest import mock

from commatrix import dohcheck


class DohCheckTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _chrome_dir(self, mode):
        d = os.path.join(self.dir, "chrome")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "policy.json"), "w") as fh:
            json.dump({"DnsOverHttpsMode": mode}, fh)
        return d

    def test_chrome_enforced_off(self):
        d = self._chrome_dir("off")
        with mock.patch.object(dohcheck, "_CHROME_POLICY_DIRS", {"chrome": d}), \
             mock.patch.object(dohcheck, "_FIREFOX_POLICY_FILES", []), \
             mock.patch.object(dohcheck, "_RESOLVED_CONF", "/nonexistent"), \
             mock.patch.object(dohcheck, "_RESOLVED_CONF_DIR", "/nonexistent"):
            posture = dohcheck.doh_posture()
        chrome = [f for f in posture["findings"] if f["source"] == "chrome"][0]
        self.assertEqual(chrome["status"], "enforced-off")
        self.assertTrue(chrome["enforced"])
        self.assertTrue(posture["doh_enforced_off"])
        self.assertFalse(posture["doh_enabled_anywhere"])

    def test_chrome_enabled_flagged(self):
        d = self._chrome_dir("automatic")
        with mock.patch.object(dohcheck, "_CHROME_POLICY_DIRS", {"chrome": d}), \
             mock.patch.object(dohcheck, "_FIREFOX_POLICY_FILES", []), \
             mock.patch.object(dohcheck, "_RESOLVED_CONF", "/nonexistent"), \
             mock.patch.object(dohcheck, "_RESOLVED_CONF_DIR", "/nonexistent"):
            posture = dohcheck.doh_posture()
        self.assertTrue(posture["doh_enabled_anywhere"])
        self.assertIn("ENABLED", posture["assessment"])

    def test_firefox_locked_off(self):
        p = os.path.join(self.dir, "policies.json")
        with open(p, "w") as fh:
            json.dump({"policies": {"DNSOverHTTPS": {"Enabled": False, "Locked": True}}}, fh)
        with mock.patch.object(dohcheck, "_CHROME_POLICY_DIRS", {}), \
             mock.patch.object(dohcheck, "_FIREFOX_POLICY_FILES", [p]), \
             mock.patch.object(dohcheck, "_RESOLVED_CONF", "/nonexistent"), \
             mock.patch.object(dohcheck, "_RESOLVED_CONF_DIR", "/nonexistent"):
            posture = dohcheck.doh_posture()
        ff = [f for f in posture["findings"] if f["source"] == "firefox"][0]
        self.assertEqual(ff["status"], "enforced-off")
        self.assertTrue(ff["enforced"])

    def test_host_params_shape(self):
        with mock.patch.object(dohcheck, "_CHROME_POLICY_DIRS", {}), \
             mock.patch.object(dohcheck, "_FIREFOX_POLICY_FILES", []), \
             mock.patch.object(dohcheck, "_RESOLVED_CONF", "/nonexistent"), \
             mock.patch.object(dohcheck, "_RESOLVED_CONF_DIR", "/nonexistent"):
            hp = dohcheck.host_params()
        self.assertIn("doh.assessment", hp)
        self.assertIn("doh.enforced_off", hp)


if __name__ == "__main__":
    unittest.main()
