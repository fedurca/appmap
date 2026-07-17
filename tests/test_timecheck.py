import unittest
from unittest import mock

from commatrix import timecheck as tc


class OffsetParseTest(unittest.TestCase):
    def test_units(self):
        self.assertAlmostEqual(tc._parse_offset_to_seconds("+12.5ms"), 0.0125)
        self.assertAlmostEqual(tc._parse_offset_to_seconds("-3 us"), -3e-6)
        self.assertAlmostEqual(tc._parse_offset_to_seconds("0.25s"), 0.25)
        self.assertAlmostEqual(tc._parse_offset_to_seconds("Offset: 5ns".split(":", 1)[1]), 5e-9)

    def test_no_match(self):
        self.assertIsNone(tc._parse_offset_to_seconds("n/a"))


class ChronyParseTest(unittest.TestCase):
    def test_system_time_slow_is_negative(self):
        tracking = (
            "Reference ID    : 0A0A0A0A (ntp.local)\n"
            "Stratum         : 3\n"
            "System time     : 0.000123456 seconds slow of NTP time\n"
            "Last offset     : -0.000100000 seconds\n"
            "Leap status     : Normal\n"
        )
        with mock.patch.object(tc.shutil, "which", return_value="/usr/bin/chronyc"), \
             mock.patch.object(tc, "_run", return_value=tracking):
            self.assertAlmostEqual(tc._chrony_offset(), -0.000123456, places=9)

    def test_system_time_fast_is_positive(self):
        tracking = "System time     : 0.002000000 seconds fast of NTP time\n"
        with mock.patch.object(tc.shutil, "which", return_value="/usr/bin/chronyc"), \
             mock.patch.object(tc, "_run", return_value=tracking):
            self.assertAlmostEqual(tc._chrony_offset(), 0.002, places=9)


class PostureTest(unittest.TestCase):
    def test_ntp_disabled(self):
        with mock.patch.object(tc, "_timedatectl_props", return_value={"NTP": "no", "NTPSynchronized": "no"}), \
             mock.patch.object(tc, "_chrony_offset", return_value=None), \
             mock.patch.object(tc, "_timesyncd_offset", return_value=None), \
             mock.patch.object(tc, "_detect_service", return_value=None):
            p = tc.ntp_posture()
        self.assertFalse(p["ntp_enabled"])
        self.assertIn("DISABLED", p["assessment"])

    def test_large_offset_flagged(self):
        with mock.patch.object(tc, "_timedatectl_props", return_value={"NTP": "yes", "NTPSynchronized": "yes"}), \
             mock.patch.object(tc, "_chrony_offset", return_value=2.5), \
             mock.patch.object(tc, "_detect_service", return_value="chrony"):
            p = tc.ntp_posture()
        self.assertIn("offset is large", p["assessment"])
        self.assertEqual(p["offset_source"], "chrony")

    def test_synchronized_ok(self):
        with mock.patch.object(tc, "_timedatectl_props", return_value={"NTP": "yes", "NTPSynchronized": "yes"}), \
             mock.patch.object(tc, "_chrony_offset", return_value=0.0005), \
             mock.patch.object(tc, "_detect_service", return_value="chrony"):
            p = tc.ntp_posture()
        self.assertEqual(p["assessment"], "clock synchronized")

    def test_host_params_shape(self):
        with mock.patch.object(tc, "_timedatectl_props", return_value={"NTP": "yes", "NTPSynchronized": "yes"}), \
             mock.patch.object(tc, "_chrony_offset", return_value=0.01), \
             mock.patch.object(tc, "_detect_service", return_value="chrony"):
            hp = tc.host_params()
        self.assertIn("time.assessment", hp)
        self.assertEqual(hp["time.synchronized"], True)
        self.assertAlmostEqual(hp["time.offset_seconds"], 0.01)


if __name__ == "__main__":
    unittest.main()
