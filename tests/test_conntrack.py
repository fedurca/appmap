import os
import unittest

from commatrix import conntrack as ct

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class ConntrackParseTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(FIXTURES, "nf_conntrack.sample"), encoding="utf-8") as fh:
            self.entries = ct.parse_conntrack_text(fh.read())

    def test_parses_all_lines(self):
        self.assertEqual(len(self.entries), 4)

    def test_tcp_service_entry(self):
        e = self.entries[0]
        self.assertEqual(e.l4proto, "tcp")
        self.assertEqual(e.state, "ESTABLISHED")
        self.assertEqual(e.orig_src, "10.0.0.5")
        self.assertEqual(e.orig_dst, "10.0.0.10")
        self.assertEqual(e.orig_sport, 44321)
        self.assertEqual(e.orig_dport, 5432)
        self.assertEqual(e.orig_bytes, 1500)
        self.assertEqual(e.reply_bytes, 2400)
        self.assertEqual(e.total_bytes, 3900)
        self.assertEqual(e.total_packets, 18)
        self.assertEqual(e.delta_time, 42)
        self.assertTrue(e.assured)
        self.assertTrue(e.has_accounting)

    def test_udp_entry_has_no_state(self):
        udp = self.entries[2]
        self.assertEqual(udp.l4proto, "udp")
        self.assertIsNone(udp.state)
        self.assertEqual(udp.orig_dport, 53)

    def test_event_line_parsing(self):
        line = (
            "[1612345678.123456]\t[DESTROY] tcp 6 src=1.1.1.1 dst=2.2.2.2 "
            "sport=1000 dport=80 packets=4 bytes=400 src=2.2.2.2 dst=1.1.1.1 "
            "sport=80 dport=1000 packets=3 bytes=900"
        )
        e = ct.parse_conntrack_line(line)
        self.assertIsNotNone(e)
        self.assertEqual(e.event, "DESTROY")
        self.assertEqual(e.orig_dport, 80)
        self.assertEqual(e.total_bytes, 1300)

    def test_blank_line_returns_none(self):
        self.assertIsNone(ct.parse_conntrack_line("   "))

    def test_resolve_source(self):
        self.assertEqual(ct.resolve_source("auto"), "procfs")
        self.assertEqual(ct.resolve_source("procfs"), "procfs")
        with self.assertRaises(ValueError):
            ct.resolve_source("bogus")


if __name__ == "__main__":
    unittest.main()
