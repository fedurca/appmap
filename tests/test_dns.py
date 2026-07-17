import unittest

from commatrix import dns


class ParseQueryResultTest(unittest.TestCase):
    def test_parse_a_record(self):
        params = {
            "question": [{"class": 1, "type": 1, "name": "example.com"}],
            "rcode": 0,
            "answer": [
                {"rr": {"key": {"class": 1, "type": 1, "name": "example.com"},
                        "address": [93, 184, 216, 34]}}
            ],
        }
        ev = dns.parse_query_result(params)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.qname, "example.com")
        self.assertEqual(ev.qtype, "A")
        self.assertEqual(ev.answers, ["93.184.216.34"])

    def test_parse_aaaa_record(self):
        params = {
            "query": [{"class": 1, "type": 28, "name": "v6.example.com"}],
            "answer": [
                {"rr": {"key": {"type": 28, "name": "v6.example.com"},
                        "address": [0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1]}}
            ],
        }
        ev = dns.parse_query_result(params)
        self.assertEqual(ev.qname, "v6.example.com")
        self.assertEqual(ev.qtype, "AAAA")
        self.assertEqual(ev.answers, ["2001:db8::1"])

    def test_empty_message_ignored(self):
        self.assertIsNone(dns.parse_query_result({}))
        self.assertIsNone(dns.parse_query_result({"answer": []}))

    def test_to_row(self):
        ev = dns.DnsEvent(ts=1.0, qname="a.com", qtype="A", rcode="0", answers=["1.2.3.4"])
        row = ev.to_row()
        self.assertEqual(row["qname"], "a.com")
        self.assertEqual(row["answers"], "1.2.3.4")
        self.assertEqual(row["source"], "resolved-monitor")


class MonitorAvailabilityTest(unittest.TestCase):
    def test_missing_socket_unavailable(self):
        self.assertFalse(dns.monitor_available("/nonexistent/commatrix/resolve.monitor"))


class DnsMonitorBufferTest(unittest.TestCase):
    def test_record_and_drain_and_lookup(self):
        mon = dns.DnsMonitor(path="/nonexistent")
        ev = dns.DnsEvent(ts=1000.0, qname="api.example.com", qtype="A",
                          rcode="0", answers=["203.0.113.7"])
        mon._record(ev)
        self.assertEqual(mon.lookup("203.0.113.7", now=1000.0), "api.example.com")
        self.assertIsNone(mon.lookup("203.0.113.7", now=1000.0 + 100000))  # TTL expired
        drained = mon.drain()
        self.assertEqual(len(drained), 1)
        self.assertEqual(mon.drain(), [])  # cleared


if __name__ == "__main__":
    unittest.main()
