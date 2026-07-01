import os
import unittest

from commatrix import conntrack as ct
from commatrix import flows as fl

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class FlowNormalizationTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(FIXTURES, "nf_conntrack.sample"), encoding="utf-8") as fh:
            self.entries = ct.parse_conntrack_text(fh.read())
        self.local_ips = {"10.0.0.10", "127.0.0.1"}
        self.listening = {5432, 443, 6379}
        self.classifier = fl.NetworkClassifier(
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
        )

    def _normalize(self):
        return fl.normalize_entries(
            self.entries, self.local_ips, self.listening, self.classifier
        )

    def test_inbound_internal(self):
        flows = self._normalize()
        pg = next(f for f in flows if f.service_port == 5432)
        self.assertEqual(pg.direction, "inbound")
        self.assertEqual(pg.local_ip, "10.0.0.10")
        self.assertEqual(pg.peer_ip, "10.0.0.5")
        self.assertEqual(pg.peer_class, "internal")
        self.assertEqual(pg.service_side, "local")

    def test_inbound_external(self):
        flows = self._normalize()
        https = next(f for f in flows if f.service_port == 443)
        self.assertEqual(https.direction, "inbound")
        self.assertEqual(https.peer_class, "external")
        self.assertEqual(https.peer_ip, "203.0.113.9")

    def test_outbound_external(self):
        flows = self._normalize()
        dns = next(f for f in flows if f.service_port == 53)
        self.assertEqual(dns.direction, "outbound")
        self.assertEqual(dns.local_ip, "10.0.0.10")
        self.assertEqual(dns.peer_ip, "8.8.8.8")
        self.assertEqual(dns.peer_class, "external")
        self.assertEqual(dns.service_side, "peer")

    def test_loopback(self):
        flows = self._normalize()
        redis = next(f for f in flows if f.service_port == 6379)
        self.assertEqual(redis.direction, "loopback")
        self.assertEqual(redis.peer_class, "loopback")

    def test_classifier(self):
        self.assertEqual(self.classifier.classify("10.1.2.3"), "internal")
        self.assertEqual(self.classifier.classify("8.8.8.8"), "external")
        self.assertEqual(self.classifier.classify("127.0.0.1"), "loopback")
        self.assertEqual(self.classifier.classify("not-an-ip"), "external")


if __name__ == "__main__":
    unittest.main()
