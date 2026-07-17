import unittest

from commatrix import dohdetect


class DohDetectTest(unittest.TestCase):
    def setUp(self):
        self.sig = dohdetect.load_doh_signatures()

    def test_signatures_loaded(self):
        self.assertTrue(self.sig.networks)
        self.assertIn(443, self.sig.doh_ports)
        self.assertIn(853, self.sig.dot_ports)

    def test_cloudflare_doh(self):
        self.assertEqual(self.sig.classify("1.1.1.1", 443), "doh:cloudflare")

    def test_google_dot(self):
        self.assertEqual(self.sig.classify("8.8.8.8", 853), "dot:google")

    def test_quad9_doh(self):
        self.assertEqual(self.sig.classify("9.9.9.9", 443), "doh:quad9")

    def test_by_domain(self):
        self.assertEqual(self.sig.classify("192.0.2.1", 443, "dns.google"), "doh:google")

    def test_non_doh_ip(self):
        self.assertIsNone(self.sig.classify("192.0.2.1", 443))

    def test_wrong_port(self):
        self.assertIsNone(self.sig.classify("1.1.1.1", 80))


if __name__ == "__main__":
    unittest.main()
