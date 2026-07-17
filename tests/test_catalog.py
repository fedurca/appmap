import unittest

from commatrix.catalog import diff_edges, identify_service, load_signatures
from commatrix.processes import ProcessInfo


class CatalogTest(unittest.TestCase):
    def setUp(self):
        self.sig = load_signatures()

    def test_signatures_loaded(self):
        self.assertIn(5432, self.sig.ports)
        self.assertTrue(self.sig.patterns)

    def test_identify_by_port(self):
        ident = identify_service(5432, self.sig, None)
        self.assertEqual(ident.service_name, "postgresql")
        self.assertEqual(ident.l7_protocol, "postgres")
        self.assertEqual(ident.source, "port")

    def test_identify_by_process(self):
        proc = ProcessInfo(pid=1, comm="postgres", cmdline="/usr/bin/postgres -D /data")
        ident = identify_service(5432, self.sig, proc)
        self.assertEqual(ident.service_name, "postgresql")
        self.assertEqual(ident.confidence, "high")
        self.assertEqual(ident.source, "process")

    def test_identify_unknown_port_with_process(self):
        proc = ProcessInfo(pid=1, comm="myapp", cmdline="/opt/myapp/bin/server")
        ident = identify_service(59999, self.sig, proc)
        self.assertEqual(ident.service_name, "myapp")
        self.assertEqual(ident.confidence, "medium")

    def test_identify_fallback(self):
        ident = identify_service(59999, self.sig, None)
        self.assertEqual(ident.service_name, "port-59999")
        self.assertEqual(ident.source, "fallback")

    def test_nodejs_pattern_matches_real_node(self):
        for cmd in ("/usr/bin/node server.js", "node", "npm run build", "/usr/local/bin/nodejs20 app"):
            proc = ProcessInfo(pid=1, comm="node", cmdline=cmd)
            ident = identify_service(3000, self.sig, proc)
            self.assertEqual(ident.service_name, "nodejs-app", cmd)

    def test_browser_not_misidentified_as_nodejs(self):
        # Regression: "--render-node-override" and substrings like "npmjs" used
        # to match the nodejs pattern, mislabelling browsers as nodejs-app.
        chrome = ProcessInfo(
            pid=1,
            comm="chrome",
            cmdline="/opt/chrome --type=gpu-process --render-node-override=/dev/dri/renderD128",
            exe="/opt/chrome",
        )
        ident = identify_service(443, self.sig, chrome)
        self.assertEqual(ident.service_name, "chrome")
        self.assertEqual(ident.l7_protocol, "https")

        cursor = ProcessInfo(
            pid=2,
            comm="cursor",
            cmdline='/usr/share/cursor/cursor --allow=["npmjs.com"] --render-node-override=/dev/dri/renderD128',
            exe="/usr/share/cursor/cursor",
        )
        ident = identify_service(443, self.sig, cursor)
        self.assertEqual(ident.service_name, "cursor")
        self.assertEqual(ident.l7_protocol, "https")

    def test_cleartext_flag(self):
        ident = identify_service(80, self.sig, None)
        self.assertTrue(ident.cleartext)

    def test_diff_edges(self):
        baseline = [
            {"host": "a", "proto": "tcp", "direction": "inbound", "peer_ip": "1.1.1.1", "service_port": 80},
        ]
        current = [
            {"host": "a", "proto": "tcp", "direction": "inbound", "peer_ip": "1.1.1.1", "service_port": 80},
            {"host": "a", "proto": "tcp", "direction": "outbound", "peer_ip": "2.2.2.2", "service_port": 443},
        ]
        report = diff_edges(baseline, current)
        self.assertTrue(report.has_changes)
        self.assertEqual(len(report.added), 1)
        self.assertEqual(len(report.removed), 0)
        self.assertEqual(len(report.common), 1)


if __name__ == "__main__":
    unittest.main()
