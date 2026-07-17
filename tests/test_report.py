import json
import os
import tempfile
import unittest

from commatrix.store import EdgeObservation, Store
from commatrix import report as rp


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "central.db")
        self.store = Store(self.db)
        self.store.upsert_host("web01", {"hostname": "web01", "system.uname": "Linux web01"})
        self.store.upsert_host("db01", {"hostname": "db01"})

        # web01 serves https to an external client
        self.store.record_edge(
            "web01",
            EdgeObservation(
                proto="tcp", direction="inbound", local_ip="10.0.0.10", peer_ip="203.0.113.9",
                service_port=443, peer_class="external", snapshot_bytes=8000, snapshot_packets=10,
                service_side="local", service_name="https", l7_protocol="https",
                process_comm="nginx",
            ),
            now=100.0,
        )
        # web01 depends on db01's postgres (db01 local_ip 10.0.0.20)
        self.store.record_edge(
            "web01",
            EdgeObservation(
                proto="tcp", direction="outbound", local_ip="10.0.0.10", peer_ip="10.0.0.20",
                service_port=5432, peer_class="internal", snapshot_bytes=1500, snapshot_packets=8,
                service_side="peer", service_name="postgresql", l7_protocol="postgres",
                process_comm="nginx",
            ),
            now=100.0,
        )
        # db01 serves postgres (its own inbound), local_ip 10.0.0.20
        self.store.record_edge(
            "db01",
            EdgeObservation(
                proto="tcp", direction="inbound", local_ip="10.0.0.20", peer_ip="10.0.0.10",
                service_port=5432, peer_class="internal", snapshot_bytes=2400, snapshot_packets=8,
                service_side="local", service_name="postgresql", l7_protocol="postgres",
                process_comm="postgres",
            ),
            now=100.0,
        )
        # external cleartext inbound (http)
        self.store.record_edge(
            "web01",
            EdgeObservation(
                proto="tcp", direction="inbound", local_ip="10.0.0.10", peer_ip="198.51.100.7",
                service_port=80, peer_class="external", snapshot_bytes=500, snapshot_packets=5,
                service_side="local", service_name="http", l7_protocol="http",
                process_comm="nginx",
            ),
            now=100.0,
        )

    def tearDown(self):
        self.store.close()

    def test_matrix_csv(self):
        text = rp.matrix_csv(self.store)
        self.assertIn("host,direction", text)
        self.assertIn("web01", text)
        self.assertIn("postgresql", text)

    def test_matrix_json(self):
        rows = json.loads(rp.matrix_json(self.store))
        self.assertEqual(len(rows), 4)

    def test_matrix_markdown(self):
        text = rp.matrix_markdown(self.store)
        self.assertIn("| Host |", text)
        self.assertIn("nginx", text)

    def test_topology_mermaid(self):
        text = rp.topology_mermaid(self.store)
        self.assertIn("flowchart LR", text)
        # web01 -> db01 edge should be linked by IP
        self.assertIn("db01", text)

    def test_topology_dot(self):
        text = rp.topology_dot(self.store)
        self.assertIn("digraph commatrix", text)

    def test_catalog_json(self):
        catalog = json.loads(rp.catalog_json(self.store))
        hosts = {h["host"]: h for h in catalog["hosts"]}
        self.assertIn("web01", hosts)
        apps = hosts["web01"]["applications"]
        self.assertIn("https", apps)
        # depends_on should reference db01 (linked via IP)
        pg_dep = apps["postgresql"]["depends_on"]
        self.assertTrue(any(d["peer"] == "db01" for d in pg_dep))

    def test_service_sheets(self):
        text = rp.service_sheets(self.store)
        self.assertIn("Application catalog", text)
        self.assertIn("Host: web01", text)

    def test_security_highlights(self):
        data = rp.security_highlights(self.store)
        # https + http external inbound = 2
        self.assertEqual(len(data["external_inbound"]), 2)
        # http is cleartext external
        self.assertTrue(any(i["l7"] == "http" for i in data["cleartext_external"]))

    def test_security_markdown(self):
        text = rp.security_markdown(self.store)
        self.assertIn("External inbound exposure", text)

    def test_report_html(self):
        text = rp.report_html(self.store)
        self.assertIn("<!DOCTYPE html>", text)
        self.assertIn("Traffic graphs", text)
        self.assertIn("<svg", text)
        self.assertIn("Top services by bytes", text)
        self.assertIn("nginx", text)
        self.assertIn("flowchart LR", text)

    def test_report_html_virustotal_link_for_external(self):
        text = rp.report_html(self.store)
        # external peer 203.0.113.9 should be a VirusTotal click-through
        self.assertIn("virustotal.com/gui/ip-address/203.0.113.9", text)
        # internal peer must NOT be linked to VirusTotal
        self.assertNotIn("ip-address/10.0.0.20", text)

    def test_report_html_has_first_seen_and_occurrences(self):
        text = rp.report_html(self.store)
        self.assertIn("First seen", text)
        self.assertIn("Seen (n)", text)

    def test_matrix_markdown_has_occurrences(self):
        text = rp.matrix_markdown(self.store)
        self.assertIn("Seen (n)", text)

    def test_write_html_report(self):
        out = os.path.join(self.tmp, "report.html")
        rp.write_html_report(self.store, out)
        with open(out, "r", encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("<!DOCTYPE html>", body)
        self.assertGreater(os.path.getsize(out), 500)


if __name__ == "__main__":
    unittest.main()
