"""Regression tests for CODE-017 and CODE-030.

CODE-017  _ip_to_host() assumed globally unique IPs, so a docker bridge address
          that exists identically on every machine in a fleet collapsed onto
          one host and produced inter-host edges that do not exist.
CODE-030  Windows data_quality was one host-wide boolean instead of a property
          of each edge.
"""

import os
import tempfile
import unittest
from types import SimpleNamespace

from commatrix import report as rp
from commatrix.platform.win import capture
from commatrix.store import EdgeObservation, Store


def _row(host, direction, local_ip, peer_ip, port, peer_class="internal", peer_name=None):
    return {
        "host": host, "direction": direction, "local_ip": local_ip,
        "peer_ip": peer_ip, "service_port": port, "peer_class": peer_class,
        "peer_name": peer_name, "service_name": None, "l7_protocol": None,
        "bytes": 0, "last_seen": 0, "max_gap": 0, "proto": "tcp",
    }


class DuplicatePrivateIpTest(unittest.TestCase):
    """CODE-017."""

    def setUp(self):
        # Both hosts run a container on the default docker bridge, and both
        # containers answer on 172.17.0.2.
        self.rows = [
            _row("web01", "inbound", "172.17.0.2", "10.0.0.10", 8080),
            _row("web02", "inbound", "172.17.0.2", "10.0.0.11", 8080),
            _row("web01", "outbound", "10.0.0.10", "172.17.0.2", 8080),
            _row("web02", "outbound", "10.0.0.11", "172.17.0.2", 8080),
        ]

    def test_ambiguous_ip_is_not_attributed_to_a_single_host(self):
        mapping = rp._ip_to_host(self.rows)
        self.assertNotIn(
            "172.17.0.2", mapping,
            "an IP claimed by two hosts identifies neither",
        )

    def test_each_host_keeps_its_own_container_node(self):
        index = rp._ip_host_index(self.rows)
        web01_peer = rp._peer_node(self.rows[2], index)
        web02_peer = rp._peer_node(self.rows[3], index)
        self.assertNotEqual(
            web01_peer, web02_peer,
            "the same private address on two hosts must not merge into one node",
        )
        self.assertNotIn("web02", web01_peer)
        self.assertNotIn("web01", web02_peer)

    def test_genuine_inter_host_edge_is_still_linked(self):
        rows = [
            _row("db01", "inbound", "10.0.0.20", "10.0.0.10", 5432),
            _row("web01", "outbound", "10.0.0.10", "10.0.0.20", 5432),
        ]
        index = rp._ip_host_index(rows)
        self.assertEqual(rp._peer_node(rows[1], index), "db01")

    def test_loopback_never_links_two_hosts(self):
        rows = [
            _row("web01", "loopback", "127.0.0.1", "127.0.0.1", 6379, "loopback"),
            _row("db01", "loopback", "127.0.0.1", "127.0.0.1", 6379, "loopback"),
        ]
        index = rp._ip_host_index(rows)
        a = rp._peer_node(rows[0], index)
        b = rp._peer_node(rows[1], index)
        self.assertNotEqual(a, b)

    def test_external_peers_stay_a_single_shared_node(self):
        rows = [
            _row("web01", "outbound", "10.0.0.10", "203.0.113.9", 443, "external"),
            _row("web02", "outbound", "10.0.0.11", "203.0.113.9", 443, "external"),
        ]
        index = rp._ip_host_index(rows)
        self.assertEqual(
            rp._peer_node(rows[0], index), rp._peer_node(rows[1], index)
        )

    def test_diagram_has_no_edge_between_the_two_web_hosts(self):
        tmp = tempfile.mkdtemp()
        store = Store(os.path.join(tmp, "c.db"))
        try:
            for host, local_ip in (("web01", "10.0.0.10"), ("web02", "10.0.0.11")):
                store.upsert_host(host, {"hostname": host})
                store.record_edge(host, EdgeObservation(
                    proto="tcp", direction="inbound", local_ip="172.17.0.2",
                    peer_ip=local_ip, service_port=8080, peer_class="internal",
                    snapshot_bytes=10, snapshot_packets=1, service_side="local",
                ), now=100.0)
                store.record_edge(host, EdgeObservation(
                    proto="tcp", direction="outbound", local_ip=local_ip,
                    peer_ip="172.17.0.2", service_port=8080, peer_class="internal",
                    snapshot_bytes=10, snapshot_packets=1, service_side="peer",
                ), now=100.0)
            dot = rp.topology_dot(store)
            ids = {}
            for line in dot.splitlines():
                if "->" in line:
                    src, rest = line.strip().split("->", 1)
                    ids[src.strip()] = rest
            self.assertNotIn(
                f"{rp._node_id('web01')} -> {rp._node_id('web02')}", dot
            )
            self.assertNotIn(
                f"{rp._node_id('web02')} -> {rp._node_id('web01')}", dot
            )
        finally:
            store.close()


class WindowsPerEdgeQualityTest(unittest.TestCase):
    """CODE-030."""

    class _Sig:
        def classify(self, *_a, **_k):
            return None

    def _collector(self):
        from commatrix.catalog import Signatures
        return SimpleNamespace(
            classifier=_Classifier(),
            signatures=Signatures(),
            doh_signatures=self._Sig(),
            dns_monitor=None,
            sni_monitor=None,
        )

    def test_accounted_connection_does_not_mark_unaccounted_edges(self):
        conns = [
            _conn("10.0.0.5", 50000, "93.184.216.34", 443, bytes_sent=1000),
            _conn("10.0.0.5", 50001, "93.184.216.35", 8080),
        ]
        with _patched_snapshot(conns):
            edges = capture.build_edges(self._collector())
        by_peer = {e.peer_ip: e for e in edges}
        self.assertIsNone(by_peer["93.184.216.34"].data_quality)
        self.assertEqual(
            by_peer["93.184.216.35"].data_quality, "socket-snapshot",
            "an edge with no byte counters must not inherit another edge's quality",
        )

    def test_all_unaccounted_stays_socket_snapshot(self):
        conns = [_conn("10.0.0.5", 50000, "93.184.216.34", 443)]
        with _patched_snapshot(conns):
            edges = capture.build_edges(self._collector())
        self.assertEqual(edges[0].data_quality, "socket-snapshot")


class _Classifier:
    def classify(self, ip):
        return "external"


def _conn(lip, lport, rip, rport, bytes_sent=0, bytes_recv=0):
    from commatrix.platform.win.iphlp import WinConn
    return WinConn(
        proto="tcp", family=2, local_ip=lip, local_port=lport,
        remote_ip=rip, remote_port=rport, state="ESTABLISHED", pid=100,
        bytes_sent=bytes_sent, bytes_recv=bytes_recv,
        accounted=bool(bytes_sent or bytes_recv),
    )


def _patched_snapshot(conns):
    from unittest import mock
    return mock.patch.multiple(
        "commatrix.platform.win.capture",
        iphlp=mock.MagicMock(snapshot=mock.Mock(return_value=conns)),
        winprocess=mock.MagicMock(collect_processes=mock.Mock(return_value={})),
    )


if __name__ == "__main__":
    unittest.main()
