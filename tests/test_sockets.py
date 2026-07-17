import os
import socket
import tempfile
import unittest

from commatrix import sockets as sk

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class SocketParseTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(FIXTURES, "proc_net_tcp.sample"), encoding="ascii") as fh:
            self.entries = sk.parse_proc_net(fh.read(), "tcp", socket.AF_INET)

    def test_ipv4_address_decoding(self):
        listen = self.entries[0]
        self.assertEqual(listen.local_ip, "0.0.0.0")
        self.assertEqual(listen.local_port, 5432)
        self.assertEqual(listen.state, "LISTEN")
        self.assertEqual(listen.inode, 10000)

    def test_established_entry(self):
        est = self.entries[2]
        self.assertEqual(est.local_ip, "10.0.0.10")
        self.assertEqual(est.local_port, 5432)
        self.assertEqual(est.remote_ip, "10.0.0.5")
        self.assertEqual(est.remote_port, 44321)
        self.assertEqual(est.state, "ESTABLISHED")
        self.assertFalse(est.is_listening)

    def test_listening_port_map(self):
        ports = sk.listening_port_map(self.entries)
        self.assertIn(5432, ports)
        self.assertIn(443, ports)

    def test_loopback_ipv4(self):
        entry = self.entries[3]
        self.assertEqual(entry.local_ip, "127.0.0.1")

    def test_ipv6_decoding(self):
        # ::1 encoded as four little-endian words.
        hex_addr = "00000000000000000000000001000000"
        self.assertEqual(sk._parse_ipv6(hex_addr), "::1")


class ReadAllSocketsTest(unittest.TestCase):
    """Guard against the socket-fallback capture path reading zero sockets.

    Regression test: ``read_all_sockets`` used to join an absolute path onto
    ``proc_root`` (``/proc`` + ``/proc/net/tcp`` -> ``/proc/proc/net/tcp``),
    which does not exist, so it silently returned no sockets on every host that
    relies on the ``/proc/net/{tcp,udp}`` fallback.
    """

    def _write_proc_root(self, root):
        net_dir = os.path.join(root, "net")
        os.makedirs(net_dir)
        with open(os.path.join(FIXTURES, "proc_net_tcp.sample"), encoding="ascii") as fh:
            sample = fh.read()
        for name in ("tcp", "tcp6", "udp", "udp6"):
            with open(os.path.join(net_dir, name), "w", encoding="ascii") as fh:
                fh.write(sample if name == "tcp" else "  sl  local_address\n")

    def test_reads_from_proc_root(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_proc_root(root)
            entries = sk.read_all_sockets(proc_root=root)
        self.assertTrue(entries, "read_all_sockets returned no sockets")
        self.assertTrue(any(e.local_port == 5432 for e in entries))


if __name__ == "__main__":
    unittest.main()
