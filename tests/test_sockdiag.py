import socket
import struct
import unittest
from unittest import mock

from commatrix import sockdiag as sd
from commatrix import conntrack as ct


def _make_tcp_info(bytes_acked, bytes_received, segs_out, segs_in, size=160):
    info = bytearray(size)
    struct.pack_into("=Q", info, sd._OFF_BYTES_ACKED, bytes_acked)
    struct.pack_into("=Q", info, sd._OFF_BYTES_RECEIVED, bytes_received)
    struct.pack_into("=I", info, sd._OFF_SEGS_OUT, segs_out)
    struct.pack_into("=I", info, sd._OFF_SEGS_IN, segs_in)
    return bytes(info)


def _make_inet_diag_msg(family, state, sport, dport, src, dst, uid, inode):
    payload = bytearray(72)
    payload[0] = family
    payload[1] = state
    struct.pack_into("!HH", payload, 4, sport, dport)
    payload[8:8 + len(src)] = src
    payload[24:24 + len(dst)] = dst
    struct.pack_into("=I", payload, 64, uid)
    struct.pack_into("=I", payload, 68, inode)
    return bytes(payload)


def _rtattr(rta_type, data):
    rta_len = 4 + len(data)
    pad = (-rta_len) & 3
    return struct.pack("=HH", rta_len, rta_type) + data + b"\x00" * pad


def _nlmsg(msg_type, body):
    msg_len = 16 + len(body)
    hdr = struct.pack("=IHHII", msg_len, msg_type, 0, 0, 0)
    blob = hdr + body
    return blob + b"\x00" * ((-len(blob)) & 3)


class TcpInfoParseTest(unittest.TestCase):
    def test_parse_tcp_info_offsets(self):
        info = _make_tcp_info(5000, 7000, 10, 8)
        sent, recv, ps, pr = sd._parse_tcp_info(info)
        self.assertEqual((sent, recv, ps, pr), (5000, 7000, 10, 8))

    def test_parse_tcp_info_short_blob_safe(self):
        # An old/short tcp_info must not raise; missing fields read as 0.
        self.assertEqual(sd._parse_tcp_info(b"\x00" * 100), (0, 0, 0, 0))


class MessageParseTest(unittest.TestCase):
    def test_parses_socket_with_bytes(self):
        src = socket.inet_pton(socket.AF_INET, "10.0.0.5")
        dst = socket.inet_pton(socket.AF_INET, "93.184.216.34")
        diag = _make_inet_diag_msg(socket.AF_INET, 1, 40000, 443, src, dst, 1000, 4242)
        info = _make_tcp_info(1234, 5678, 20, 15)
        body = diag + _rtattr(sd.INET_DIAG_INFO, info)
        buf = _nlmsg(sd.SOCK_DIAG_BY_FAMILY, body) + _nlmsg(sd.NLMSG_DONE, b"\x00" * 4)

        out = []
        done = sd._parse_messages(buf, out)
        self.assertTrue(done)
        self.assertEqual(len(out), 1)
        s = out[0]
        self.assertEqual(s.local_ip, "10.0.0.5")
        self.assertEqual(s.remote_ip, "93.184.216.34")
        self.assertEqual(s.remote_port, 443)
        self.assertEqual(s.bytes_sent, 1234)
        self.assertEqual(s.bytes_recv, 5678)
        self.assertEqual(s.packets_sent, 20)
        self.assertEqual(s.inode, 4242)

    def test_listen_socket_skipped(self):
        src = socket.inet_pton(socket.AF_INET, "0.0.0.0")
        dst = socket.inet_pton(socket.AF_INET, "0.0.0.0")
        diag = _make_inet_diag_msg(socket.AF_INET, sd._TCP_LISTEN, 443, 0, src, dst, 0, 1)
        buf = _nlmsg(sd.SOCK_DIAG_BY_FAMILY, diag)
        out = []
        sd._parse_messages(buf, out)
        self.assertEqual(out, [])


class ConntrackIntegrationTest(unittest.TestCase):
    def test_resolve_source_accepts_socket_diag(self):
        self.assertEqual(ct.resolve_source("socket-diag"), "socket-diag")

    def test_auto_prefers_sockdiag_over_sockets(self):
        with mock.patch.object(ct, "proc_available", return_value=False), \
             mock.patch.object(ct, "conntrack_tool_available", return_value=False), \
             mock.patch.object(ct.sockdiag, "available", return_value=True):
            self.assertEqual(ct.resolve_source("auto"), "socket-diag")

    def test_entries_from_sockdiag_carry_bytes(self):
        fake = sd.DiagSocket(
            proto="tcp", family=socket.AF_INET,
            local_ip="10.0.0.5", local_port=40000,
            remote_ip="93.184.216.34", remote_port=443,
            state="ESTABLISHED", inode=1, uid=1000,
            bytes_sent=1000, bytes_recv=2000, packets_sent=5, packets_recv=7,
        )
        with mock.patch.object(ct.sockdiag, "read_tcp_diag", return_value=[fake]), \
             mock.patch.object(ct, "read_all_sockets", return_value=[]):
            entries = ct.entries_from_sockdiag()
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e.orig_dport, 443)
        self.assertEqual(e.total_bytes, 3000)
        self.assertEqual(e.total_packets, 12)


if __name__ == "__main__":
    unittest.main()
