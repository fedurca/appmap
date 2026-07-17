import struct
import unittest

from commatrix import sni


def _ext(etype, data):
    return struct.pack("!HH", etype, len(data)) + data


def _sni_extension(host):
    hb = host.encode("ascii")
    entry = struct.pack("!B", 0) + struct.pack("!H", len(hb)) + hb  # name_type=0
    server_name_list = struct.pack("!H", len(entry)) + entry
    return _ext(0x0000, server_name_list)


def _client_hello(host=None, ech=False):
    exts = b""
    if host is not None:
        exts += _sni_extension(host)
    if ech:
        exts += _ext(0xFE0D, b"\x00\x01\x02")
    body = b"\x03\x03"                      # client_version
    body += b"\x00" * 32                    # random
    body += b"\x00"                         # session_id len
    body += struct.pack("!H", 2) + b"\x13\x01"  # cipher suites
    body += b"\x01\x00"                     # compression methods
    body += struct.pack("!H", len(exts)) + exts
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body  # type + 3-byte len
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


class ClientHelloParseTest(unittest.TestCase):
    def test_sni_extracted(self):
        result = sni.parse_client_hello(_client_hello("example.com"))
        self.assertIsNotNone(result)
        name, ech = result
        self.assertEqual(name, "example.com")
        self.assertFalse(ech)

    def test_ech_flagged(self):
        result = sni.parse_client_hello(_client_hello(host=None, ech=True))
        self.assertIsNotNone(result)
        name, ech = result
        self.assertIsNone(name)
        self.assertTrue(ech)

    def test_non_tls_returns_none(self):
        self.assertIsNone(sni.parse_client_hello(b"GET / HTTP/1.1\r\n"))

    def test_truncated_safe(self):
        self.assertIsNone(sni.parse_client_hello(b"\x16\x03\x01\x00"))


class FrameParseTest(unittest.TestCase):
    def _ipv4_tcp_frame(self, dst_ip, dst_port, payload):
        import socket as s
        eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
        # IPv4 header (20 bytes, IHL=5)
        ip = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0]) + b"\x0a\x00\x00\x01" + s.inet_aton(dst_ip)
        # TCP header (20 bytes, data offset=5)
        tcp = struct.pack("!HH", 12345, dst_port) + b"\x00" * 8 + bytes([0x50, 0x18, 0, 0, 0, 0, 0, 0])
        return eth + ip + tcp + payload

    def test_frame_with_sni(self):
        frame = self._ipv4_tcp_frame("93.184.216.34", 443, _client_hello("host.example"))
        ev = sni._parse_frame(frame, {443, 853})
        self.assertIsNotNone(ev)
        self.assertEqual(ev.dst_ip, "93.184.216.34")
        self.assertEqual(ev.sni, "host.example")

    def test_frame_wrong_port_ignored(self):
        frame = self._ipv4_tcp_frame("93.184.216.34", 8080, _client_hello("host.example"))
        self.assertIsNone(sni._parse_frame(frame, {443, 853}))


if __name__ == "__main__":
    unittest.main()
