"""Tests for the Windows platform backend parsers (run on any OS).

Only the pure parsing/decoding logic is exercised; the ctypes/winreg/subprocess
calls are Windows-only and covered by integration on a Windows host.
"""

import socket
import struct
import unittest

from commatrix import platform as plat
from commatrix.platform.win import iphlp, wintime, windoh, winetw
from commatrix import sni


def _port_dw(port):
    # Inverse of iphlp._decode_port: low 2 bytes are the port in network order.
    return (port >> 8) | ((port & 0xFF) << 8)


class IphlpParseTest(unittest.TestCase):
    def test_decode_port_v4(self):
        self.assertEqual(iphlp._decode_port(_port_dw(44321)), 44321)
        self.assertEqual(iphlp._decode_v4(struct.unpack("<L", socket.inet_aton("10.0.0.5"))[0]), "10.0.0.5")

    def test_parse_tcp_table_v4(self):
        laddr = struct.unpack("<L", socket.inet_aton("10.0.0.5"))[0]
        raddr = struct.unpack("<L", socket.inet_aton("93.184.216.34"))[0]
        row = struct.pack("<IIIIII", 5, laddr, _port_dw(50000), raddr, _port_dw(443), 4242)
        buf = struct.pack("<I", 1) + row
        conns = iphlp.parse_tcp_table_v4(buf)
        self.assertEqual(len(conns), 1)
        c = conns[0]
        self.assertEqual(c.local_ip, "10.0.0.5")
        self.assertEqual(c.remote_ip, "93.184.216.34")
        self.assertEqual(c.remote_port, 443)
        self.assertEqual(c.state, "ESTABLISHED")
        self.assertEqual(c.pid, 4242)
        self.assertFalse(c.is_listening)

    def test_listening_state(self):
        row = struct.pack("<IIIIII", 2, 0, _port_dw(3389), 0, 0, 100)
        conns = iphlp.parse_tcp_table_v4(struct.pack("<I", 1) + row)
        self.assertTrue(conns[0].is_listening)


class WinTimeParseTest(unittest.TestCase):
    def test_parse_status(self):
        text = (
            "Leap Indicator: 0(no warning)\n"
            "Stratum: 3 (secondary reference)\n"
            "Source: time.windows.com,0x8\n"
            "Phase Offset: -0.0123456s\n"
        )
        st = wintime.parse_w32tm_status(text)
        self.assertEqual(st["source"], "time.windows.com,0x8")
        self.assertAlmostEqual(st["offset_seconds"], -0.0123456, places=6)
        self.assertTrue(st["synchronized"])

    def test_local_cmos_not_synced(self):
        st = wintime.parse_w32tm_status("Source: Local CMOS Clock\nLeap Indicator: 0\n")
        self.assertFalse(st["synchronized"])


class WinDohTest(unittest.TestCase):
    def test_chrome_enforced_off(self):
        values = {(r"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode"): "off"}
        posture = windoh.doh_posture(read=lambda sk, n: values.get((sk, n)))
        chrome = [f for f in posture["findings"] if f["source"] == "chrome"][0]
        self.assertEqual(chrome["status"], "enforced-off")
        self.assertTrue(posture["doh_enforced_off"])

    def test_chrome_on_flagged(self):
        values = {(r"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode"): "automatic"}
        posture = windoh.doh_posture(read=lambda sk, n: values.get((sk, n)))
        self.assertTrue(posture["doh_enabled_anywhere"])


class WinDnsParseTest(unittest.TestCase):
    def test_parse_dns_events(self):
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>3008</EventID></System>"
            "<EventData>"
            "<Data Name='QueryName'>example.com</Data>"
            "<Data Name='QueryType'>1</Data>"
            "<Data Name='QueryResults'>::ffff:93.184.216.34;</Data>"
            "</EventData></Event>"
        )
        events = winetw.parse_dns_events(xml)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].qname, "example.com")
        self.assertEqual(events[0].qtype, "A")
        self.assertIn("93.184.216.34", events[0].answers)


class WinSniIpLayerTest(unittest.TestCase):
    def _client_hello(self, host):
        hb = host.encode("ascii")
        entry = b"\x00" + struct.pack("!H", len(hb)) + hb
        snl = struct.pack("!H", len(entry)) + entry
        ext = struct.pack("!HH", 0x0000, len(snl)) + snl
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
        hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
        return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

    def test_parse_ip_packet_v4(self):
        ip = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0]) + b"\x0a\x00\x00\x01" + socket.inet_aton("93.184.216.34")
        tcp = struct.pack("!HH", 12345, 443) + b"\x00" * 8 + bytes([0x50, 0x18, 0, 0, 0, 0, 0, 0])
        pkt = ip + tcp + self._client_hello("win.example")
        ev = sni.parse_ip_packet(pkt, {443, 853})
        self.assertIsNotNone(ev)
        self.assertEqual(ev.dst_ip, "93.184.216.34")
        self.assertEqual(ev.sni, "win.example")


class PlatformDispatchTest(unittest.TestCase):
    def test_flags_and_helpers(self):
        self.assertIn(True, (plat.IS_LINUX, plat.IS_WINDOWS, not plat.IS_LINUX))
        self.assertIsInstance(plat.running_as_service(), bool)
        self.assertIsInstance(plat.is_privileged(), bool)

    def test_win_available_false_on_linux(self):
        if not plat.IS_WINDOWS:
            self.assertFalse(iphlp.available())
            self.assertFalse(winetw.available())


if __name__ == "__main__":
    unittest.main()
