"""Regression tests for the parsing, injection, cache and privilege findings.

SEC-009/027  SNI IP->name caches are hard-bounded, not TTL-pruned only
SEC-012      DNS varlink receive buffer is capped
SEC-013      a deeply nested JSON payload cannot kill the DNS thread
SEC-015      zabbix_sender batch fields are escaped
SEC-021      markdown outputs neutralise HTML and table framing
SEC-025      the ACL grants the account the collector actually runs as
SEC-028      event-log XML rejects DTD / entity declarations
"""

import os
import tempfile
import unittest
from unittest import mock

from commatrix import dns, report as rp, sni, zabbix
from commatrix.platform.win import perms, winetw
from commatrix.store import EdgeObservation, Store


class IpNameCacheBoundTest(unittest.TestCase):
    """SEC-009 / SEC-027."""

    def test_cache_is_bounded_even_when_nothing_has_expired(self):
        cache = dns.IpNameCache(max_entries=100, ttl=900.0)
        now = 1000.0
        for i in range(5000):
            # Every entry is fresh, so TTL pruning alone would free nothing.
            cache.put(f"10.1.{i // 256}.{i % 256}", f"h{i}.example", now)
        self.assertLessEqual(len(cache), 100)

    def test_expired_entries_are_dropped(self):
        cache = dns.IpNameCache(max_entries=100, ttl=10.0)
        cache.put("10.0.0.1", "old.example", 1000.0)
        self.assertEqual(cache.get("10.0.0.1", 1005.0), "old.example")
        self.assertIsNone(cache.get("10.0.0.1", 1020.0))

    def test_sni_monitor_cache_is_bounded(self):
        mon = sni.SniMonitor()
        mon._ip_names = dns.IpNameCache(max_entries=50, ttl=900.0)
        for i in range(2000):
            mon._record(sni.SniEvent(
                ts=1000.0, dst_ip=f"10.2.{i // 256}.{i % 256}",
                dst_port=443, sni=f"s{i}.example",
            ))
        self.assertLessEqual(len(mon._ip_names), 50)


class DnsBufferAndDepthTest(unittest.TestCase):
    """SEC-012 / SEC-013."""

    def test_deeply_nested_payload_is_rejected_without_raising(self):
        mon = dns.DnsMonitor(path="/nonexistent")
        bomb = b"[" * 200000 + b"]" * 200000
        mon._handle_message(bomb)  # must not raise RecursionError
        self.assertEqual(mon.malformed_messages, 1)
        self.assertEqual(mon.drain(), [])

    def test_depth_probe_ignores_brackets_inside_strings(self):
        payload = b'{"qname": "[[[[[[[[[["}'
        self.assertFalse(dns._exceeds_depth(payload, 5))

    def test_depth_probe_flags_real_nesting(self):
        self.assertTrue(dns._exceeds_depth(b"[" * 50, 10))

    def test_buffer_cap_exists_and_is_sane(self):
        self.assertLessEqual(dns.MAX_MESSAGE_BYTES, 4 << 20)

    def test_unterminated_stream_drops_the_connection(self):
        # NOTE: against the pre-fix code this test does not fail, it hangs --
        # which is precisely SEC-012. Do not run it under a reverted dns.py
        # without a timeout.
        mon = dns.DnsMonitor(path="/nonexistent")
        mon._backoff = 0.0

        class _Sock:
            def __init__(self):
                self.closed = False
                self.sent = []

            def settimeout(self, _t):
                pass

            def connect(self, _p):
                pass

            def sendall(self, data):
                self.sent.append(data)

            def recv(self, _n):
                # Never a NUL: the old code buffered this forever.
                return b"x" * 65536

            def close(self):
                self.closed = True

        sock = _Sock()
        with mock.patch("commatrix.dns.socket.socket", return_value=sock):
            mon._run_once()
        self.assertEqual(mon.oversize_resets, 1)
        self.assertTrue(sock.closed)


class ZabbixSenderEscapingTest(unittest.TestCase):
    """SEC-015."""

    def test_quote_escapes_quotes_and_backslashes(self):
        self.assertEqual(zabbix._sender_quote('a"b'), '"a\\"b"')
        self.assertEqual(zabbix._sender_quote("a\\b"), '"a\\\\b"')

    def test_newlines_cannot_inject_extra_items(self):
        payload = zabbix._sender_quote('x"\nother.host" "evil.key" "1')
        self.assertNotIn("\n", payload)
        self.assertEqual(payload.count('"'), 2 + payload.count('\\"'))

    def test_batch_payload_has_one_line_per_item(self):
        captured = {}

        def _fake_run(cmd, **kwargs):
            captured["input"] = kwargs.get("input")
            return mock.Mock(returncode=0)

        with mock.patch("commatrix.zabbix.shutil.which", return_value="/bin/true"), \
             mock.patch("commatrix.zabbix.subprocess.run", _fake_run):
            zabbix.send_via_sender(
                "srv", "host1",
                {"k1": 'v"\ninjected.host" "k2" "9'},
            )
        self.assertEqual(len([l for l in captured["input"].splitlines() if l]), 1)


class MarkdownNeutralisationTest(unittest.TestCase):
    """SEC-021."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.tmp, "c.db"))
        self.addCleanup(self.store.close)
        self.store.upsert_host("web01", {"hostname": "web01"})
        self.store.record_edge("web01", EdgeObservation(
            proto="tcp", direction="inbound", local_ip="10.0.0.10",
            peer_ip="203.0.113.9", service_port=443, peer_class="external",
            snapshot_bytes=10, snapshot_packets=1, service_side="local",
            service_name="https", l7_protocol="http",
            peer_name='<img src=x onerror=alert(1)>',
            peer_domain="a|b",
            process_comm="ngi\nnx",
        ), now=100.0)

    def test_matrix_markdown_has_no_raw_html(self):
        text = rp.matrix_markdown(self.store)
        self.assertNotIn("<img", text)
        self.assertIn("&lt;img", text)

    def test_matrix_markdown_keeps_table_framing(self):
        text = rp.matrix_markdown(self.store)
        body = [l for l in text.splitlines() if l.startswith("| web01")]
        self.assertEqual(len(body), 1, "a newline in a field must not split the row")
        self.assertNotIn("| a|b |", body[0])

    def test_security_markdown_has_no_raw_html(self):
        text = rp.security_markdown(self.store)
        self.assertNotIn("<img", text)

    def test_service_sheets_has_no_raw_html(self):
        text = rp.service_sheets(self.store)
        self.assertNotIn("<img", text)

    def test_md_cell_escapes_pipes(self):
        self.assertEqual(rp._md_cell("a|b"), "a\\|b")


class WindowsAclTest(unittest.TestCase):
    """SEC-025."""

    def test_service_account_is_granted(self):
        self.assertIn("commatrix", perms._principals())

    def test_restrict_grants_service_account_after_the_reset(self):
        calls = []

        def _fake_run(args, **kwargs):
            calls.append(list(args))
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("commatrix.platform.win.perms.subprocess.run", _fake_run):
            perms.restrict(r"C:\ProgramData\commatrix\commatrix.db")

        self.assertIn("/inheritance:r", calls[0])
        granted = " ".join(" ".join(c) for c in calls)
        self.assertIn("SYSTEM:F", granted)
        self.assertIn("Administrators:F", granted)
        self.assertIn(
            "commatrix:F", granted,
            "the account the collector runs as must keep access to its own DB",
        )

    def test_directory_grants_use_inheritance_flags(self):
        calls = []

        def _fake_run(args, **kwargs):
            calls.append(list(args))
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("commatrix.platform.win.perms.subprocess.run", _fake_run):
            perms.restrict(r"C:\ProgramData\commatrix", is_dir=True)
        granted = " ".join(" ".join(c) for c in calls)
        self.assertIn("commatrix:(OI)(CI)F", granted)


class EventXmlHardeningTest(unittest.TestCase):
    """SEC-028."""

    def test_safe_parser_rejects_doctype_and_entities(self):
        """The hardened parser refuses an internal DTD outright.

        xml.etree happily expands internally declared entities -- that is the
        whole mechanism behind a billion-laughs bomb -- so the guard has to be
        on the parser, not on the shape of the document we happen to wrap.
        """

        from xml.etree import ElementTree

        doc = '<!DOCTYPE r [<!ENTITY a "EXPANDED">]><r><v>&a;</v></r>'
        # Baseline: the stdlib parser does expand it.
        self.assertEqual(ElementTree.fromstring(doc).find("v").text, "EXPANDED")
        with self.assertRaises(winetw.XmlSecurityError):
            winetw._reject_dtd(doc)

    def test_escaped_text_is_not_mistaken_for_a_declaration(self):
        good = (
            '<Event><System><EventRecordID>4</EventRecordID></System>'
            '<EventData><Data Name="QueryName">'
            '&lt;!DOCTYPE-lookalike.example</Data></EventData></Event>'
        )
        self.assertEqual(
            [e.qname for e in winetw.parse_dns_events(good)],
            ["<!DOCTYPE-lookalike.example"],
        )

    def test_doctype_in_an_event_batch_yields_nothing(self):
        bomb = (
            '<!DOCTYPE lolz [<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>'
            '<Event><EventData><Data Name="QueryName">&lol2;</Data>'
            "</EventData></Event>"
        )
        self.assertEqual(winetw.parse_dns_events(bomb), [])

    def test_normal_event_still_parses(self):
        good = (
            '<Event><System><EventRecordID>3</EventRecordID></System>'
            '<EventData><Data Name="QueryName">ok.example</Data>'
            '<Data Name="QueryResults">1.2.3.4;</Data></EventData></Event>'
        )
        events = winetw.parse_dns_events(good)
        self.assertEqual([e.qname for e in events], ["ok.example"])

    def test_oversize_document_is_discarded(self):
        huge = "<Event/>" * 8
        with mock.patch.object(winetw, "MAX_XML_BYTES", 4):
            self.assertEqual(winetw.parse_dns_events(huge), [])


if __name__ == "__main__":
    unittest.main()
