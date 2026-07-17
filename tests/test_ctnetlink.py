import socket
import struct
import unittest

from commatrix import ctnetlink as cn


def _attr(atype, data):
    length = 4 + len(data)
    pad = (-length) & 3
    return struct.pack("=HH", length, atype) + data + b"\x00" * pad


def _nested(atype, *children):
    return _attr(atype, b"".join(children))


def _build_ct_new(src="10.0.0.5", dst="93.184.216.34", sport=44321, dport=443,
                  proto=6, obytes=1000, opkts=8, rbytes=2000, rpkts=7, state=3):
    ip = _nested(cn.CTA_TUPLE_IP,
                 _attr(cn.CTA_IP_V4_SRC, socket.inet_aton(src)),
                 _attr(cn.CTA_IP_V4_DST, socket.inet_aton(dst)))
    pr = _nested(cn.CTA_TUPLE_PROTO,
                 _attr(cn.CTA_PROTO_NUM, bytes([proto])),
                 _attr(cn.CTA_PROTO_SRC_PORT, struct.pack("!H", sport)),
                 _attr(cn.CTA_PROTO_DST_PORT, struct.pack("!H", dport)))
    tuple_orig = _nested(cn.CTA_TUPLE_ORIG, ip, pr)
    counters = _nested(cn.CTA_COUNTERS_ORIG,
                       _attr(cn.CTA_COUNTERS_PACKETS, struct.pack("!Q", opkts)),
                       _attr(cn.CTA_COUNTERS_BYTES, struct.pack("!Q", obytes)))
    rcounters = _nested(cn.CTA_COUNTERS_REPLY,
                        _attr(cn.CTA_COUNTERS_PACKETS, struct.pack("!Q", rpkts)),
                        _attr(cn.CTA_COUNTERS_BYTES, struct.pack("!Q", rbytes)))
    protoinfo = _nested(cn.CTA_PROTOINFO,
                        _nested(cn.CTA_PROTOINFO_TCP,
                                _attr(cn.CTA_PROTOINFO_TCP_STATE, bytes([state]))))
    nfgen = struct.pack("=BBH", socket.AF_INET, 0, 0)
    return nfgen + tuple_orig + counters + rcounters + protoinfo


def _wrap_nlmsg(msgtype, body):
    total = 16 + len(body)
    hdr = struct.pack("=IHHII", total, msgtype, 0, 0, 0)
    blob = hdr + body
    return blob + b"\x00" * ((-len(blob)) & 3)


class ParseTest(unittest.TestCase):
    def test_parse_ct_new(self):
        body = _build_ct_new()
        e = cn.parse_ct_message(cn.IPCTNL_MSG_CT_NEW, body)
        self.assertIsNotNone(e)
        self.assertEqual(e.l4proto, "tcp")
        self.assertEqual(e.orig_src, "10.0.0.5")
        self.assertEqual(e.orig_dst, "93.184.216.34")
        self.assertEqual(e.orig_dport, 443)
        self.assertEqual(e.orig_bytes, 1000)
        self.assertEqual(e.reply_bytes, 2000)
        self.assertEqual(e.total_bytes, 3000)
        self.assertEqual(e.total_packets, 15)
        self.assertEqual(e.state, "ESTABLISHED")
        self.assertEqual(e.event, "NEW")

    def test_destroy_event(self):
        body = _build_ct_new()
        e = cn.parse_ct_message(cn.IPCTNL_MSG_CT_DELETE, body)
        self.assertEqual(e.event, "DESTROY")

    def test_parse_messages_wraps(self):
        msgtype = (cn.NFNL_SUBSYS_CTNETLINK << 8) | cn.IPCTNL_MSG_CT_NEW
        buf = _wrap_nlmsg(msgtype, _build_ct_new()) + _wrap_nlmsg(cn.NLMSG_DONE, b"\x00" * 4)
        entries = cn.parse_messages(buf)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].orig_dport, 443)

    def test_truncated_is_safe(self):
        self.assertIsNone(cn.parse_ct_message(cn.IPCTNL_MSG_CT_NEW, b"\x02"))


class ListenerBufferTest(unittest.TestCase):
    def test_active_and_destroyed_drain(self):
        lis = cn.ConntrackEventListener()
        from commatrix.conntrack import ConntrackEntry
        active = ConntrackEntry(l4proto="tcp", state="ESTABLISHED", orig_src="10.0.0.1",
                                orig_dst="10.0.0.2", orig_sport=1, orig_dport=443,
                                orig_bytes=10, orig_packets=1, reply_src=None, reply_dst=None,
                                reply_sport=None, reply_dport=None, reply_bytes=0,
                                reply_packets=0, event="NEW")
        lis._record(active)
        self.assertEqual(len(lis.drain()), 1)
        # active persists across drains
        self.assertEqual(len(lis.drain()), 1)
        destroyed = ConntrackEntry(l4proto="tcp", state="CLOSE", orig_src="10.0.0.1",
                                   orig_dst="10.0.0.2", orig_sport=1, orig_dport=443,
                                   orig_bytes=99, orig_packets=9, reply_src=None, reply_dst=None,
                                   reply_sport=None, reply_dport=None, reply_bytes=0,
                                   reply_packets=0, event="DESTROY")
        lis._record(destroyed)
        drained = lis.drain()
        self.assertTrue(any(e.orig_bytes == 99 for e in drained))
        # after destroy, no longer active
        self.assertEqual(lis.drain(), [])


if __name__ == "__main__":
    unittest.main()
