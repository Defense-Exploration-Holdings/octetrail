"""SIP requests and responses parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, UnpackError, http, sip

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sip_fixture", ROOT / "tools/sip_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class SipTests(unittest.TestCase):
    def test_invite(self):
        r = sip.Request(F.INVITE)
        self.assertEqual((r.method, r.uri, r.version), ("INVITE", "sip:bob@biloxi.example", "2.0"))
        self.assertEqual(len(r.headers["via"]), 2)
        self.assertEqual(r.headers["cseq"], "314159 INVITE")
        self.assertEqual((r.body, r.data), (b"v=0\r\no=alice\r\n", b""))
        self.assertIsInstance(r, http.Request)
        self.assertIsInstance(r, Packet)

    def test_response(self):
        r = sip.Response(F.OK)
        self.assertEqual((r.version, r.status, r.reason), ("2.0", "200", "OK"))
        self.assertEqual((r.body, r.data), (b"v=0\n", b"NEXT"))
        self.assertTrue(bytes(r).startswith(b"SIP/2.0 200 OK\r\n"))

    def test_defaults(self):
        self.assertEqual(
            bytes(sip.Request()),
            b"INVITE sip:user@example.com SIP/2.0\r\n"
            b"To: \r\nFrom: \r\nCall-ID: \r\nCSeq: \r\nContact: \r\n\r\n",
        )
        self.assertTrue(bytes(sip.Response()).startswith(b"SIP/2.0 200 OK\r\nTo: \r\n"))

    def test_only_sip_methods_and_protocol(self):
        for raw in (
            b"GET / SIP/2.0\r\n\r\n",
            b"INVITE sip:x HTTP/1.1\r\n\r\n",
            b"invite sip:x SIP/2.0\r\n\r\n",
        ):
            with self.assertRaises(UnpackError):
                sip.Request(raw)
        with self.assertRaises(UnpackError):
            sip.Response(b"HTTP/1.1 200 OK\r\n\r\n")
        with self.assertRaises(UnpackError):
            http.Request(F.INVITE)
        self.assertEqual(http.Request(b"GET / HTTP/1.1\r\n\r\n").method, "GET")

    def test_short_body(self):
        with self.assertRaises(NeedData) as caught:
            sip.Request(F.INVITE[:-2])
        self.assertEqual(str(caught.exception), "short body (missing 2 bytes)")

    def test_matches_dpkt_fixture_driver(self):
        self.assertEqual(len(F.cases()), 19)
        self.assertEqual(F.DECLARED, {})


if __name__ == "__main__":
    unittest.main()
