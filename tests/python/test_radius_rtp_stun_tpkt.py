"""RADIUS, RTP, STUN and TPKT on dpkt's vectors and generated messages."""

import importlib.util
import struct
import time
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, UnpackError, radius, rtp, stun, tpkt

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "radius_rtp_stun_tpkt_fixture", ROOT / "tools/radius_rtp_stun_tpkt_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class RadiusRtpStunTpktTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("radius_two", "rtp_dpkt", "stun_dpkt_padded", "tpkt_cotp"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_radius_attributes(self):
        message = radius.RADIUS(CASES["radius_two"])
        self.assertEqual(message.attrs, [(1, b"user"), (2, b"password")])
        self.assertEqual(message.data, b"")
        self.assertEqual(radius.parse_attrs(b"\x01\x06user\x00\x00more"), [(1, b"user")])
        self.assertEqual(radius.parse_attrs(b"\x1a\xffvendor"), [(26, b"vendor")])
        view = radius.parse_attrs(memoryview(b"\x01\x04ab"))[0][1]
        self.assertIsInstance(view, memoryview)

    def test_radius_odd_byte_is_declared(self):
        for buf, message in (
            (b"\x01\x03a\x05", "index out of range"),
            (bytearray(b"\x05"), "bytearray index out of range"),
        ):
            with self.assertRaises(radius.ShortAttributeError) as caught:
                radius.parse_attrs(buf)
            self.assertIsInstance(caught.exception, UnpackError)
            self.assertIsInstance(caught.exception, IndexError)
            self.assertEqual(str(caught.exception), message)
        with self.assertRaises(IndexError):
            radius.RADIUS(CASES["radius_one_byte"])

    def test_radius_many_attributes_parse_in_linear_time(self):
        start = time.perf_counter()
        attrs = radius.parse_attrs(b"\x01\x02" * 200000)
        self.assertEqual(len(attrs), 200000)
        self.assertLess(time.perf_counter() - start, 5)

    def test_rtp_bits(self):
        packet = rtp.RTP(CASES["rtp_dpkt"])
        self.assertEqual((packet.version, packet.pt, packet.seq, packet.ts), (2, 8, 19713, 65760))
        self.assertEqual(len(packet), 172)
        self.assertEqual(bytes(packet), CASES["rtp_dpkt"])
        packet = rtp.RTP(CASES["rtp_csrc"])
        self.assertEqual((packet.cc, packet.csrc), (2, bytes(range(8))))
        built = rtp.RTP()
        for name in ("version", "p", "x", "cc", "m", "pt"):
            setattr(built, name, 1)
            self.assertEqual(getattr(built, name), 1)
        self.assertEqual(built._type, 0x7181)
        with self.assertRaises(NeedData):
            rtp.RTP(CASES["rtp_short"])

    def test_stun_attributes(self):
        message = stun.STUN(CASES["stun_dpkt_padded"])
        self.assertEqual((message.type, message.len), (stun.BINDING_REQUEST, 84))
        attrs = stun.parse_attrs(message.data)
        self.assertEqual(len(attrs), 6)
        self.assertEqual(attrs[0], (stun.USERNAME, b"pLyZHR:GwL3AHBovubLvCqn"))
        self.assertEqual(attrs[4][0], stun.MESSAGE_INTEGRITY)
        self.assertEqual(stun.tlv(b"\x00\x06\x00\x03abc\x00rest"), (6, 3, b"abc", b"rest"))
        self.assertEqual(stun.parse_attrs(b"\x00\x06\x00\x10short"), [(6, b"short")])

    def test_stun_short_header_is_declared(self):
        for action in (lambda: stun.parse_attrs(b"\x00\x01\x00\x00\x00"), lambda: stun.tlv(b"")):
            with self.assertRaises(stun.ShortAttributeError) as caught:
                action()
            self.assertIsInstance(caught.exception, UnpackError)
            self.assertIsInstance(caught.exception, struct.error)
            self.assertEqual(str(caught.exception), "unpack requires a buffer of 4 bytes")

    def test_tpkt(self):
        packet = tpkt.TPKT(CASES["tpkt_cotp"])
        self.assertEqual((packet.v, packet.len, packet.data), (3, 11, CASES["tpkt_cotp"][4:]))
        self.assertEqual(bytes(tpkt.TPKT(len=4)), b"\x03\x00\x00\x04")


if __name__ == "__main__":
    unittest.main()
