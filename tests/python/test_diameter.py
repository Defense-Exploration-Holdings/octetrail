"""Diameter messages parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import time
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, UnpackError, diameter

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "diameter_fixture", ROOT / "tools/diameter_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {name: bytes.fromhex(wire) for name, wire in F.cases().items()}


class DiameterTests(unittest.TestCase):
    def test_dpkt_vectors(self):
        for name, length in (("dpkt_s", 40), ("dpkt_t", 44)):
            with self.subTest(name=name):
                message = diameter.Diameter(CASES[name])
                self.assertIsInstance(message, Packet)
                self.assertEqual((message.len, message.cmd, message.request_flag), (length, 280, 1))
                self.assertEqual(len(message.avps), 2)
                self.assertEqual(message.avps[0].data, b"h002")
                self.assertEqual(bytes(message), CASES[name])
                self.assertEqual(len(message), length)
        self.assertEqual(diameter.Diameter(CASES["dpkt_t"]).avps[0].vendor, 0xDEADBEEF)

    def test_length_below_header_reads_to_the_end(self):
        message = diameter.Diameter(CASES["avp_len_zero"])
        self.assertEqual(message.avps[0].data, b"abcd")
        self.assertEqual(len(message.avps), 2)

    def test_errors(self):
        with self.assertRaisesRegex(NeedData, "^got 3, 8 needed at least$"):
            diameter.Diameter(CASES["avp_header_cut"])
        with self.assertRaisesRegex(UnpackError, "^invalid AVP: "):
            diameter.Diameter(CASES["avp_vendor_cut"])

    def test_bytearray(self):
        message = diameter.Diameter(bytearray(CASES["host_vendor"]))
        self.assertIsInstance(message.avps[1].data, bytearray)

    def test_many_avps_parse_in_linear_time(self):
        count = 60000
        raw = F.diameter(F.avp(7, 0, 8, b"") * count)
        started = time.perf_counter()
        message = diameter.Diameter(raw)
        self.assertEqual(len(message.avps), count)
        self.assertLess(time.perf_counter() - started, 5)

    def test_build(self):
        avp = diameter.AVP(code=264, flags=0x40, len=12, data=b"h002")
        message = diameter.Diameter(len=32, cmd=280, flags=0x80, data=[avp])
        header = bytes.fromhex("0100002080000118") + bytes(12)
        self.assertEqual(bytes(message), header + CASES["dpkt_s"][20:32])
        # Packing leaves the 24-bit fields as ints, so a message packs twice.
        self.assertEqual((message.len, message.cmd, avp.len), (32, 280, 12))
        self.assertEqual(bytes(message), header + CASES["dpkt_s"][20:32])

    def test_zero_lengths_are_filled_on_pack(self):
        avp = diameter.AVP(code=264, flags=0x40, data=b"h002")
        message = diameter.Diameter(cmd=280, flags=0x80, data=[avp])
        header = bytes.fromhex("0100002080000118") + bytes(12)
        self.assertEqual(bytes(message), header + CASES["dpkt_s"][20:32])
        self.assertEqual((message.len, avp.len), (32, 12))
        vendor = diameter.AVP(code=1, flags=0x80, vendor=7, data=b"ab")
        self.assertEqual(bytes(vendor)[5:8], b"\0\0\x0e")


if __name__ == "__main__":
    unittest.main()
