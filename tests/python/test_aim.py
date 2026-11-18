"""AIM OSCAR frames parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, UnpackError, aim

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("aim_fixture", ROOT / "tools/aim_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
RAW = bytes.fromhex(F.DPKT_FLAP)


class AimTests(unittest.TestCase):
    def test_dpkt_vector(self):
        flap = aim.FLAP(RAW)
        self.assertIsInstance(flap, Packet)
        self.assertEqual((flap.ast, flap.type, flap.seq, flap.len), (0x2A, 2, 44275, 129))
        self.assertEqual(bytes(flap), RAW)
        snac = aim.SNAC(flap.data)
        self.assertEqual((snac.family, snac.subtype, snac.reqid), (3, 11, 0xFA455564))
        found = []
        rest = snac.data[19:]
        while rest:
            t, length, value, rest = aim.tlv(rest)
            found.append((t, length, value))
        self.assertEqual(len(found), 10)
        self.assertEqual(found[0], (1, 2, b"\x12\x90"))

    def test_flap_errors(self):
        with self.assertRaisesRegex(UnpackError, "^invalid FLAP header$"):
            aim.FLAP(b"xxxxxx")
        with self.assertRaisesRegex(NeedData, "^0 left, 255 needed$"):
            aim.FLAP(b"*\x02\x12\x34\x00\xff")
        with self.assertRaises(NeedData):
            aim.FLAP(b"*\x02")

    def test_flap_keeps_bytes_past_len(self):
        flap = aim.FLAP(F.flap(2, 7, b"abcd", 2))
        self.assertEqual(flap.data, b"abcd")

    def test_tlv(self):
        self.assertEqual(aim.tlv(b"\x00\x01\x00\x02\x12\x90rest"), (1, 2, b"\x12\x90", b"rest"))
        with self.assertRaisesRegex(UnpackError, "^invalid type, length fields$"):
            aim.tlv(b"x")
        with self.assertRaisesRegex(NeedData, "^2 left, 4 needed$"):
            aim.tlv(b"\x00\x01\x00\x04ab")

    def test_build(self):
        flap = aim.FLAP(type=2, seq=1, data=aim.SNAC(family=1, subtype=2, data=b"x"))
        self.assertEqual(
            bytes(flap), b"*\x02\x00\x01\x00\x00" + bytes.fromhex("00010002000000000000") + b"x"
        )


if __name__ == "__main__":
    unittest.main()
