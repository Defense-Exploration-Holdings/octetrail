"""ASN.1 BER decoded the way dpkt 1.9.8 does."""

import importlib.util
import struct
import unittest
from pathlib import Path

import octetrail
from octetrail import UnpackError, asn1

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("asn1_fixture", ROOT / "tools/asn1_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {name: bytes.fromhex(wire) for name, wire in F.cases().items()}
NEST = b"\x30\x84\xff\xff\xff\xff"


class Asn1Tests(unittest.TestCase):
    def test_dpkt_ldap_vector(self):
        (top,) = asn1.decode(CASES["ldap"])
        self.assertEqual(top[0], 0x30)
        message_id, request = top[1]
        self.assertEqual(message_id, (asn1.INTEGER, 11))
        self.assertEqual(request[0], 0x63)
        self.assertEqual(request[1][-1][1][-1], (asn1.OCTET_STRING, b"createtimestamp"))

    def test_dpkt_quirks(self):
        # A constructed element holds everything to the end of the buffer.
        self.assertEqual(
            asn1.decode(CASES["constructed_runs_to_end"]),
            [(0x30, [(2, 5), (4, b"x")]), (4, b"x")],
        )
        self.assertEqual(asn1.decode(b"\x20\x80"), [(32, []), (32, [])])
        self.assertEqual(asn1.decode(CASES["int_3_reads_4"])[0], (2, 0x010203))

    def test_utctime(self):
        self.assertEqual(asn1.utctime("201005012345+1234"), 1601815785)
        self.assertEqual(asn1.utctime("201005012345-1234"), 1601906265)
        self.assertEqual(asn1.decode(CASES["dpkt_utc"]), [(23, 1601861025)])

    def test_slices_keep_the_buffer_type(self):
        found = asn1.decode(bytearray(CASES["set_of_strings"]))
        self.assertEqual(found, [(0x31, [(4, bytearray(b"a")), (4, bytearray(b"b"))])])
        self.assertIs(type(found[0][1][0][1]), bytearray)

    def test_builtin_errors_are_also_unpack_errors(self):
        for name, cls, base in (
            ("int_1_cut", asn1.ShortIndexError, IndexError),
            ("long_2_cut", asn1.ShortStructError, struct.error),
            ("utc_letters", asn1.TimeValueError, ValueError),
        ):
            with self.subTest(name=name), self.assertRaises(cls) as caught:
                asn1.decode(CASES[name])
            self.assertIsInstance(caught.exception, UnpackError)
            self.assertIsInstance(caught.exception, base)
        with self.assertRaisesRegex(UnpackError, "^excessive long-form ASN.1 length 133$"):
            asn1.decode(b"\x04\x85")

    def test_nesting_is_bounded(self):
        level = asn1.decode(NEST * asn1.MAX_DEPTH + b"\x04\x01a")
        for _ in range(asn1.MAX_DEPTH):
            ((t, level),) = level
            self.assertEqual(t, 0x30)
        self.assertEqual(level, [(4, b"a")])
        with self.assertRaises(asn1.NestingError) as caught:
            asn1.decode(NEST * (asn1.MAX_DEPTH + 1))
        self.assertIsInstance(caught.exception, UnpackError)
        self.assertIsInstance(caught.exception, RecursionError)
        self.assertIs(asn1.NestingError, octetrail.NestingError)

    def test_exponential_output_is_bounded(self):
        # dpkt would build 2**40 elements here.
        with self.assertRaises(asn1.ParseLimitError) as caught:
            asn1.decode(b"\x30\x00" * 40)
        self.assertIsInstance(caught.exception, UnpackError)
        self.assertIsInstance(caught.exception, asn1.LimitError)
        self.assertEqual(len(asn1.decode(b"\x30\x00" * 12)), 12)


if __name__ == "__main__":
    unittest.main()
