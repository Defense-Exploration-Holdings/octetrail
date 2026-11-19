"""Gzip headers parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, UnpackError, gzip

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("gzip_fixture", ROOT / "tools/gzip_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {name: bytes.fromhex(wire) for name, wire in F.cases().items()}


class GzipTests(unittest.TestCase):
    def test_dpkt_vector(self):
        packet = gzip.Gzip(CASES["dpkt_hello"])
        self.assertIsInstance(packet, Packet)
        self.assertEqual((packet.method, packet.flags), (gzip.GZIP_MDEFLATE, gzip.GZIP_FNAME))
        self.assertEqual((packet.mtime, packet.os), (0x5685C180, gzip.GZIP_OS_UNIX))
        self.assertEqual(packet.filename, "hello.txt")
        self.assertEqual(packet.decompress(), b"Hello world!\n")

    def test_optional_fields(self):
        packet = gzip.Gzip(CASES["extra"])
        self.assertEqual((packet.extra.id, packet.extra.len), (b"ID", 1))
        self.assertEqual(packet.data, b"\x01\x02")
        self.assertEqual(bytes(packet), CASES["extra"])
        self.assertEqual(gzip.Gzip(CASES["comment"]).comment, b"note")
        self.assertEqual(gzip.Gzip(CASES["encrypt"]).data, b"body")
        self.assertEqual(gzip.Gzip(CASES["hcrc"]).data, b"body")

    def test_errors(self):
        for name, text in (
            ("extra_cut", "Gzip extra"),
            ("name_unterminated", "Gzip end of file name not found"),
            ("comment_unterminated", "Gzip end of comment not found"),
            ("encrypt_short", "Gzip encrypt"),
            ("hcrc_short", "Gzip hcrc"),
        ):
            with self.subTest(name=name), self.assertRaisesRegex(NeedData, "^" + text + "$"):
                gzip.Gzip(CASES[name])

    def test_magic_and_method_are_checked(self):
        good = bytes(gzip.Gzip(data=b"x"))
        with self.assertRaisesRegex(UnpackError, "not a gzip member"):
            gzip.Gzip(b"PK" + good[2:])
        with self.assertRaisesRegex(UnpackError, "unsupported gzip method 0"):
            gzip.Gzip(good[:2] + b"\x00" + good[3:])

    def test_filename_not_utf8_is_both_errors(self):
        with self.assertRaises(gzip.FilenameDecodeError) as caught:
            gzip.Gzip(CASES["name_not_utf8"])
        self.assertIsInstance(caught.exception, UnpackError)
        self.assertIsInstance(caught.exception, UnicodeDecodeError)
        self.assertEqual(
            str(caught.exception),
            "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
        )

    def test_build_sets_flags(self):
        packet = gzip.Gzip(filename="a.txt", comment=b"c", data=b"x")
        raw = bytes(packet)
        self.assertEqual(packet.flags, gzip.GZIP_FNAME | gzip.GZIP_FCOMMENT)
        parsed = gzip.Gzip(raw)
        self.assertEqual((parsed.filename, parsed.comment, parsed.data), ("a.txt", b"c", b"x"))

    def test_compress_keeps_the_whole_stream(self):
        payload = bytes(range(256)) * 400
        packet = gzip.Gzip(data=payload)
        packet.compress()
        self.assertEqual(packet.decompress(), payload)


if __name__ == "__main__":
    unittest.main()
