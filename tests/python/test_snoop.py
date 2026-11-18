"""Snoop capture files read and written the way dpkt 1.9.8 does."""

import importlib.util
import io
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, UnpackError, snoop

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("snoop_fixture", ROOT / "tools/snoop_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
FILES = {name: bytes.fromhex(wire) for name, wire in F.files().items()}


class _Recorder(io.BytesIO):
    def __init__(self, raw):
        super().__init__(raw)
        self.sizes = []

    def read(self, size=-1):
        self.sizes.append(size)
        return super().read(size)


class SnoopTests(unittest.TestCase):
    def test_round_trip(self):
        out = io.BytesIO()
        writer = snoop.Writer(out)
        writer.writepkt(b"abcde", ts=100.25)
        writer.writepkts([(2.5, b"x" * 8)])
        raw = out.getvalue()
        self.assertEqual(len(raw), 16 + 24 + 8 + 24 + 8)
        reader = snoop.Reader(io.BytesIO(raw))
        self.assertEqual((reader.datalink(), reader.dloff), (snoop.SDL_ETHER, 14))
        self.assertEqual(reader.readpkts(), [(100.25, b"abcde"), (2.5, b"x" * 8)])

    def test_headers_use_the_packet_base(self):
        header = snoop.PktHdr(FILES["one"][16:])
        self.assertIsInstance(header, Packet)
        self.assertEqual((header.incl_len, header.rec_len, header.ts_sec), (5, 32, 100))
        self.assertEqual(bytes(snoop.FileHdr()), F.file_header())

    def test_microseconds_round_up_like_dpkt(self):
        out = io.BytesIO()
        snoop.Writer(out).writepkt(b"a", ts=1.9999999)
        header = snoop.PktHdr(out.getvalue()[16:40])
        self.assertEqual((header.ts_sec, header.ts_usec), (1, 1000000))

    def test_short_files_need_data(self):
        for name in ("empty", "header_short"):
            with self.subTest(name=name), self.assertRaises(NeedData):
                snoop.Reader(io.BytesIO(FILES[name]))
        with self.assertRaises(NeedData):
            snoop.Reader(io.BytesIO(FILES["record_cut"])).readpkts()

    def test_bad_magic_is_both_errors(self):
        with self.assertRaises(snoop.HeaderError) as caught:
            snoop.Reader(io.BytesIO(FILES["bad_magic"]))
        self.assertIsInstance(caught.exception, UnpackError)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertEqual(str(caught.exception), "invalid snoop header")

    def test_unknown_linktype_is_both_errors(self):
        with self.assertRaises(snoop.LinktypeError) as caught:
            snoop.Reader(io.BytesIO(FILES["linktype_fddi"]))
        self.assertIsInstance(caught.exception, UnpackError)
        self.assertIsInstance(caught.exception, KeyError)
        self.assertEqual((str(caught.exception), caught.exception.args), ("8", (8,)))

    def test_huge_record_length_reads_in_bounded_pieces(self):
        source = _Recorder(FILES["rec_huge"])
        self.assertEqual(snoop.Reader(source).readpkts(), [(1.0, b"abcd")])
        self.assertLessEqual(max(source.sizes), 1 << 20)

    def test_short_record_length_reads_the_rest_like_dpkt(self):
        packets = snoop.Reader(io.BytesIO(FILES["rec_short"])).readpkts()
        self.assertEqual(packets, [(1.0, b"abcd")])


if __name__ == "__main__":
    unittest.main()
