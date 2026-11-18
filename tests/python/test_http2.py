"""HTTP/2 frames parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import time
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, UnpackError, http2

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("http2_fixture", ROOT / "tools/http2_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class Http2Tests(unittest.TestCase):
    def test_frames(self):
        settings = http2.FrameFactory(F.SETTINGS)
        self.assertIsInstance(settings, http2.SettingsFrame)
        self.assertIsInstance(settings, Packet)
        self.assertEqual(
            [(s.identifier, s.value) for s in settings.settings], [(3, 100), (4, 65536)]
        )
        headers = http2.FrameFactory(F.HEADERS)
        self.assertEqual(headers.block_fragment, b"\x82\x86\x84")
        padded = http2.FrameFactory(F.frame(0, b"\x02hi\x00\x00", flags=0x08))
        self.assertEqual(padded.payload, b"hi")

    def test_multi_factory(self):
        frames, used = http2.frame_multi_factory(F.PREFACE + F.STREAM, preface=True)
        self.assertEqual([type(f).__name__ for f in frames][:2], ["SettingsFrame", "HeadersFrame"])
        self.assertEqual(used, len(F.PREFACE + F.STREAM))
        frames, used = http2.frame_multi_factory(F.STREAM + F.frame(0, b"abc", length=9))
        self.assertEqual((len(frames), used), (4, len(F.STREAM)))
        self.assertEqual(http2.frame_multi_factory(F.PREFACE[:10], preface=True), ([], 0))

    def test_errors(self):
        with self.assertRaisesRegex(http2.HTTP2Exception, "^Invalid frame type: 0xa$"):
            http2.FrameFactory(F.frame(10, b"x"))
        with self.assertRaises(UnpackError):
            http2.frame_multi_factory(F.SETTINGS + F.frame(6, b"1234"))
        with self.assertRaises(NeedData):
            http2.FrameFactory(b"\x00\x00\x00")
        self.assertTrue(issubclass(http2.HTTP2Exception, UnpackError))

    def test_many_frames_parse_in_linear_time(self):
        count = 50000
        started = time.perf_counter()
        frames, used = http2.frame_multi_factory(F.frame(0, b"x") * count)
        self.assertEqual((len(frames), used), (count, count * 10))
        self.assertLess(time.perf_counter() - started, 5)


if __name__ == "__main__":
    unittest.main()
