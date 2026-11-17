"""Telnet option stripping on dpkt's vectors and generated buffers."""

import importlib.util
import time
import unittest
from pathlib import Path

import octetrail
from octetrail import telnet

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "telnet_fixture", ROOT / "tools/telnet_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class TelnetTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(F.cases()))
        for name, found in report["cases"].items():
            self.assertNotIn("error", found, name)

    def test_dpkt_vectors(self):
        lines, options = telnet.strip_options(bytes.fromhex(F.DPKT[0]))
        self.assertEqual(lines, [b"fugly", b"yoda", b"bashtard"])
        self.assertEqual(options, {b"USER": b"dugsong", b"DISPLAY": b"doughboy.citi.umich.edu:0.0"})
        self.assertEqual(
            telnet.strip_options(bytes.fromhex("0100020000")), ([b"\x01", b"\x02"], {})
        )

    def test_types_follow_the_input(self):
        lines, _ = telnet.strip_options(bytearray(b"a\r\nb"))
        self.assertEqual([type(x) for x in lines], [bytearray, bytearray])
        with self.assertRaises(AttributeError):
            telnet.strip_options(memoryview(b"a"))

    def test_linear_time(self):
        buf = (b"\xff\xfa\x18USER\x01x\x00\xff\xf0line\r\x00") * 50000
        start = time.perf_counter()
        lines, options = telnet.strip_options(buf)
        self.assertEqual((len(lines), options), (50000, {b"USER": b"x"}))
        self.assertLess(time.perf_counter() - start, 5)


if __name__ == "__main__":
    unittest.main()
