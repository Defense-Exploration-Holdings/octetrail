"""H.225.0 call signaling parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import time
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, UnpackError, h225

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("h225_fixture", ROOT / "tools/h225_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {name: bytes.fromhex(wire) for name, wire in F.cases().items()}


class H225Tests(unittest.TestCase):
    def test_dpkt_setup_vector(self):
        packet = h225.H225(CASES["dpkt_setup"])
        self.assertIsInstance(packet, Packet)
        self.assertEqual((packet.tpkt.v, packet.tpkt.len, packet.proto), (3, 1041, 8))
        self.assertEqual(packet.type, h225.SETUP)
        self.assertEqual(
            [(ie.type, ie.len) for ie in packet.data],
            [(h225.BEARER_CAPABILITY, 3), (h225.DISPLAY, 14), (h225.USER_TO_USER, 1008)],
        )
        self.assertEqual(bytes(packet), CASES["dpkt_setup"])
        self.assertEqual(len(packet), 1038)  # dpkt leaves out the reference and type.

    def test_element_forms(self):
        packet = h225.H225(CASES["mixed"])
        self.assertEqual(
            [(ie.type, ie.len, ie.data) for ie in packet.data],
            [
                (4, 3, b"\x88\x93\xa5"),
                (0xA1, 0, b""),
                (126, 2, b"hi"),
                (40, 1, b"x"),
                (0x80, 0, b""),
            ],
        )
        self.assertEqual(bytes(packet), CASES["mixed"])
        self.assertEqual(h225.H225(CASES["length_past_end"]).data[0].data, b"Jon")

    def test_errors(self):
        for name, text in (
            ("tpkt_version0", "invalid TPKT version"),
            ("tpkt_rsvd", "invalid TPKT reserved value"),
            ("tpkt_len", "invalid TPKT length"),
        ):
            with self.subTest(name=name), self.assertRaisesRegex(UnpackError, "^" + text + "$"):
                h225.H225(CASES[name])
        with self.assertRaises(UnpackError) as caught:
            h225.H225(CASES["length_cut"])
        self.assertEqual(str(caught.exception), "invalid IE: b'('")
        with self.assertRaises(NeedData):
            h225.H225(CASES["tpkt_short"])

    def test_many_elements_parse_in_linear_time(self):
        def best(n):
            raw = F.message(b"\xa1" * n)
            times = []
            for _ in range(3):
                start = time.perf_counter()
                self.assertEqual(len(h225.H225(raw).data), n)
                times.append(time.perf_counter() - start)
            return min(times)

        self.assertLess(best(64000), 80 * best(4000))


if __name__ == "__main__":
    unittest.main()
