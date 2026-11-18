"""IEEE 802.11 and radiotap frames parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import unittest
from pathlib import Path

from octetrail import Packet, UnpackError, ieee80211, radiotap

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "ieee80211_fixture", ROOT / "tools/ieee80211_radiotap_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {name: bytes.fromhex(wire) for name, (_target, wire) in F.cases().items()}


class Ieee80211Tests(unittest.TestCase):
    def test_dpkt_beacon(self):
        frame = ieee80211.IEEE80211(bytes.fromhex(F.DPKT["ieee80211.80211_beacon.0"]))
        self.assertIsInstance(frame, Packet)
        self.assertEqual((frame.type, frame.subtype), (ieee80211.MGMT_TYPE, ieee80211.M_BEACON))
        self.assertEqual(frame.mgmt.src, bytes.fromhex("0026cb186a30"))
        self.assertEqual(frame.beacon.interval, 102)
        self.assertEqual(frame.ssid.info, b"CAEN")
        self.assertEqual(len(frame.ies), 20)
        self.assertEqual(frame.capability.privacy, 1)

    def test_probe_request_ies(self):
        frame = ieee80211.IEEE80211(CASES["probe_req"])
        self.assertEqual([(ie.id, ie.len) for ie in frame.ies], [(0, 4), (1, 2), (221, 1)])
        self.assertEqual(frame.ssid.info, b"note")
        self.assertEqual(frame.ie_221.data, b"x")

    def test_ie_walk_stops_at_last_four_bytes(self):
        frame = ieee80211.IEEE80211(CASES["probe_req_tail_four"])
        self.assertEqual([ie.id for ie in frame.ies], [0])

    def test_fcs(self):
        frame = ieee80211.IEEE80211(CASES["fcs_frame"], fcs=True)
        self.assertTrue(frame.fcs_present)
        self.assertEqual(frame.fcs, 0x04030201)
        self.assertEqual(frame.ack.dst, F.MAC)

    def test_unknown_subtype_is_unpack_error(self):
        with self.assertRaisesRegex(UnpackError, "KeyError: type=1 subtype=10"):
            ieee80211.IEEE80211(CASES["ctl_ps_poll"])

    def test_bit_fields(self):
        frame = ieee80211.IEEE80211(framectl=0)
        frame.type, frame.subtype, frame.to_ds = ieee80211.DATA_TYPE, ieee80211.D_QOS_DATA, 1
        self.assertEqual(frame.framectl, 0x8801)


class RadiotapTests(unittest.TestCase):
    def test_fields_and_frame(self):
        packet = radiotap.Radiotap(CASES["rt_fields"])
        self.assertIsInstance(packet, Packet)
        names = [type(field).__name__ for field in packet.fields]
        self.assertEqual(names, ["TSFT", "Flags", "Rate", "Channel", "AntennaSignal", "RxFlags"])
        self.assertIsInstance(packet.data, ieee80211.IEEE80211)

    def test_aligned_field_values(self):
        packet = radiotap.Radiotap(CASES["rt_fields_aligned"])
        names = [type(field).__name__ for field in packet.fields]
        self.assertEqual(names, ["TSFT", "Flags", "Rate", "Channel", "AntennaSignal", "RxFlags"])
        self.assertEqual((packet.tsft.usecs, packet.flags.val, packet.flags.fcs), (1, 0x10, 1))
        self.assertIsInstance(packet.data, ieee80211.IEEE80211)

    def test_extended_present_words(self):
        packet = radiotap.Radiotap(CASES["rt_ext"])
        self.assertEqual(bytes(packet.present_flags), bytes.fromhex("0200008000000000"))

    def test_short_present_is_both_errors(self):
        for name in ("rt_ext_short", "rt_present_short"):
            with self.subTest(name=name):
                with self.assertRaises(radiotap.PresentFlagsError) as caught:
                    radiotap.Radiotap(CASES[name])
                self.assertIsInstance(caught.exception, UnpackError)
                self.assertIsInstance(caught.exception, IndexError)
                self.assertEqual(str(caught.exception), "bytearray index out of range")

    def test_long_present_chain_is_linear(self):
        words = b"\x00\x00\x00\x80" * 10000 + b"\x00\x00\x00\x00"
        packet = radiotap.Radiotap(bytes([0, 0]) + (4 + len(words)).to_bytes(2, "little") + words)
        self.assertEqual(len(packet.present_flags), len(words))


if __name__ == "__main__":
    unittest.main()
