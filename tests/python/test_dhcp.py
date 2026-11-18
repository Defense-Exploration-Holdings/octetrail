"""DHCP messages parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import struct
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, UnpackError, dhcp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dhcp_fixture", ROOT / "tools/dhcp_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class DhcpTests(unittest.TestCase):
    def test_dpkt_vector(self):
        raw = bytes.fromhex(F.DHCP_DPKT)
        message = dhcp.DHCP(raw)
        self.assertIsInstance(message, Packet)
        self.assertEqual(bytes(message), raw)
        self.assertEqual(len(message), 300)
        self.assertEqual(message.chaddr, bytes.fromhex("000255 82f3a6".replace(" ", "")))
        self.assertEqual(message.opts[4], (dhcp.DHCP_OPT_HOSTNAME, b"Guinevere"))
        self.assertEqual(message.data, bytes(5))

    def test_options(self):
        message = dhcp.DHCP(F.HEADER + b"\x00\x35\x01\x05\x0c\x09ab")
        self.assertEqual(message.opts, [(0x35, b"\x05"), (0x0C, b"ab")])
        self.assertEqual(message.data, b"")
        message = dhcp.DHCP(F.HEADER + b"\x35\x01\x05\xfftail")
        self.assertEqual(message.data, b"tail")
        message = dhcp.DHCP(bytearray(F.HEADER + b"\x35\x01\x05\xff"))
        self.assertIsInstance(message.opts[0][1], bytearray)

    def test_missing_length_is_both_errors(self):
        for raw, text in (
            (F.HEADER + b"\x00\x35", "index out of range"),
            (bytearray(F.HEADER + b"\x35"), "bytearray index out of range"),
        ):
            with self.assertRaises(dhcp.MissingLengthError) as caught:
                dhcp.DHCP(raw)
            self.assertIsInstance(caught.exception, UnpackError)
            self.assertIsInstance(caught.exception, IndexError)
            self.assertEqual(str(caught.exception), text)

    def test_short_header(self):
        with self.assertRaises(NeedData):
            dhcp.DHCP(F.HEADER[:239])

    def test_packing(self):
        message = dhcp.DHCP(opts=[(dhcp.DHCP_OPT_MSGTYPE, bytes([dhcp.DHCPACK]))])
        self.assertEqual(bytes(message)[-4:], b"\x35\x01\x05\xff")
        self.assertEqual(len(message), 240 + 3 + 1)
        self.assertEqual(dhcp.DHCP(opts=[]).pack_opts(), b"")
        # As in dpkt, the default options hold str values and do not pack.
        with self.assertRaises(struct.error):
            bytes(dhcp.DHCP())


if __name__ == "__main__":
    unittest.main()
