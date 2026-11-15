"""Installed-provider tests for the bytes-only, opaque Ethernet II subset."""

import unittest
from pathlib import Path

from octetrail import NeedData, ethernet

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/ethernet-ii.hex"
DST = bytes.fromhex("02aabbccddee")
SRC = bytes.fromhex("021122334455")


class EthernetTests(unittest.TestCase):
    def test_default_fields_and_serialized_zero_addresses(self):
        packet = ethernet.Ethernet()
        self.assertEqual(
            (packet.dst, packet.src, packet.type, packet.data), (b"", b"", 0x0800, b"")
        )
        self.assertEqual(bytes(packet), bytes.fromhex("0000000000000000000000000800"))
        self.assertEqual(len(packet), 14)
        reparsed = ethernet.Ethernet(bytes(packet))
        self.assertEqual((reparsed.dst, reparsed.src), (bytes(6), bytes(6)))

    def test_omitted_addresses_keep_empty_field_defaults(self):
        for supplied, expected in (({"dst": DST}, (DST, b"")), ({"src": SRC}, (b"", SRC))):
            with self.subTest(supplied=supplied):
                packet = ethernet.Ethernet(**supplied)
                self.assertEqual((packet.dst, packet.src), expected)
                self.assertEqual(
                    bytes(packet)[:12], expected[0].ljust(6, b"\0") + expected[1].ljust(6, b"\0")
                )

    def test_literal_parse_has_unsigned_fields_and_owned_bytes(self):
        raw = bytes.fromhex(FIXTURE.read_text())
        packet = ethernet.Ethernet(raw)
        self.assertIs(type(packet.dst), bytes)
        self.assertIs(type(packet.src), bytes)
        self.assertIs(type(packet.type), int)
        self.assertIs(type(packet.data), bytes)
        self.assertEqual(
            (packet.dst, packet.src, packet.type, packet.data), (DST, SRC, 0x88B5, b"octetrail")
        )
        self.assertEqual(bytes(packet), raw)
        self.assertEqual(len(packet), 23)

    def test_constructor_matches_literal_without_upstream_encoder(self):
        packet = ethernet.Ethernet(dst=DST, src=SRC, type=0x88B5, data=b"octetrail")
        self.assertEqual(bytes(packet), bytes.fromhex(FIXTURE.read_text()))
        self.assertEqual(packet.data, b"octetrail")

    def test_ethernet_ii_unsigned_type_boundaries_use_network_order(self):
        for value in (0x0600, 0x7FFF, 0x8000, 0x88B5, 0xFFFF):
            with self.subTest(value=value):
                expected = DST + SRC + bytes((value >> 8, value & 0xFF)) + b"opaque"
                packet = ethernet.Ethernet(dst=DST, src=SRC, type=value, data=b"opaque")
                self.assertEqual(packet.type, value)
                self.assertEqual(bytes(packet), expected)
                reparsed = ethernet.Ethernet(expected)
                self.assertEqual((reparsed.type, reparsed.data), (value, b"opaque"))

    def test_payload_length_does_not_add_padding_or_frame_check_sequence(self):
        for size in (0, 1, 45, 46, 47, 1500):
            with self.subTest(size=size):
                payload = b"x" * size
                raw = DST + SRC + b"\x88\xb6" + payload
                packet = ethernet.Ethernet(raw)
                self.assertEqual(len(packet), 14 + size)
                self.assertEqual(bytes(packet), raw)
                self.assertEqual(packet.data, payload)

    def test_binary_payload_is_preserved_without_tail_heuristics(self):
        payload = bytes(range(256)) + bytes(8)
        packet = ethernet.Ethernet(dst=DST, src=SRC, type=0x88B5, data=payload)
        expected = DST + SRC + b"\x88\xb5" + payload
        self.assertEqual(bytes(packet), expected)
        self.assertEqual(ethernet.Ethernet(expected).data, payload)

    def test_each_public_field_can_be_replaced(self):
        packet = ethernet.Ethernet(bytes.fromhex(FIXTURE.read_text()))
        packet.dst = SRC
        packet.src = DST
        packet.type = 0xFFFF
        packet.data = b"replacement\x00\xff"
        self.assertEqual(
            (packet.dst, packet.src, packet.type, packet.data),
            (SRC, DST, 0xFFFF, b"replacement\x00\xff"),
        )
        self.assertEqual(bytes(packet), SRC + DST + b"\xff\xffreplacement\x00\xff")
        self.assertEqual(len(packet), 27)
        packet.data = b""
        self.assertEqual(bytes(packet), SRC + DST + b"\xff\xff")
        self.assertEqual(len(packet), 14)

    def test_serialized_bytes_are_stable_and_independent_of_later_mutations(self):
        raw = bytes.fromhex(FIXTURE.read_text())
        packet = ethernet.Ethernet(raw)
        first = bytes(packet)
        for _ in range(3):
            self.assertEqual(bytes(packet), first)
            self.assertEqual(len(packet), len(first))
        packet.data = b"new"
        self.assertEqual(first, raw)
        self.assertEqual(bytes(packet), DST + SRC + b"\x88\xb5new")

    def test_instances_do_not_share_mutable_fields(self):
        first = ethernet.Ethernet(type=0x88B5, data=b"first")
        second = ethernet.Ethernet(type=0x88B5, data=b"second")
        first.dst = DST
        first.data = b"changed"
        self.assertEqual((second.dst, second.data), (b"", b"second"))

    def test_explicit_empty_or_incomplete_buffer_requires_header(self):
        raw = bytes.fromhex(FIXTURE.read_text())
        for size in range(14):
            with self.subTest(size=size), self.assertRaises(NeedData):
                ethernet.Ethernet(raw[:size])


if __name__ == "__main__":
    unittest.main()
