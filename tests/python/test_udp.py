"""Installed offline UDP tests using preconstructed benign independent bytes."""

import unittest
from pathlib import Path

from octetrail import NeedData, PackError, udp

LITERAL = bytes.fromhex((Path(__file__).resolve().parents[1] / "fixtures/udp-base.hex").read_text())


class UDPTests(unittest.TestCase):
    def test_defaults_and_empty_serialization(self):
        packet = udp.UDP()
        self.assertEqual(
            (packet.sport, packet.dport, packet.ulen, packet.sum, packet.data),
            (0xDEAD, 0, 8, 0, b""),
        )
        self.assertEqual(bytes(packet), bytes.fromhex("dead000000080000"))
        self.assertEqual((len(packet), packet.pack_hdr()), (8, bytes(packet)))

    def test_literal_fields_exact_bytes_and_owned_payload(self):
        packet = udp.UDP(LITERAL)
        self.assertEqual(
            (packet.sport, packet.dport, packet.ulen, packet.sum, packet.data),
            (12345, 54321, 12, 0x1234, b"rail"),
        )
        self.assertIs(type(packet.data), bytes)
        self.assertEqual(bytes(packet), LITERAL)
        self.assertEqual(packet.pack_hdr(), LITERAL[:8])
        self.assertEqual(len(packet), 12)

    def test_keyword_constructor_and_positional_override_behavior(self):
        self.assertEqual(
            bytes(udp.UDP(sport=12345, dport=54321, ulen=12, sum=0x1234, data=b"rail")), LITERAL
        )
        self.assertEqual(bytes(udp.UDP(LITERAL, sum=0, data=b"", ulen=8)), LITERAL)

    def test_retained_length_does_not_trim_or_extend_payload(self):
        for length in (0, 7, 8, 12, 65535):
            raw = LITERAL[:4] + length.to_bytes(2) + LITERAL[6:]
            packet = udp.UDP(raw)
            self.assertEqual((packet.ulen, packet.data, len(packet)), (length, b"rail", 12))
            self.assertEqual(bytes(packet), raw)

    def test_payload_mutation_never_refreshes_checksum_or_length(self):
        for checksum in (0, 0x8000, 65535):
            packet = udp.UDP(sport=12345, dport=54321, ulen=12, sum=checksum, data=b"rail")
            packet.data = b"ordinary changed bytes"
            self.assertEqual(bytes(packet), LITERAL[:6] + checksum.to_bytes(2) + packet.data)
            self.assertEqual((packet.ulen, packet.sum), (12, checksum))
            self.assertEqual(bytes(packet), bytes(packet))

    def test_mutable_fields_and_replacement_unpack(self):
        packet = udp.UDP(LITERAL)
        packet.sport, packet.ulen, packet.sum, packet.data = 65535, 11, 0, b"new"
        self.assertEqual(bytes(packet), bytes.fromhex("ffffd431000b00006e6577"))
        packet.unpack(bytes.fromhex("dead000000080000"))
        self.assertEqual(
            (packet.sport, packet.dport, packet.ulen, packet.sum, packet.data),
            (0xDEAD, 0, 8, 0, b""),
        )

    def test_every_short_header_raises_public_need_data(self):
        for size in range(8):
            with self.subTest(size=size), self.assertRaises(NeedData):
                udp.UDP(LITERAL[:size])

    def test_unsigned_fields_and_deferred_pack_errors(self):
        packet = udp.UDP(sport=65535, dport=32768, ulen=0, sum=65535)
        self.assertEqual(bytes(packet), bytes.fromhex("ffff80000000ffff"))
        for name in ("sport", "dport", "ulen", "sum"):
            for value in (-1, 65536, 1.25, None, "integer"):
                packet = udp.UDP(**{name: value})
                with self.subTest(name=name, value=value), self.assertRaises(PackError):
                    bytes(packet)
                self.assertEqual(len(packet), 8)

    def test_complete_buffer_boundary_is_an_explicit_resource_policy(self):
        packet = udp.UDP(data=b"x" * 65527)
        self.assertEqual(len(bytes(packet)), 65535)
        self.assertEqual(packet.ulen, 8)
        packet.data += b"x"
        self.assertEqual(len(packet), 65536)
        with self.assertRaises(udp.LimitError):
            bytes(packet)
        with self.assertRaises(udp.LimitError):
            udp.UDP(LITERAL[:8] + b"x" * 65528)

    def test_only_the_declared_bytes_input_surface_is_supported(self):
        for value in (bytearray(LITERAL), memoryview(LITERAL), "text"):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                udp.UDP(value)
        for value in (bytearray(b"rail"), memoryview(b"rail"), "rail"):
            packet = udp.UDP(data=value)
            self.assertEqual(packet.pack_hdr(), bytes.fromhex("dead000000080000"))
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                bytes(packet)
        with self.assertRaises(TypeError):
            udp.UDP(LITERAL, LITERAL)
        with self.assertRaises(TypeError):
            udp.UDP(unknown=1)

    def test_instances_are_independent_and_no_application_dispatch_occurs(self):
        first, second = udp.UDP(LITERAL), udp.UDP(LITERAL)
        first.data = b"new"
        self.assertEqual(second.data, b"rail")
        for name in ("dns", "tcp", "ip"):
            self.assertFalse(hasattr(second, name))
        self.assertEqual((udp.UDP_HDR_LEN, udp.UDP_PORT_MAX), (8, 65535))


if __name__ == "__main__":
    unittest.main()
