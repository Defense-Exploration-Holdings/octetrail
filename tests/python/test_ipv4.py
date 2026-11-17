"""Installed fixed-header IPv4 API tests using benign independent bytes."""

import unittest
from pathlib import Path

from octetrail import NeedData, PackError, UnpackError, ip

LITERAL = bytes.fromhex(
    (Path(__file__).resolve().parents[1] / "fixtures/ipv4-base.hex").read_text()
)
SRC = bytes.fromhex("c0000201")
DST = bytes.fromhex("c6336402")


class IPv4Tests(unittest.TestCase):
    def test_default_fields_and_checksum(self):
        p = ip.IP()
        self.assertEqual(
            (p.v, p.hl, p.len, p.ttl, p.p, p.sum, p.src, p.dst, p.data, p.opts),
            (4, 5, 20, 64, 0, 0, bytes(4), bytes(4), b"", b""),
        )
        self.assertEqual(bytes(p), bytes.fromhex("450000140000000040007aeb0000000000000000"))
        self.assertEqual(p.sum, 0x7AEB)

    def test_literal_parse_and_exact_fields(self):
        p = ip.IP(LITERAL)
        self.assertEqual(
            (p.src, p.dst, p.id, p.df, p.offset, p.len, p.sum, p.data),
            (SRC, DST, 0x1234, 1, 0, 24, 0x3B7E, b"rail"),
        )
        self.assertIs(type(p.data), bytes)
        self.assertEqual(bytes(p), LITERAL)

    def test_constructor_auto_checksum_and_length_match_literal(self):
        p = ip.IP(src=SRC, dst=DST, id=0x1234, df=1, p=253, data=b"rail", len=20)
        self.assertEqual(p.pack_hdr()[10:12], b"\0\0")
        self.assertEqual(bytes(p), LITERAL)
        self.assertEqual((p.len, p.sum), (24, 0x3B7E))

    def test_literal_checksum_uses_independent_word_sum(self):
        total = sum((LITERAL[i] << 8) + LITERAL[i + 1] for i in range(0, 20, 2))
        while total > 65535:
            total = (total & 65535) + (total >> 16)
        self.assertEqual(total, 65535)

    def test_payload_length_change_retains_explicit_sum_until_reset(self):
        p = ip.IP(LITERAL)
        p.data = b"other"
        self.assertEqual(bytes(p), LITERAL[:20] + b"other")
        self.assertEqual((p.len, len(p)), (24, 25))
        p.sum = 0
        raw = bytes(p)
        self.assertEqual(p.len, 25)
        total = sum(int.from_bytes(raw[i : i + 2], "big") for i in range(0, 20, 2))
        while total >> 16:
            total = (total & 65535) + (total >> 16)
        self.assertEqual(total, 65535)

    def test_zero_result_checksum_is_stable(self):
        p = ip.IP(id=0x7AEB)
        raw = bytes(p)
        self.assertEqual(p.sum, 0)
        self.assertEqual(bytes(p), raw)

    def test_unsigned_fields_and_flag_units(self):
        p = ip.IP(src=SRC, dst=DST, p=253, tos=255, id=65535, ttl=255, rf=1, df=1, mf=1, offset=3)
        raw = bytes(p)
        self.assertEqual(raw[4:8], b"\xff\xff\xe0\x03")
        q = ip.IP(raw)
        self.assertEqual((q.rf, q.df, q.mf, q.offset), (1, 1, 1, 3))

    def test_complete_header_is_required_but_payload_may_be_short(self):
        for length in range(20):
            with self.subTest(length=length), self.assertRaises(NeedData):
                ip.IP(LITERAL[:length])
        short = ip.IP(LITERAL[:-1])
        self.assertEqual((short.len, short.data), (24, b"rai"))
        self.assertEqual(bytes(short), LITERAL[:-1])
        self.assertEqual(ip.IP(b"\x4f" + LITERAL[1:]).opts, b"rail")

    def test_offset_setter_uses_wire_units_and_preserves_flags(self):
        p = ip.IP(LITERAL)
        for offset, flags in ((24, b"\x40\x18"), (8, b"\x40\x08")):
            p.offset = offset
            p.sum = 0
            raw = bytes(p)
            self.assertEqual((p.df, p.offset), (1, offset))
            self.assertEqual(raw[6:8], flags)
            self.assertEqual(raw[20:], b"rail")
            total = sum(int.from_bytes(raw[i : i + 2], "big") for i in range(0, 20, 2))
            while total >> 16:
                total = (total & 65535) + (total >> 16)
            self.assertEqual(total, 65535)

    def test_bad_ihl_maps_to_public_unpack_error(self):
        with self.assertRaises(UnpackError):
            ip.IP(b"\x44" + LITERAL[1:])
        self.assertEqual(bytes(ip.IP(hl=4))[:1], b"\x44")

    def test_any_version_options_as_assigned_and_offload_length(self):
        for first in (0x05, 0x65, 0xF5):
            with self.subTest(first=first):
                packet = ip.IP(bytes([first]) + LITERAL[1:])
                self.assertEqual((packet.v, packet.data), (first >> 4, b"rail"))
        self.assertEqual(bytes(ip.IP(opts=b"\0" * 4))[:4], b"\x45\x00\x00\x18")
        packet = ip.IP(hl=6, opts=b"\x01" * 4, data=b"rail")
        self.assertEqual(ip.IP(bytes(packet)).opts, b"\x01" * 4)
        offload = ip.IP(LITERAL[:2] + b"\0\0" + LITERAL[4:] + b"xx")
        self.assertEqual((offload.len, offload.data), (0, b"railxx"))
        with self.assertRaises(NotImplementedError):
            _ = ip.IP().off

    def test_trailing_capture_bytes_are_not_payload(self):
        p = ip.IP(LITERAL + b"padding")
        self.assertEqual(p.data, b"rail")
        self.assertEqual(bytes(p), LITERAL)

    def test_checksum_is_preserved_not_validated_on_parse(self):
        raw = LITERAL[:10] + b"\0\x01" + LITERAL[12:]
        self.assertEqual(bytes(ip.IP(raw)), raw)

    def test_packing_errors_and_datagram_bound(self):
        for values in ({"ttl": 256}, {"id": -1}, {"src": "text"}):
            with self.subTest(values=values), self.assertRaises(PackError):
                bytes(ip.IP(**values))
        with self.assertRaises(PackError):
            bytes(ip.IP(data=b"x" * 65516))
        self.assertEqual(len(bytes(ip.IP(data=b"x" * 65515))), 65535)

    def test_owned_payload_instances_and_no_higher_layer_dispatch(self):
        first = ip.IP(LITERAL)
        second = ip.IP(LITERAL)
        first.data = b"changed"
        self.assertEqual(second.data, b"rail")
        self.assertFalse(hasattr(second, "tcp"))
        self.assertFalse(hasattr(second, "udp"))


if __name__ == "__main__":
    unittest.main()
