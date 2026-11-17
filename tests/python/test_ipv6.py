"""Bounded offline IPv6 and raw dispatch using independently encoded bytes."""

import importlib.util
import io
import struct
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import octetrail
from octetrail import (
    NeedData,
    PackError,
    UnpackError,
    ethernet,
    ip,
    ip6,
    pcap,
    pcapng,
    raw,
    tcp,
    udp,
)

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ipv6_fixture", ROOT / "tools/ipv6_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class IPv6Tests(unittest.TestCase):
    def test_literal_capture_records_keep_iteration_and_explicit_raw_selection(self):
        ipv6 = bytes.fromhex(F.fixtures()[0]["wire"])
        ipv4 = F.C.encode({"kind": "opaque", "p": 253, "payload": "6e6f7465"})[14:]

        def block(kind, body):
            size = 12 + len(body)
            return struct.pack("<II", kind, size) + body + struct.pack("<I", size)

        for link in (1, 101):
            frames = [F.MAC + ipv6, F.MAC[:12] + b"\x08\x00" + ipv4] if link == 1 else [ipv6, ipv4]
            classic = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link)
            ng = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
            ng += block(1, struct.pack("<HHI", link, 0, 65535))
            for frame in frames:
                classic += struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
                ng += block(
                    6,
                    struct.pack("<IIIII", 0, 0, 1000000, len(frame), len(frame))
                    + frame
                    + bytes(-len(frame) % 4),
                )
            for reader, capture in ((pcap.Reader, classic), (pcapng.Reader, ng)):
                parsed = reader(io.BytesIO(capture))
                self.assertEqual(parsed.datalink(), link)
                rows = list(parsed)
                self.assertEqual(rows, [(1.0, frame) for frame in frames])
                packets = [
                    ethernet.Ethernet(wire).data if link == 1 else raw.decode(wire)
                    for _, wire in rows
                ]
                self.assertEqual([type(p) for p in packets], [ip6.IP6, ip.IP])

    def test_independent_cases_fields_exact_bytes_and_declared_differences(self):
        actual = F.exercise(octetrail, "octetrail")
        self.assertEqual(
            actual["cases"], {c["id"]: F.expected(c, "octetrail") for c in F.fixtures()}
        )

    def test_ethernet_alias_and_type_inference_and_raw_both_versions(self):
        wire = bytes.fromhex(F.fixtures()[0]["wire"])
        frame = ethernet.Ethernet(data=ip6.IP6(wire), type=0x88B5, dst=F.MAC[:6], src=F.MAC[6:12])
        self.assertEqual(frame.type, 0x88B5)
        self.assertEqual(bytes(frame), F.MAC + wire)
        parsed = ethernet.Ethernet(bytes(frame))
        self.assertIs(parsed.ip6, parsed.data)
        self.assertIsInstance(raw.decode(wire), ip6.IP6)
        v4 = bytes.fromhex(F.C.encode({"kind": "opaque", "p": 253, "payload": "6e6f7465"}).hex())[
            14:
        ]
        self.assertIsInstance(raw.decode(v4), ip.IP)
        self.assertEqual(bytes(raw.decode(v4)), v4)
        with self.assertRaises(NeedData):
            raw.decode(b"")
        with self.assertRaises(UnpackError):
            raw.decode(b"\x50")
        with self.assertRaises(TypeError):
            raw.decode(bytearray(wire))

    def test_non_atomic_fragments_stay_bytes_at_any_extension_position(self):
        for kinds in ((44,), (0, 44), (60, 44)):
            for field in (1, 8, 9):
                c = F.fixture("fragment", 6, b"note", kinds, fragment=field)
                packet = ip6.IP6(bytes.fromhex(c["wire"]))
                self.assertTrue(packet.fragmented)
                self.assertIsInstance(packet.data, bytes)
                self.assertFalse(hasattr(packet, "tcp"))
                self.assertEqual(bytes(packet).hex(), c["wire"])
        c = F.fixture("atomic", 6, b"note", (44,))
        self.assertIsInstance(ip6.IP6(bytes.fromhex(c["wire"])).data, tcp.TCP)

    def test_non_atomic_fragment_does_not_parse_headers_inside_fragment_data(self):
        fragment = struct.pack("!BBHI", 60, 0, 1, 17)
        body = bytes((6, 0)) + bytes(6) + bytes(20)
        fixed = struct.pack("!IHBB16s16s", 0x60000000, len(fragment + body), 44, 0, F.SRC, F.DST)
        packet = ip6.IP6(fixed + fragment + body)
        self.assertEqual(len(packet.all_extension_headers), 1)
        self.assertEqual(packet.data, body)
        self.assertEqual(packet.p, 60)
        packet.data = tcp.TCP()
        with self.assertRaises(PackError):
            bytes(packet)

    def test_extension_count_bytes_and_packet_bounds(self):
        c = F.fixture("many", 253, b"", (60,) * 17)
        with self.assertRaises(ip6.LimitError):
            ip6.IP6(bytes.fromhex(c["wire"]))
        packet = ip6.IP6(
            nxt=60,
            all_extension_headers=(ip6.ExtensionHeader(60, bytes((253, 255)) + bytes(2046)),),
            data=b"note",
        )
        self.assertEqual(len(bytes(packet)), 2092)
        packet.all_extension_headers += (ip6.ExtensionHeader(60, bytes((253, 0)) + bytes(6)),)
        with self.assertRaises(ip6.LimitError):
            bytes(packet)
        with self.assertRaises(ip6.LimitError):
            ip6.IP6(bytes(65576))
        with self.assertRaises(ip6.LimitError):
            bytes(ip6.IP6(nxt=253, data=bytes(65536)))

    def test_incomplete_base_and_nested_fallback_and_resource_propagation(self):
        for count in range(40):
            with self.assertRaises(NeedData):
                ip6.IP6(bytes(count))
        self.assertEqual(ethernet.Ethernet(F.MAC + b"short").data, b"short")
        for error in (ValueError("caller"), MemoryError("memory")):
            with (
                patch.object(ip6._native, "_ipv6_unpack", side_effect=error),
                self.assertRaises(type(error)) as result,
            ):
                ethernet.Ethernet(F.MAC + bytes(40))
            self.assertIs(result.exception, error)

    def test_nested_limit_refusal_preserves_bytes_but_direct_decode_is_strict(self):
        wire = bytes.fromhex(F.fixtures()[0]["wire"])
        error = ip6.LimitError("configured parse bound")
        with patch.object(ip6._native, "_ipv6_unpack", side_effect=error):
            frame = ethernet.Ethernet(F.MAC + wire)
            self.assertEqual(frame.data, wire)
            self.assertFalse(hasattr(frame, "ip6"))
            self.assertEqual(bytes(frame), F.MAC + wire)
            for decoder in (ip6.IP6, raw.decode):
                with self.assertRaises(ip6.LimitError) as result:
                    decoder(wire)
                self.assertIs(result.exception, error)

    def test_unchanged_capture_checksum_refusal_does_not_prevent_roundtrip(self):
        for protocol in (6, 17):
            wire = F.ordinary_routed_capture(protocol)
            with patch.object(
                ip6._native,
                "_ipv6_checksum",
                side_effect=AssertionError("unsupported checksum called"),
            ):
                packet = ip6.IP6(wire)
                self.assertEqual(bytes(packet), wire)
                self.assertEqual(packet.data.sum, 0)
                self.assertEqual(bytes(ethernet.Ethernet(F.MAC + wire)), F.MAC + wire)
                packet.data.data = b"other note"
                with self.assertRaises(NotImplementedError):
                    bytes(packet)
                self.assertEqual(packet.data.sum, 0)

    def test_opaque_esp_no_next_and_caller_length_checksum(self):
        c = F.fixture("opaque-esp", 50, b"ordinary opaque bytes")
        packet = ip6.IP6(bytes.fromhex(c["wire"]))
        self.assertEqual(packet.data, b"ordinary opaque bytes")
        self.assertEqual(bytes(packet).hex(), c["wire"])
        child = udp.UDP(sport=1, dport=2, ulen=12, sum=0x1234, data=b"note")
        packet = ip6.IP6(nxt=17, data=child)
        self.assertEqual(len(bytes(packet)), 52)
        self.assertEqual((packet.plen, child.sum, child.ulen), (0, 0x1234, 12))
        child.data = b"new note"
        bytes(packet)
        self.assertEqual((packet.plen, child.sum, child.ulen), (0, 0x1234, 12))

    def test_chain_validation_cycles_and_active_routing_checksum_exclusion(self):
        packet = ip6.IP6(
            nxt=6, all_extension_headers=(ip6.ExtensionHeader(60, bytes((6, 0)) + bytes(6)),)
        )
        with self.assertRaises(PackError):
            bytes(packet)
        packet = ip6.IP6(
            nxt=43,
            all_extension_headers=(ip6.ExtensionHeader(43, bytes((6, 0, 0, 1)) + bytes(4)),),
            data=tcp.TCP(),
        )
        with self.assertRaises(NotImplementedError):
            bytes(packet)
        packet.data = packet
        with self.assertRaises(TypeError):
            bytes(packet)
        packet = ip6.IP6()
        for key, value in (("fc", 256), ("flow", 1 << 20), ("v", 16)):
            with self.assertRaises(ValueError):
                setattr(packet, key, value)

    def test_optimized_probe_rejects_wrong_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/ipv6_differential.py",
                "--probe",
                "--module",
                "octetrail",
                "--version",
                "9.9.9",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wrong provider version", result.stderr)


if __name__ == "__main__":
    unittest.main()
