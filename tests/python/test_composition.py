"""Independent benign Ethernet/IPv4/TCP/UDP fixtures through the installed API."""

import importlib.util
import io
import struct
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import octetrail
from octetrail import ethernet, ip, pcap, pcapng, tcp, udp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "composition_fixture", ROOT / "tools/composition_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class CompositionTests(unittest.TestCase):
    def test_independent_fields_bytes_construction_and_roundtrips(self):
        for case in F.fixtures():
            with self.subTest(case=case["id"]):
                actual = F.exercise(octetrail, case)
                expected = F.expected(bytes.fromhex(case["wire"]))
                self.assertEqual(actual["parse"], expected)
                self.assertEqual(actual["roundtrip"], case["wire"])
                if case["spec"] is not None:
                    self.assertEqual(actual["constructed_wire"], case["wire"])
                    self.assertEqual(actual["constructed_reparse"], expected)
                    self.assertEqual(actual["keyword_parse"], expected)
                    self.assertTrue(actual["aliases"])

    def test_mutation_retains_stored_sums_and_reset_recomputes_like_198(self):
        self.assertEqual(F.mutations(octetrail), F.expected_mutations("1.9.8"))

    def test_wire_type_inference_retains_stored_type_and_aliases_are_parse_snapshots(self):
        packet = F.construct(octetrail, {"kind": "tcp", "payload": "7261696c"})
        packet.type = 0x88B5
        raw = bytes(packet)
        self.assertEqual((packet.type, raw[12:14]), (0x88B5, b"\x08\x00"))
        parsed = ethernet.Ethernet(raw)
        self.assertIs(parsed.ip, parsed.data)
        self.assertIs(parsed.ip.tcp, parsed.ip.data)
        old = parsed.ip.tcp
        parsed.ip.data = udp.UDP()
        self.assertIs(parsed.ip.tcp, old)  # Upstream aliases are snapshots, not live properties.

    def test_unknown_and_undecodable_children_keep_bytes(self):
        packet = ip.IP(p=6, src=F.SRC, dst=F.DST, data=b"rail")
        raw = bytes(ethernet.Ethernet(data=packet))
        parsed = ethernet.Ethernet(raw)
        self.assertIsInstance(parsed.ip, ip.IP)
        self.assertEqual(parsed.ip.data, b"rail")
        self.assertFalse(hasattr(parsed.ip, "tcp"))
        self.assertEqual(bytes(parsed), raw)
        short = F.MACS + b"\x08\x00short"
        self.assertEqual(ethernet.Ethernet(short).data, b"short")

    def test_ipv4_header_longer_than_total_length_decodes_like_dpkt(self):
        # A 24-byte header that declares a 20-byte datagram keeps its options and no payload.
        raw = struct.pack("!BBHHHBBH4s4s", 0x46, 0, 20, 0, 0, 64, 253, 0, F.SRC, F.DST)
        raw += b"\x01" * 4
        wire = F.MACS + b"\x08\x00" + raw
        packet = ip.IP(raw)
        self.assertEqual((packet.opts, packet.data), (b"\x01" * 4, b""))
        frame = ethernet.Ethernet(wire)
        self.assertIsInstance(frame.ip, ip.IP)
        # The zero checksum makes packing set the length to the 24 bytes present.
        self.assertEqual(bytes(frame)[16:18], b"\x00\x18")

    def test_nested_fallback_does_not_swallow_programmer_or_resource_errors(self):
        raw = F.MACS + b"\x08\x00" + bytes(20)
        for error in (
            ValueError("caller error"),
            TypeError("caller type"),
            MemoryError("allocation"),
        ):
            with self.subTest(error=type(error).__name__):
                with (
                    patch.object(ip._native, "_ipv4_layout", side_effect=error) as layout,
                    self.assertRaises(type(error)) as raised,
                ):
                    ethernet.Ethernet(raw)
                self.assertIs(raised.exception, error)
                layout.assert_called_once_with(bytes(20))

    def test_options_pack_as_assigned_and_object_cycles_fail(self):
        # dpkt packs IPv4 and TCP options as assigned, whatever hl or off says.
        self.assertEqual(len(bytes(ip.IP(hl=15, opts=b"\x01" * 44))), 64)
        self.assertEqual(len(bytes(tcp.TCP(off=15, opts=b"\x01" * 44))), 64)
        # IPv4, TCP and Ethernet pack their payload the way dpkt's Packet does,
        # without a cycle check.
        for packet in (ip.IP(), tcp.TCP(), ethernet.Ethernet()):
            packet.data = packet
            with self.assertRaises(RecursionError):
                bytes(packet)

    def test_udp_length_is_caller_owned_and_zero_checksum_maps_to_ones(self):
        case = next(c for c in F.fixtures() if c["id"] == "udp_zero_checksum_maps_to_ones")
        packet = F.construct(octetrail, case["spec"])
        self.assertFalse(hasattr(packet, "ip"))
        bytes(packet)
        self.assertEqual(
            packet.data.sum,
            int.from_bytes(bytes.fromhex(case["wire"])[24:26], "big"),
        )
        self.assertEqual(packet.data.data.sum, 65535)
        child = udp.UDP(data=b"rail")
        parent = ip.IP(p=17, data=child)
        bytes(parent)
        self.assertEqual(child.ulen, 8)

    def test_independent_pcap_and_pcapng_offline_consumers(self):
        frames = [bytes.fromhex(c["wire"]) for c in F.fixtures()[:2]]
        classic = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        for index, frame in enumerate(frames, 1):
            classic += struct.pack("<IIII", index, 0, len(frame), len(frame)) + frame

        def block(kind, body):
            length = 12 + len(body)
            return struct.pack("<II", kind, length) + body + struct.pack("<I", length)

        ng = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        ng += block(1, struct.pack("<HHI", 1, 0, 65535))
        for index, frame in enumerate(frames, 1):
            ng += block(
                6,
                struct.pack("<IIIII", 0, 0, index * 1000000, len(frame), len(frame))
                + frame
                + bytes((-len(frame)) % 4),
            )
        for reader, raw in ((pcap.Reader, classic), (pcapng.Reader, ng)):
            observations = []
            for timestamp, wire in reader(io.BytesIO(raw)):
                packet = ethernet.Ethernet(wire)
                observations.append((timestamp, packet.ip.src, packet.ip.tcp.sport, bytes(packet)))
            self.assertEqual(
                observations, [(float(n), F.SRC, 32000, f) for n, f in enumerate(frames, 1)]
            )

    def test_optimized_probe_rejects_wrong_version(self):
        process = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/composition_differential.py",
                "--probe",
                "--module",
                "octetrail",
                "--version",
                "9.9.9",
            ],
            input="[]",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("wrong provider version", process.stderr)

    def test_origin_validation_cannot_accept_an_external_source_tree(self):
        fake = SimpleNamespace(__file__=str(ROOT / "external.py"))
        metadata = SimpleNamespace(version="0.7.1", locate_file=lambda name: ROOT / name)
        with (
            patch.object(F.importlib, "import_module", return_value=fake),
            patch.object(F.importlib.metadata, "distribution", return_value=metadata),
            self.assertRaisesRegex(ValueError, "unverified provider origin"),
        ):
            F.provenance("octetrail", "0.7.1")


if __name__ == "__main__":
    unittest.main()
