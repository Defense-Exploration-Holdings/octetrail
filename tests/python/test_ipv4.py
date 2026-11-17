"""IPv4 on dpkt's vectors and generated offline datagrams."""

import importlib.util
import subprocess
import sys
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

import octetrail
from octetrail import NeedData, UnpackError, ip, ip6, ipip, tcp, udp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ipv4_fixture", ROOT / "tools/ipv4_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(v) for k, v in F.cases().items()}


class IPv4Tests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("literal", "dpkt_udp", "dpkt_options_tcp", "ip_in_ip", "ipv6_in_ip"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_dpkt_vectors_round_trip(self):
        for name in ("dpkt_udp", "dpkt_options_tcp", "dpkt_iplen_udp", "literal"):
            packet = ip.IP(CASES[name])
            self.assertEqual(bytes(packet), CASES[name], name)
        packet = ip.IP(CASES["dpkt_udp"])
        self.assertIs(packet.udp, packet.data)
        self.assertEqual((packet.udp.sport, packet.udp.data), (111, b"foobar"))
        offload = ip.IP(CASES["dpkt_zero_length_tcp"])
        self.assertIsInstance(offload.data, tcp.TCP)
        self.assertEqual(offload.tcp.data, b"X" * 2048)
        self.assertEqual(ip.IP(CASES["literal_with_padding"]).data, b"rail")

    def test_header_errors(self):
        for name in ("dpkt_header_length_2", "ihl_4", "ihl_0"):
            with self.assertRaises(UnpackError) as result:
                ip.IP(CASES[name])
            self.assertNotIsInstance(result.exception, NeedData)
            self.assertEqual(str(result.exception), "invalid header length")
        with self.assertRaises(NeedData) as result:
            ip.IP(CASES["short"])
        self.assertEqual(str(result.exception), "got 19, 20 needed at least")

    def test_slicing_follows_dpkt(self):
        packet = ip.IP(CASES["total_inside_header"])
        self.assertEqual((packet.opts, packet.data), (b"\x01" * 4, b""))
        self.assertEqual(ip.IP(CASES["total_beyond_buffer"]).data, b"cut")
        self.assertEqual(ip.IP(CASES["total_zero_keeps_rest"]).data, b"offload")
        self.assertEqual(ip.IP(CASES["ihl_15_short_options"]).opts, b"\x01" * 8)
        self.assertEqual(ip.IP(CASES["version_6_nibble"]).v, 6)
        packet = ip.IP(bytearray(CASES["ihl_6_options"]))
        self.assertEqual((type(packet.opts), packet.data), (bytearray, bytearray(b"rail")))

    def test_fragments_and_payload_fallback(self):
        later = ip.IP(CASES["later_fragment_udp"])
        self.assertIsInstance(later.data, bytes)
        # dpkt names the alias after the payload class, which is bytes here.
        self.assertIs(vars(later)["bytes"], later.data)
        self.assertIsInstance(ip.IP(CASES["first_fragment_udp"]).data, udp.UDP)
        self.assertEqual(ip.IP(CASES["tcp_short"]).data, b"\x00\x01\x02")
        self.assertEqual(ip.IP(CASES["unknown_protocol"]).data, b"opaque")
        self.assertFalse(hasattr(ip.IP(CASES["unknown_protocol"]), "bytes"))

    def test_ipv6_payload_with_fragment_offset_error_stays_bytes(self):
        raw = CASES["ipv6_fragment_after_ah"]
        packet = ip.IP(raw)
        self.assertEqual((type(packet.data), packet.data), (bytes, raw[20:]))
        with self.assertRaises(ip6.FragmentOffsetError) as result:
            ip6.IP6(raw[20:])
        self.assertIsInstance(result.exception, AttributeError)

    def test_protocol_table(self):
        self.assertIs(ip6.IP6._protosw, ip.IP._protosw)
        self.assertIs(ipip.IPIP, ip.IP)
        self.assertIsInstance(ip.IP(CASES["ip_in_ip"]).ip.udp, udp.UDP)
        self.assertIsInstance(ip.IP(CASES["ipv6_in_ip"]).ip6, ip6.IP6)
        self.assertEqual(ip.get_ip_proto_name(17), "UDP")
        self.assertIsNone(ip.get_ip_proto_name(999))

        class Opaque(octetrail.Packet):
            __hdr__ = (("x", "B", 0),)

        try:
            ip.IP.set_proto(253, Opaque)
            self.assertIs(ip6.IP6.get_proto(253), Opaque)
            self.assertIsInstance(ip.IP(CASES["unknown_protocol"]).opaque, Opaque)
        finally:
            del ip.IP._protosw[253]

    def test_checksums(self):
        child = udp.UDP(sport=1, dport=0xFFDB)
        packet = ip.IP(src=b"\0\0\0\1", dst=b"\0\0\0\1", p=17, data=child)
        bytes(packet)
        self.assertEqual(child.sum, 0xFFFF)
        fragment = udp.UDP(sport=1, dport=2, ulen=12, data=b"note")
        bytes(ip.IP(src=F.SRC, dst=F.DST, p=17, mf=1, data=fragment))
        self.assertEqual(fragment.sum, 0)
        kept = ip.IP(sum=1, len=99, data=b"rail")
        self.assertEqual(bytes(kept)[2:4], b"\x00\x63")
        built = ip.IP(data=b"Hello world!")
        self.assertEqual(bytes(built)[10:12], b"\x7a\xdf")
        self.assertEqual(bytes(ip.IP(data=b"Hello world!", len=0)), bytes(built))

    def test_off_is_deprecated(self):
        packet = ip.IP(df=1)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.assertEqual(packet.off, 0x4000)
            packet.off = 3
        self.assertEqual([str(w.message) for w in caught], ["IP.off is deprecated"] * 2)
        self.assertEqual(packet._flags_offset, 0x4003)

    def test_payload_errors_other_than_parse_errors_propagate(self):
        for error in (ValueError("caller"), MemoryError("allocation")):
            with (
                patch.object(ip._native, "_ipv4_layout", side_effect=error),
                self.assertRaises(type(error)) as result,
            ):
                ip.IP(CASES["literal"])
            self.assertIs(result.exception, error)

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/ipv4_differential.py",
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
