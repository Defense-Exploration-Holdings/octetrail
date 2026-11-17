"""TCP and UDP on dpkt's vectors and generated offline segments and datagrams."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import octetrail
from octetrail import NeedData, Packet, UnpackError, ip6, tcp, udp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "tcp_udp_fixture", ROOT / "tools/tcp_udp_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class TcpUdpTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("tcp_dpkt_synack", "tcp_options", "udp_plain", "ip6_tcp", "ip6_udp"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_dpkt_tcp_vectors(self):
        segment = tcp.TCP(CASES["tcp_dpkt_synack"])
        self.assertIsInstance(segment, Packet)
        self.assertEqual(
            (segment.flags, segment.off, segment.win), (tcp.TH_SYN | tcp.TH_ACK, 7, 5840)
        )
        self.assertEqual((segment.dport, segment.seq, segment.ack), (3372, 290218379, 951057940))
        self.assertEqual(bytes(segment), CASES["tcp_dpkt_synack"])
        offset = tcp.TCP(CASES["tcp_dpkt_offset"])
        offset.off = 8
        self.assertEqual(bytes(offset)[12], 0x80)
        self.assertEqual(
            tcp.parse_opts(b"\x02\x04\x23\x00\x01\x01\x04\x02"),
            [(2, b"\x23\x00"), (1, b""), (1, b""), (4, b"")],
        )
        self.assertEqual(tcp.parse_opts(b"\x02\x00\x01"), [(2, b""), (1, b"")])
        self.assertEqual(tcp.parse_opts(b"\xff"), [None])
        self.assertEqual(tcp.tcp_flags_to_str(0x1FF), "FIN,SYN,RST,PUSH,ACK,URG,ECE,CWR,NS")

    def test_tcp_header_errors_and_slicing(self):
        for name in ("tcp_offset_4", "tcp_offset_0"):
            with self.assertRaises(UnpackError) as result:
                tcp.TCP(CASES[name])
            self.assertNotIsInstance(result.exception, NeedData)
            self.assertEqual(str(result.exception), "invalid header length")
        with self.assertRaises(NeedData):
            tcp.TCP(CASES["tcp_short"])
        short = tcp.TCP(CASES["tcp_offset_15_short"])
        self.assertEqual((short.opts, short.data), (b"\x01" * 8, b""))
        nonce = tcp.TCP(CASES["tcp_reserved_and_nonce"])
        self.assertEqual((nonce.flags, nonce._off_flags), (0x1FF, 0x5FFF))
        self.assertEqual(bytes(nonce), CASES["tcp_reserved_and_nonce"])
        view = tcp.TCP(bytearray(CASES["tcp_options"]))
        self.assertEqual((type(view.opts), view.data), (bytearray, bytearray(b"x")))

    def test_udp_is_a_fixed_header(self):
        datagram = udp.UDP(CASES["udp_ulen_short"])
        self.assertIsInstance(datagram, Packet)
        self.assertEqual((datagram.ulen, datagram.data), (8, b"payload"))
        self.assertEqual(len(udp.UDP(CASES["udp_large"])), 70008)
        with self.assertRaises(NeedData) as result:
            udp.UDP(CASES["udp_short"])
        self.assertEqual(str(result.exception), "got 7, 8 needed at least")
        self.assertEqual(bytes(udp.UDP(data=b"payload"))[4:6], b"\x00\x08")

    def test_keywords_and_layers(self):
        segment = tcp.TCP(sport=1, opts=b"\x01", note="kept")
        self.assertEqual(segment.note, "kept")
        self.assertEqual(len(segment), 21)
        nested = tcp.TCP(data=udp.UDP(data=b"in"))
        self.assertEqual(len(nested), 30)
        self.assertIsInstance(nested[udp.UDP], udp.UDP)
        with self.assertRaises(ValueError):
            tcp.TCP().flags = 0x200
        cycle = udp.UDP()
        cycle.data = cycle
        with self.assertRaises(RecursionError):
            bytes(cycle)

    def test_ipv6_decodes_and_checksums(self):
        packet = ip6.IP6(CASES["ip6_tcp"])
        self.assertIs(packet.tcp, packet.data)
        self.assertEqual(
            ip6.IP6(CASES["ip6_tcp_bad_offset"]).data, CASES["ip6_tcp_bad_offset"][40:]
        )
        datagram = udp.UDP(sport=1, dport=0xFFDB)
        bytes(ip6.IP6(nxt=17, plen=8, data=datagram))
        self.assertNotEqual(datagram.sum, 0)

    def test_native_errors_other_than_header_errors_propagate(self):
        error = MemoryError("allocation")
        with (
            patch.object(tcp._native, "_tcp_layout", side_effect=error),
            self.assertRaises(MemoryError) as result,
        ):
            tcp.TCP(CASES["tcp_plain"])
        self.assertIs(result.exception, error)

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/tcp_udp_differential.py",
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
