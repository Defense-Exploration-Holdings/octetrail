"""IPv6 and its extension headers, parsed and packed the way dpkt 1.9.8 does."""

import gc
import importlib.util
import io
import struct
import subprocess
import sys
import time
import unittest
from pathlib import Path

from octetrail import (
    NeedData,
    PackError,
    Packet,
    UnpackError,
    ethernet,
    ip,
    ip6,
    pcap,
    raw,
    tcp,
    udp,
)

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ipv6_fixture", ROOT / "tools/ipv6_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
MAC = bytes.fromhex("02aabbccddee02112233445586dd")


def case(name):
    return bytes.fromhex(F.cases()[name])


class IPv6Tests(unittest.TestCase):
    def test_fixture_runs_on_the_installed_package(self):
        import octetrail

        report = F.exercise(octetrail)
        self.assertEqual(report["cases"]["dpkt_tcp"]["data_class"], "TCP")
        self.assertEqual(report["constructed"]["protosw"], [0, 4, 6, 17, 41])

    def test_dpkt_vectors(self):
        s = case("dpkt_tcp")
        packet = ip6.IP6(s)
        self.assertEqual((packet.v, packet.fc, packet.flow, packet.p), (6, 0, 0, 6))
        self.assertIs(packet.tcp, packet.data)
        packet.data.sum = 0
        self.assertEqual(bytes(packet), s)
        self.assertEqual(dict(packet)["src"], s[8:24])
        s = case("dpkt_routing")
        packet = ip6.IP6(s)
        self.assertEqual(len(packet.extension_hdrs[43].addresses), 2)
        self.assertIsInstance(packet.tcp, tcp.TCP)
        self.assertEqual(bytes(packet), s)
        s = case("dpkt_fragment")
        self.assertEqual(bytes(ip6.IP6(s)), s)

    def test_extension_header_classes(self):
        fh = ip6.IP6FragmentHeader(b"\x06\xee\xff\xf9\x00\x00\xff\xff")
        self.assertEqual((fh.nxt, fh.id, fh.frag_off, fh.m_flag), (6, 65535, 8191, 1))
        self.assertIsInstance(fh, Packet)
        s = bytes.fromhex("3b0401020000c910" + "00" * 16 + "0100c2040000000005020000010200" + "00")
        self.assertEqual(len(ip6.IP6OptsHeader(s).options), 3)
        self.assertEqual(bytes(ip6.IP6OptsHeader(s)), s)
        s = b"\x3b\x04\x00\x00\x02\x02\x02\x02\x01\x01\x01\x01" + b"x" * 8
        ah = ip6.IP6AHHeader(s)
        self.assertEqual(
            (ah.length, ah.auth_data, ah.spi, ah.seq), (24, b"x" * 8, 0x2020202, 0x1010101)
        )
        self.assertEqual(bytes(ah), s)
        esp = ip6.IP6ESPHeader(bytes(8) + b"rest")
        self.assertEqual((esp.length, esp.data), (12, b"rest"))
        with self.assertRaisesRegex(NeedData, "got 7, 8 needed at least"):
            ip6.IP6RoutingHeader(bytes(7))
        with self.assertRaises(NeedData):
            ip6.IP6DstOptsHeader(b"\x3b\x00\x05")

    def test_payload_and_dispatch(self):
        self.assertIsInstance(ip6.IP6(case("udp")).udp, udp.UDP)
        self.assertIsInstance(ip6.IP6(case("ipv4_in_ipv6")).ip, ip.IP)
        self.assertIsInstance(ip6.IP6(case("ipv6_in_ipv6")).ip6, ip6.IP6)
        self.assertEqual(ip6.IP6(case("unknown_protocol")).data, b"opaque")
        self.assertEqual(len(ip6.IP6(case("plen_zero_reads_all")).data), 12)
        self.assertEqual(ip6.IP6(case("trailing_bytes")).data.data, b"note")
        self.assertEqual(ip6.IP6(case("version_four")).v, 4)
        self.assertIsInstance(ip6.IP6(case("first_fragment")).data, udp.UDP)
        self.assertIsInstance(ip6.IP6(case("later_fragment")).data, bytes)
        message = "'IP6HopOptsHeader' object has no attribute 'frag_off'"
        for error in (ip6.FragmentOffsetError, UnpackError, AttributeError):
            with self.assertRaisesRegex(error, message):
                ip6.IP6(case("fragment_then_options"))
        frame = ethernet.Ethernet(MAC + case("fragment_then_options"))
        self.assertEqual(frame.data, case("fragment_then_options"))
        packet = ip6.IP6(case("esp"))
        self.assertFalse(hasattr(packet, "p"))
        with self.assertRaises(AttributeError):
            bytes(packet)
        ip6.IP6.set_proto(253, udp.UDP)
        try:
            self.assertIs(ip6.IP6.get_proto(253), udp.UDP)
        finally:
            del ip6.IP6._protosw[253]

    def test_jumbo_udp_payload(self):
        for size in (65535, 65536, 200000):
            datagram = struct.pack(">HHHH", 1000, 53, 0, 0x1234) + b"x" * (size - 8)
            wire = F.base(17, datagram, plen=0)
            packet = ip6.IP6(wire)
            self.assertIsInstance(packet.data, udp.UDP)
            self.assertIs(packet.udp, packet.data)
            self.assertEqual((packet.data.sport, packet.data.sum), (1000, 0x1234))
            self.assertEqual(len(packet.data.data), size - 8)
            self.assertEqual(bytes(packet), wire)
            self.assertIsInstance(ethernet.Ethernet(MAC + wire).data.data, udp.UDP)
        # UDP has no size limit, as in dpkt.
        self.assertEqual(len(udp.UDP(datagram)), 200000)

    def test_jumbo_checksums_use_a_32_bit_length(self):
        def ones_complement(buf):
            buf += b"\0" * (len(buf) % 2)
            total = sum(struct.unpack(">%dH" % (len(buf) // 2), buf))
            while total > 0xFFFF:
                total = (total & 0xFFFF) + (total >> 16)
            return ~total & 0xFFFF

        tcp_header = struct.pack(">HHIIBBHHH", 1, 2, 3, 4, 0x50, 0x10, 100, 0, 0)
        for nxt, transport in (
            (17, struct.pack(">HHHH", 1000, 53, 0, 0)),
            (6, tcp_header),
        ):
            for size in (1000, 65535, 65536, 200000):
                segment = transport + b"x" * (size - len(transport))
                packet = ip6.IP6(F.base(nxt, segment, plen=0))
                packet.data.sum = 0
                wire = bytes(packet)
                src, dst = packet.src, packet.dst
                pseudo = struct.pack(">16s16sI3xB", src, dst, size, nxt)
                self.assertEqual(packet.data.sum, ones_complement(pseudo + segment))
                self.assertEqual(ones_complement(pseudo + wire[40:]), 0)

    def test_layer_lookup(self):
        packet = ip6.IP6(case("udp"))
        self.assertIs(packet[udp.UDP], packet.data)
        self.assertIn(udp.UDP, packet)
        self.assertNotIn(tcp.TCP, packet)
        with self.assertRaises(KeyError):
            packet[tcp.TCP]
        packet = ip6.IP6(case("dpkt_tcp"))
        self.assertIs(packet[tcp.TCP], packet.data)
        self.assertNotIn(udp.UDP, packet)
        inner = ip.IP(src=b"\n\0\0\1", dst=b"\n\0\0\2", p=17, data=udp.UDP(ulen=8))
        packet = ip6.IP6(F.base(4, bytes(inner)))
        self.assertIs(packet[ip.IP], packet.data)
        self.assertIs(packet[udp.UDP], packet.data.data)
        self.assertNotIn(ip6.IP6, packet)

    def test_layer_lookup_through_built_layers(self):
        inner = ip6.IP6(nxt=59)
        packet = ip6.IP6(data=tcp.TCP(data=inner))
        self.assertIn(tcp.TCP, packet)
        self.assertIs(packet[ip6.IP6], inner)
        self.assertIn(ip6.IP6, packet)
        self.assertNotIn(udp.UDP, packet)
        packet = ip6.IP6(data=udp.UDP(data=inner))
        self.assertIn(udp.UDP, packet)
        self.assertIn(ip6.IP6, packet)

    def test_errors_keep_the_headers_read(self):
        with self.assertRaisesRegex(NeedData, "got 39, 40 needed at least"):
            ip6.IP6(case("short_header"))
        packet = ip6.IP6()
        with self.assertRaisesRegex(NeedData, "got 1, 2 needed at least"):
            packet.unpack(case("short_extension"))
        self.assertEqual([type(e) for e in packet.all_extension_headers], [ip6.IP6FragmentHeader])
        self.assertEqual(packet.nxt, 44)
        with self.assertRaises(UnpackError):
            ip6.IP6(case("options_need_data"))

    def test_packing_and_checksums(self):
        packet = ip6.IP6(src=F.SRC, dst=F.DST, nxt=17, data=udp.UDP(F.UDP))
        wire = bytes(packet)
        self.assertEqual(packet.p, 17)
        self.assertNotEqual(packet.data.sum, 0)
        self.assertEqual(wire[:6], b"\x60\0\0\0\0\0")
        self.assertEqual(len(packet), 40 + len(F.UDP))
        pseudo = struct.pack(">16s16sxBH", F.SRC, F.DST, 17, len(F.UDP))
        total = sum(
            struct.unpack(">%dH" % ((len(pseudo) + len(wire[40:])) // 2), pseudo + wire[40:])
        )
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        self.assertEqual(total, 0xFFFF)
        with self.assertRaises(PackError):
            bytes(ip6.IP6(src="text"))
        with self.assertRaises(ValueError):
            ip6.IP6(flow=1 << 20)
        packet = ip6.IP6(src=F.SRC, dst=F.DST, data=b"x")
        packet.extension_hdrs = {
            60: ip6.IP6DstOptsHeader(F.opts(17)),
            0: ip6.IP6HopOptsHeader(F.opts(60)),
        }
        self.assertEqual(bytes(packet)[40:], F.opts(60) + F.opts(17) + b"x")
        self.assertEqual(packet.p, 17)

    def test_ah_data_is_copied_on_first_use(self):
        packet = ip6.IP6(case("ah_chain"))
        first = packet.all_extension_headers[0]
        self.assertNotIn("auth_data", vars(first))
        self.assertEqual(first.auth_data, b"xxxxxxxx")
        self.assertEqual(first.data, case("ah_chain")[52:])
        second = packet.all_extension_headers[1]
        second.data = b"new"
        self.assertEqual((second.data, second.auth_data), (b"new", b"xxxxxxxx"))
        self.assertIn("length=20, auth_data=b'xxxxxxxx'", repr(packet.all_extension_headers[2]))
        with self.assertRaisesRegex(AttributeError, "'IP6AHHeader' object has no attribute 'note'"):
            first.note  # noqa: B018

    def test_long_chains_parse_in_linear_time(self):
        def chain(count):
            body = b"".join(F.ah(51, b"") for _ in range(count)) + F.ah(59, b"")
            return F.base(51, body, plen=0)

        def parse(count):
            raw = chain(count)
            # The fastest of a few runs, with the collector paused, keeps a
            # slow or busy runner's pauses out of the comparison.
            best = None
            gc.collect()
            gc.disable()
            try:
                for _ in range(3):
                    start = time.perf_counter()
                    packet = ip6.IP6(raw)
                    elapsed = time.perf_counter() - start
                    best = elapsed if best is None else min(best, elapsed)
            finally:
                gc.enable()
            return packet, best

        small, small_time = parse(1000)
        large, large_time = parse(16000)
        self.assertEqual(len(large.all_extension_headers), 16001)
        self.assertEqual(len(small.all_extension_headers), 1001)
        # 16 times the headers: linear parsing takes about 16 to 21 times as
        # long and quadratic parsing 256 times. The bound sits between the two.
        self.assertLess(large_time, max(small_time, 0.001) * 80)

    def test_raw_ethernet_and_captures(self):
        wire = case("udp")
        self.assertIsInstance(raw.decode(wire), ip6.IP6)
        captured = case("dpkt_tcp")
        frame = ethernet.Ethernet(MAC + captured)
        self.assertIs(frame.ip6, frame.data)
        self.assertEqual(bytes(frame), MAC + captured)
        capture = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
        capture += struct.pack("<IIII", 1, 0, len(wire), len(wire)) + wire
        rows = list(pcap.Reader(io.BytesIO(capture)))
        self.assertEqual(rows, [(1.0, wire)])
        self.assertIsInstance(raw.decode(rows[0][1]).data, udp.UDP)

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
