"""OSPF and SCTP on dpkt's vectors and generated offline packets."""

import importlib.util
import subprocess
import sys
import time
import tracemalloc
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, crc32c, ip, ip6, ospf, sctp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "ospf_sctp_fixture", ROOT / "tools/ospf_sctp_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class OspfSctpTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("sctp_dpkt_init", "sctp_dpkt_data", "ospf_hello", "ip_sctp", "ip6_ospf"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_dpkt_sctp_vectors(self):
        raw = CASES["sctp_dpkt_init"]
        packet = sctp.SCTP(raw)
        self.assertEqual((packet.sport, packet.dport, len(packet)), (32836, 80, 72))
        self.assertEqual((packet.chunks[0].type, packet.chunks[0].len), (sctp.INIT, 60))
        self.assertEqual(bytes(packet), raw)
        packet.sum = 0
        self.assertEqual(bytes(packet), raw)
        data = CASES["sctp_dpkt_data"]
        chunk = sctp.SCTP(data).chunks[0]
        self.assertEqual((chunk.type, chunk.len, len(chunk)), (sctp.DATA, 419, 420))
        self.assertEqual(chunk.data[-14:], b"keep-alive\r\n\r\n")
        self.assertEqual(bytes(chunk), data[12:])
        malformed = sctp.SCTP(CASES["sctp_dpkt_malformed"])
        self.assertEqual(len(malformed.chunks), 2)
        self.assertEqual((malformed.chunks[1].len, malformed.chunks[1].data), (0, b"\0\0"))
        self.assertEqual(malformed.data, b"")

    def test_bytearray_chunks_keep_their_bytes(self):
        raw = bytearray(CASES["sctp_dpkt_init"])
        expected = bytes(raw[16:72])
        packet = sctp.SCTP(raw)
        raw[16:72] = bytes(56)
        # dpkt copies each chunk while parsing, so a later change to the
        # caller's buffer does not show in the chunk.
        chunk = packet.chunks[0]
        self.assertEqual((type(chunk.data), bytes(chunk.data)), (bytearray, expected))

    def test_short_chunk_is_need_data_and_stays_bytes_inside_ip(self):
        with self.assertRaises(NeedData) as result:
            sctp.SCTP(CASES["sctp_short_chunk"])
        self.assertEqual(str(result.exception), "got 2, 4 needed at least")
        raw = CASES["ip_sctp_short_chunk"]
        self.assertEqual(ip.IP(raw).data, raw[20:])

    def test_overlapping_chunks_parse_in_linear_time(self):
        # Each DATA chunk of length two steps four bytes and holds the rest
        # of the packet but two bytes.
        raw = F.sctp(b"\x00\x02" * 60000 + bytes(4))
        tracemalloc.start()
        try:
            start = time.perf_counter()
            packet = sctp.SCTP(raw)
            elapsed = time.perf_counter() - start
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        # Copying each chunk's data while parsing would allocate about 3.6 GB;
        # slicing it on first use stays far below this bound.
        self.assertLess(peak, 128 * 1024 * 1024)
        self.assertLess(elapsed, 30)
        self.assertEqual(len(packet.chunks), 30001)
        self.assertEqual(packet.chunks[0].data, raw[16:-2])
        self.assertEqual(len(packet.chunks[-2].data), 2)

    def test_dispatch_and_ospf_checksum(self):
        self.assertIs(ip.IP.get_proto(ip.IP_PROTO_SCTP), sctp.SCTP)
        self.assertIs(ip6.IP6.get_proto(ip.IP_PROTO_OSPF), ospf.OSPF)
        self.assertIsInstance(ip.IP(CASES["ip_ospf"]).ospf, ospf.OSPF)
        self.assertIsInstance(ip6.IP6(CASES["ip6_sctp"]).sctp, sctp.SCTP)
        self.assertEqual(bytes(ospf.OSPF()), bytes(12) + b"\xff\xff" + bytes(10))

    def test_crc32c(self):
        self.assertEqual(crc32c.cksum(b""), 0)
        self.assertEqual(crc32c.cksum(b"123456789"), int.from_bytes(b"\x83\x92\x06\xe3", "big"))
        self.assertEqual(crc32c.crc32c_table[1], 0xF26B8303)
        self.assertEqual(crc32c.cksum(bytearray(b"abc")), crc32c.cksum(b"abc"))

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/ospf_sctp_differential.py",
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
