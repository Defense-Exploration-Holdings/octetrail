"""GRE and PIM on dpkt's vectors and generated offline packets."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, UnpackError, gre, ip, ip6, ipx, pim

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "gre_pim_fixture", ROOT / "tools/gre_pim_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class GrePimTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("gre_dpkt_v1", "gre_dpkt_nested_sre", "gre_ipv6", "pim_dpkt", "ip6_gre"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_dpkt_gre_vectors(self):
        packet = gre.GRE(CASES["gre_dpkt_v1"])
        self.assertEqual((packet.v, packet.p, packet.seq, packet.ack), (1, 0x880A, 430001, 539254))
        self.assertEqual((packet.callid, packet.len, packet.data), (6016, 103, b"A" * 103))
        self.assertEqual(
            (len(packet), bytes(packet)), (len(CASES["gre_dpkt_v1"]), CASES["gre_dpkt_v1"])
        )
        nested = gre.GRE(CASES["gre_dpkt_nested_sre"])
        self.assertEqual([s.data for s in nested.sre], [b"\xff\xff", b""])
        self.assertEqual(bytes(nested), CASES["gre_dpkt_nested_sre"])
        carried = gre.GRE(CASES["gre_dpkt_ipx"])
        self.assertIs(carried.ipx, carried.data)
        self.assertIsInstance(carried.data, ipx.IPX)

    def test_gre_errors(self):
        with self.assertRaises(UnpackError) as result:
            gre.GRE(CASES["gre_short_options"])
        self.assertNotIsInstance(result.exception, NeedData)
        self.assertTrue(str(result.exception).startswith("invalid GRE: "))
        with self.assertRaises(NeedData) as result:
            gre.GRE(CASES["gre_sre_missing_end"])
        self.assertEqual(str(result.exception), "got 1, 4 needed at least")
        self.assertEqual(
            ip6.IP6(CASES["ip6_gre_short_options"]).data, CASES["ip6_gre_short_options"][40:]
        )

    def test_ipv4_dispatch_from_protocol_names(self):
        self.assertIs(ip.IP.get_proto(ip.IP_PROTO_GRE), gre.GRE)
        self.assertIs(ip.IP.get_proto(ip.IP_PROTO_PIM), pim.PIM)
        packet = ip.IP(CASES["ip_gre"])
        self.assertEqual((packet.gre.key, packet.gre.ip.p), (5, 59))
        self.assertIsInstance(ip.IP(CASES["ip_pim"]).pim, pim.PIM)
        self.assertEqual(
            ip.IP(CASES["ip_gre_short_options"]).data, CASES["ip_gre_short_options"][20:]
        )

    def test_long_sre_chain_parses_in_linear_time(self):
        raw = F.gre(0x4000, 0x88B5, bytes(4) + b"\x00\x01\x01\x01x" * 50000 + bytes(4) + b"end")
        packet = gre.GRE(raw)
        self.assertEqual((len(packet.sre), packet.data), (50001, b"end"))

    def test_pim_checksum(self):
        message = pim.PIM(CASES["pim_dpkt"])
        message.sum = 0
        self.assertEqual(bytes(message), CASES["pim_dpkt"])
        message.v, message.type = 3, 1
        self.assertEqual(bytes(message)[0], 0x31)
        self.assertIsInstance(ip6.IP6(CASES["ip6_pim"]).pim, pim.PIM)

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/gre_pim_differential.py",
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
