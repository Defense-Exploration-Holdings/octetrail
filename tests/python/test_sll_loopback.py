"""SLL, SLL2 and loopback headers on dpkt's vectors and generated captures."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, arp, ethernet, ip, ip6, loopback, sll, sll2

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "sll_loopback_fixture", ROOT / "tools/sll_loopback_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class SllLoopbackTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("sll_dpkt", "sll2_dpkt", "loop_ip_little", "loop_ethernet"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_cooked_headers_use_the_ethernet_table(self):
        self.assertIsInstance(sll.SLL(CASES["sll_dpkt"]).ip, ip.IP)
        self.assertEqual(sll.SLL(CASES["sll_dpkt_unknown"]).ethtype, 0x1234)
        self.assertIsInstance(sll.SLL(CASES["sll_arp"]).arp, arp.ARP)
        self.assertEqual(sll.SLL(CASES["sll_ip_short"]).data, b"\x45\x00")
        packet = sll2.SLL2(CASES["sll2_negative_index"])
        self.assertEqual(packet.intindex, -1)
        self.assertIs(sll.SLL._typesw, ethernet.Ethernet._typesw)
        self.assertIs(sll2.SLL2._typesw, ethernet.Ethernet._typesw)

    def test_loopback_families_in_either_byte_order(self):
        for name, family, cls in (
            ("loop_ip_little", 2, ip.IP),
            ("loop_ip_big", 2, ip.IP),
            ("loop_ip6_24", 24, ip6.IP6),
            ("loop_ip6_28_big", 28, ip6.IP6),
            ("loop_ip6_30", 30, ip6.IP6),
            ("loop_ethernet", 0, ethernet.Ethernet),
        ):
            with self.subTest(name=name):
                packet = loopback.Loopback(CASES[name])
                self.assertEqual(packet.family, family)
                self.assertIsInstance(packet.data, cls)
        with self.assertRaises(NeedData):
            loopback.Loopback(CASES["loop_ip_short"])

    def test_fragment_offset_error(self):
        for cls, name in (
            (sll.SLL, "sll_fragment_after_hop"),
            (sll2.SLL2, "sll2_fragment_after_hop"),
        ):
            packet = cls(CASES[name])
            self.assertIsInstance(packet.data, bytes)
            self.assertEqual(bytes(packet), CASES[name])
        self.assertIsInstance(sll.SLL(CASES["sll_ip_fragment_after_hop"]).ip.data, bytes)
        self.assertIsInstance(
            loopback.Loopback(CASES["loop_ip_fragment_after_hop"]).data.data, bytes
        )
        frame = loopback.Loopback(CASES["loop_ethernet_fragment_after_hop"]).data
        self.assertIsInstance(frame.data, bytes)
        with self.assertRaises(octetrail.UnpackError):
            loopback.Loopback(CASES["loop_fragment_after_hop"])

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/sll_loopback_differential.py",
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
