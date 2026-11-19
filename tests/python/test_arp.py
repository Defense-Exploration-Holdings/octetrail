"""ARP alone and inside Ethernet frames, on generated offline bytes."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, PackError, arp, ethernet

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("arp_fixture", ROOT / "tools/arp_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class ArpTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("request", "ethernet", "vlan", "llc_snap"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_fields_and_round_trip(self):
        message = arp.ARP(CASES["request"])
        self.assertEqual((message.hrd, message.pro, message.op), (1, 0x0800, 1))
        self.assertEqual(
            (message.sha, message.spa, message.tpa), (F.MAC, b"\x0a\0\0\1", b"\x0a\0\0\2")
        )
        self.assertEqual(bytes(message), CASES["request"])
        self.assertEqual(arp.ARP(CASES["reply_with_padding"]).data, bytes(18))
        with self.assertRaises(NeedData):
            arp.ARP(CASES["short"])

    def test_other_address_lengths(self):
        # Hardware 8 bytes, protocol 16 bytes (an IPv6-sized protocol address).
        sha, spa, tha, tpa = b"H" * 8, b"P" * 16, b"h" * 8, b"p" * 16
        raw = b"\x00\x06\x86\xdd\x08\x10\x00\x01" + sha + spa + tha + tpa + b"tail"
        message = arp.ARP(raw)
        self.assertEqual((message.hln, message.pln), (8, 16))
        self.assertEqual((message.sha, message.spa, message.tha, message.tpa), (sha, spa, tha, tpa))
        self.assertEqual(message.data, b"tail")
        self.assertEqual(bytes(message), raw)
        self.assertEqual(len(message), len(raw))
        with self.assertRaises(NeedData):
            arp.ARP(raw[:40])
        message.sha = b"short"
        with self.assertRaises(PackError):
            bytes(message)

    def test_ethernet_decodes_and_infers_arp(self):
        self.assertIsInstance(ethernet.Ethernet(CASES["ethernet"]).arp, arp.ARP)
        self.assertIsInstance(ethernet.Ethernet(CASES["vlan"]).data, arp.ARP)
        self.assertIsInstance(ethernet.Ethernet(CASES["llc_snap"]).llc.arp, arp.ARP)
        self.assertEqual(
            ethernet.Ethernet(CASES["ethernet_short"]).data, CASES["ethernet_short"][14:]
        )
        frame = ethernet.Ethernet(src=F.MAC, data=arp.ARP())
        self.assertEqual(bytes(frame)[12:14], b"\x08\x06")

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/arp_differential.py",
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
