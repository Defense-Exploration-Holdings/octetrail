"""AH and ESP on dpkt's vectors and generated offline packets."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, ah, esp, ip, ip6, udp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "esp_ah_fixture", ROOT / "tools/esp_ah_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class EspAhTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("ah_dpkt_ip", "ah_ah_ip", "esp_plain", "ip_ah", "ip6_esp"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_dpkt_ah_vectors(self):
        raw = CASES["ah_dpkt_ip"]
        packet = ah.AH(raw)
        self.assertEqual(packet.nxt, 4)
        self.assertIsInstance(packet.data, ip.IP)
        self.assertEqual((len(packet), bytes(packet)), (46, raw))
        other = ah.AH(CASES["ah_dpkt_not_ip"])
        self.assertEqual((other.nxt, type(other.data), len(other)), (0x37, bytes, 46))
        self.assertEqual(bytes(ah.AH()), bytes(12))

    def test_auth_length_and_dispatch(self):
        packet = ah.AH(CASES["ah_words_four"])
        self.assertEqual(packet.auth, b"icv-twelve!!")
        self.assertIsInstance(packet.udp, udp.UDP)
        self.assertEqual(ah.AH(CASES["ah_words_one"]).auth, b"")
        self.assertEqual(ah.AH(CASES["ah_tcp_short"]).data, b"\x00\x50")
        with self.assertRaises(NeedData):
            ah.AH(CASES["ah_short"])

    def test_fragment_offset_error_keeps_inner_ipv6_as_bytes(self):
        raw = CASES["ah_fragment_after_hop"]
        packet = ah.AH(raw)
        self.assertIsInstance(packet.data, bytes)
        self.assertEqual(bytes(packet), raw)
        with self.assertRaises(ip6.FragmentOffsetError):
            ip6.IP6(packet.data)
        self.assertIsInstance(ip.IP(CASES["ip_ah_fragment_after_hop"]).ah.data, bytes)
        self.assertIsInstance(ip6.IP6(CASES["ip6_ah_fragment_after_hop"]).data, bytes)

    def test_ip_tables(self):
        self.assertIs(ip.IP.get_proto(ip.IP_PROTO_AH), ah.AH)
        self.assertIs(ip.IP.get_proto(ip.IP_PROTO_ESP), esp.ESP)
        self.assertIsInstance(ip.IP(CASES["ip_ah"]).ah, ah.AH)
        self.assertEqual(ip.IP(CASES["ip_esp"]).esp.data, b"secret")
        self.assertEqual(ip.IP(CASES["ip_esp_short"]).data, CASES["ip_esp_short"][20:])
        # IPv6 reads AH and ESP as extension headers, as dpkt does.
        self.assertIsInstance(ip6.IP6(CASES["ip6_ah"]).udp, udp.UDP)

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/esp_ah_differential.py",
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
