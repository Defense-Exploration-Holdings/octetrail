"""PPP and PPPoE on generated offline frames."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, PackError, ethernet, ip, ip6, ppp, pppoe

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ppp_fixture", ROOT / "tools/ppp_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class PppTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("ppp_ip", "ppp_ip6_two_byte", "pppoe_session_ip", "eth_pppoe_session"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_protocol_field_compression(self):
        self.assertIsInstance(ppp.PPP(CASES["ppp_ip"]).ip, ip.IP)
        two = ppp.PPP(CASES["ppp_ip_two_byte"])
        self.assertEqual(two.p, 0x21)
        self.assertIsInstance(ppp.PPP(CASES["ppp_ip6"]).ip6, ip6.IP6)
        self.assertEqual(ppp.PPP(CASES["ppp_lcp"]).p, 0xC021)
        self.assertEqual(ppp.PPP(CASES["ppp_ip_short"]).data, b"\x45\x00")
        with self.assertRaises(NeedData):
            ppp.PPP(CASES["ppp_two_byte_cut"])
        self.assertEqual(bytes(ppp.PPP(p=0xC021, data=b"x")), b"\xff\x03\xc0\x21x")
        with self.assertRaises(PackError):
            bytes(ppp.PPP(p=0x10000))

    def test_pppoe_session_and_discovery(self):
        session = pppoe.PPPoE(CASES["pppoe_session_ip"])
        self.assertIsInstance(session.ppp, pppoe.PPP)
        self.assertIsInstance(session.ppp.ip, ip.IP)
        # As in dpkt, a protocol below 0x100 packs as one byte, and the zero
        # IPv4 checksum is computed.
        packed = bytes(session)
        self.assertEqual(len(packed), len(CASES["pppoe_session_ip"]) - 1)
        self.assertEqual(packed[4:7], b"\x00\x18\x21")
        self.assertNotEqual(session.ppp.ip.sum, 0)
        self.assertEqual(pppoe.PPPoE(CASES["pppoe_padi"]).data, b"\x01\x01\x00\x00")
        self.assertEqual(pppoe.PPPoE(CASES["pppoe_session_cut"]).data, b"\x00")
        bits = pppoe.PPPoE(CASES["pppoe_version_bits"])
        self.assertEqual((bits.v, bits.type), (2, 3))

    def test_ethernet_types(self):
        self.assertIs(ethernet.Ethernet.get_type(ethernet.ETH_TYPE_PPPoE), pppoe.PPPoE)
        self.assertIs(ethernet.Ethernet.get_type(ethernet.ETH_TYPE_PPP), ppp.PPP)
        self.assertNotIn(ethernet.ETH_TYPE_PPPoE_DISC, ethernet.Ethernet._typesw)
        self.assertIsInstance(ethernet.Ethernet(CASES["eth_ppp"]).ppp.ip, ip.IP)

    def test_fragment_offset_error_keeps_inner_ipv6_as_bytes(self):
        for name in ("ppp_fragment_after_hop", "ppp_fragment_after_hop_compressed"):
            packet = ppp.PPP(CASES[name])
            self.assertIsInstance(packet.data, bytes)
            # As in dpkt, packing writes the protocol in one byte when it fits.
            self.assertEqual(bytes(packet), b"\xff\x03\x57" + CASES[name][-len(packet.data) :])
            with self.assertRaises(ip6.FragmentOffsetError):
                ip6.IP6(packet.data)
        self.assertIsInstance(ppp.PPP(CASES["ppp_ip_fragment_after_hop"]).ip.data, bytes)
        self.assertIsInstance(pppoe.PPPoE(CASES["pppoe_fragment_after_hop"]).ppp.data, bytes)
        frame = ethernet.Ethernet(CASES["eth_pppoe_fragment_after_hop"])
        self.assertIsInstance(frame.pppoe.ppp.data, bytes)
        self.assertIsInstance(
            ethernet.Ethernet(CASES["eth_ppp_fragment_after_hop"]).ppp.data, bytes
        )

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/ppp_differential.py",
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
