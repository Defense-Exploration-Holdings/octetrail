"""CDP, DTP and EDP on dpkt's vectors and generated offline packets."""

import importlib.util
import subprocess
import sys
import time
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, UnpackError, cdp, dtp, edp, ethernet

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cdp_dtp_edp_fixture", ROOT / "tools/cdp_dtp_edp_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class CdpDtpEdpTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("cdp_dpkt", "eth_cdp_dpkt", "dtp_dpkt", "edp_dpkt", "eth_dtp"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_dpkt_vectors(self):
        raw = CASES["cdp_dpkt"]
        self.assertEqual(bytes(cdp.CDP(raw)), raw)
        frame = ethernet.Ethernet(CASES["eth_cdp_dpkt"])
        self.assertIsInstance(frame.data.data, cdp.CDP)
        self.assertEqual(len(frame.data.data.tlvs), 8)
        self.assertEqual(len(frame), len(CASES["eth_cdp_dpkt"]))
        packet = dtp.DTP(CASES["dtp_dpkt"])
        self.assertEqual((packet.v, packet.data), (4, [(1, b"\x12\x34")]))
        self.assertEqual(bytes(packet), CASES["dtp_dpkt"][1:])
        message = edp.EDP(CASES["edp_dpkt"])
        self.assertEqual((message.hlen, message.sum, message.seq), (316, 40566, 27))
        message.sum = 0
        self.assertEqual(bytes(message), CASES["edp_dpkt"])

    def test_cdp_entries_pack_their_length(self):
        packet = cdp.CDP(CASES["cdp_zero_length"])
        self.assertEqual(packet.tlvs[1], b"\x00\x06\x00\x0erest of it")
        with self.assertRaises(NeedData) as result:
            cdp.CDP(CASES["cdp_address_short"])
        self.assertEqual(str(result.exception), "got 6, 8 needed at least")
        frame = ethernet.Ethernet(CASES["eth_cdp_short_entry"])
        self.assertIsInstance(frame.data.data, bytes)

    def test_dtp_errors(self):
        with self.assertRaises(UnpackError) as result:
            dtp.DTP(CASES["dtp_entry_short"])
        self.assertNotIsInstance(result.exception, NeedData)
        with self.assertRaises(NeedData):
            dtp.DTP(b"")

    def test_long_entry_lists_parse_in_linear_time(self):
        entries = F.tlv(1, 4) * 16000
        start = time.perf_counter()
        self.assertEqual(len(cdp.CDP(F.cdp(entries)).tlvs), 16000)
        self.assertEqual(len(dtp.DTP(b"\x01" + F.tlv(1, 0) * 16000).data), 16000)
        self.assertLess(time.perf_counter() - start, 5)

    def test_ethernet_types(self):
        self.assertIs(ethernet.Ethernet.get_type(ethernet.ETH_TYPE_CDP), cdp.CDP)
        self.assertIs(ethernet.Ethernet.get_type(ethernet.ETH_TYPE_DTP), dtp.DTP)
        self.assertIs(ethernet.Ethernet.get_type(ethernet.ETH_TYPE_EDP), edp.EDP)

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/cdp_dtp_edp_differential.py",
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
