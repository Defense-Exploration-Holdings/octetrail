"""NTP, RIP, TFTP and HSRP on dpkt's vectors and generated messages."""

import importlib.util
import subprocess
import sys
import time
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, UnpackError, hsrp, ntp, rip, tftp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "ntp_rip_tftp_hsrp_fixture", ROOT / "tools/ntp_rip_tftp_hsrp_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class NtpRipTftpHsrpTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("ntp_dpkt", "rip_auth_first", "tftp_rrq", "tftp_err", "hsrp_active"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_ntp_bits(self):
        message = ntp.NTP(CASES["ntp_dpkt"])
        self.assertEqual((message.li, message.v, message.mode), (0, 4, ntp.SERVER))
        self.assertEqual(bytes(message), CASES["ntp_dpkt"])

    def test_rip_entries(self):
        message = rip.RIP(CASES["rip_auth_first"])
        self.assertEqual(message.auth.auth, bytes.fromhex(F.RIP_AUTH)[4:])
        self.assertEqual(len(message.rtes), 1)
        self.assertIs(message.data, message.rtes)
        self.assertEqual(bytes(message), CASES["rip_auth_first"])
        with self.assertRaises(NeedData):
            rip.RIP(CASES["rip_entry_cut"])
        start = time.perf_counter()
        many = rip.RIP(F.rip([F.RIP_RTE] * 20000))
        self.assertEqual(len(many.rtes), 20000)
        self.assertLess(time.perf_counter() - start, 5)

    def test_tftp_requests(self):
        request = tftp.TFTP(CASES["tftp_rrq"])
        self.assertEqual((request.filename, request.mode), (b"rfc1350.txt", b"octet"))
        self.assertEqual(bytes(request), CASES["tftp_rrq"])
        with self.assertRaises(tftp.RequestError) as result:
            tftp.TFTP(CASES["tftp_rrq_no_nul"])
        self.assertIsInstance(result.exception, UnpackError)
        self.assertIsInstance(result.exception, IndexError)
        self.assertEqual(str(result.exception), "list index out of range")
        with self.assertRaises(UnpackError):
            tftp.TFTP(CASES["tftp_data_short"])

    def test_hsrp(self):
        message = hsrp.HSRP(CASES["hsrp_active"])
        self.assertEqual((message.state, message.auth), (hsrp.ACTIVE, b"cisco\0\0\0"))
        self.assertEqual(bytes(hsrp.HSRP())[8:16], b"cisco\0\0\0")

    def test_optimized_probe_rejects_wrong_provider_version(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-O",
                ROOT / "tools/ntp_rip_tftp_hsrp_differential.py",
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
