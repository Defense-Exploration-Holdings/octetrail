"""Portmap, Rx, TNS, Yahoo Messenger, SMB and RFB on dpkt's vectors."""

import importlib.util
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, PackError, pmap, rfb, rx, smb, tns, yahoo

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "small_apps_fixture", ROOT / "tools/small_apps_differential.py"
)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class SmallAppsTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name, found in report["cases"].items():
            if not name.endswith(("_short", "_cut", "_empty")):
                self.assertNotIn("error", found, name)

    def test_smb_pid(self):
        packet = smb.SMB(CASES["smb_dpkt"])
        self.assertEqual((packet.flags, packet.pid, packet.uid, packet.mid), (8, 31482, 2048, 595))
        built = smb.SMB()
        built.pid = 528416
        self.assertEqual((built._pidhi, built._pidlo), (8, 4128))

    def test_tns_message(self):
        packet = tns.TNS(CASES["tns_with_tail"])
        self.assertTrue(packet.msg.startswith(b"\x014"))
        self.assertEqual(packet.data, b"tail")
        with self.assertRaises(NeedData) as caught:
            tns.TNS(CASES["tns_cut"])
        self.assertEqual(str(caught.exception), "short message (missing 10 bytes)")

    def test_fixed_headers(self):
        self.assertEqual(pmap.Pmap(CASES["pmap_mapping"]).prog, pmap.PMAP_PROG)
        self.assertEqual(rx.Rx(CASES["rx_data"]).flags, rx.LAST_PACKET)
        self.assertEqual(rfb.CutText(CASES["rfb_cut_text"]).data, b"hello")
        self.assertEqual(yahoo.YMSG(CASES["ymsg"]).data, b"hello")
        with self.assertRaises(PackError):
            bytes(yahoo.YHOO())  # As in dpkt, the text defaults are strings.


if __name__ == "__main__":
    unittest.main()
