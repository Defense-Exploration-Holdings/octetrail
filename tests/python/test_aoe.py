"""ATA over Ethernet on dpkt's vectors and Ethernet frames."""

import importlib.util
import unittest
from pathlib import Path

import octetrail
from octetrail import NeedData, aoe, aoeata, aoecfg, ethernet

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("aoe_fixture", ROOT / "tools/aoe_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {k: bytes.fromhex(h) for k, (_, h) in F.cases().items()}


class AoeTests(unittest.TestCase):
    def test_every_case_runs(self):
        report = F.exercise(octetrail)
        self.assertEqual(set(report["cases"]), set(CASES))
        for name in ("aoe_ata", "aoe_cfg", "ethernet_aoe", "ethernet_aoe_ata"):
            self.assertNotIn("error", report["cases"][name], name)

    def test_commands(self):
        self.assertIs(aoe.AOE.get_cmd(aoe.AOE_CMD_ATA), aoeata.AOEATA)
        self.assertIs(aoe.AOE.get_cmd(aoe.AOE_CMD_CFG), aoecfg.AOECFG)
        packet = aoe.AOE(CASES["aoe_ata"])
        self.assertIs(packet.aoeata, packet.data)
        self.assertEqual(bytes(packet), CASES["aoe_ata"])
        # A short command body stays bytes, as in dpkt.
        self.assertIsInstance(aoe.AOE(CASES["aoe_ata_short"]).data, bytes)
        with self.assertRaises(NeedData):
            aoe.AOE(CASES["aoe_short"])

    def test_bits(self):
        packet = aoe.AOE()
        self.assertEqual((packet.ver, packet.fl), (1, 0))
        packet.ver, packet.fl = 2, 12
        self.assertEqual(packet._ver_fl, 0x2C)

    def test_ethernet_decodes_aoe(self):
        frame = ethernet.Ethernet(CASES["ethernet_aoe"])
        self.assertIsInstance(frame.aoe, aoe.AOE)
        self.assertEqual(frame.aoe.aoecfg.data, b"conf")
        self.assertEqual(bytes(frame), CASES["ethernet_aoe"])


if __name__ == "__main__":
    unittest.main()
