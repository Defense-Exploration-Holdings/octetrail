"""QQ headers parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, qq

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("qq_fixture", ROOT / "tools/qq_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class QqTests(unittest.TestCase):
    def test_basic(self):
        packet = qq.QQBasicPacket(F.BASIC + b"payload")
        self.assertIsInstance(packet, Packet)
        self.assertEqual((packet.header_type, packet.source), (2, 0x0F5A))
        self.assertEqual((packet.command, packet.qqNum), (qq.QQ_CMD_LOGIN, 123456))
        self.assertEqual(packet.data, b"payload")
        self.assertEqual(bytes(packet), F.BASIC + b"payload")

    def test_qq3_and_qq5(self):
        self.assertEqual(qq.QQ3Packet(F.QQ3).source, 0x0F5A)
        self.assertEqual(qq.QQ5Packet(F.QQ5).qqNum, 654321)
        self.assertEqual(len(qq.QQ3Packet()), 46)

    def test_short(self):
        for cls, raw in ((qq.QQBasicPacket, F.BASIC[:10]), (qq.QQ5Packet, b"")):
            with self.subTest(cls=cls.__name__), self.assertRaises(NeedData):
                cls(raw)

    def test_command_table(self):
        self.assertEqual(qq.command_str[qq.QQ_CMD_SEND_IM], "QQ_CMD_SEND_IM")


if __name__ == "__main__":
    unittest.main()
