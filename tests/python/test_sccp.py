"""SCCP messages parsed and packed the way dpkt 1.9.8 does."""

import importlib.util
import unittest
from pathlib import Path

from octetrail import NeedData, Packet, sccp

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sccp_fixture", ROOT / "tools/sccp_differential.py")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = {name: bytes.fromhex(wire) for name, wire in F.cases().items()}


class SccpTests(unittest.TestCase):
    def test_dpkt_vector(self):
        message = sccp.SCCP(CASES["dpkt"])
        self.assertIsInstance(message, Packet)
        self.assertEqual(message.msg, b"\xab\xcd\xef\x01")
        self.assertEqual(message.data, b"\x23\x45\x67\x89")
        self.assertIsInstance(message.keypadbutton, sccp.KeypadButton)
        # As in dpkt, msg is a zero-width field: packing leaves it out.
        self.assertEqual(bytes(message), CASES["dpkt"][:12] + message.data)

    def test_messages_decode_by_id(self):
        for name, attribute in (
            ("start_media", "startmediatransmission"),
            ("call_info", "callinfo"),
            ("display_prompt", "displaypromptstatus"),
        ):
            with self.subTest(name=name):
                self.assertTrue(hasattr(sccp.SCCP(CASES[name]), attribute))
        self.assertEqual(sccp.SCCP(CASES["call_info"]).callinfo.calling_party_name[:6], b"caller")

    def test_unknown_and_short_messages_stay_bytes(self):
        for name in ("dpkt_unknown", "unknown", "select_softkeys", "msg_short"):
            with self.subTest(name=name):
                message = sccp.SCCP(CASES[name])
                self.assertFalse([v for v in vars(message).values() if isinstance(v, Packet)])

    def test_length_past_buffer(self):
        with self.assertRaisesRegex(NeedData, "^not enough data$"):
            sccp.SCCP(CASES["dpkt_long"])
        with self.assertRaises(NeedData):
            sccp.SCCP(CASES["short"])

    def test_build(self):
        message = sccp.SCCP(len=8, msgid=sccp.ACTIVATE_CALL_PLANE, msg=b"\x01\x00\x00\x00")
        self.assertEqual(bytes(message), bytes.fromhex("080000000000000016010000"))
        message.data = message.msg
        self.assertEqual(bytes(message), bytes.fromhex("08000000000000001601000001000000"))


if __name__ == "__main__":
    unittest.main()
